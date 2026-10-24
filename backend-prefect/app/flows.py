"""Flows y tasks de Prefect: cada paso del pipeline de seguridad es observable en la UI.

Los parámetros sensibles (contraseña, tokens, códigos) se tipan como SecretStr para
que Prefect los muestre ofuscados, y las tasks usan NO_CACHE para que un resultado
nunca se reutilice entre ejecuciones.
"""

import base64
import io

import jwt
import qrcode
from prefect import flow, get_run_logger, task
from prefect.cache_policies import NO_CACHE
from pydantic import SecretStr

from . import config
from .anti_replay import anti_replay_cache, pre_auth_sessions
from .repository import get_repository
from .security import (
    SCOPE_ACCESS,
    SCOPE_BASIC,
    SCOPE_PRE_AUTH,
    create_token,
    decode_token,
    generate_backup_code,
    hash_backup_code,
    normalize_backup_code,
    verify_password,
)
from .state_machine import TwoFactorStatus, transition
from .strategies import TOTPStrategy, get_strategy
from .totp import build_otpauth_uri, generate_secret


class InvalidCredentials(Exception):
    pass


class InvalidPreAuthToken(Exception):
    pass


class ReplayAttackDetected(Exception):
    pass


class InvalidSecondFactor(Exception):
    pass


class EnrollmentError(Exception):
    pass


def _mask(code: str) -> str:
    return code[:2] + "*" * max(len(code) - 2, 0)


def _replay_key(method: str, code: str) -> str:
    return f"{method}:{normalize_backup_code(code) if method == 'backup' else code.strip()}"


# ---------------------------------------------------------------------------
# Login (primer factor) -> pre_auth_token
# ---------------------------------------------------------------------------

@task(name="verify_credentials", cache_policy=NO_CACHE)
def verify_credentials(username: str, password: SecretStr) -> dict:
    logger = get_run_logger()
    user = get_repository().get_user_by_username(username)
    if not user or not verify_password(password.get_secret_value(), user["password_hash"]):
        logger.warning("Credenciales inválidas para '%s'", username)
        raise InvalidCredentials("Usuario o contraseña incorrectos")
    logger.info("Primer factor OK para '%s' (estado 2FA: %s)", username, user["twofa_status"])
    return user


@task(name="issue_pre_auth_token", cache_policy=NO_CACHE)
def issue_pre_auth_token(user: dict) -> dict:
    logger = get_run_logger()
    if user["twofa_status"] == TwoFactorStatus.ACTIVE.value:
        token, payload = create_token(user, SCOPE_PRE_AUTH, config.PRE_AUTH_TTL_SECONDS, mfa_verified=False)
        pre_auth_sessions.register(payload["jti"], payload["exp"])
        logger.info("Step-Up requerido: pre_auth_token emitido (solo válido para /auth/verify-2fa)")
        return {"status": "MFA_REQUIRED", "pre_auth_token": token, "expires_in": config.PRE_AUTH_TTL_SECONDS}

    token, _ = create_token(user, SCOPE_BASIC, config.ACCESS_TTL_SECONDS, mfa_verified=False)
    logger.info("2FA no activo (%s): token básico emitido, solo permite configurar 2FA", user["twofa_status"])
    return {"status": "MFA_SETUP_REQUIRED", "access_token": token, "twofa_status": user["twofa_status"]}


@flow(name="login-flow")
def login_flow(username: str, password: SecretStr) -> dict:
    user = verify_credentials(username, password)
    return issue_pre_auth_token(user)


# ---------------------------------------------------------------------------
# Verificación del segundo factor (Step-Up) -> access_token con mfa_verified
# ---------------------------------------------------------------------------

@task(name="validate_pre_auth_state", cache_policy=NO_CACHE)
def validate_pre_auth_state(pre_auth_token: SecretStr) -> dict:
    logger = get_run_logger()
    try:
        claims = decode_token(pre_auth_token.get_secret_value(), {SCOPE_PRE_AUTH})
    except jwt.InvalidTokenError as exc:
        logger.error("pre_auth_token rechazado: %s", exc)
        raise InvalidPreAuthToken(f"pre_auth_token inválido: {exc}") from exc

    session = pre_auth_sessions.get(claims["jti"])
    if session is None:
        raise InvalidPreAuthToken("pre_auth_token desconocido (¿se reinició el servidor?)")
    if session["consumed"]:
        raise InvalidPreAuthToken("pre_auth_token ya fue utilizado; inicia sesión de nuevo")
    if session["attempts"] >= config.MAX_2FA_ATTEMPTS:
        raise InvalidPreAuthToken("Demasiados intentos fallidos; inicia sesión de nuevo")

    user = get_repository().get_user(int(claims["sub"]))
    if not user or user["twofa_status"] != TwoFactorStatus.ACTIVE.value:
        raise InvalidPreAuthToken("El usuario no tiene 2FA activo")

    logger.info(
        "Estado intermedio válido: usuario '%s', intento %d/%d",
        user["username"], session["attempts"] + 1, config.MAX_2FA_ATTEMPTS,
    )
    return {"user": user, "jti": claims["jti"]}


@task(name="check_anti_replay_cache", cache_policy=NO_CACHE)
def check_anti_replay_cache(user_id: int, code: SecretStr, method: str) -> None:
    logger = get_run_logger()
    key = _replay_key(method, code.get_secret_value())
    if anti_replay_cache.was_used(user_id, key):
        logger.error(
            "REPLAY ATTACK: el código %s del usuario %s ya se usó en los últimos %d s",
            _mask(code.get_secret_value()), user_id, config.ANTI_REPLAY_TTL_SECONDS,
        )
        raise ReplayAttackDetected("Este código ya fue utilizado. Espera el siguiente código.")
    logger.info("Código %s no visto en los últimos %d s", _mask(code.get_secret_value()), config.ANTI_REPLAY_TTL_SECONDS)


@task(name="execute_mfa_strategy", cache_policy=NO_CACHE)
def execute_mfa_strategy(user: dict, code: SecretStr, method: str, jti: str | None = None) -> dict:
    logger = get_run_logger()
    strategy = get_strategy(method, get_repository())
    logger.info("Estrategia seleccionada: %s", type(strategy).__name__)

    result = strategy.verify(user, code.get_secret_value())
    if not result.ok:
        if jti:
            attempts = pre_auth_sessions.record_failure(jti)
            logger.warning("Intento fallido %d/%d", attempts, config.MAX_2FA_ATTEMPTS)
        logger.error("%s", result.detail)
        raise InvalidSecondFactor(result.detail)

    if result.window_offset is not None:
        logger.info("MATCH en la ventana %s", result.window_label)
    else:
        logger.info("%s", result.detail)
    return {"method": result.method, "window": result.window_label, "detail": result.detail}


@task(name="issue_elevated_session", cache_policy=NO_CACHE)
def issue_elevated_session(user: dict, code: SecretStr, method: str, jti: str) -> dict:
    logger = get_run_logger()
    # mark_used es atómico: si dos requests con el mismo código llegan a la vez, solo uno pasa.
    if not anti_replay_cache.mark_used(user["id"], _replay_key(method, code.get_secret_value())):
        logger.error("REPLAY ATTACK detectado en carrera concurrente")
        raise ReplayAttackDetected("Este código ya fue utilizado. Espera el siguiente código.")
    if not pre_auth_sessions.consume(jti):
        raise InvalidPreAuthToken("pre_auth_token ya fue utilizado")

    token, payload = create_token(
        user, SCOPE_ACCESS, config.ACCESS_TTL_SECONDS, mfa_verified=True, amr=["pwd", method]
    )
    logger.info("Código marcado como usado. Access token emitido con mfa_verified=true (exp %s)", payload["exp"])
    return {"access_token": token, "token_type": "bearer", "expires_in": config.ACCESS_TTL_SECONDS}


@flow(name="verify-2fa-flow")
def verify_2fa_flow(pre_auth_token: SecretStr, code: SecretStr, method: str = "totp") -> dict:
    state = validate_pre_auth_state(pre_auth_token)
    user = state["user"]
    check_anti_replay_cache(user["id"], code, method)
    result = execute_mfa_strategy(user, code, method, state["jti"])
    session = issue_elevated_session(user, code, method, state["jti"])
    return {**session, "method": result["method"], "window": result["window"]}


# ---------------------------------------------------------------------------
# Aprovisionamiento (Process Manager): DISABLED -> PENDING_VERIFICATION -> ACTIVE
# ---------------------------------------------------------------------------

@task(name="generate_totp_secret", cache_policy=NO_CACHE)
def generate_totp_secret(user: dict) -> str:
    logger = get_run_logger()
    if user["twofa_status"] == TwoFactorStatus.ACTIVE.value:
        raise EnrollmentError("El 2FA ya está activo para este usuario")
    logger.info("Generando semilla TOTP de 160 bits para '%s'", user["username"])
    return generate_secret()


@task(name="persist_pending_state", cache_policy=NO_CACHE)
def persist_pending_state(user: dict, secret: str) -> str:
    new_state = transition(user["twofa_status"], TwoFactorStatus.PENDING_VERIFICATION)
    get_repository().update_two_factor(user["id"], new_state, secret)
    get_run_logger().info("Estado 2FA: %s -> %s", user["twofa_status"], new_state.value)
    return new_state.value


@task(name="build_provisioning_qr", cache_policy=NO_CACHE)
def build_provisioning_qr(username: str, secret: str) -> dict:
    uri = build_otpauth_uri(secret, username, config.ISSUER)
    buffer = io.BytesIO()
    qrcode.make(uri).save(buffer, format="PNG")
    get_run_logger().info("QR otpauth:// generado para '%s'", username)
    return {"otpauth_uri": uri, "qr_png_base64": base64.b64encode(buffer.getvalue()).decode()}


@flow(name="2fa-enrollment-start-flow")
def start_enrollment_flow(user_id: int) -> dict:
    user = get_repository().get_user(user_id)
    secret = generate_totp_secret(user)
    status = persist_pending_state(user, secret)
    qr = build_provisioning_qr(user["username"], secret)
    return {"status": status, "secret": secret, **qr}


@task(name="load_pending_enrollment", cache_policy=NO_CACHE)
def load_pending_enrollment(user_id: int) -> dict:
    user = get_repository().get_user(user_id)
    if not user or user["twofa_status"] != TwoFactorStatus.PENDING_VERIFICATION.value:
        raise EnrollmentError("No hay un aprovisionamiento 2FA pendiente; genera el QR primero")
    get_run_logger().info("Aprovisionamiento pendiente encontrado para '%s'", user["username"])
    return user


@task(name="activate_two_factor", cache_policy=NO_CACHE)
def activate_two_factor(user: dict, code: SecretStr) -> str:
    anti_replay_cache.mark_used(user["id"], _replay_key("totp", code.get_secret_value()))
    new_state = transition(user["twofa_status"], TwoFactorStatus.ACTIVE)
    get_repository().update_two_factor(user["id"], new_state, user["totp_secret"])
    get_run_logger().info("Estado 2FA: %s -> %s", user["twofa_status"], new_state.value)
    return new_state.value


@task(name="generate_backup_codes", cache_policy=NO_CACHE)
def generate_backup_codes(user: dict) -> list[str]:
    codes = [generate_backup_code() for _ in range(config.BACKUP_CODES_COUNT)]
    get_repository().replace_backup_codes(user["id"], [hash_backup_code(c) for c in codes])
    get_run_logger().info("%d códigos de respaldo generados (se guardan solo sus hashes)", len(codes))
    return codes


@flow(name="2fa-enrollment-confirm-flow")
def confirm_enrollment_flow(user_id: int, code: SecretStr) -> dict:
    user = load_pending_enrollment(user_id)
    check_anti_replay_cache(user["id"], code, "totp")
    result = execute_mfa_strategy(user, code, TOTPStrategy.name)
    status = activate_two_factor(user, code)
    backup_codes = generate_backup_codes(user)
    return {"status": status, "window": result["window"], "backup_codes": backup_codes}
