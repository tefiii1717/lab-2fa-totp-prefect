from datetime import datetime, timezone
from typing import Literal

import jwt
from fastapi import Depends, FastAPI, HTTPException, status
from fastapi.responses import JSONResponse
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field, SecretStr

from . import config
from .flows import (
    EnrollmentError,
    InvalidCredentials,
    InvalidPreAuthToken,
    InvalidSecondFactor,
    ReplayAttackDetected,
    confirm_enrollment_flow,
    login_flow,
    start_enrollment_flow,
    verify_2fa_flow,
)
from .repository import UsernameTaken, get_repository
from .security import SCOPE_ACCESS, SCOPE_BASIC, decode_token, hash_password
from .state_machine import InvalidStateTransition

app = FastAPI(title="Lab 2FA TOTP + Prefect", version="1.0.0")
bearer = HTTPBearer(auto_error=False)


# Cada excepción de dominio que sale de un flow se traduce a un código HTTP.
ERROR_STATUS = {
    InvalidCredentials: status.HTTP_401_UNAUTHORIZED,
    InvalidPreAuthToken: status.HTTP_401_UNAUTHORIZED,
    InvalidSecondFactor: status.HTTP_401_UNAUTHORIZED,
    ReplayAttackDetected: status.HTTP_409_CONFLICT,
    EnrollmentError: status.HTTP_409_CONFLICT,
    InvalidStateTransition: status.HTTP_409_CONFLICT,
}


for exc_type, http_status in ERROR_STATUS.items():
    def _handler(_request, exc, http_status=http_status):
        return JSONResponse(
            status_code=http_status,
            content={"detail": str(exc), "error": type(exc).__name__},
        )

    app.add_exception_handler(exc_type, _handler)


class Credentials(BaseModel):
    username: str = Field(min_length=3, max_length=50)
    password: SecretStr = Field(min_length=6)


class CodeIn(BaseModel):
    code: SecretStr


class Verify2FAIn(BaseModel):
    pre_auth_token: SecretStr
    code: SecretStr
    method: Literal["totp", "backup"] = "totp"


def require_token(scopes: set[str], require_mfa: bool = False):
    def dependency(creds: HTTPAuthorizationCredentials | None = Depends(bearer)) -> dict:
        if creds is None:
            raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Falta el header Authorization: Bearer <token>")
        try:
            claims = decode_token(creds.credentials, scopes)
        except jwt.InvalidTokenError as exc:
            raise HTTPException(status.HTTP_401_UNAUTHORIZED, f"Token inválido: {exc}") from exc
        if require_mfa and claims.get("mfa_verified") is not True:
            raise HTTPException(status.HTTP_403_FORBIDDEN, "Se requiere autenticación con segundo factor")
        return claims

    return dependency


@app.post("/auth/register", status_code=status.HTTP_201_CREATED)
def register(body: Credentials):
    try:
        user = get_repository().create_user(body.username, hash_password(body.password.get_secret_value()))
    except UsernameTaken:
        raise HTTPException(status.HTTP_409_CONFLICT, "Ese usuario ya existe") from None
    return {"id": user["id"], "username": user["username"], "twofa_status": user["twofa_status"]}


@app.post("/auth/login")
def login(body: Credentials):
    return login_flow(body.username, body.password)


@app.post("/auth/2fa/setup")
def setup_2fa(claims: dict = Depends(require_token({SCOPE_BASIC}))):
    return start_enrollment_flow(int(claims["sub"]))


@app.post("/auth/2fa/confirm")
def confirm_2fa(body: CodeIn, claims: dict = Depends(require_token({SCOPE_BASIC}))):
    return confirm_enrollment_flow(int(claims["sub"]), body.code)


@app.post("/auth/verify-2fa")
def verify_2fa(body: Verify2FAIn):
    return verify_2fa_flow(body.pre_auth_token, body.code, body.method)


@app.get("/api/me")
def me(claims: dict = Depends(require_token({SCOPE_BASIC, SCOPE_ACCESS}))):
    user = get_repository().get_user(int(claims["sub"]))
    if not user:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Usuario no encontrado")
    return {
        "id": user["id"],
        "username": user["username"],
        "twofa_status": user["twofa_status"],
        "backup_codes_left": get_repository().count_unused_backup_codes(user["id"]),
        "token_claims": claims,
    }


@app.get("/api/boveda-secreta")
def boveda_secreta(claims: dict = Depends(require_token({SCOPE_BASIC, SCOPE_ACCESS}, require_mfa=True))):
    return {
        "mensaje": f"Bienvenido a la bóveda, {claims['username']}. Superaste el Step-Up con 2FA.",
        "secreto": "La respuesta es 42.",
        "amr": claims.get("amr"),
        "servido_en": datetime.now(timezone.utc).isoformat(),
    }


@app.get("/health")
def health():
    return {"status": "ok", "db_backend": config.DB_BACKEND}


# Web app de login (estática) en la raíz.
app.mount("/", StaticFiles(directory=config.BASE_DIR / "web", html=True), name="web")
