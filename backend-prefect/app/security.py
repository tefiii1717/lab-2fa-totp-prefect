import hashlib
import hmac
import os
import secrets
import time
import uuid

import jwt

from . import config

PBKDF2_ITERATIONS = 200_000

# Scopes de los tokens (Step-Up Authentication)
SCOPE_PRE_AUTH = "pre_auth"  # solo sirve para POST /auth/verify-2fa
SCOPE_BASIC = "basic"        # usuario sin 2FA activo: solo puede configurarlo
SCOPE_ACCESS = "access"      # sesión elevada tras el segundo factor


def hash_password(password: str) -> str:
    salt = os.urandom(16)
    dk = hashlib.pbkdf2_hmac("sha256", password.encode(), salt, PBKDF2_ITERATIONS)
    return f"pbkdf2_sha256${PBKDF2_ITERATIONS}${salt.hex()}${dk.hex()}"


def verify_password(password: str, stored: str) -> bool:
    try:
        _, iterations, salt_hex, hash_hex = stored.split("$")
    except ValueError:
        return False
    dk = hashlib.pbkdf2_hmac("sha256", password.encode(), bytes.fromhex(salt_hex), int(iterations))
    return hmac.compare_digest(dk.hex(), hash_hex)


def generate_backup_code() -> str:
    raw = secrets.token_hex(4).upper()
    return f"{raw[:4]}-{raw[4:]}"


def normalize_backup_code(code: str) -> str:
    return code.strip().replace("-", "").replace(" ", "").upper()


def hash_backup_code(code: str) -> str:
    return hashlib.sha256(normalize_backup_code(code).encode()).hexdigest()


def create_token(user: dict, scope: str, ttl_seconds: int, **claims) -> tuple[str, dict]:
    now = int(time.time())
    payload = {
        "sub": str(user["id"]),
        "username": user["username"],
        "scope": scope,
        "jti": uuid.uuid4().hex,
        "iat": now,
        "exp": now + ttl_seconds,
        **claims,
    }
    return jwt.encode(payload, config.JWT_SECRET, algorithm=config.JWT_ALGORITHM), payload


def decode_token(token: str, expected_scopes: set[str]) -> dict:
    """Lanza jwt.InvalidTokenError si la firma, la expiración o el scope no son válidos."""
    payload = jwt.decode(token, config.JWT_SECRET, algorithms=[config.JWT_ALGORITHM])
    if payload.get("scope") not in expected_scopes:
        raise jwt.InvalidTokenError(f"Scope '{payload.get('scope')}' no permitido aquí")
    return payload
