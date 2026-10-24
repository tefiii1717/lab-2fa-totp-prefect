"""TOTP (RFC 6238) implementado desde cero sobre HMAC-SHA1 (RFC 4226).

Solo se usa la librería estándar: `hmac`/`hashlib` para el hash y `base64`
para Base32. No se usa ninguna librería que entregue el código ya calculado.
"""

import base64
import hashlib
import hmac
import secrets
import struct
import time
from urllib.parse import quote, urlencode

DIGITS = 6
PERIOD = 30


def generate_secret(num_bytes: int = 20) -> str:
    """Semilla aleatoria de 160 bits codificada en Base32 (sin padding)."""
    return base64.b32encode(secrets.token_bytes(num_bytes)).decode("ascii").rstrip("=")


def b32decode(secret: str) -> bytes:
    cleaned = secret.strip().replace(" ", "").replace("-", "").upper()
    cleaned += "=" * (-len(cleaned) % 8)
    return base64.b32decode(cleaned)


def hotp(key: bytes, counter: int, digits: int = DIGITS) -> str:
    # 1) HMAC-SHA1 del contador como entero big-endian de 8 bytes
    digest = hmac.new(key, struct.pack(">Q", counter), hashlib.sha1).digest()
    # 2) Truncamiento dinámico: los 4 bits bajos del último byte dan el offset
    offset = digest[-1] & 0x0F
    binary = struct.unpack(">I", digest[offset:offset + 4])[0] & 0x7FFFFFFF
    # 3) Reducción a N dígitos con ceros a la izquierda
    return str(binary % (10 ** digits)).zfill(digits)


def time_step(timestamp: float | None = None, period: int = PERIOD) -> int:
    """Contador C = floor(UnixTime / 30)."""
    return int((time.time() if timestamp is None else timestamp) // period)


def totp(secret: str, timestamp: float | None = None, digits: int = DIGITS) -> str:
    return hotp(b32decode(secret), time_step(timestamp), digits)


def build_otpauth_uri(secret: str, account: str, issuer: str) -> str:
    """URI compatible con Google/Microsoft Authenticator (Key Uri Format)."""
    label = quote(f"{issuer}:{account}")
    params = urlencode(
        {"secret": secret, "issuer": issuer, "algorithm": "SHA1", "digits": DIGITS, "period": PERIOD}
    )
    return f"otpauth://totp/{label}?{params}"
