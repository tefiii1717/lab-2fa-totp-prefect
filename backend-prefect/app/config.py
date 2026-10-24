import os
import secrets
from pathlib import Path

from dotenv import load_dotenv

BASE_DIR = Path(__file__).resolve().parent.parent
load_dotenv(BASE_DIR / ".env")

# Si no se define JWT_SECRET, se genera uno por arranque (los tokens mueren al reiniciar).
JWT_SECRET = os.getenv("JWT_SECRET") or secrets.token_urlsafe(48)
JWT_ALGORITHM = "HS256"

ISSUER = os.getenv("TOTP_ISSUER", "LabPatrones2FA")

PRE_AUTH_TTL_SECONDS = int(os.getenv("PRE_AUTH_TTL_SECONDS", "300"))
ACCESS_TTL_SECONDS = int(os.getenv("ACCESS_TTL_SECONDS", "900"))
MAX_2FA_ATTEMPTS = int(os.getenv("MAX_2FA_ATTEMPTS", "5"))

# Ventana anti-replay: 3 pasos de 30 s (C-1, C, C+1).
ANTI_REPLAY_TTL_SECONDS = int(os.getenv("ANTI_REPLAY_TTL_SECONDS", "90"))
BACKUP_CODES_COUNT = int(os.getenv("BACKUP_CODES_COUNT", "8"))

# "sqlite" (por defecto) o "supabase"
DB_BACKEND = os.getenv("DB_BACKEND", "sqlite").lower()
SQLITE_PATH = os.getenv("SQLITE_PATH", str(BASE_DIR / "lab2fa.db"))
SUPABASE_URL = os.getenv("SUPABASE_URL", "")
SUPABASE_KEY = os.getenv("SUPABASE_SERVICE_ROLE_KEY", "")
