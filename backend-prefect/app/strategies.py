"""Strategy Pattern para el segundo factor."""

import hmac
import time
from abc import ABC, abstractmethod
from dataclasses import dataclass
from typing import Callable

from .repository import UserRepository
from .security import hash_backup_code, normalize_backup_code
from .totp import b32decode, hotp, time_step

WINDOW_LABELS = {
    -1: "C-1 (el reloj del celular va ~30 s ATRASADO)",
    0: "C (reloj sincronizado)",
    1: "C+1 (el reloj del celular va ~30 s ADELANTADO)",
}


@dataclass
class VerificationResult:
    ok: bool
    method: str
    detail: str
    window_offset: int | None = None

    @property
    def window_label(self) -> str | None:
        return None if self.window_offset is None else WINDOW_LABELS[self.window_offset]


class SecondFactorStrategy(ABC):
    name: str

    @abstractmethod
    def verify(self, user: dict, code: str) -> VerificationResult: ...


class TOTPStrategy(SecondFactorStrategy):
    name = "totp"

    def __init__(self, clock: Callable[[], float] = time.time):
        self.clock = clock

    def verify(self, user, code):
        code = code.strip()
        if not (len(code) == 6 and code.isdigit()):
            return VerificationResult(False, self.name, "El código TOTP debe tener 6 dígitos")
        if not user.get("totp_secret"):
            return VerificationResult(False, self.name, "El usuario no tiene secreto TOTP")

        key = b32decode(user["totp_secret"])
        current = time_step(self.clock())
        # Se evalúa primero la ventana actual y luego las adyacentes (tolerancia ±1 paso).
        for offset in (0, -1, 1):
            if hmac.compare_digest(hotp(key, current + offset), code):
                return VerificationResult(True, self.name, "Código TOTP válido", window_offset=offset)
        return VerificationResult(False, self.name, "Código TOTP incorrecto en las ventanas C-1, C y C+1")


class BackupCodeStrategy(SecondFactorStrategy):
    name = "backup"

    def __init__(self, repository: UserRepository):
        self.repository = repository

    def verify(self, user, code):
        if len(normalize_backup_code(code)) != 8:
            return VerificationResult(False, self.name, "Formato de código de respaldo inválido")
        if self.repository.consume_backup_code(user["id"], hash_backup_code(code)):
            remaining = self.repository.count_unused_backup_codes(user["id"])
            return VerificationResult(True, self.name, f"Código de respaldo consumido; quedan {remaining}")
        return VerificationResult(False, self.name, "Código de respaldo inválido o ya utilizado")


def get_strategy(method: str, repository: UserRepository) -> SecondFactorStrategy:
    strategies: dict[str, Callable[[], SecondFactorStrategy]] = {
        TOTPStrategy.name: TOTPStrategy,
        BackupCodeStrategy.name: lambda: BackupCodeStrategy(repository),
    }
    try:
        return strategies[method]()
    except KeyError:
        raise ValueError(f"Método de segundo factor desconocido: {method}") from None
