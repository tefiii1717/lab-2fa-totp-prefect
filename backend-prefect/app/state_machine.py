"""Máquina de estados del aprovisionamiento 2FA (Process Manager).

DISABLED ──setup──▶ PENDING_VERIFICATION ──primer código válido──▶ ACTIVE
                         │  ▲
                         └──┘ setup de nuevo (regenera el QR)

El secreto solo se vuelve obligatorio en el login cuando el estado es ACTIVE,
así un usuario que genera el QR y nunca lo escanea no queda bloqueado.
"""

from enum import Enum


class TwoFactorStatus(str, Enum):
    DISABLED = "DISABLED"
    PENDING_VERIFICATION = "PENDING_VERIFICATION"
    ACTIVE = "ACTIVE"


ALLOWED_TRANSITIONS: dict[TwoFactorStatus, set[TwoFactorStatus]] = {
    TwoFactorStatus.DISABLED: {TwoFactorStatus.PENDING_VERIFICATION},
    TwoFactorStatus.PENDING_VERIFICATION: {
        TwoFactorStatus.PENDING_VERIFICATION,
        TwoFactorStatus.ACTIVE,
        TwoFactorStatus.DISABLED,
    },
    TwoFactorStatus.ACTIVE: {TwoFactorStatus.DISABLED},
}


class InvalidStateTransition(Exception):
    pass


def transition(current: str | TwoFactorStatus, target: TwoFactorStatus) -> TwoFactorStatus:
    current = TwoFactorStatus(current)
    if target not in ALLOWED_TRANSITIONS[current]:
        raise InvalidStateTransition(f"Transición no permitida: {current.value} -> {target.value}")
    return target
