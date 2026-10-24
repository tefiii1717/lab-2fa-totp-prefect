import base64
import time

import pytest
from fastapi.testclient import TestClient
from prefect.testing.utilities import prefect_test_harness

from app import config
from app.anti_replay import anti_replay_cache, pre_auth_sessions
from app.strategies import TOTPStrategy
from app.totp import PERIOD, hotp, time_step, totp

RFC_SECRET = base64.b32encode(b"12345678901234567890").decode()


@pytest.fixture(scope="session", autouse=True)
def prefect_harness():
    with prefect_test_harness():
        yield


@pytest.fixture()
def client(tmp_path, monkeypatch):
    from app import repository

    monkeypatch.setattr(config, "SQLITE_PATH", str(tmp_path / "test.db"))
    repository.get_repository.cache_clear()
    anti_replay_cache.clear()
    pre_auth_sessions.clear()
    from app.main import app

    yield TestClient(app)
    repository.get_repository.cache_clear()


@pytest.mark.parametrize(
    "timestamp,expected",
    [(59, "94287082"), (1111111109, "07081804"), (1234567890, "89005924"), (20000000000, "65353130")],
)
def test_rfc6238_vectors(timestamp, expected):
    assert totp(RFC_SECRET, timestamp, digits=8) == expected


def test_totp_strategy_reports_window():
    user = {"totp_secret": RFC_SECRET}
    now = 1_700_000_015.0
    key = base64.b32decode(RFC_SECRET)
    strategy = TOTPStrategy(clock=lambda: now)
    for offset in (-1, 0, 1):
        result = strategy.verify(user, hotp(key, time_step(now) + offset))
        assert result.ok and result.window_offset == offset
    assert not strategy.verify(user, hotp(key, time_step(now) + 2)).ok


def wait_for_fresh_window(min_seconds_left: int = 8):
    left = PERIOD - (time.time() % PERIOD)
    if left < min_seconds_left:
        time.sleep(left + 0.2)


def enroll(client, username="ana", password="secreta123"):
    assert client.post("/auth/register", json={"username": username, "password": password}).status_code == 201
    login = client.post("/auth/login", json={"username": username, "password": password}).json()
    assert login["status"] == "MFA_SETUP_REQUIRED"
    basic = {"Authorization": f"Bearer {login['access_token']}"}

    # Un token básico no abre la bóveda.
    assert client.get("/api/boveda-secreta", headers=basic).status_code == 403

    setup = client.post("/auth/2fa/setup", headers=basic).json()
    assert setup["status"] == "PENDING_VERIFICATION"
    assert setup["otpauth_uri"].startswith("otpauth://totp/")

    # Mientras está pendiente, el login sigue sin exigir 2FA (no bloquea al usuario).
    relogin = client.post("/auth/login", json={"username": username, "password": password}).json()
    assert relogin["status"] == "MFA_SETUP_REQUIRED"

    wait_for_fresh_window()
    confirm = client.post("/auth/2fa/confirm", headers=basic, json={"code": totp(setup["secret"])})
    assert confirm.status_code == 200, confirm.text
    body = confirm.json()
    assert body["status"] == "ACTIVE" and len(body["backup_codes"]) == config.BACKUP_CODES_COUNT
    return setup["secret"], body["backup_codes"]


def pre_auth(client, username="ana", password="secreta123"):
    login = client.post("/auth/login", json={"username": username, "password": password}).json()
    assert login["status"] == "MFA_REQUIRED"
    return login["pre_auth_token"]


def test_full_flow_replay_and_backup(client):
    secret, backup_codes = enroll(client)

    # El pre_auth_token no sirve para recursos protegidos.
    token = pre_auth(client)
    assert client.get("/api/boveda-secreta", headers={"Authorization": f"Bearer {token}"}).status_code == 401

    # El código usado al confirmar ya está quemado en la caché anti-replay.
    res = client.post("/auth/verify-2fa", json={"pre_auth_token": token, "code": totp(secret)})
    assert res.status_code == 409 and res.json()["error"] == "ReplayAttackDetected"

    # Código incorrecto -> 401
    res = client.post("/auth/verify-2fa", json={"pre_auth_token": token, "code": "000000" if totp(secret) != "000000" else "111111"})
    assert res.status_code == 401

    # Código de la siguiente ventana (C+1) es aceptado y queda registrado en logs.
    next_code = totp(secret, time.time() + PERIOD)
    res = client.post("/auth/verify-2fa", json={"pre_auth_token": token, "code": next_code})
    assert res.status_code == 200, res.text
    assert res.json()["window"].startswith("C+1")
    access = res.json()["access_token"]
    vault = client.get("/api/boveda-secreta", headers={"Authorization": f"Bearer {access}"})
    assert vault.status_code == 200

    # El mismo pre_auth_token no se puede reutilizar.
    res = client.post("/auth/verify-2fa", json={"pre_auth_token": token, "code": totp(secret)})
    assert res.status_code == 401

    # Replay del mismo código con un pre_auth_token nuevo -> 409
    res = client.post("/auth/verify-2fa", json={"pre_auth_token": pre_auth(client), "code": next_code})
    assert res.status_code == 409

    # Código de respaldo: sirve una sola vez.
    res = client.post(
        "/auth/verify-2fa",
        json={"pre_auth_token": pre_auth(client), "code": backup_codes[0], "method": "backup"},
    )
    assert res.status_code == 200, res.text
    pre_auth_sessions.clear()
    anti_replay_cache.clear()  # aun sin caché, la BD impide reutilizarlo
    res = client.post(
        "/auth/verify-2fa",
        json={"pre_auth_token": pre_auth(client), "code": backup_codes[0], "method": "backup"},
    )
    assert res.status_code == 401


def test_max_attempts(client):
    enroll(client, "luis")
    token = pre_auth(client, "luis")
    for _ in range(config.MAX_2FA_ATTEMPTS):
        client.post("/auth/verify-2fa", json={"pre_auth_token": token, "code": "abc"})
    res = client.post("/auth/verify-2fa", json={"pre_auth_token": token, "code": "123456"})
    assert res.status_code == 401 and "intentos" in res.json()["detail"]
