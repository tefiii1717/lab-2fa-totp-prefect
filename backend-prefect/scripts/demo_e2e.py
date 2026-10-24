"""Ensaya las pruebas de aceptación contra el backend en vivo (simula la app móvil).

Uso (con el backend y `prefect server start` corriendo):
    python scripts/demo_e2e.py [http://127.0.0.1:8000]
"""

import secrets
import sys
import time
from pathlib import Path

import httpx

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from app.totp import PERIOD, totp  # noqa: E402

BASE = sys.argv[1] if len(sys.argv) > 1 else "http://127.0.0.1:8000"
client = httpx.Client(base_url=BASE, timeout=60)


def step(title, response):
    print(f"[{response.status_code}] {title}: {response.json()}")
    return response


def main():
    username, password = f"demo_{secrets.token_hex(3)}", "secreta123"
    step("registro", client.post("/auth/register", json={"username": username, "password": password}))
    basic = client.post("/auth/login", json={"username": username, "password": password}).json()["access_token"]
    headers = {"Authorization": f"Bearer {basic}"}

    setup = client.post("/auth/2fa/setup", headers=headers).json()
    print("Semilla Base32:", setup["secret"], "| estado:", setup["status"])

    if PERIOD - time.time() % PERIOD < 5:
        time.sleep(6)
    step("confirmar 2FA", client.post("/auth/2fa/confirm", headers=headers, json={"code": totp(setup["secret"])}))

    print("Esperando a la siguiente ventana de 30 s para tener un código nuevo...")
    time.sleep(PERIOD - time.time() % PERIOD + 1)

    code = totp(setup["secret"])
    pre = client.post("/auth/login", json={"username": username, "password": password}).json()
    ok = step("verify-2fa", client.post("/auth/verify-2fa", json={"pre_auth_token": pre["pre_auth_token"], "code": code}))
    access = ok.json()["access_token"]
    step("bóveda", client.get("/api/boveda-secreta", headers={"Authorization": f"Bearer {access}"}))

    pre = client.post("/auth/login", json={"username": username, "password": password}).json()
    step("REPLAY (debe ser 409)", client.post("/auth/verify-2fa", json={"pre_auth_token": pre["pre_auth_token"], "code": code}))


if __name__ == "__main__":
    main()
