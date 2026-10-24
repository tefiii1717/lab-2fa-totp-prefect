# Lab 2FA TOTP desde cero + Observabilidad con Prefect

Prueba de concepto del curso **Patrones Arquitectónicos Avanzados**.

```
/mobile-authenticator   App Authenticator propia (React Native + Expo, TOTP desde cero)
/backend-prefect        API FastAPI + flows de Prefect + web app de login
```

## Arquitectura

```
Web (login)  ──POST /auth/login──▶  login-flow ──▶ pre_auth_token (scope pre_auth)
                                                         │
App móvil (modo avión): HMAC-SHA1(secreto, UnixTime // 30) → 6 dígitos
                                                         │
Web ──POST /auth/verify-2fa {pre_auth_token, code}──▶ verify-2fa-flow
        1. validate_pre_auth_state   ¿token temporal válido, no consumido, < 5 intentos?
        2. check_anti_replay_cache   ¿(user_id, código) usado en los últimos 90 s? → ReplayAttackDetected
        3. execute_mfa_strategy      TOTPStrategy (C-1, C, C+1) | BackupCodeStrategy
        4. issue_elevated_session    marca el código como usado + JWT con mfa_verified: true
                                                         │
Web ──GET /api/boveda-secreta (Bearer access_token)──▶ 200
```

| Patrón | Dónde |
|---|---|
| **Máquina de estados / Process Manager** | [`app/state_machine.py`](backend-prefect/app/state_machine.py) + flows `2fa-enrollment-start-flow` y `2fa-enrollment-confirm-flow`: `DISABLED → PENDING_VERIFICATION → ACTIVE`. El login solo exige 2FA en `ACTIVE`, así que generar el QR y no escanearlo no bloquea al usuario. |
| **Step-Up Authentication** | [`app/security.py`](backend-prefect/app/security.py): scopes `pre_auth` (solo vale para `/auth/verify-2fa`), `basic` (sin 2FA, solo permite configurarlo) y `access` (`mfa_verified: true`). |
| **Strategy** | [`app/strategies.py`](backend-prefect/app/strategies.py): `SecondFactorStrategy` → `TOTPStrategy`, `BackupCodeStrategy`. |
| **Anti-replay / idempotencia** | [`app/anti_replay.py`](backend-prefect/app/anti_replay.py): caché en memoria con TTL de 90 s; el registro es atómico (lock) para que dos requests simultáneos con el mismo código no pasen ambos. Los códigos de respaldo además se consumen con un `UPDATE ... WHERE used_at IS NULL`. |
| **Observabilidad** | [`app/flows.py`](backend-prefect/app/flows.py): cada endpoint ejecuta un `@flow`; cada paso es una `@task` con `get_run_logger()`. Contraseñas, tokens y códigos van como `SecretStr` y Prefect los muestra como `**********`. |

## Requisitos

- Python 3.11+ (probado con 3.13)
- Node.js 20+ (probado con 22)
- Celular con **Expo Go** (SDK 58) o un emulador Android / simulador iOS

## 1. Servidor de Prefect

```bash
cd backend-prefect
python -m venv .venv
.venv\Scripts\activate          # Windows  (macOS/Linux: source .venv/bin/activate)
pip install -r requirements.txt
prefect server start
```

UI en http://127.0.0.1:4200. Déjalo corriendo en esa terminal.

## 2. Backend

En otra terminal, con el mismo venv activado:

```bash
cd backend-prefect
prefect config set PREFECT_API_URL=http://127.0.0.1:4200/api
uvicorn app.main:app --host 0.0.0.0 --port 8000
```

- Web app de login: http://127.0.0.1:8000
- Swagger: http://127.0.0.1:8000/docs
- Usa **un solo worker** (sin `--workers`): las cachés anti-replay y de pre-auth viven en memoria del proceso.
- Opcional: copia `.env.example` a `.env` y define `JWT_SECRET` para que los tokens sobrevivan a reinicios.

### Base de datos

Por defecto usa SQLite (`backend-prefect/lab2fa.db`, se crea solo). Para usar **Supabase**:

1. En Supabase → SQL Editor, ejecuta [`supabase_schema.sql`](backend-prefect/supabase_schema.sql).
2. En `.env`: `DB_BACKEND=supabase`, `SUPABASE_URL=...`, `SUPABASE_SERVICE_ROLE_KEY=...` (la service_role key solo va en el backend, nunca en la web ni en la app).

### Endpoints

| Método | Ruta | Token | Descripción |
|---|---|---|---|
| POST | `/auth/register` | — | Crea usuario (`DISABLED`) |
| POST | `/auth/login` | — | `MFA_REQUIRED` + `pre_auth_token`, o `MFA_SETUP_REQUIRED` + token básico |
| POST | `/auth/2fa/setup` | básico | Genera semilla y QR, estado `PENDING_VERIFICATION` |
| POST | `/auth/2fa/confirm` | básico | Primer código válido → `ACTIVE` + 8 códigos de respaldo |
| POST | `/auth/verify-2fa` | `pre_auth_token` en el body | `{pre_auth_token, code, method: "totp" \| "backup"}` → `access_token` |
| GET | `/api/boveda-secreta` | access (`mfa_verified`) | Ruta protegida |
| GET | `/api/me` | básico o access | Datos del usuario y claims |

## 3. App móvil

```bash
cd mobile-authenticator
npm install
npm run verify-totp   # vectores oficiales RFC 4226 / RFC 6238
npx expo start
```

Escanea el QR de Expo con la app **Expo Go**. La app:

- calcula el código con SHA-1, HMAC y Base32 implementados a mano en [`src/totp.ts`](mobile-authenticator/src/totp.ts) (sin `otplib`, `speakeasy` ni similares, y sin red);
- escanea el QR `otpauth://totp/...` del backend (`expo-camera`) o acepta la semilla Base32 / URI pegada a mano (para emuladores sin cámara);
- muestra el código en grande con barra y cuenta regresiva de 30 → 0 s;
- guarda las cuentas en `expo-secure-store`. Mantén presionada una cuenta para borrarla.

## Guion de la demo (pruebas de aceptación)

Preparación: en la web, **Registrarme** → **Entrar** → **Generar QR**.

1. **Paridad estándar.** Escanea el QR con la app propia y con Google/Microsoft Authenticator. Ambas muestran los mismos 6 dígitos. Escribe el código en la web → `ACTIVE` y guarda los códigos de respaldo.
2. **Modo avión.** Activa el modo avión en el celular y espera a que cambie la ventana. **Cerrar sesión y entrar con 2FA** → escribe el código → la web llama a `GET /api/boveda-secreta` y muestra la bóveda.
3. **Replay attack.** En la bóveda, pulsa **Probar ataque de repetición** (vuelve a hacer login y reenvía el mismo código), o hazlo a mano antes de que pasen 30 s. Respuesta `409 ReplayAttackDetected`. En Prefect → Runs, el `verify-2fa-flow` sale **Failed** y la task en rojo es `check_anti_replay_cache`.
4. **Clock skew / respaldo.** En los logs de la task `execute_mfa_strategy` se ve `MATCH en la ventana C`, `C-1 (... ATRASADO)` o `C+1 (... ADELANTADO)`. Para forzarlo, adelanta o atrasa ~30 s la hora del celular. O usa la pestaña **Código de respaldo** con uno de los 8 códigos (cada uno sirve una sola vez).

Para ensayar todo sin celular: `python scripts/demo_e2e.py` (con backend y Prefect corriendo) simula la app y termina con el replay rechazado.

## Tests

```bash
cd backend-prefect
pytest -q
```

Cubren los vectores RFC 6238, las ventanas C-1/C/C+1, el flujo completo (estado pendiente, step-up, replay, reutilización del pre_auth_token, códigos de respaldo) y el límite de intentos. Usan `prefect_test_harness`, así que no necesitan el servidor.

## Notas de alcance

Es un laboratorio controlado: las cachés están en memoria, el secreto TOTP se guarda en claro en la BD y no hay HTTPS. En producción habría que usar Redis para las cachés, cifrar la semilla en reposo (KMS) y servir todo con TLS.

**Windows:** si `pip install` o `prefect` fallan con *"El nombre del archivo o la extensión es demasiado largo"*, la ruta del proyecto es demasiado larga. Clona el repo en una ruta corta (p. ej. `C:\dev\lab2fa`) o activa las rutas largas de Windows.
