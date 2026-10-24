// Estado solo en memoria: al recargar la página se pierde la sesión (laboratorio).
const state = {
  credentials: null, // se guarda para la demo de replay
  preAuthToken: null,
  accessToken: null,
  method: "totp",
  lastCode: null,
  lastMethod: null,
};

const $ = (id) => document.getElementById(id);
const views = ["view-login", "view-verify", "view-setup", "view-vault"];

function show(view) {
  views.forEach((v) => $(v).classList.toggle("hidden", v !== view));
}

function alertBox(message, kind = "error") {
  const box = $("alert");
  box.textContent = message;
  box.className = `alert ${kind}`;
}

function clearAlert() {
  $("alert").className = "alert hidden";
}

async function api(path, { method = "POST", body, token } = {}) {
  const headers = { "Content-Type": "application/json" };
  if (token) headers.Authorization = `Bearer ${token}`;
  const res = await fetch(path, { method, headers, body: body ? JSON.stringify(body) : undefined });
  const data = await res.json().catch(() => ({}));
  if (!res.ok) {
    const detail = Array.isArray(data.detail) ? data.detail.map((d) => d.msg).join("; ") : data.detail;
    const err = new Error(`${res.status} · ${data.error ? data.error + ": " : ""}${detail || res.statusText}`);
    err.status = res.status;
    throw err;
  }
  return data;
}

function decodeJwt(token) {
  const payload = token.split(".")[1].replace(/-/g, "+").replace(/_/g, "/");
  return JSON.parse(atob(payload));
}

async function withBusy(button, fn) {
  button.disabled = true;
  try {
    await fn();
  } catch (err) {
    alertBox(err.message);
  } finally {
    button.disabled = false;
  }
}

function logout() {
  Object.assign(state, { credentials: null, preAuthToken: null, accessToken: null, lastCode: null });
  $("login-form").reset();
  $("setup-qr").classList.add("hidden");
  $("setup-done").classList.add("hidden");
  $("setup-btn").classList.remove("hidden");
  show("view-login");
}

async function handleLoginResult(result) {
  if (result.status === "MFA_REQUIRED") {
    state.preAuthToken = result.pre_auth_token;
    $("verify-form").reset();
    show("view-verify");
    $("verify-form").code.focus();
    return;
  }
  // 2FA aún no activo: token básico, solo para configurarlo.
  state.accessToken = result.access_token;
  $("setup-status").textContent = result.twofa_status;
  show("view-setup");
}

async function loadVault() {
  const vault = await api("/api/boveda-secreta", { method: "GET", token: state.accessToken });
  $("vault-output").textContent = JSON.stringify(vault, null, 2);
  $("claims-output").textContent = JSON.stringify(decodeJwt(state.accessToken), null, 2);
  show("view-vault");
}

$("login-form").addEventListener("submit", (e) => {
  e.preventDefault();
  const form = e.currentTarget;
  withBusy(form.querySelector("button[type=submit]"), async () => {
    clearAlert();
    state.credentials = { username: form.username.value.trim(), password: form.password.value };
    await handleLoginResult(await api("/auth/login", { body: state.credentials }));
  });
});

$("register-btn").addEventListener("click", (e) => {
  const form = $("login-form");
  if (!form.reportValidity()) return;
  withBusy(e.currentTarget, async () => {
    const body = { username: form.username.value.trim(), password: form.password.value };
    await api("/auth/register", { body });
    alertBox(`Usuario "${body.username}" creado. Ahora pulsa Entrar.`, "success");
  });
});

document.querySelectorAll(".tab").forEach((tab) =>
  tab.addEventListener("click", () => {
    state.method = tab.dataset.method;
    document.querySelectorAll(".tab").forEach((t) => t.classList.toggle("active", t === tab));
    const input = $("verify-form").code;
    $("code-label").firstChild.textContent = state.method === "totp" ? "Código de 6 dígitos " : "Código de respaldo (XXXX-XXXX) ";
    input.inputMode = state.method === "totp" ? "numeric" : "text";
    input.value = "";
    input.focus();
  })
);

$("verify-form").addEventListener("submit", (e) => {
  e.preventDefault();
  const form = e.currentTarget;
  withBusy(form.querySelector("button[type=submit]"), async () => {
    clearAlert();
    const code = form.code.value.trim();
    try {
      const result = await api("/auth/verify-2fa", {
        body: { pre_auth_token: state.preAuthToken, code, method: state.method },
      });
      state.accessToken = result.access_token;
      state.lastCode = code;
      state.lastMethod = state.method;
      alertBox(`Segundo factor OK (${result.method}${result.window ? " · ventana " + result.window : ""}).`, "success");
      await loadVault();
    } catch (err) {
      // Si el pre_auth_token caducó o se agotaron los intentos, hay que volver al login.
      if (err.status === 401 && /pre_auth_token|intentos/i.test(err.message)) logout();
      throw err;
    }
  });
});

$("setup-btn").addEventListener("click", (e) => {
  const button = e.currentTarget;
  withBusy(button, async () => {
    clearAlert();
    const result = await api("/auth/2fa/setup", { token: state.accessToken });
    $("setup-status").textContent = result.status;
    $("qr-img").src = `data:image/png;base64,${result.qr_png_base64}`;
    $("secret-text").textContent = result.secret;
    $("uri-text").textContent = result.otpauth_uri;
    $("setup-qr").classList.remove("hidden");
    button.textContent = "Regenerar QR";
  });
});

$("confirm-form").addEventListener("submit", (e) => {
  e.preventDefault();
  const form = e.currentTarget;
  withBusy(form.querySelector("button"), async () => {
    clearAlert();
    const result = await api("/auth/2fa/confirm", { token: state.accessToken, body: { code: form.code.value.trim() } });
    $("setup-status").textContent = result.status;
    $("backup-list").replaceChildren(
      ...result.backup_codes.map((c) => Object.assign(document.createElement("li"), { textContent: c }))
    );
    $("setup-qr").classList.add("hidden");
    $("setup-btn").classList.add("hidden");
    $("setup-done").classList.remove("hidden");
    alertBox(`2FA activado (match en ventana ${result.window}).`, "success");
  });
});

$("replay-btn").addEventListener("click", (e) => {
  withBusy(e.currentTarget, async () => {
    if (!state.credentials || !state.lastCode) throw new Error("No hay un código previo que repetir.");
    const login = await api("/auth/login", { body: state.credentials });
    try {
      await api("/auth/verify-2fa", {
        body: { pre_auth_token: login.pre_auth_token, code: state.lastCode, method: state.lastMethod },
      });
      alertBox("⚠ El backend aceptó el código repetido: la protección anti-replay NO funcionó.");
    } catch (err) {
      alertBox(`Replay bloqueado correctamente → ${err.message}`, err.status === 409 ? "success" : "error");
    }
  });
});

document.querySelectorAll("[data-action=logout]").forEach((b) =>
  b.addEventListener("click", () => {
    clearAlert();
    logout();
  })
);

document.querySelectorAll("[data-copy]").forEach((b) =>
  b.addEventListener("click", async () => {
    await navigator.clipboard.writeText($(b.dataset.copy).textContent);
    b.textContent = "copiado";
    setTimeout(() => (b.textContent = "copiar"), 1500);
  })
);
