"""Backend de autenticación: OAuth 2.0 + PKCE, refresh con rotación, Step-Up TOTP y anti-replay."""

from __future__ import annotations

import logging
import re
import time
from typing import Any
from urllib.parse import urlencode

import segno
from fastapi import FastAPI, Form, Request
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse, Response
from pydantic import BaseModel

from . import config, pages, pkce, tokens, totp
from .store import build_store

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
log = logging.getLogger("auth")

app = FastAPI(title="UniSabana Auth — OAuth 2.0 + PKCE + Step-Up TOTP", version="1.0.0")
store = build_store()

@app.middleware("http")
async def security_headers(request: Request, call_next):
    response = await call_next(request)
    response.headers.setdefault("X-Content-Type-Options", "nosniff")
    # Evita que el ?code= de la URL de callback se filtre por el header Referer.
    response.headers.setdefault("Referrer-Policy", "no-referrer")
    if request.url.path.startswith(("/oauth", "/mfa")):
        response.headers.setdefault("X-Frame-Options", "DENY")  # anti-clickjacking del login
    return response


# ---------------------------------------------------------------------------
# Errores con formato JSON uniforme: {"error": "...", "message": "...", ...}
# ---------------------------------------------------------------------------
class ApiError(Exception):
    def __init__(self, status: int, code: str, message: str, headers: dict[str, str] | None = None, **extra: Any):
        self.status, self.code, self.message, self.headers, self.extra = status, code, message, headers, extra


@app.exception_handler(ApiError)
async def api_error_handler(_: Request, exc: ApiError) -> JSONResponse:
    return JSONResponse(
        {"error": exc.code, "message": exc.message, **exc.extra},
        status_code=exc.status,
        headers=exc.headers,
    )


NO_STORE = {"Cache-Control": "no-store", "Pragma": "no-cache"}


def bearer_claims(request: Request) -> dict[str, Any]:
    header = request.headers.get("Authorization", "")
    if not header.startswith("Bearer "):
        raise ApiError(401, "missing_token", "Falta el header Authorization: Bearer <token>",
                       headers={"WWW-Authenticate": "Bearer"})
    try:
        return tokens.decode(header.removeprefix("Bearer ").strip(), "access")
    except tokens.TokenError as exc:
        raise ApiError(401, exc.reason, "Access token inválido o vencido",
                       headers={"WWW-Authenticate": f'Bearer error="invalid_token"'}) from exc


def is_allowed_redirect(redirect_uri: str) -> bool:
    if redirect_uri in config.ALLOWED_REDIRECT_URIS:
        return True
    return bool(config.ALLOW_EXPO_GO_REDIRECTS and re.fullmatch(config.EXPO_GO_REDIRECT_RE, redirect_uri))


def with_query(uri: str, params: dict[str, str]) -> str:
    return f"{uri}{'&' if '?' in uri else '?'}{urlencode(params)}"


# ---------------------------------------------------------------------------
# Punto 1 — OAuth 2.0 Authorization Code + PKCE (RFC 7636)
# ---------------------------------------------------------------------------
AUTHORIZE_FIELDS = ("response_type", "client_id", "redirect_uri", "state", "code_challenge", "code_challenge_method")


def validate_authorize(params: dict[str, str]) -> str | None:
    """Devuelve un mensaje de error o None si la solicitud es válida."""
    if params.get("client_id") != config.CLIENT_ID:
        return "client_id desconocido."
    if not is_allowed_redirect(params.get("redirect_uri", "")):
        return "redirect_uri no registrada para este cliente."
    if params.get("response_type") != "code":
        return "response_type debe ser 'code'."
    if not params.get("state"):
        return "Falta el parámetro state (protección anti-CSRF)."
    if params.get("code_challenge_method") != "S256":
        return "Solo se acepta code_challenge_method=S256."
    if not pkce.is_valid_challenge(params.get("code_challenge", "")):
        return "code_challenge inválido (se espera SHA-256 en Base64URL sin relleno)."
    return None


@app.get("/oauth/authorize", response_class=HTMLResponse)
def authorize_form(request: Request) -> HTMLResponse:
    params = {k: request.query_params.get(k, "") for k in AUTHORIZE_FIELDS}
    if error := validate_authorize(params):
        return HTMLResponse(pages.error_page(error), status_code=400)
    return HTMLResponse(pages.login_page(params, demo_email=config.DEMO_USER_EMAIL))


@app.post("/oauth/authorize", response_model=None)
def authorize_submit(
    response_type: str = Form(""),
    client_id: str = Form(""),
    redirect_uri: str = Form(""),
    state: str = Form(""),
    code_challenge: str = Form(""),
    code_challenge_method: str = Form(""),
    email: str = Form(""),
    password: str = Form(""),
    decision: str = Form("allow"),
) -> Response:
    params = {
        "response_type": response_type, "client_id": client_id, "redirect_uri": redirect_uri,
        "state": state, "code_challenge": code_challenge, "code_challenge_method": code_challenge_method,
    }
    if error := validate_authorize(params):
        return HTMLResponse(pages.error_page(error), status_code=400)

    if decision == "deny":
        return RedirectResponse(with_query(redirect_uri, {"error": "access_denied", "state": state}), 303)

    user = store.authenticate(email, password)
    if user is None:
        return HTMLResponse(
            pages.login_page(params, error="Correo o contraseña incorrectos.", demo_email=email),
            status_code=401,
        )

    code = store.create_auth_code(client_id, redirect_uri, code_challenge, user.id)
    log.info("authorize: code emitido para %s -> %s", user.email, redirect_uri)
    return RedirectResponse(with_query(redirect_uri, {"code": code, "state": state}), 303)


@app.post("/auth/oauth/token")
def token_exchange(
    grant_type: str = Form(""),
    code: str = Form(""),
    redirect_uri: str = Form(""),
    client_id: str = Form(""),
    code_verifier: str = Form(""),
) -> JSONResponse:
    if grant_type != "authorization_code":
        raise ApiError(400, "unsupported_grant_type", "Solo se admite authorization_code.")
    if client_id != config.CLIENT_ID:
        raise ApiError(401, "invalid_client", "client_id desconocido.")

    record = store.consume_auth_code(code)  # un solo uso: se elimina al leerlo
    if record is None:
        raise ApiError(400, "invalid_grant", "Código de autorización inválido, vencido o ya usado.")
    if record.client_id != client_id or record.redirect_uri != redirect_uri:
        raise ApiError(400, "invalid_grant", "client_id o redirect_uri no coinciden con la autorización.")
    if not pkce.verify(code_verifier, record.code_challenge):
        log.warning("token: PKCE fallido para %s", record.user_id)
        raise ApiError(400, "invalid_grant", "PKCE falló: SHA256(code_verifier) != code_challenge.")

    access_token, ttl = tokens.create_access_token(record.user_id)
    refresh_token = store.issue_refresh_token(record.user_id)
    log.info("token: sesión emitida para %s", record.user_id)
    # La app guarda el refresh_token en Keychain / Keystore (expo-secure-store).
    return JSONResponse(
        {
            "access_token": access_token,
            "token_type": "Bearer",
            "expires_in": ttl,
            "refresh_token": refresh_token,
            "refresh_expires_in": config.REFRESH_TOKEN_TTL,
        },
        headers=NO_STORE,
    )


# ---------------------------------------------------------------------------
# Punto 2 — Refresh con rotación (y detección de reuso)
# ---------------------------------------------------------------------------
async def _read_refresh_token(request: Request) -> str | None:
    """Lee {"refresh_token": "..."} del cuerpo JSON."""
    try:
        data = await request.json()
    except ValueError:
        return None
    token = data.get("refresh_token") if isinstance(data, dict) else None
    return token if isinstance(token, str) and token else None


@app.post("/auth/refresh")
async def refresh(request: Request) -> JSONResponse:
    token = await _read_refresh_token(request)
    result = store.rotate_refresh_token(token) if token else None
    log.info("refresh: llamada #%d -> %s", store.refresh_calls, "ok" if result else "rechazado")
    if result is None:
        raise ApiError(401, "invalid_refresh_token", "Refresh token vencido, revocado o inexistente.", headers=NO_STORE)

    user_id, new_refresh = result
    access_token, ttl = tokens.create_access_token(user_id)
    return JSONResponse(
        {"access_token": access_token, "token_type": "Bearer", "expires_in": ttl, "refresh_token": new_refresh},
        headers=NO_STORE,
    )


@app.post("/auth/logout", status_code=204)
async def logout(request: Request) -> Response:
    token = await _read_refresh_token(request)
    if token:
        store.revoke_refresh_token(token)
    return Response(status_code=204)


# ---------------------------------------------------------------------------
# Recursos protegidos
# ---------------------------------------------------------------------------
@app.get("/api/perfil")
def perfil(request: Request) -> dict[str, Any]:
    claims = bearer_claims(request)
    user = store.users_by_id.get(claims["sub"])
    if user is None:
        raise ApiError(401, "invalid_token", "Usuario inexistente.")
    return {
        "id": user.id,
        "email": user.email,
        "name": user.name,
        "mfa_verified": bool(claims.get("mfa_verified")),
        "token_expires_at": claims["exp"],
    }


@app.get("/api/boveda-critica")
@app.get("/api/boveda")  # alias
def boveda_critica(request: Request) -> dict[str, Any]:
    claims = bearer_claims(request)
    if not claims.get("mfa_verified"):
        raise ApiError(
            403, "mfa_required", "Este recurso exige un segundo factor (TOTP).",
            step_up_token=tokens.create_step_up_token(claims["sub"]),
            step_up_expires_in=config.STEP_UP_TOKEN_TTL,
        )
    user = store.users_by_id[claims["sub"]]
    return {
        "owner": user.name,
        "elevated_until": claims["exp"],
        "items": [
            {"label": "Cuenta de nómina", "value": "**** **** 4821", "detail": "Saldo: $ 18.450.200 COP"},
            {"label": "Llave de firma digital", "value": "SIG-7F3A-99C2-E104", "detail": "Vence 2027-03-01"},
            {"label": "Historia académica", "value": "Promedio 4.62", "detail": "Créditos aprobados: 128"},
            {"label": "Código de recuperación", "value": "R9KX-2MPL-77QA", "detail": "Uso único"},
        ],
    }


# ---------------------------------------------------------------------------
# Punto 4 — Verificación TOTP con ventanas C-1, C, C+1 y caché anti-replay
# ---------------------------------------------------------------------------
class MfaVerifyIn(BaseModel):
    step_up_token: str
    code: str


CODE_RE = re.compile(r"^\d{6}$")


@app.post("/auth/mfa/verify")
def mfa_verify(payload: MfaVerifyIn) -> JSONResponse:
    if not CODE_RE.match(payload.code):
        raise ApiError(400, "invalid_code_format", "El código debe tener exactamente 6 dígitos.")
    try:
        claims = tokens.decode(payload.step_up_token, "step_up")
    except tokens.TokenError as exc:
        raise ApiError(401, "invalid_step_up_token", "step_up_token inválido o vencido.") from exc

    user = store.users_by_id.get(claims["sub"])
    if user is None:
        raise ApiError(401, "invalid_step_up_token", "Usuario inexistente.")
    if store.mfa_failures_for(claims["jti"]) >= config.MFA_MAX_ATTEMPTS:
        raise ApiError(429, "too_many_attempts", "Demasiados intentos. Solicita la bóveda de nuevo.")

    # 1) Anti-replay ANTES de validar: un código ya usado nunca vuelve a servir mientras viva en caché.
    replay_key = f"{user.id}:{payload.code}"
    if store.is_replay(replay_key):
        log.warning("mfa: REPLAY detectado para %s", user.email)
        raise ApiError(409, "replay_attack_detected", "Replay Attack Detected")

    # 2) Validación TOTP con tolerancia de reloj (C-1, C, C+1)
    matched = totp.verify(totp.base32_decode(user.totp_secret), payload.code, time.time(), window=1)
    if matched is None:
        failures = store.register_mfa_failure(claims["jti"])
        raise ApiError(401, "invalid_code", "Código TOTP incorrecto.",
                       attempts_left=max(config.MFA_MAX_ATTEMPTS - failures, 0))

    # 3) Registrar el código (TTL 90 s) y elevar privilegios
    store.remember_code(replay_key)
    elevated, ttl = tokens.create_access_token(user.id, mfa_verified=True)
    log.info("mfa: elevación concedida a %s (ventana %+d)", user.email, matched - totp.time_counter(time.time()))
    return JSONResponse(
        {"elevated_token": elevated, "token_type": "Bearer", "expires_in": ttl, "mfa_verified": True},
        headers=NO_STORE,
    )


# ---------------------------------------------------------------------------
# Utilidades de demo
# ---------------------------------------------------------------------------
@app.get("/mfa/qr", response_class=HTMLResponse)
def mfa_qr() -> HTMLResponse:
    uri = totp.provisioning_uri(config.TOTP_SECRET, config.DEMO_USER_EMAIL, config.TOTP_ISSUER)
    svg = segno.make(uri, error="m").svg_inline(scale=6, dark="#000", light="#fff")
    return HTMLResponse(pages.qr_page(svg, totp.normalize_base32(config.TOTP_SECRET), uri))


@app.get("/api/demo/stats")
def demo_stats() -> dict[str, int]:
    return {"refresh_calls": store.refresh_calls}


@app.get("/health")
def health() -> dict[str, Any]:
    return {"status": "ok", "time": int(time.time())}

