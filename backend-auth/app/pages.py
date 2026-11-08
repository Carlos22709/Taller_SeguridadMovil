"""Páginas HTML servidas por el servidor de autorización (login y QR de enrolamiento)."""

from __future__ import annotations

from html import escape

_BASE_CSS = """
:root { color-scheme: light dark; --bg:#f4f6fb; --card:#fff; --ink:#14213d; --muted:#5c6784;
        --brand:#003a70; --brand-ink:#fff; --line:#d9deea; --danger:#b42318; }
@media (prefers-color-scheme: dark) {
  :root { --bg:#0e1424; --card:#161e33; --ink:#e8ecf6; --muted:#9aa5c2; --brand:#4f8cff;
          --line:#2a3552; --danger:#ff8a80; }
}
* { box-sizing: border-box; }
body { margin:0; min-height:100vh; display:grid; place-items:center; background:var(--bg);
       color:var(--ink); font-family: system-ui, -apple-system, "Segoe UI", Roboto, sans-serif; padding:16px; }
.card { width:100%; max-width:400px; background:var(--card); border:1px solid var(--line);
        border-radius:16px; padding:28px; box-shadow:0 10px 30px rgba(0,0,0,.08); }
h1 { font-size:1.35rem; margin:0 0 4px; }
p { color:var(--muted); margin:0 0 20px; line-height:1.45; }
label { display:block; font-size:.85rem; font-weight:600; margin:14px 0 6px; }
input[type=email], input[type=password] { width:100%; padding:12px 14px; border-radius:10px;
        border:1px solid var(--line); background:transparent; color:var(--ink); font-size:1rem; }
button { width:100%; margin-top:20px; padding:13px; border:0; border-radius:10px; font-size:1rem;
         font-weight:600; background:var(--brand); color:var(--brand-ink); cursor:pointer; }
button.secondary { background:transparent; color:var(--muted); margin-top:8px; }
.error { background:color-mix(in srgb, var(--danger) 12%, transparent); color:var(--danger);
         padding:10px 12px; border-radius:10px; font-size:.9rem; margin-bottom:6px; }
.badge { display:inline-block; font-size:.75rem; font-weight:600; padding:4px 10px; border-radius:999px;
         background:color-mix(in srgb, var(--brand) 14%, transparent); color:var(--brand); margin-bottom:14px; }
code { font-family: ui-monospace, "Cascadia Code", Consolas, monospace; font-size:.85rem; word-break:break-all; }
.qr { background:#fff; padding:12px; border-radius:12px; display:flex; justify-content:center; margin:8px 0 16px; }
.hint { font-size:.8rem; color:var(--muted); margin-top:16px; }
"""


def _page(title: str, body: str) -> str:
    return f"""<!doctype html>
<html lang="es"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>{escape(title)}</title><style>{_BASE_CSS}</style></head>
<body><main class="card">{body}</main></body></html>"""


def login_page(params: dict[str, str], error: str | None = None, demo_email: str = "") -> str:
    hidden = "".join(
        f'<input type="hidden" name="{escape(k)}" value="{escape(v)}">' for k, v in params.items()
    )
    error_html = f'<div class="error" role="alert">{escape(error)}</div>' if error else ""
    body = f"""
<span class="badge">Servidor de autorización · OAuth 2.0 + PKCE</span>
<h1>Iniciar sesión en UniSabana</h1>
<p>La app <strong>UniSabana Mobile</strong> solicita acceso a tu cuenta. Tus credenciales
solo se escriben aquí, nunca dentro de la app.</p>
{error_html}
<form method="post" action="/oauth/authorize" autocomplete="on">
  {hidden}
  <label for="email">Correo institucional</label>
  <input id="email" name="email" type="email" required value="{escape(demo_email)}" autocomplete="username">
  <label for="password">Contraseña</label>
  <input id="password" name="password" type="password" required autocomplete="current-password">
  <button type="submit" name="decision" value="allow">Autorizar e ingresar</button>
  <button type="submit" name="decision" value="deny" class="secondary" formnovalidate>Cancelar</button>
</form>"""
    return _page("Iniciar sesión · UniSabana", body)


def error_page(message: str) -> str:
    body = f"""<span class="badge">OAuth 2.0</span><h1>Solicitud inválida</h1>
<div class="error" role="alert">{escape(message)}</div>
<p class="hint">Por seguridad no se redirige a la aplicación cuando el cliente o la URI de redirección no son válidos.</p>"""
    return _page("Error · UniSabana", body)


def qr_page(svg: str, secret: str, uri: str) -> str:
    body = f"""<span class="badge">Enrolamiento 2FA (RFC 6238)</span>
<h1>Configura tu Authenticator</h1>
<p>Escanea este código con la app UniSabana y con Google Authenticator. Ambas deben mostrar los mismos 6 dígitos.</p>
<div class="qr">{svg}</div>
<label>Semilla Base32 (entrada manual)</label><code>{escape(secret)}</code>
<label>URI</label><code>{escape(uri)}</code>
<p class="hint">Solo para la demo del laboratorio: en producción esta página exige sesión y se muestra una única vez.</p>"""
    return _page("Enrolamiento 2FA · UniSabana", body)
