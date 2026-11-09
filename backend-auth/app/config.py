"""Configuración del backend leída desde variables de entorno (ver .env.example)."""

from __future__ import annotations

import os
import secrets


def _int(name: str, default: int) -> int:
    return int(os.getenv(name, str(default)))


def _list(name: str, default: str) -> list[str]:
    return [item.strip() for item in os.getenv(name, default).split(",") if item.strip()]


# Si no se define, se genera uno aleatorio en cada arranque (los tokens viejos dejan de servir).
JWT_SECRET: str = os.getenv("JWT_SECRET") or secrets.token_urlsafe(48)
JWT_ALGORITHM = "HS256"
JWT_ISSUER = "unisabana-auth"

# Tiempos de vida (segundos)
ACCESS_TOKEN_TTL = _int("ACCESS_TOKEN_TTL", 5 * 60)
REFRESH_TOKEN_TTL = _int("REFRESH_TOKEN_TTL", 30 * 24 * 60 * 60)
ELEVATED_TOKEN_TTL = _int("ELEVATED_TOKEN_TTL", 10 * 60)
STEP_UP_TOKEN_TTL = _int("STEP_UP_TOKEN_TTL", 5 * 60)
AUTH_CODE_TTL = _int("AUTH_CODE_TTL", 60)
REPLAY_CACHE_TTL = _int("REPLAY_CACHE_TTL", 90)
MFA_MAX_ATTEMPTS = _int("MFA_MAX_ATTEMPTS", 5)

# Cliente OAuth público (app móvil): NO tiene client_secret.
CLIENT_ID = os.getenv("CLIENT_ID", "unisabana-mobile")
ALLOWED_REDIRECT_URIS = _list(
    "ALLOWED_REDIRECT_URIS",
    "unisabana-auth://callback",
)
# Expo Go (desarrollo): la redirect URI es exp://<ip-del-pc>:8081/--/callback y la IP cambia según la red.
# En producción (development/standalone build) se usa unisabana-auth://callback y esto se desactiva.
ALLOW_EXPO_GO_REDIRECTS = os.getenv("ALLOW_EXPO_GO_REDIRECTS", "true").lower() == "true"
EXPO_GO_REDIRECT_RE = r"^exp://[A-Za-z0-9.\-]+(:\d{1,5})?/--/callback$"

# Usuario demo
DEMO_USER_EMAIL = os.getenv("DEMO_USER_EMAIL", "estudiante@unisabana.edu.co")
DEMO_USER_PASSWORD = os.getenv("DEMO_USER_PASSWORD", "sabana123")
DEMO_USER_NAME = os.getenv("DEMO_USER_NAME", "Estudiante UniSabana")
TOTP_SECRET = os.getenv("TOTP_SECRET", "JBSWY3DPEHPK3PXP")
TOTP_ISSUER = os.getenv("TOTP_ISSUER", "UniSabana")
