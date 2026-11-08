"""Emisión y validación de JWT (access, elevated y step-up)."""

from __future__ import annotations

import secrets
import time
from typing import Any, Literal

import jwt

from . import config

TokenType = Literal["access", "step_up"]


class TokenError(Exception):
    def __init__(self, reason: str):
        super().__init__(reason)
        self.reason = reason


def _encode(claims: dict[str, Any], ttl: int) -> str:
    now = int(time.time())
    payload = {
        "iss": config.JWT_ISSUER,
        "iat": now,
        "exp": now + ttl,
        "jti": secrets.token_hex(8),
        **claims,
    }
    return jwt.encode(payload, config.JWT_SECRET, algorithm=config.JWT_ALGORITHM)


def create_access_token(user_id: str, mfa_verified: bool = False) -> tuple[str, int]:
    ttl = config.ELEVATED_TOKEN_TTL if mfa_verified else config.ACCESS_TOKEN_TTL
    token = _encode({"sub": user_id, "typ": "access", "mfa_verified": mfa_verified}, ttl)
    return token, ttl


def create_step_up_token(user_id: str) -> str:
    return _encode({"sub": user_id, "typ": "step_up"}, config.STEP_UP_TOKEN_TTL)


def decode(token: str, expected_type: TokenType) -> dict[str, Any]:
    try:
        claims = jwt.decode(
            token,
            config.JWT_SECRET,
            algorithms=[config.JWT_ALGORITHM],  # lista fija: evita el ataque "alg: none"
            issuer=config.JWT_ISSUER,
            options={"require": ["exp", "iat", "sub", "typ", "jti"]},
        )
    except jwt.ExpiredSignatureError as exc:
        raise TokenError("token_expired") from exc
    except jwt.PyJWTError as exc:
        raise TokenError("invalid_token") from exc
    if claims.get("typ") != expected_type:
        raise TokenError("invalid_token_type")
    return claims
