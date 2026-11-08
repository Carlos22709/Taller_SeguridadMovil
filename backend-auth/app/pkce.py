"""Verificación PKCE (RFC 7636), método S256."""

from __future__ import annotations

import base64
import hashlib
import hmac
import re

# 43..128 caracteres "unreserved": [A-Z] [a-z] [0-9] - . _ ~
VERIFIER_RE = re.compile(r"^[A-Za-z0-9\-._~]{43,128}$")
CHALLENGE_RE = re.compile(r"^[A-Za-z0-9\-_]{43}$")  # SHA-256 en base64url sin relleno = 43 chars


def s256_challenge(code_verifier: str) -> str:
    digest = hashlib.sha256(code_verifier.encode("ascii")).digest()
    return base64.urlsafe_b64encode(digest).rstrip(b"=").decode("ascii")


def is_valid_challenge(code_challenge: str) -> bool:
    return bool(CHALLENGE_RE.match(code_challenge))


def verify(code_verifier: str, code_challenge: str) -> bool:
    if not VERIFIER_RE.match(code_verifier):
        return False
    return hmac.compare_digest(s256_challenge(code_verifier), code_challenge)
