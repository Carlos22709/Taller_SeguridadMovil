"""TOTP (RFC 6238) implementado a mano sobre HMAC-SHA1 de la librería estándar.

No se usa pyotp ni ninguna librería de alto nivel: solo hmac/hashlib.
"""

from __future__ import annotations

import hashlib
import hmac
import re

STEP_SECONDS = 30
DIGITS = 6

_BASE32_ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567"
_BASE32_RE = re.compile(r"^[A-Z2-7]+=*$")


def normalize_base32(secret: str) -> str:
    return re.sub(r"[\s-]", "", secret).upper()


def base32_decode(secret: str) -> bytes:
    """Decodifica Base32 (RFC 4648) sin depender de base64.b32decode."""
    clean = normalize_base32(secret)
    if not clean or not _BASE32_RE.match(clean):
        raise ValueError("Secreto Base32 inválido")
    clean = clean.rstrip("=")

    buffer = 0
    bits = 0
    out = bytearray()
    for char in clean:
        buffer = (buffer << 5) | _BASE32_ALPHABET.index(char)
        bits += 5
        if bits >= 8:
            bits -= 8
            out.append((buffer >> bits) & 0xFF)
    return bytes(out)


def hotp(key: bytes, counter: int, digits: int = DIGITS) -> str:
    # 1) Contador como entero de 64 bits big-endian (8 bytes)
    message = counter.to_bytes(8, "big")
    # 2) H = HMAC-SHA1(K, T)  -> 20 bytes
    digest = hmac.new(key, message, hashlib.sha1).digest()
    # 3) Truncamiento dinámico
    offset = digest[19] & 0x0F
    bin_code = (
        ((digest[offset] & 0x7F) << 24)
        | ((digest[offset + 1] & 0xFF) << 16)
        | ((digest[offset + 2] & 0xFF) << 8)
        | (digest[offset + 3] & 0xFF)
    )
    # 4) Módulo 10^digits con ceros a la izquierda
    return str(bin_code % (10**digits)).zfill(digits)


def time_counter(unix_time: float, step: int = STEP_SECONDS) -> int:
    return int(unix_time // step)


def totp(key: bytes, unix_time: float, digits: int = DIGITS, step: int = STEP_SECONDS) -> str:
    return hotp(key, time_counter(unix_time, step), digits)


def verify(key: bytes, code: str, unix_time: float, window: int = 1) -> int | None:
    """Valida el código en las ventanas C-1, C, C+1. Devuelve el contador que coincidió o None."""
    current = time_counter(unix_time)
    matched: int | None = None
    # Se recorren todas las ventanas sin cortar antes para no filtrar información por tiempos.
    for delta in range(-window, window + 1):
        candidate = hotp(key, current + delta, len(code))
        if hmac.compare_digest(candidate, code) and matched is None:
            matched = current + delta
    return matched


def provisioning_uri(secret: str, account: str, issuer: str) -> str:
    from urllib.parse import quote

    label = quote(f"{issuer}:{account}")
    return (
        f"otpauth://totp/{label}?secret={normalize_base32(secret)}"
        f"&issuer={quote(issuer)}&algorithm=SHA1&digits={DIGITS}&period={STEP_SECONDS}"
    )
