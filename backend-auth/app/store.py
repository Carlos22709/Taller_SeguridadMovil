"""Almacenamiento en memoria (usuarios, códigos de autorización, refresh tokens, caché anti-replay)."""

from __future__ import annotations

import hashlib
import hmac
import secrets
import threading
import time
from dataclasses import dataclass, field

from . import config


def _hash_password(password: str, salt: bytes) -> bytes:
    return hashlib.pbkdf2_hmac("sha256", password.encode(), salt, 200_000)


def hash_token(token: str) -> str:
    """Los refresh tokens se guardan hasheados: si se filtra la memoria no se pueden reutilizar."""
    return hashlib.sha256(token.encode()).hexdigest()


@dataclass
class User:
    id: str
    email: str
    name: str
    salt: bytes
    password_hash: bytes
    totp_secret: str

    def check_password(self, password: str) -> bool:
        return hmac.compare_digest(_hash_password(password, self.salt), self.password_hash)


@dataclass
class AuthCode:
    client_id: str
    redirect_uri: str
    code_challenge: str
    user_id: str
    expires_at: float


@dataclass
class RefreshRecord:
    user_id: str
    family_id: str
    expires_at: float
    revoked: bool = False


@dataclass
class Store:
    lock: threading.Lock = field(default_factory=threading.Lock)
    users_by_email: dict[str, User] = field(default_factory=dict)
    users_by_id: dict[str, User] = field(default_factory=dict)
    auth_codes: dict[str, AuthCode] = field(default_factory=dict)
    refresh_tokens: dict[str, RefreshRecord] = field(default_factory=dict)
    replay_cache: dict[str, float] = field(default_factory=dict)
    mfa_failures: dict[str, int] = field(default_factory=dict)
    refresh_calls: int = 0

    # ---------- Usuarios ----------
    def add_user(self, email: str, password: str, name: str, totp_secret: str) -> User:
        salt = secrets.token_bytes(16)
        user = User(
            id=f"usr_{secrets.token_hex(6)}",
            email=email.lower(),
            name=name,
            salt=salt,
            password_hash=_hash_password(password, salt),
            totp_secret=totp_secret,
        )
        self.users_by_email[user.email] = user
        self.users_by_id[user.id] = user
        return user

    def authenticate(self, email: str, password: str) -> User | None:
        user = self.users_by_email.get(email.strip().lower())
        if user and user.check_password(password):
            return user
        return None

    # ---------- Códigos de autorización (un solo uso) ----------
    def create_auth_code(self, client_id: str, redirect_uri: str, code_challenge: str, user_id: str) -> str:
        code = secrets.token_urlsafe(32)
        with self.lock:
            self.auth_codes[code] = AuthCode(
                client_id=client_id,
                redirect_uri=redirect_uri,
                code_challenge=code_challenge,
                user_id=user_id,
                expires_at=time.time() + config.AUTH_CODE_TTL,
            )
        return code

    def consume_auth_code(self, code: str) -> AuthCode | None:
        with self.lock:
            record = self.auth_codes.pop(code, None)
        if record is None or record.expires_at < time.time():
            return None
        return record

    # ---------- Refresh tokens con rotación y detección de reuso ----------
    def issue_refresh_token(self, user_id: str, family_id: str | None = None) -> str:
        token = secrets.token_urlsafe(48)
        with self.lock:
            self.refresh_tokens[hash_token(token)] = RefreshRecord(
                user_id=user_id,
                family_id=family_id or secrets.token_hex(8),
                expires_at=time.time() + config.REFRESH_TOKEN_TTL,
            )
        return token

    def rotate_refresh_token(self, token: str) -> tuple[str, str] | None:
        """Devuelve (user_id, nuevo_refresh_token) o None si es inválido.

        Si se presenta un token ya rotado (revocado), se asume robo y se revoca toda la familia.
        """
        with self.lock:
            self.refresh_calls += 1
            record = self.refresh_tokens.get(hash_token(token))
            if record is None:
                return None
            if record.revoked:
                self._revoke_family_locked(record.family_id)
                return None
            if record.expires_at < time.time():
                record.revoked = True
                return None
            record.revoked = True
            user_id, family_id = record.user_id, record.family_id
        return user_id, self.issue_refresh_token(user_id, family_id)

    def revoke_refresh_token(self, token: str) -> None:
        with self.lock:
            record = self.refresh_tokens.get(hash_token(token))
            if record:
                self._revoke_family_locked(record.family_id)

    def _revoke_family_locked(self, family_id: str) -> None:
        for record in self.refresh_tokens.values():
            if record.family_id == family_id:
                record.revoked = True

    # ---------- Anti-replay TOTP ----------
    def is_replay(self, key: str) -> bool:
        now = time.time()
        with self.lock:
            for k in [k for k, exp in self.replay_cache.items() if exp < now]:
                del self.replay_cache[k]
            return key in self.replay_cache

    def remember_code(self, key: str) -> None:
        with self.lock:
            self.replay_cache[key] = time.time() + config.REPLAY_CACHE_TTL

    # ---------- Límite de intentos MFA por step_up_token ----------
    def register_mfa_failure(self, jti: str) -> int:
        with self.lock:
            self.mfa_failures[jti] = self.mfa_failures.get(jti, 0) + 1
            return self.mfa_failures[jti]

    def mfa_failures_for(self, jti: str) -> int:
        return self.mfa_failures.get(jti, 0)


def build_store() -> Store:
    store = Store()
    store.add_user(
        email=config.DEMO_USER_EMAIL,
        password=config.DEMO_USER_PASSWORD,
        name=config.DEMO_USER_NAME,
        totp_secret=config.TOTP_SECRET,
    )
    return store
