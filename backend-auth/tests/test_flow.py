import secrets
import time
from urllib.parse import parse_qs, urlparse

import pytest
from fastapi.testclient import TestClient

from app import config, main, pkce, totp
from app.store import build_store

REDIRECT = "unisabana-auth://callback"


@pytest.fixture(autouse=True)
def fresh_store(monkeypatch):
    monkeypatch.setattr(main, "store", build_store())


@pytest.fixture
def client():
    return TestClient(main.app)


def authorize(client, verifier, state="estado-123", redirect=REDIRECT):
    form = {
        "response_type": "code",
        "client_id": config.CLIENT_ID,
        "redirect_uri": redirect,
        "state": state,
        "code_challenge": pkce.s256_challenge(verifier),
        "code_challenge_method": "S256",
        "email": config.DEMO_USER_EMAIL,
        "password": config.DEMO_USER_PASSWORD,
        "decision": "allow",
    }
    res = client.post("/oauth/authorize", data=form, follow_redirects=False)
    assert res.status_code == 303, res.text
    location = urlparse(res.headers["location"])
    return parse_qs(location.query)


def login(client, delivery="body"):
    verifier = secrets.token_urlsafe(48)
    query = authorize(client, verifier)
    res = client.post("/auth/oauth/token", data={
        "grant_type": "authorization_code",
        "code": query["code"][0],
        "redirect_uri": REDIRECT,
        "client_id": config.CLIENT_ID,
        "code_verifier": verifier,
        "token_delivery": delivery,
    })
    assert res.status_code == 200, res.text
    return res


def current_code(offset=0):
    return totp.totp(totp.base32_decode(config.TOTP_SECRET), time.time() + offset)


# ---------------- OAuth + PKCE ----------------
def test_authorize_page_requires_registered_redirect(client):
    res = client.get("/oauth/authorize", params={
        "response_type": "code", "client_id": config.CLIENT_ID, "redirect_uri": "https://evil.example/cb",
        "state": "x", "code_challenge": pkce.s256_challenge("a" * 43), "code_challenge_method": "S256",
    })
    assert res.status_code == 400


@pytest.mark.parametrize("uri,expected", [
    ("exp://192.168.1.20:8081/--/callback", 200),
    ("exp://10.0.2.2:8081/--/callback", 200),
    ("exp://evil.example/--/otra", 400),
    ("evil://192.168.1.20:8081/--/callback", 400),
])
def test_expo_go_redirects(client, uri, expected):
    res = client.get("/oauth/authorize", params={
        "response_type": "code", "client_id": config.CLIENT_ID, "redirect_uri": uri,
        "state": "x", "code_challenge": pkce.s256_challenge("a" * 43), "code_challenge_method": "S256",
    })
    assert res.status_code == expected


def test_authorize_rejects_plain_method(client):
    res = client.get("/oauth/authorize", params={
        "response_type": "code", "client_id": config.CLIENT_ID, "redirect_uri": REDIRECT,
        "state": "x", "code_challenge": "a" * 43, "code_challenge_method": "plain",
    })
    assert res.status_code == 400


def test_redirect_returns_same_state(client):
    query = authorize(client, secrets.token_urlsafe(48), state="mi-state")
    assert query["state"] == ["mi-state"]
    assert "code" in query


def test_wrong_password_does_not_redirect(client):
    res = client.post("/oauth/authorize", data={
        "response_type": "code", "client_id": config.CLIENT_ID, "redirect_uri": REDIRECT, "state": "s",
        "code_challenge": pkce.s256_challenge("a" * 43), "code_challenge_method": "S256",
        "email": config.DEMO_USER_EMAIL, "password": "mala",
    }, follow_redirects=False)
    assert res.status_code == 401


def test_token_exchange_with_wrong_verifier_fails(client):
    query = authorize(client, secrets.token_urlsafe(48))
    res = client.post("/auth/oauth/token", data={
        "grant_type": "authorization_code", "code": query["code"][0], "redirect_uri": REDIRECT,
        "client_id": config.CLIENT_ID, "code_verifier": secrets.token_urlsafe(48),
    })
    assert res.status_code == 400
    assert res.json()["error"] == "invalid_grant"


def test_auth_code_is_single_use(client):
    verifier = secrets.token_urlsafe(48)
    query = authorize(client, verifier)
    data = {"grant_type": "authorization_code", "code": query["code"][0], "redirect_uri": REDIRECT,
            "client_id": config.CLIENT_ID, "code_verifier": verifier}
    assert client.post("/auth/oauth/token", data=data).status_code == 200
    assert client.post("/auth/oauth/token", data=data).status_code == 400


def test_token_response_has_no_store_and_both_tokens(client):
    res = login(client)
    body = res.json()
    assert body["token_type"] == "Bearer" and body["access_token"] and body["refresh_token"]
    assert res.headers["cache-control"] == "no-store"


def test_cookie_delivery_hides_refresh_token(client):
    res = login(client, delivery="cookie")
    assert "refresh_token" not in res.json()
    cookie = res.headers["set-cookie"]
    assert "HttpOnly" in cookie and "SameSite=strict" in cookie and "Path=/auth" in cookie


# ---------------- Refresh ----------------
def test_refresh_rotates_and_detects_reuse(client):
    first = login(client).json()["refresh_token"]
    res = client.post("/auth/refresh", json={"refresh_token": first})
    assert res.status_code == 200
    second = res.json()["refresh_token"]
    assert second != first

    # Reusar el token viejo => se revoca toda la familia (incluido el nuevo)
    assert client.post("/auth/refresh", json={"refresh_token": first}).status_code == 401
    assert client.post("/auth/refresh", json={"refresh_token": second}).status_code == 401


def test_refresh_via_cookie(client):
    login(client, delivery="cookie")  # TestClient guarda la cookie
    res = client.post("/auth/refresh")
    assert res.status_code == 200 and "refresh_token" not in res.json()


def test_protected_api_requires_valid_token(client):
    assert client.get("/api/perfil").status_code == 401
    assert client.get("/api/perfil", headers={"Authorization": "Bearer basura"}).status_code == 401
    token = login(client).json()["access_token"]
    assert client.get("/api/perfil", headers={"Authorization": f"Bearer {token}"}).status_code == 200


# ---------------- Step-Up + Anti-Replay ----------------
def test_step_up_flow_and_replay(client):
    access = login(client).json()["access_token"]
    auth = {"Authorization": f"Bearer {access}"}

    res = client.get("/api/boveda-critica", headers=auth)
    assert res.status_code == 403
    body = res.json()
    assert body["error"] == "mfa_required" and body["step_up_token"]

    code = current_code()
    res = client.post("/auth/mfa/verify", json={"step_up_token": body["step_up_token"], "code": code})
    assert res.status_code == 200, res.text
    elevated = res.json()["elevated_token"]

    res = client.get("/api/boveda-critica", headers={"Authorization": f"Bearer {elevated}"})
    assert res.status_code == 200 and res.json()["items"]

    # Replay: mismo código con un step_up_token nuevo
    step_up = client.get("/api/boveda-critica", headers=auth).json()["step_up_token"]
    res = client.post("/auth/mfa/verify", json={"step_up_token": step_up, "code": code})
    assert res.status_code == 409
    assert res.json()["message"] == "Replay Attack Detected"


def test_clock_skew_window(client):
    access = login(client).json()["access_token"]
    auth = {"Authorization": f"Bearer {access}"}
    step_up = client.get("/api/boveda-critica", headers=auth).json()["step_up_token"]
    assert client.post("/auth/mfa/verify", json={"step_up_token": step_up, "code": current_code(-30)}).status_code == 200
    step_up = client.get("/api/boveda-critica", headers=auth).json()["step_up_token"]
    assert client.post("/auth/mfa/verify", json={"step_up_token": step_up, "code": current_code(-120)}).status_code == 401


def test_step_up_token_cannot_be_used_as_access_token(client):
    access = login(client).json()["access_token"]
    step_up = client.get("/api/boveda-critica", headers={"Authorization": f"Bearer {access}"}).json()["step_up_token"]
    assert client.get("/api/boveda-critica", headers={"Authorization": f"Bearer {step_up}"}).status_code == 401


def test_mfa_attempts_are_limited(client):
    access = login(client).json()["access_token"]
    step_up = client.get("/api/boveda-critica", headers={"Authorization": f"Bearer {access}"}).json()["step_up_token"]
    bad = "000000" if current_code() != "000000" else "111111"
    for _ in range(config.MFA_MAX_ATTEMPTS):
        client.post("/auth/mfa/verify", json={"step_up_token": step_up, "code": bad})
    res = client.post("/auth/mfa/verify", json={"step_up_token": step_up, "code": current_code()})
    assert res.status_code == 429
