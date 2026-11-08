import pytest

from app import pkce, totp

# RFC 6238, Apéndice B (SHA-1, semilla ASCII "12345678901234567890", 8 dígitos)
RFC_KEY = b"12345678901234567890"
RFC_VECTORS = [
    (59, "94287082"),
    (1111111109, "07081804"),
    (1111111111, "14050471"),
    (1234567890, "89005924"),
    (2000000000, "69279037"),
    (20000000000, "65353130"),
]


@pytest.mark.parametrize("unix_time,expected", RFC_VECTORS)
def test_rfc6238_vectors(unix_time, expected):
    assert totp.totp(RFC_KEY, unix_time, digits=8) == expected


@pytest.mark.parametrize("unix_time,expected", RFC_VECTORS)
def test_six_digit_codes_are_last_six_of_rfc(unix_time, expected):
    assert totp.totp(RFC_KEY, unix_time) == expected[-6:]


def test_base32_decode_matches_rfc_seed():
    assert totp.base32_decode("GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ") == RFC_KEY
    assert totp.base32_decode("gezd gnbv-gy3t qojq gezd gnbv gy3t qojq") == RFC_KEY


def test_base32_rejects_invalid():
    with pytest.raises(ValueError):
        totp.base32_decode("JBSWY3DP!!")
    with pytest.raises(ValueError):
        totp.base32_decode("")


def test_verify_accepts_adjacent_windows_only():
    key = totp.base32_decode("JBSWY3DPEHPK3PXP")
    now = 1_700_000_000
    for delta in (-30, 0, 30):
        assert totp.verify(key, totp.totp(key, now + delta), now) is not None
    for delta in (-90, 90):
        assert totp.verify(key, totp.totp(key, now + delta), now) is None


def test_pkce_rfc7636_example():
    # RFC 7636, Apéndice B
    verifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
    assert pkce.s256_challenge(verifier) == "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"
    assert pkce.verify(verifier, "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM")


def test_pkce_rejects_short_verifier():
    assert not pkce.verify("corto", pkce.s256_challenge("corto"))
