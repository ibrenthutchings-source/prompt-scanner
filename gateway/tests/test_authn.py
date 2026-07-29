import base64

from app.authn import basic_auth_ok
from app.config import Settings


def _settings(**overrides) -> Settings:
    return Settings(_env_file=None, **overrides)


def _header(username: str, password: str) -> str:
    token = base64.b64encode(f"{username}:{password}".encode()).decode()
    return f"Basic {token}"


def test_disabled_when_password_unset():
    # Local-dev default: no SCANNER_DASHBOARD_PASSWORD means no gate at all,
    # so a missing header must still pass.
    settings = _settings(dashboard_password=None)
    assert basic_auth_ok(None, settings) is True


def test_correct_credentials_pass():
    settings = _settings(dashboard_username="ciso", dashboard_password="hunter2")
    assert basic_auth_ok(_header("ciso", "hunter2"), settings) is True


def test_wrong_password_rejected():
    settings = _settings(dashboard_username="ciso", dashboard_password="hunter2")
    assert basic_auth_ok(_header("ciso", "wrong"), settings) is False


def test_missing_header_rejected_when_enabled():
    settings = _settings(dashboard_password="hunter2")
    assert basic_auth_ok(None, settings) is False


def test_malformed_header_rejected():
    settings = _settings(dashboard_password="hunter2")
    assert basic_auth_ok("Basic not-valid-base64!!", settings) is False
    assert basic_auth_ok("Bearer sometoken", settings) is False
