import pytest
from pydantic import ValidationError

from app.config import Settings


TEST_SECRET = "tests-explicitly-configure-this-signing-key-9347-AZ"


def test_missing_or_weak_jwt_secret_is_rejected(monkeypatch):
    monkeypatch.delenv("JWT_SECRET", raising=False)
    with pytest.raises(ValidationError):
        Settings(_env_file=None)
    with pytest.raises(ValidationError):
        Settings(_env_file=None, jwt_secret="x" * 48)


def test_cors_origins_uses_documented_environment_key(monkeypatch):
    monkeypatch.setenv("JWT_SECRET", TEST_SECRET)
    monkeypatch.setenv("CORS_ORIGINS", "https://console.example.test, https://ops.example.test ")
    settings = Settings(_env_file=None)
    assert settings.allowed_origins == [
        "https://console.example.test",
        "https://ops.example.test",
    ]
