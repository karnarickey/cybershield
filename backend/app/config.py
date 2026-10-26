from functools import lru_cache

import math

from pydantic import AliasChoices, Field, SecretStr, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    database_url: str = Field(default="sqlite:///./cybershield.db", validation_alias="DATABASE_URL")
    jwt_secret: SecretStr = Field(validation_alias="JWT_SECRET")
    jwt_expire_minutes: int = Field(default=60, validation_alias="JWT_EXPIRE_MINUTES")
    cors_origins: str = Field(
        default="http://localhost:3000,http://localhost:5173",
        validation_alias=AliasChoices("CORS_ORIGINS", "CORS_ALLOWED_ORIGINS"),
    )
    app_name: str = "CyberShield Incident Response API"

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
        case_sensitive=False,
        populate_by_name=True,
    )

    @field_validator("jwt_secret")
    @classmethod
    def require_strong_signing_secret(cls, secret: SecretStr) -> SecretStr:
        value = secret.get_secret_value()
        if len(value) < 32 or len(set(value)) < 12:
            raise ValueError("JWT_SECRET must be a high-entropy secret of at least 32 characters")
        entropy = -sum(
            (count / len(value)) * math.log2(count / len(value))
            for count in (value.count(char) for char in set(value))
        )
        if entropy < 3.5:
            raise ValueError("JWT_SECRET must be a high-entropy secret of at least 32 characters")
        return secret

    @property
    def allowed_origins(self) -> list[str]:
        return [origin.strip() for origin in self.cors_origins.split(",") if origin.strip()]


@lru_cache
def get_settings() -> Settings:
    return Settings()
