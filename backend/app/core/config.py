from pydantic_settings import BaseSettings
from functools import lru_cache


class Settings(BaseSettings):
    APP_NAME: str = "Threat Analyser"
    ENV: str = "development"
    SECRET_KEY: str = "change-me-in-prod"
    ACCESS_TOKEN_EXPIRE_MINUTES: int = 60 * 12
    ALGORITHM: str = "HS256"

    DATABASE_URL: str = "postgresql+psycopg2://threat:threat@db:5432/threat_analyser"
    REDIS_URL: str = "redis://redis:6379/0"

    CORS_ORIGINS: str = "*"

    class Config:
        env_file = ".env"
        extra = "ignore"


@lru_cache
def get_settings() -> Settings:
    return Settings()


settings = get_settings()
