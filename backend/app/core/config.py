from pydantic_settings import BaseSettings
from functools import lru_cache


class Settings(BaseSettings):
    APP_NAME: str = "CyberTrace"
    ENV: str = "development"
    SECRET_KEY: str = "change-me-in-prod"
    ACCESS_TOKEN_EXPIRE_MINUTES: int = 60 * 12
    ALGORITHM: str = "HS256"

    DATABASE_URL: str = "postgresql://neondb_owner:npg_7ONEDK0pmPha@ep-shy-feather-b36m9clz-pooler.c-4.ap-southeast-1.aws.neon.tech/neondb?sslmode=require"
    REDIS_URL: str = "redis://redis:6379/0"

    CORS_ORIGINS: str = "*"

    class Config:
        env_file = ".env"
        extra = "ignore"


@lru_cache
def get_settings() -> Settings:
    return Settings()


settings = get_settings()
