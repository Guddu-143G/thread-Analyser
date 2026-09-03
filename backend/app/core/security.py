import hashlib
import secrets
from datetime import datetime, timedelta, timezone

from jose import jwt
from passlib.context import CryptContext

from app.core.config import settings

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")


def hash_password(password: str) -> str:
    return pwd_context.hash(password)


def verify_password(plain: str, hashed: str) -> bool:
    return pwd_context.verify(plain, hashed)


def create_access_token(data: dict, expires_minutes: int | None = None) -> str:
    to_encode = data.copy()
    expire = datetime.now(timezone.utc) + timedelta(
        minutes=expires_minutes or settings.ACCESS_TOKEN_EXPIRE_MINUTES
    )
    to_encode.update({"exp": expire})
    return jwt.encode(to_encode, settings.SECRET_KEY, algorithm=settings.ALGORITHM)


def decode_access_token(token: str) -> dict:
    return jwt.decode(token, settings.SECRET_KEY, algorithms=[settings.ALGORITHM])


def generate_api_key() -> str:
    return f"ta_{secrets.token_urlsafe(32)}"


def hash_api_key(key: str) -> str:
    return hashlib.sha256(key.encode()).hexdigest()


def hash_token(raw_token: str) -> str:
    """SHA-256 token hashing for data-at-rest protection."""
    return hashlib.sha256(raw_token.encode("utf-8")).hexdigest()


class NeonAuthHandler:
    """
    Neon Auth & Neon Authorize (Row-Level Security) Handler.
    Synchronizes managed identity provider claims and configures session claims.
    """
    def __init__(self, jwks_url: str = "https://auth.neon.tech/.well-known/jwks.json"):
        self.jwks_url = jwks_url

    def generate_rls_claims_sql(self, user_id: str, org_id: str) -> str:
        """Returns the PostgreSQL session parameter command for RLS evaluation."""
        import json
        claims = json.dumps({"sub": user_id, "org_id": org_id})
        return f"SET LOCAL request.jwt.claims = '{claims}';"
