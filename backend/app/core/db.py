from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker, declarative_base

from app.core.config import settings

import os

connect_args = {}
db_url = settings.DATABASE_URL
is_serverless = os.environ.get("VERCEL") or os.environ.get("AWS_LAMBDA_FUNCTION_NAME")

if db_url.startswith("sqlite"):
    if is_serverless and not db_url.startswith("sqlite:////tmp/"):
        db_url = "sqlite:////tmp/threat_analyser.db"
    connect_args = {"check_same_thread": False}
else:
    try:
        import psycopg2  # noqa: F401
    except ImportError:
        fallback_path = "/tmp/threat_analyser.db" if is_serverless else "./threat_analyser.db"
        db_url = f"sqlite:///{fallback_path}"
        connect_args = {"check_same_thread": False}


engine = create_engine(db_url, connect_args=connect_args, pool_pre_ping=True)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()


def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()
