import os
import tempfile
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker, declarative_base
from sqlalchemy.pool import NullPool, QueuePool

from app.core.config import settings

connect_args = {}
raw_env_url = os.environ.get("DATABASE_URL", "").strip()
db_url = raw_env_url or settings.DATABASE_URL
is_serverless = bool(os.environ.get("VERCEL") or os.environ.get("AWS_LAMBDA_FUNCTION_NAME"))

tmp_db_path = os.path.join(tempfile.gettempdir(), "threat_analyser.db").replace("\\", "/")

# In Vercel or serverless, if no valid external Postgres is provided or still points to docker host @db:5432
if is_serverless:
    if not raw_env_url or "@db:" in db_url or "@localhost:" in db_url or "sqlite" in db_url:
        db_url = f"sqlite:///{tmp_db_path}"

if db_url.startswith("sqlite"):
    connect_args = {"check_same_thread": False}
    engine = create_engine(db_url, connect_args=connect_args, pool_pre_ping=True)
else:
    if db_url.startswith("postgres://"):
        db_url = db_url.replace("postgres://", "postgresql+psycopg2://", 1)
    pool_class = NullPool if is_serverless else QueuePool
    engine = create_engine(db_url, poolclass=pool_class, pool_pre_ping=True)

SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()

_initialized = False

def init_db_if_needed():
    global _initialized
    if _initialized:
        return
    try:
        from app.models import models, sbom  # noqa: F401
        Base.metadata.create_all(bind=engine)
        # Pre-seed default administrator so login works immediately
        with SessionLocal() as db:
            from app.models.models import User, Organization, Role
            from app.core.security import hash_password
            default_email = "subhojitacharya143@gmail.com"
            user = db.query(User).filter(User.email == default_email).first()
            if not user:
                org = db.query(Organization).first()
                if not org:
                    org = Organization(name="CyberTrace SecOps")
                    db.add(org)
                    db.flush()
                new_user = User(
                    org_id=org.id,
                    email=default_email,
                    hashed_password=hash_password("Subhoguddu143"),
                    role=Role.admin
                )
                db.add(new_user)
                db.commit()
        _initialized = True
    except Exception as e:
        print(f"[DB Init Warning] {e}")

def get_db():
    init_db_if_needed()
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()
