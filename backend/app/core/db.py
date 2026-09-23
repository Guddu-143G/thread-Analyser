import os
import shutil
import tempfile
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker, declarative_base
from sqlalchemy.pool import NullPool, QueuePool

from app.core.config import settings

# Locate bundled SQLite database if available
cur_file_dir = os.path.dirname(os.path.abspath(__file__))
backend_dir = os.path.dirname(os.path.dirname(cur_file_dir))
root_dir = os.path.dirname(backend_dir)
candidates = [
    os.path.join(root_dir, "threat_analyser.db"),
    os.path.join(backend_dir, "threat_analyser.db"),
    os.path.join(os.getcwd(), "threat_analyser.db"),
    "threat_analyser.db",
]
existing_local_db = next((p for p in candidates if os.path.isfile(p)), None)

tmp_dir = tempfile.gettempdir()
try:
    os.makedirs(tmp_dir, exist_ok=True)
except Exception:
    pass
tmp_db_path = os.path.join(tmp_dir, "threat_analyser.db").replace("\\", "/")
tmp_db_url = f"sqlite:///{tmp_db_path}" if not tmp_db_path.startswith("/") else f"sqlite://{tmp_db_path}"

# Seed tmp database from existing pre-populated file if in serverless
if existing_local_db and not os.path.exists(tmp_db_path):
    try:
        shutil.copyfile(existing_local_db, tmp_db_path)
    except Exception:
        pass

is_serverless = bool(os.environ.get("VERCEL") or os.environ.get("AWS_LAMBDA_FUNCTION_NAME"))
raw_env_url = (os.environ.get("DATABASE_URL") or getattr(settings, "DATABASE_URL", "")).strip()

fallback_sqlite_url = tmp_db_url if is_serverless else (
    f"sqlite:///{os.path.abspath(existing_local_db).replace('\\', '/')}" if existing_local_db else tmp_db_url
)

db_url = raw_env_url
if not db_url or "@db:" in db_url or ("@localhost:5432" in db_url and not os.environ.get("USE_LOCAL_POSTGRES")):
    db_url = fallback_sqlite_url

if db_url.startswith("postgres://"):
    db_url = db_url.replace("postgres://", "postgresql+psycopg2://", 1)
elif db_url.startswith("postgresql://") and not db_url.startswith("postgresql+"):
    db_url = db_url.replace("postgresql://", "postgresql+psycopg2://", 1)

def create_configured_engine(target_url):
    if target_url.startswith("sqlite"):
        return create_engine(target_url, connect_args={"check_same_thread": False}, pool_pre_ping=True)
    pool_class = NullPool if is_serverless else QueuePool
    return create_engine(
        target_url,
        poolclass=pool_class,
        pool_pre_ping=True,
        connect_args={"connect_timeout": 5}
    )

engine = None
try:
    engine = create_configured_engine(db_url)
    if not db_url.startswith("sqlite"):
        with engine.connect() as conn:
            pass
except Exception as err:
    print(f"[Database Engine Warning] Failed connecting to {db_url}: {err}. Falling back to SQLite.", flush=True)
    db_url = fallback_sqlite_url
    engine = create_configured_engine(fallback_sqlite_url)

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
