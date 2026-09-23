import sys
import os
import traceback

os.environ["VERCEL"] = "1"

# Ensure backend directory is in sys.path
current_dir = os.path.dirname(os.path.abspath(__file__))
root_dir = os.path.dirname(current_dir)
backend_dir = os.path.join(root_dir, "backend")

for candidate in [
    backend_dir,
    os.path.join(current_dir, "backend"),
    os.path.abspath(os.path.join(current_dir, "..", "backend")),
    root_dir,
]:
    if os.path.exists(candidate) and candidate not in sys.path:
        sys.path.insert(0, candidate)

try:
    from app.main import app
except Exception as e:
    err_trace = traceback.format_exc()
    print(f"[Vercel Startup Error]: {err_trace}", flush=True)
    from fastapi import FastAPI
    from fastapi.responses import JSONResponse
    from fastapi.middleware.cors import CORSMiddleware

    app = FastAPI(title="CyberTrace Diagnostic")
    app.add_middleware(
        CORSMiddleware,
        allow_origins=["*"],
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )

    @app.api_route("/", methods=["GET", "POST", "PUT", "DELETE", "OPTIONS", "HEAD"])
    @app.api_route("/{path:path}", methods=["GET", "POST", "PUT", "DELETE", "OPTIONS", "HEAD"])
    async def catch_all_error(path: str = ""):
        return JSONResponse(
            status_code=503,
            content={
                "error": "Backend initialization failed",
                "detail": str(e),
                "traceback": err_trace,
                "current_dir": current_dir,
                "sys_path": sys.path[:5],
                "root_files": os.listdir(root_dir) if os.path.exists(root_dir) else [],
                "backend_exists": os.path.exists(backend_dir),
            }
        )

