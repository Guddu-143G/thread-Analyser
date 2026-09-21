import sys
import os

# Set VERCEL environment flag
os.environ["VERCEL"] = "1"

# Ensure backend directory is in sys.path
current_dir = os.path.dirname(os.path.abspath(__file__))
root_dir = os.path.dirname(current_dir)
backend_dir = os.path.join(root_dir, "backend")

if backend_dir not in sys.path:
    sys.path.insert(0, backend_dir)

# Ensure sqlite uses writable /tmp in serverless environment
if not os.environ.get("DATABASE_URL") or "sqlite" in os.environ.get("DATABASE_URL", ""):
    os.environ["DATABASE_URL"] = "sqlite:////tmp/threat_analyser.db"

try:
    # Import the FastAPI ASGI application
    from app.main import app as main_app
except Exception as err:
    import traceback
    traceback.print_exc()
    from fastapi import FastAPI
    from fastapi.responses import JSONResponse
    main_app = FastAPI(title="CyberTrace Fallback API")
    @main_app.api_route("/{path:path}", methods=["GET", "POST", "PUT", "DELETE", "OPTIONS", "HEAD"])
    async def catch_all(path: str):
        return JSONResponse(
            status_code=500,
            content={"error": "Backend initialization failed", "detail": str(err)}
        )

# Normalization ASGI middleware: ensures /auth/login maps to /api/auth/login if /api prefix is omitted
class PathNormalizerMiddleware:
    def __init__(self, asgi_app):
        self.asgi_app = asgi_app

    async def __call__(self, scope, receive, send):
        if scope["type"] in ("http", "websocket"):
            path = scope.get("path", "")
            if path and not path.startswith("/api/") and path != "/api" and path != "/" and not path.startswith("/docs") and not path.startswith("/openapi"):
                scope["path"] = f"/api{path}"
        await self.asgi_app(scope, receive, send)

handler = PathNormalizerMiddleware(main_app)
app = handler
