from __future__ import annotations

import logging
from contextlib import asynccontextmanager

from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse

from app.api.admin import router as admin_router
from app.api.dashboard import router as dashboard_router
from app.api.live import router as live_router
from app.api.scan import router as scan_router
from app.authn import basic_auth_ok
from app.config import get_settings
from app.council import get_council
from app.db import init_db
from app.pipeline import drain_background
from app.proxy.router import close_http_client
from app.proxy.router import router as proxy_router

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s %(message)s")
log = logging.getLogger("prompt_scanner")


@asynccontextmanager
async def lifespan(app: FastAPI):
    await init_db()
    warmed = await get_council().prewarm()
    log.info("startup complete (council cache prewarmed: %s)", warmed)
    yield
    log.info("shutting down — draining in-flight council reviews")
    await drain_background()
    await close_http_client()


app = FastAPI(
    title="Prompt Scanner Gateway",
    description="API gateway that audits outbound LLM prompts for PII/PHI/IP/regulatory risk.",
    version="0.1.0",
    lifespan=lifespan,
)

settings = get_settings()
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.dashboard_origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.middleware("http")
async def api_key_gate(request: Request, call_next):
    """Optional shared-secret gate for the management API surfaces.

    The proxy routes are deliberately exempt — they carry the *provider's*
    credentials in their own auth header, and requiring a second key there
    would break drop-in compatibility with existing SDK configs.
    """
    settings = get_settings()
    if not settings.require_api_key:
        return await call_next(request)
    path = request.url.path
    exempt = path.startswith("/anthropic") or path.startswith("/openai") or path in (
        "/", "/health", "/docs", "/openapi.json", "/redoc",
    )
    if exempt or request.headers.get("x-api-key") == settings.api_key:
        return await call_next(request)
    return JSONResponse(status_code=401, content={"detail": "missing or invalid X-API-Key"})


@app.middleware("http")
async def dashboard_auth_gate(request: Request, call_next):
    """HTTP Basic Auth in front of the CISO dashboard's API + admin routes.

    Only active once SCANNER_DASHBOARD_PASSWORD is set — see app/authn.py.
    """
    settings = get_settings()
    path = request.url.path
    protected = path.startswith("/v1/dashboard") or path.startswith("/v1/admin")
    if not protected or basic_auth_ok(request.headers.get("authorization"), settings):
        return await call_next(request)
    return JSONResponse(
        status_code=401,
        content={"detail": "authentication required"},
        headers={"WWW-Authenticate": 'Basic realm="Prompt Scanner Dashboard"'},
    )


app.include_router(scan_router)
app.include_router(dashboard_router)
app.include_router(live_router)
app.include_router(admin_router)
app.include_router(proxy_router)


@app.get("/")
async def root() -> dict:
    return {
        "service": "prompt-scanner-gateway",
        "status": "ok",
        "proxy": {"anthropic": "/anthropic/v1/messages", "openai": "/openai/v1/chat/completions"},
        "dashboard_api": "/v1/dashboard/summary",
        "live_feed": "/v1/live",
    }


@app.get("/health")
async def health() -> dict:
    return {"status": "ok"}
