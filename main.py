"""
main.py — FastAPI application entry point for the Bug Bounty Recon Assistant.
"""

import logging
import sys
from contextlib import asynccontextmanager
from pathlib import Path

import uvicorn
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse, JSONResponse

import config
from core.memory import init_db
from core.tools import check_tools
from core.llm import llm_engine
from api.routes_scan import router as scan_router
from api.routes_chat import router as chat_router
from api.routes_report import router as report_router

# ─── Logging Setup ────────────────────────────────────────────────────────────
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    handlers=[
        logging.StreamHandler(sys.stdout),
    ],
)
logger = logging.getLogger("recon_assistant")


# ─── Lifespan ─────────────────────────────────────────────────────────────────

@asynccontextmanager
async def lifespan(app: FastAPI):
    """Startup / shutdown lifecycle."""
    logger.info("=" * 60)
    logger.info("  Bug Bounty Recon Assistant — Starting Up")
    logger.info("=" * 60)

    # Initialize database
    init_db()
    logger.info("✓ Database initialized")

    # Check tool availability
    available, missing = check_tools()
    logger.info(f"✓ Recon tools available: {available}")
    if missing:
        logger.warning(f"⚠ Missing tools (will be skipped): {missing}")

    # Initialize LLM engine (model selection)
    if config.NVIDIA_API_KEY:
        try:
            model = await llm_engine.initialize()
            logger.info(f"✓ LLM engine ready — model: {model}")
        except Exception as e:
            logger.error(f"✗ LLM initialization failed: {e}")
    else:
        logger.warning("⚠ NVIDIA_API_KEY not set — AI features disabled")

    logger.info(f"✓ Server ready at http://{config.HOST}:{config.PORT}")
    logger.info("=" * 60)

    yield

    # Shutdown
    await llm_engine.close()
    logger.info("Shutdown complete")


# ─── App Initialization ───────────────────────────────────────────────────────

app = FastAPI(
    title="Bug Bounty Recon Assistant",
    description="AI-powered automated reconnaissance and vulnerability analysis for bug bounty hunters",
    version="1.0.0",
    lifespan=lifespan,
    docs_url="/api/docs",
    redoc_url="/api/redoc",
    openapi_url="/api/openapi.json",
)

# CORS
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ─── API Routes ───────────────────────────────────────────────────────────────
app.include_router(scan_router, prefix="/api", tags=["Scans"])
app.include_router(chat_router, prefix="/api", tags=["Chat"])
app.include_router(report_router, prefix="/api", tags=["Reports"])

# ─── Health Check ─────────────────────────────────────────────────────────────

@app.get("/api/health", tags=["System"])
async def health_check():
    """System health check — tool availability and LLM connectivity."""
    available, missing = check_tools()
    api_connected = await llm_engine.is_api_connected()

    return JSONResponse({
        "status": "ok",
        "model_selected": llm_engine.model or "not initialized",
        "tools_available": available,
        "tools_missing": missing,
        "api_connected": api_connected,
        "nvidia_api_key_set": bool(config.NVIDIA_API_KEY),
    })


# ─── Static Files ─────────────────────────────────────────────────────────────
static_dir = Path(__file__).parent / "static"
if static_dir.exists():
    app.mount("/static", StaticFiles(directory=str(static_dir)), name="static")

    @app.get("/", include_in_schema=False)
    async def serve_ui():
        return FileResponse(str(static_dir / "index.html"))

    @app.get("/{full_path:path}", include_in_schema=False)
    async def catch_all(full_path: str):
        # Serve index.html for all non-API routes (SPA routing)
        if not full_path.startswith("api/") and not full_path.startswith("ws/"):
            index = static_dir / "index.html"
            if index.exists():
                return FileResponse(str(index))
        return JSONResponse({"detail": "Not found"}, status_code=404)


# ─── Entry Point ──────────────────────────────────────────────────────────────

if __name__ == "__main__":
    uvicorn.run(
        "main:app",
        host=config.HOST,
        port=config.PORT,
        reload=config.DEBUG,
        log_level="info",
        access_log=True,
    )
