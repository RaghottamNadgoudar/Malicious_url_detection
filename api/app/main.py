"""
FastAPI application entry point.
"""

import os
import time
from contextlib import asynccontextmanager
from typing import AsyncGenerator

from fastapi import FastAPI, Request, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from dotenv import load_dotenv

from app.routes.analyze import router as analyze_router
from app.routes.health import router as health_router
from app.utils.logger import get_logger

# Load .env if present
load_dotenv()

logger = get_logger("main")


# ── Lifespan ──────────────────────────────────────────────────────────────────

@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncGenerator:
    """Startup / shutdown lifecycle."""
    logger.info("=" * 60)
    logger.info("  URL Security Platform API  v1.0.0")
    logger.info("=" * 60)

    # Pre-import singletons so they initialise at startup (not first request)
    from app.services.predictor import predictor_service
    from app.services.url_expander import url_expansion_service
    from app.services.redirect_analyzer import redirect_analyzer_service
    from app.services.feature_extractor import feature_extractor_service
    from app.services.risk_scorer import risk_scorer_service

    model_status = "Neural Net" if predictor_service.model_loaded else "Heuristic Fallback"
    logger.info(f"  Predictor: {model_status}")
    logger.info("  All services ready.")
    logger.info("=" * 60)

    yield  # ← app runs here

    logger.info("Shutting down — clearing caches.")
    url_expansion_service.clear_cache()


# ── App factory ───────────────────────────────────────────────────────────────

def create_app() -> FastAPI:
    app = FastAPI(
        title="URL Security Platform",
        description=(
            "Production-ready URL security analysis platform. "
            "Combines URL expansion, redirect chain tracing, "
            "feature engineering, and ML-based threat detection."
        ),
        version="1.0.0",
        lifespan=lifespan,
        docs_url="/docs",
        redoc_url="/redoc",
    )

    # ── CORS ──────────────────────────────────────────────────────────────────
    origins_raw = os.getenv(
        "CORS_ORIGINS",
        "http://localhost:5173,http://localhost:3000,http://localhost:5000",
    )
    origins = [o.strip() for o in origins_raw.split(",") if o.strip()]

    app.add_middleware(
        CORSMiddleware,
        allow_origins=origins,
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )

    # ── Request timing middleware ─────────────────────────────────────────────
    @app.middleware("http")
    async def add_timing_header(request: Request, call_next):
        t0 = time.perf_counter()
        response = await call_next(request)
        elapsed = round((time.perf_counter() - t0) * 1000, 1)
        response.headers["X-Process-Time-Ms"] = str(elapsed)
        return response

    # ── Global error handler ──────────────────────────────────────────────────
    @app.exception_handler(Exception)
    async def global_exception_handler(request: Request, exc: Exception):
        logger.error(f"Unhandled exception on {request.url}: {exc}", exc_info=True)
        return JSONResponse(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            content={"detail": "Internal server error", "error": str(exc)},
        )

    # ── Routers ───────────────────────────────────────────────────────────────
    app.include_router(health_router)
    app.include_router(analyze_router)

    return app


app = create_app()


if __name__ == "__main__":
    import uvicorn

    uvicorn.run(
        "app.main:app",
        host=os.getenv("HOST", "0.0.0.0"),
        port=int(os.getenv("PORT", "5000")),
        reload=os.getenv("DEBUG", "false").lower() == "true",
        log_level=os.getenv("LOG_LEVEL", "info"),
    )
