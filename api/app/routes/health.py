"""Health check route."""

import time
from fastapi import APIRouter
from app.schemas.response import HealthResponse
from app.services.predictor import predictor_service

router = APIRouter(tags=["Health"])

_START_TIME = time.time()


@router.get("/health", response_model=HealthResponse, summary="Health Check")
async def health() -> HealthResponse:
    """Returns API health status and model availability."""
    return HealthResponse(
        status="healthy",
        version="1.0.0",
        model_loaded=predictor_service.model_loaded,
        uptime_seconds=round(time.time() - _START_TIME, 1),
    )
