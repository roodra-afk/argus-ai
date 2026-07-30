from fastapi import APIRouter

from app.core.config import settings
from app.services.analysis_service import analysis_service

router = APIRouter(
    prefix="/api/v1"
)

@router.get("/")
def root():
    return {
        "message": "Argus API is running"
    }


@router.get("/health")
def health():
    return {
        "status": "healthy",
        "version": settings.version
    }

@router.get("/analysis/status")
def analysis_status():
    return analysis_service.get_status()
