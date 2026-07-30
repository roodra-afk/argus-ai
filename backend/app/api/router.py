from fastapi import APIRouter

from app.core.config import settings

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
