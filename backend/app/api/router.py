from fastapi import APIRouter, UploadFile, File

from app.core.config import settings
from app.schemas.upload_response import UploadResponse
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

@router.post(
    "/analysis/upload",
    response_model=UploadResponse
)
def upload_file(file: UploadFile = File(...)):
    event = analysis_service.analyze_file(file)
    
    return UploadResponse (
        filename  = file.filename,
        sha256 = event.sha256
    )
