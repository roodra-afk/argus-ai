from fastapi import HTTPException
from fastapi import APIRouter, UploadFile, File

from app.core.config import settings
from app.schemas.upload_response import UploadResponse
from app.services.analysis_service import analysis_service
from app.schemas.chat_request import ChatRequest
from app.schemas.chat_response import ChatResponse
from app.services.ai_service import ai_service

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
    
    return UploadResponse(
        filename=file.filename,
        sha256=event.sha256,
    
        detected_type=event.detected_type,
    
        risk_score=event.risk_score,
        verdict=event.verdict,
    
        vt_detections=event.virustotal_info["detections"],
        vt_total_engines=event.virustotal_info["total_engines"],
    
        signed=event.signature_info["signed"],
    
        ai_explanation=event.ai_explanation
    )

@router.post(
    "/analysis/chat",
    response_model=ChatResponse
)
def chat(request: ChatRequest):
    event = analysis_service.get_analysis(request.filename)

    if event is None:
        raise HTTPException(
            status_code=404,
            detail="Analysis not found. Upload the file first."
        )

    answer = ai_service.chat(
        event,
        request.question
    )

    return ChatResponse(
        answer=answer
    )
