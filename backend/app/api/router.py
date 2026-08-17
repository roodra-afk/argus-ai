import json

from fastapi import APIRouter, Depends, File, HTTPException, Query, UploadFile
from fastapi.responses import FileResponse

from app.core.config import settings

from app.schemas.upload_response import UploadResponse
from app.schemas.analysis_history import AnalysisHistoryItem
from app.schemas.chat_request import ChatRequest
from app.schemas.chat_response import ChatResponse

from app.services.analysis_service import analysis_service
from app.services.ai_service import ai_service
from app.services.report_service import report_service

from app.db.database import get_db
from app.repositories.analysis_repository import AnalysisRepository


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
def upload_file(
    file: UploadFile = File(...),
    db=Depends(get_db),
):
    event = analysis_service.analyze_file(
        file,
        db,
    )

    return UploadResponse(
        filename=file.filename,
        sha256=event.sha256,

        reused=event.reused,

        detected_type=event.detected_type,

        risk_score=event.risk_score,
        verdict=event.verdict,

        vt_detections=(
            event.virustotal_info["detections"]
            if event.virustotal_info
            else None
        ),
        vt_total_engines=(
            event.virustotal_info["total_engines"]
            if event.virustotal_info
            else None
        ),

        signed=event.signature_info["signed"],

        pe_info=event.pe_info,
        mitre_info=event.mitre_info,

        ai_explanation=event.ai_explanation
    )

@router.get(
    "/analysis/history",
)
def analysis_history(
    page: int = Query(1, ge=1),
    limit: int = Query(10, ge=1, le=100),
    search: str | None = None,
    verdict: str = "All",
    sort: str = "newest",
    db=Depends(get_db),
):
    repository = AnalysisRepository(db)

    result = repository.list_recent(
        page=page,
        limit=limit,
        search=search,
        verdict=verdict,
        sort=sort,
    )

    total = result["total"]

    total_pages = (
        (total + limit - 1) // limit
        if total > 0
        else 0
    )

    return {
        "items": [
            AnalysisHistoryItem(
                id=analysis.id,
                filename=analysis.filename,
                sha256=analysis.sha256,
                detected_type=analysis.detected_type,
                risk_score=analysis.risk_score,
                verdict=analysis.verdict,
                vt_detections=analysis.vt_detections,
                vt_total_engines=analysis.vt_total_engines,
                signed=analysis.signed,
                created_at=analysis.created_at,
            )
            for analysis in result["items"]
        ],
        "total": total,
        "page": page,
        "limit": limit,
        "total_pages": total_pages,
    }

@router.get("/analysis/stats")
def analysis_stats(
    db=Depends(get_db),
):
    repository = AnalysisRepository(db)

    return repository.get_stats()

@router.get("/analysis/{sha256}/report")
def download_report(sha256: str):
    report_path = report_service.get_report_path(sha256)

    if not report_path.exists():
        raise HTTPException(
            status_code=404,
            detail="Analysis report not found."
        )

    return FileResponse(
        path=report_path,
        media_type="application/pdf",
        filename=f"argus-{sha256[:16]}.pdf",
    )

@router.get(
    "/analysis/{sha256}",
    response_model=UploadResponse
)
def get_analysis_by_sha256(
    sha256: str,
    db=Depends(get_db),
):
    repository = AnalysisRepository(db)

    analysis = repository.get_by_sha256(sha256)

    if analysis is None:
        raise HTTPException(
            status_code=404,
            detail="Analysis not found."
        )

    return UploadResponse(
        filename=analysis.filename,
        sha256=analysis.sha256,

        detected_type=analysis.detected_type,

        risk_score=analysis.risk_score,
        verdict=analysis.verdict,

        vt_detections=analysis.vt_detections,
        vt_total_engines=analysis.vt_total_engines,

        signed=analysis.signed,

        pe_info=(
            json.loads(analysis.pe_info)
            if analysis.pe_info
            else None
        ),

        mitre_info=(
            json.loads(analysis.mitre_info)
            if analysis.mitre_info
            else []
        ),

        ai_explanation=analysis.ai_explanation
    )


@router.post(
    "/analysis/chat",
    response_model=ChatResponse
)
def chat(
    request: ChatRequest,
    db=Depends(get_db),
):
    event = analysis_service.get_analysis_for_chat(
        request.filename,
        db,
    )

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
