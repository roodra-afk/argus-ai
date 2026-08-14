from datetime import datetime

from pydantic import BaseModel


class AnalysisHistoryItem(BaseModel):
    id: int
    filename: str
    sha256: str
    detected_type: str | None = None
    risk_score: int | None = None
    verdict: str | None = None
    vt_detections: int | None = None
    vt_total_engines: int | None = None
    signed: bool | None = None
    created_at: datetime
