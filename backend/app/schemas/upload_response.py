from pydantic import BaseModel


class UploadResponse(BaseModel):
    filename: str
    sha256: str

    detected_type: str

    risk_score: int
    verdict: str

    vt_detections: int
    vt_total_engines: int

    signed: bool

    ai_explanation: str | None = None
