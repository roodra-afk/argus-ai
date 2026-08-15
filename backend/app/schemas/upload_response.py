from pydantic import BaseModel


class SectionPermissions(BaseModel):
    read: bool
    write: bool
    execute: bool


class SectionInfo(BaseModel):
    name: str
    virtual_size: int
    raw_size: int
    entropy: float
    permissions: SectionPermissions
    findings: list[str]


class PackerInfo(BaseModel):
    detected: bool
    reason_count: int
    import_count: int
    reasons: list[str]


class PEInfo(BaseModel):
    architecture: str
    section_count: int
    sections: list[SectionInfo]
    entry_point: str
    dlls: list[str]
    suspicious_apis: list[str]
    packer: PackerInfo


class MITRETechnique(BaseModel):
    technique: str
    name: str
    confidence: str
    evidence: list[str]


class UploadResponse(BaseModel):
    filename: str
    sha256: str

    reused: bool = False

    detected_type: str

    risk_score: int
    verdict: str

    vt_detections: int
    vt_total_engines: int

    signed: bool

    pe_info: PEInfo | None = None
    mitre_info: list[MITRETechnique] = []

    ai_explanation: str | None = None
