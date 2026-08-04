class SecurityEvent:
    def __init__(
        self,
        filename: str,
        sha256: str,
        source: str,
        file_size: int,
    ):
        self.filename = filename
        self.extension = None
        self.sha256 = sha256
        self.source = source
        self.file_size = file_size
        self.mime_type = None
        self.risk_score = None
        self.verdict = None
        self.detected_type = None
        self.validation_warnings = []
        self.pe_info = None
        self.string_info = None
        self.entropy_info = None
        self.signature_info = None
