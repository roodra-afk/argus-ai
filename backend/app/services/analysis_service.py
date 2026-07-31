from app.core.file_types import EXPECTED_EXTENSIONS
from app.core.signatures import FILE_SIGNATURES
from app.models.security_event import SecurityEvent

import mimetypes
import os
import hashlib

class AnalysisService:
    def get_status(self):
        return {
            "service": "Analysis Service",
            "status": "ready"
        }

    def calc_sha256(self, file):
        sha256 = hashlib.sha256()

        while chunk := file.file.read(4096):
            sha256.update(chunk)

        file.file.seek(0)

        return sha256.hexdigest()

    def extract_metadata(self, event):
        event.extension = os.path.splitext(event.filename)[1].lower()

        mime_type, _ = mimetypes.guess_type(event.filename)
        event.mime_type = mime_type

    def detect_file_type(self, file, event):
        header = file.file.read(8)

        event.detected_type = "Unknown"

        for signature, file_type in FILE_SIGNATURES.items():
            if header.startswith(signature):
                event.detected_type = file_type
                break

        file.file.seek(0)

    def validate_file(self, event):
        self.validate_extension(event)

    def validate_extension(self, event):
        expected_extension = EXPECTED_EXTENSIONS.get(event.detected_type)
        
        if expected_extension is None:
            return
        
        if event.extension != expected_extension:
            event.validation_warnings.append(
                f"Extension mismatch: expected {expected_extension}, found {event.extension}"
            )
        
    def analyze_file(self, file):
        sha256 = self.calc_sha256(file)

        event = SecurityEvent(
            filename=file.filename,
            sha256=sha256,
            source="manual_upload",
            file_size=file.size
        )

        self.extract_metadata(event)
        self.detect_file_type(file, event)
        self.validate_file(event)

        print(vars(event))
        
        return event
    
analysis_service = AnalysisService()
