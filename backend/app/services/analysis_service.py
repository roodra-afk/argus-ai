from app.core.mime_types import EXPECTED_MIME_TYPES
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
        self.validate_mime(event)

    def validate_mapping(self, event, mapping, actual_value, field_name):
        expected_value = mapping.get(event.detected_type)

        if expected_value is None:
            return

        if actual_value != expected_value:
            event.validation_warnings.append(
                f"{field_name} mismatch: expected {expected_value}, found {actual_value}"
            )

    def validate_extension(self, event):
        self.validate_mapping(
            event,
            EXPECTED_EXTENSIONS,
            event.extension,
            "Extension"
        )

    def validate_mime(self, event):
        self.validate_mapping(
            event,
            EXPECTED_MIME_TYPES,
            event.mime_type,
            "MIME"
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
