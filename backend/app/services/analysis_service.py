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

    def analyze_file(self,file):
        sha256 = self.calc_sha256(file)
        print(file.size)

        event = SecurityEvent(
            filename=file.filename,
            sha256=sha256,
            source="manual_upload",
            file_size=file.size
        )

        self.extract_metadata(event)

        print(vars(event))
        
        return event
    
analysis_service = AnalysisService()
