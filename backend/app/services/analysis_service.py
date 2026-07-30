from app.models.security_event import SecurityEvent

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

    def analyze_file(self,file):
        sha256 = self.calc_sha256(file)
        print(file.size)

        event = SecurityEvent(
            filename=file.filename,
            sha256=sha256,
            source="manual_upload",
            file_size=file.size
        )

        return event

    
analysis_service = AnalysisService()
