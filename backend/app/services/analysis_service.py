import json

from app.db.database import SessionLocal
from app.repositories.analysis_repository import AnalysisRepository
from app.services.report_service import report_service
from app.services.mitre_service import mitre_service
from app.services.virustotal_service import virustotal_service
from app.services.signature_service import signature_service
from app.services.risk_service import risk_service
from app.services.entropy_service import entropy_service
from app.services.string_service import string_service
from app.services.pe_service import pe_service
from app.core.executable_extensions import EXECUTABLE_EXTENSIONS
from app.core.mime_types import EXPECTED_MIME_TYPES
from app.core.file_types import EXPECTED_EXTENSIONS
from app.core.signatures import FILE_SIGNATURES
from app.models.security_event import SecurityEvent
from app.services.ai_service import ai_service

import mimetypes
import os
import hashlib

class AnalysisService:
    def __init__(self):
        self.analysis_cache = {}
    
        self.db = SessionLocal()
        self.analysis_repository = AnalysisRepository(self.db)
            
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
        self.validate_double_extension(event)

    def add_warning(self, event, message):
        event.validation_warnings.append(message)

    def validate_mapping(self, event, mapping, actual_value, field_name):
        expected_value = mapping.get(event.detected_type)

        if expected_value is None:
            return

        if actual_value != expected_value:
            self.add_warning(
                event,
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

    def validate_double_extension(self, event):
        parts = event.filename.split(".")

        if len(parts) < 3:
            return

        last_extension = "." + parts[-1]

        if last_extension not in EXECUTABLE_EXTENSIONS:
            return

        self.add_warning(
            event,
            f"Suspicious double extension detected: {event.filename}"
        )
        
    def analyze_file(self, file):
        sha256 = self.calc_sha256(file)

        event = SecurityEvent(
            filename=file.filename,
            sha256=sha256,
            source="manual_upload",
            file_size=file.size
        )

        event.virustotal_info = virustotal_service.lookup_file(event.sha256)

        self.extract_metadata(event)
        self.detect_file_type(file, event)
        self.validate_file(event)

        event.string_info = string_service.get_summary(file)
        event.entropy_info = entropy_service.get_summary(file)
        
        if event.detected_type == "Windows Executable":
            pe = pe_service.load_pe(file)
            event.pe_info = pe_service.get_summary(pe)
            event.signature_info = signature_service.get_summary(pe)
            event.mitre_info = mitre_service.get_summary(pe)

        risk = risk_service.get_summary(event)
                
        event.risk_score = risk["score"]
        event.verdict = risk["verdict"]
        
        event.ai_explanation = ai_service.generate_explanation(event)
        
        report_service.generate(event, "report.pdf")
        
        self.analysis_cache[event.filename] = event
        
        self.analysis_repository.save(event)
        
        return event

    def get_analysis(self, filename):
        return self.analysis_cache.get(filename)

    def get_persisted_analysis(self, sha256):
        db = SessionLocal()
    
        try:
            repository = AnalysisRepository(db)
            analysis = repository.get_by_sha256(sha256)
    
            if analysis is None:
                return None
    
            event = SecurityEvent(
                filename=analysis.filename,
                sha256=analysis.sha256,
                source="database",
                file_size=analysis.file_size,
            )
    
            event.detected_type = analysis.detected_type
            event.risk_score = analysis.risk_score
            event.verdict = analysis.verdict
    
            event.validation_warnings = (
                json.loads(analysis.validation_warnings)
                if analysis.validation_warnings
                else []
            )
    
            event.pe_info = (
                json.loads(analysis.pe_info)
                if analysis.pe_info
                else None
            )
    
            event.string_info = (
                json.loads(analysis.string_info)
                if analysis.string_info
                else None
            )
    
            event.entropy_info = (
                json.loads(analysis.entropy_info)
                if analysis.entropy_info
                else None
            )
    
            event.signature_info = (
                json.loads(analysis.signature_info)
                if analysis.signature_info
                else None
            )
    
            event.virustotal_info = (
                json.loads(analysis.virustotal_info)
                if analysis.virustotal_info
                else None
            )
    
            event.mitre_info = (
                json.loads(analysis.mitre_info)
                if analysis.mitre_info
                else []
            )
    
            event.ai_explanation = analysis.ai_explanation
    
            return event
    
        finally:
            db.close()
    
    def get_analysis_for_chat(self, filename):
        # First try the in-memory cache
        event = self.get_analysis(filename)
    
        if event is not None:
            return event
    
        # Fall back to SQLite
        db = SessionLocal()
    
        try:
            repository = AnalysisRepository(db)
            analysis = repository.get_by_filename(filename)
    
            if analysis is None:
                return None
    
            event = SecurityEvent(
                filename=analysis.filename,
                sha256=analysis.sha256,
                source=analysis.source,
                file_size=analysis.file_size or 0,
            )
    
            event.detected_type = analysis.detected_type
            event.risk_score = analysis.risk_score
            event.verdict = analysis.verdict
    
            event.virustotal_info = {
                "detections": analysis.vt_detections,
                "total_engines": analysis.vt_total_engines,
            }
    
            event.signature_info = {
                "signed": analysis.signed,
            }
    
            event.pe_info = (
                json.loads(analysis.pe_info)
                if analysis.pe_info
                else None
            )
    
            event.mitre_info = (
                json.loads(analysis.mitre_info)
                if analysis.mitre_info
                else []
            )
    
            event.ai_explanation = analysis.ai_explanation
    
            return event
    
        finally:
            db.close()
    
analysis_service = AnalysisService()
