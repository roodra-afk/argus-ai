import json

from sqlalchemy import asc, desc, func, select

from app.db.models import Analysis


class AnalysisRepository:

    def __init__(self, db):
        self.db = db

    def save(self, event):
        analysis = Analysis(
            filename=event.filename,
            sha256=event.sha256,
            source=event.source,
            file_size=event.file_size,
            detected_type=event.detected_type,
            risk_score=event.risk_score,
            verdict=event.verdict,
            vt_detections=(
                event.virustotal_info.get("detections")
                if event.virustotal_info
                else None
            ),
            vt_total_engines=(
                event.virustotal_info.get("total_engines")
                if event.virustotal_info
                else None
            ),
            signed=(
                event.signature_info.get("signed")
                if event.signature_info
                else None
            ),
            pe_info=(
                json.dumps(event.pe_info)
                if event.pe_info
                else None
            ),
            mitre_info=(
                json.dumps(event.mitre_info)
                if event.mitre_info
                else None
            ),
            ai_explanation=event.ai_explanation,
        )

        self.db.add(analysis)
        self.db.commit()
        self.db.refresh(analysis)

        return analysis

    def get_by_sha256(self, sha256):
        statement = (
            select(Analysis)
            .where(Analysis.sha256 == sha256)
            .order_by(Analysis.created_at.desc())
        )

        return self.db.execute(statement).scalars().first()

    def get_by_filename(self, filename):
        statement = (
            select(Analysis)
            .where(Analysis.filename == filename)
            .order_by(Analysis.created_at.desc())
        )
    
        return self.db.execute(statement).scalars().first()

    def list_recent(
        self,
        page=1,
        limit=10,
        search=None,
        verdict=None,
        sort="newest",
    ):
        statement = select(Analysis)
    
        if search:
            search_pattern = f"%{search.lower()}%"
    
            statement = statement.where(
                func.lower(Analysis.filename).like(search_pattern)
                | func.lower(Analysis.sha256).like(search_pattern)
            )
    
        if verdict and verdict != "All":
            statement = statement.where(
                Analysis.verdict == verdict
            )
    
        if sort == "oldest":
            statement = statement.order_by(
                asc(Analysis.created_at)
            )
    
        elif sort == "highest-risk":
            statement = statement.order_by(
                desc(Analysis.risk_score)
            )
    
        elif sort == "lowest-risk":
            statement = statement.order_by(
                asc(Analysis.risk_score)
            )
    
        else:
            statement = statement.order_by(
                desc(Analysis.created_at)
            )
    
        count_statement = select(
            func.count()
        ).select_from(
            statement.subquery()
        )
    
        total = self.db.scalar(count_statement) or 0
    
        offset = (page - 1) * limit
    
        statement = (
            statement
            .offset(offset)
            .limit(limit)
        )
    
        analyses = self.db.execute(
            statement
        ).scalars().all()
    
        return {
            "items": analyses,
            "total": total,
        }

    def get_stats(self):
        total = self.db.scalar(
            select(func.count(Analysis.id))
        )
    
        malicious = self.db.scalar(
            select(func.count(Analysis.id))
            .where(Analysis.verdict == "Malicious")
        )
    
        suspicious = self.db.scalar(
            select(func.count(Analysis.id))
            .where(Analysis.verdict == "Suspicious")
        )
    
        benign = self.db.scalar(
            select(func.count(Analysis.id))
            .where(Analysis.verdict == "Benign")
        )
    
        average_risk = self.db.scalar(
            select(func.avg(Analysis.risk_score))
        )
    
        return {
            "total": total or 0,
            "malicious": malicious or 0,
            "suspicious": suspicious or 0,
            "benign": benign or 0,
            "average_risk": (
                round(float(average_risk), 2)
                if average_risk is not None
                else 0
            ),
        }

    def get_by_id(self, analysis_id):
        return self.db.get(Analysis, analysis_id)
