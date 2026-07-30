class AnalysisService:
    def get_status(self):
        return {
            "service": "Analysis Service",
            "status": "ready"
        }

analysis_service = AnalysisService()
