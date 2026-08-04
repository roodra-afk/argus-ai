class RiskService:
    def get_status(self):
        return {
            "service": "Risk Service",
            "status": "ready"
        }

    def calculate_score(self, event):
        score = 0
    
        if event.validation_warnings:
            score += 20
    
        if (
            event.pe_info and
            event.pe_info["suspicious_apis"]
        ):
            score += 5
    
        if (
            event.entropy_info and
            event.entropy_info["entropy"] >= 7.2
        ):
            score += 25
    
        if event.pe_info:
            reason_count = event.pe_info["packer"]["reason_count"]
            score += reason_count * 10
    
        if event.virustotal_info:
            detections = event.virustotal_info["detections"]
    
            if detections >= 20:
                score += 60
            elif detections >= 10:
                score += 40
            elif detections >= 5:
                score += 20
    
        return min(score, 100)

    def calculate_verdict(self, score):
        if score >= 50:
            return "Malicious"

        if score >= 20:
            return "Suspicious"

        return "Benign"

    def get_summary(self, event):
        score = self.calculate_score(event)

        return {
            "score": score,
            "verdict": self.calculate_verdict(score)
        }

risk_service = RiskService()
