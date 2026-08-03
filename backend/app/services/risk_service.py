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
            score += 10

        if (
            event.entropy_info and
            event.entropy_info["entropy"] >= 7.2
        ):
            score += 25

        if (
            event.string_info and
            event.string_info["urls"]
        ):
            score += 5
            
        return score

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
