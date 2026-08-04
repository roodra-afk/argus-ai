import requests
import os

from dotenv import load_dotenv

class VirusTotalService:
    def __init__(self):
        load_dotenv()
        
        print("API key:", os.getenv("VIRUSTOTAL_API_KEY"))
        
        self.api_key=os.getenv("VIRUSTOTAL_API_KEY")
        self.base_url = "https://www.virustotal.com/api/v3"
        
    def get_status(self):
        return {
            "service": "VirusTotal Service",
            "status": "ready"
        }
        
    def is_configured(self):
        return self.api_key is not None

    def get_headers(self):
        return {
            "x-apikey": self.api_key
        }

    def get(self, endpoint):
        response = requests.get(
            f"{self.base_url}{endpoint}",
            headers=self.get_headers()
        )

        return response

    def lookup_file(self, sha256):
        if not self.is_configured():
            print("Virustotal API key not configured")
            return None

        response = self.get(f"/files/{sha256}")

        print("Status:", response.status_code)
        print("Respones:", response.text)
        
        if response.status_code != 200:
            return None

        data = response.json()["data"]["attributes"]

        stats = data["last_analysis_stats"]
        total_engines = sum(stats.values())

        return {
            "detections": stats["malicious"],
            "suspicious": stats["suspicious"],
            "undetected": stats["undetected"],
            "total_engines": total_engines,
            "sha256": data["sha256"],
            "times_submitted": data["times_submitted"],
            "first_submission": data["first_submission_date"],
            "last_analysis": data["last_analysis_date"],
            "reputation": data["reputation"],
            "tags": data.get("tags", []),
            "magic": data["magic"]
        }

        return None
        
virustotal_service = VirusTotalService()
