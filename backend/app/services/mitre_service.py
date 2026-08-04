from app.core.mitre_mapping import MITRE_MAPPING


class MITREService:
    def get_status(self):
        return {
            "service": "MITRE Service",
            "status": "ready"
        }

    def get_summary(self, pe):
        techniques = []

        if not hasattr(pe, "DIRECTORY_ENTRY_IMPORT"):
            return techniques

        seen = set()

        for entry in pe.DIRECTORY_ENTRY_IMPORT:
            for imp in entry.imports:
                if not imp.name:
                    continue

                api = imp.name.decode()

                if api not in MITRE_MAPPING:
                    continue

                technique = MITRE_MAPPING[api]

                if technique["technique"] in seen:
                    continue

                seen.add(technique["technique"])

                techniques.append({
                    "technique": technique["technique"],
                    "name": technique["name"],
                    "confidence": technique["confidence"],
                    "evidence": [api]
                })

        return techniques


mitre_service = MITREService()
