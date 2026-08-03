import math

class EntropyService:
    def get_status(self):
        return{
            "service": "Entropy Service",
            "status": "ready"
        }

    def calculate_entropy(self, data):
        if not data:
            return 0.0

        entropy = 0.0

        for byte in range(256):
            probability = data.count(byte) / len(data)

            if probability > 0:
                entropy -= probability * math.log2(probability)

        return round(entropy, 2)

    def get_summary(self, file):
        data = file.file.read()

        file.file.seek(0)

        return {
            "entropy": self.calculate_entropy(data)
        }

entropy_service = EntropyService()
