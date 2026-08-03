import re

class StringService:
    def get_status(self):
        return {
            "service": "String Service",
            "status": "ready"
        }

    def extract_strings(self, file):
        data = file.file.read()

        file.file.seek(0)

        pattern = rb"[\x20-\x7E]{4,}"

        matches = re.findall(pattern, data)

        return [match.decode(errors="ignore") for match in matches]

    def extract_urls(self, strings):
        pattern = r"https?://[^\s\"'<>]+"

        urls = set()

        for string in strings:
            matches = re.findall(pattern, string)

            for url in matches:
                urls.add(url.rstrip("0#{}|"))

        return sorted(urls)

    def get_summary(self, file):
        strings = self.extract_strings(file)

        return {
            "urls": self.extract_urls(strings)
        }
        
string_service = StringService()
