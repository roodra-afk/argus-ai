import pefile

class SignatureService:
    def get_status(self):
        return {
            "service": "Signature Service",
            "status": "ready" 
        }

    def get_summary(self, pe):
        security_directory = pe.OPTIONAL_HEADER.DATA_DIRECTORY[
            pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_SECURITY"]
        ]
        
        return {
            "signed": security_directory.VirtualAddress != 0
        }
    
signature_service = SignatureService()
