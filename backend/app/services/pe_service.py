from app.core.suspicious_apis import SUSPICIOUS_APIS

import pefile

MACHINE_TYPES = {
    0x14C: "x86",
    0x8664: "x64",
}

class PEService:
    def get_status(self):
        return {
            "service": "PE Service",
            "status": "ready"
        }

    def load_pe(self, file):
        pe = pefile.PE(data=file.file.read())

        file.file.seek(0)

        return pe

    def get_machine_type(self, pe):
        machine = pe.FILE_HEADER.Machine

        return MACHINE_TYPES.get(machine, hex(machine))

    def get_section_count(self, pe):
        return len(pe.sections)

    def get_summary(self, pe):
        return {
            "architecture": self.get_machine_type(pe),
            "sections": self.get_section_count(pe),
            "entry_point": self.get_entry_point(pe),
            "dlls": self.get_imported_dlls(pe),
            "suspicious_apis": self.get_suspicious_apis(pe),
        }

    def get_entry_point(self, pe):
        return hex(pe.OPTIONAL_HEADER.AddressOfEntryPoint)

    def get_imported_dlls(self, pe):
        dlls = []

        if not hasattr(pe, "DIRECTORY_ENTRY_IMPORT"):
            return dlls

        for entry in pe.DIRECTORY_ENTRY_IMPORT:
            dlls.append(entry.dll.decode())

        return dlls

    def get_imported_apis(self, pe):
        apis = []

        if not hasattr(pe, "DIRECTORY_ENTRY_IMPORT"):
            return apis

        for entry in pe.DIRECTORY_ENTRY_IMPORT:
            for imp in entry.imports:
                if imp.name:
                    apis.append(imp.name.decode())

        return apis

    def get_suspicious_apis(self, pe):
        suspicious = set()

        for api in self.get_imported_apis(pe):
            if api in SUSPICIOUS_APIS:
                suspicious.add(api)

        return sorted(suspicious)
        
pe_service = PEService()
