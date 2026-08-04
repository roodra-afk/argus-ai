from app.core.suspicious_sections import SUSPICIOUS_SECTIONS
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
            "section_count": self.get_section_count(pe),
            "sections": self.get_sections(pe),
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

    def get_sections(self, pe):
        sections = []

        for section in pe.sections:
            section_info = {
                "name": self.get_section_name(section),
                "virtual_size": section.Misc_VirtualSize,
                "raw_size": section.SizeOfRawData,
                "entropy": self.calculate_entropy(section),
                "permissions": self.get_permissions(section),
                "findings": self.analyze_section(section)
            }

            sections.append(section_info)

        return sections

    def calculate_entropy(self, section):
        return round(section.get_entropy(), 2)

    def get_section_name(self, section):
        return section.Name.decode().rstrip("\x00")

    def get_permissions(self, section):
        characteristics = section.Characteristics
        
        return {
            "read": bool(characteristics & 0x40000000),
            "write": bool(characteristics & 0x80000000),
            "execute": bool(characteristics & 0x20000000),
        }

    def analyze_section(self, section):
        findings = []

        entropy = self.calculate_entropy(section)
        permissions = self.get_permissions(section)

        name = self.get_section_name(section).lower()

        if name in SUSPICIOUS_SECTIONS:
            findings.append("Suspicious section name")

        if entropy >= 7.5:
            findings.append("High entropy section")

        if (
            permissions["read"] and
            permissions["write"] and
            permissions["execute"]
        ):
            findings.append("RWX section")

        if (
            permissions["write"] and
            permissions["execute"]
        ):
            findings.append("Writable executable section")

        return findings
        
pe_service = PEService()
