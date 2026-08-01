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
        }

    def get_entry_point(self, pe):
        return hex(pe.OPTIONAL_HEADER.AddressOfEntryPoint)

pe_service = PEService()
