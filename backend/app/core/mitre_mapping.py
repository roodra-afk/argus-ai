MITRE_MAPPING = {
    "CreateRemoteThread": {
        "technique": "T1055",
        "name": "Process Injection",
        "confidence": "High"
    },
    "WriteProcessMemory": {
        "technique": "T1055",
        "name": "Process Injection",
        "confidence": "High"
    },
    "VirtualAllocEx": {
        "technique": "T1055",
        "name": "Process Injection",
        "confidence": "High"
    },
    "VirtualProtect": {
        "technique": "T1620",
        "name": "Reflective Code Loading",
        "confidence": "Medium"
    },
    "LoadLibraryA": {
        "technique": "T1106",
        "name": "Native API",
        "confidence": "Low"
    },
    "LoadLibraryW": {
        "technique": "T1106",
        "name": "Native API",
        "confidence": "Low"
    },
    "GetProcAddress": {
        "technique": "T1106",
        "name": "Native API",
        "confidence": "Low"
    },
    "ShellExecuteA": {
        "technique": "T1204",
        "name": "User Execution",
        "confidence": "Low"
    },
    "ShellExecuteW": {
        "technique": "T1204",
        "name": "User Execution",
        "confidence": "Low"
    },
    "WinExec": {
        "technique": "T1204",
        "name": "User Execution",
        "confidence": "Medium"
    }
}
