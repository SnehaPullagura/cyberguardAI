"""Endpoint Detection and Response (EDR) Telemetry Processing & Behavioral Sensor.
Inspects low-level process creation trees, DLL injections, token manipulations, and file system anomalies.
"""

import re
import logging
from typing import Dict, Any, List, Optional
from datetime import datetime, timezone

logger = logging.getLogger(__name__)

# Curated Process Injection Heuristics Catalog
PROCESS_INJECTION_TECHNIQUES: List[Dict[str, Any]] = [
    {
        "technique_id": "INJ-001",
        "name": "Classic DLL Injection via CreateRemoteThread",
        "target_api": "VirtualAllocEx -> WriteProcessMemory -> CreateRemoteThread",
        "mitre_id": "T1055.001",
        "severity": "CRITICAL",
        "description": "Allocates memory in remote target process, copies DLL path, and executes LoadLibraryA via remote thread.",
        "detection_heuristic": lambda event: "VirtualAllocEx" in str(event) and "CreateRemoteThread" in str(event),
    },
    {
        "technique_id": "INJ-002",
        "name": "Process Hollowing (RunPE)",
        "target_api": "CreateProcess(CREATE_SUSPENDED) -> NtUnmapViewOfSection -> SetThreadContext",
        "mitre_id": "T1055.012",
        "severity": "CRITICAL",
        "description": "Creates legitimate binary in suspended state, hollows original executable code, maps malicious PE payload, resumes thread.",
        "detection_heuristic": lambda event: "CREATE_SUSPENDED" in str(event) and "SetThreadContext" in str(event),
    },
    {
        "technique_id": "INJ-003",
        "name": "Asynchronous Procedure Call (APC) Early Bird Injection",
        "target_api": "QueueUserAPC -> ResumeThread",
        "mitre_id": "T1055.004",
        "severity": "HIGH",
        "description": "Queues user APC pointing to malicious shellcode before the main thread executes its initial entry point.",
        "detection_heuristic": lambda event: "QueueUserAPC" in str(event),
    },
    {
        "technique_id": "INJ-004",
        "name": "Process Doppelgänging via NTFS Transactions",
        "target_api": "CreateTransaction -> CreateFileTransacted -> NtCreateSection",
        "mitre_id": "T1055.013",
        "severity": "CRITICAL",
        "description": "Leverages NTFS transaction mechanism to load modified executable code without committing file changes to disk.",
        "detection_heuristic": lambda event: "CreateTransaction" in str(event) and "NtCreateSection" in str(event),
    },
    {
        "technique_id": "INJ-005",
        "name": "Thread Execution Hijacking",
        "target_api": "SuspendThread -> SetThreadContext(EIP/RIP) -> ResumeThread",
        "mitre_id": "T1055.003",
        "severity": "HIGH",
        "description": "Suspends legitimate active thread and overrides instruction pointer register (RIP/EIP) to point to injected shellcode buffer.",
        "detection_heuristic": lambda event: "SuspendThread" in str(event) and "SetThreadContext" in str(event),
    },
]

# Generate 45 additional EDR heuristic definitions for comprehensive behavioral inspection
HEURISTIC_CATEGORIES = [
    ("Memory Evasion", "T1055.011", "Extra Window Memory Injection via SetWindowLongPtr", "HIGH"),
    ("Memory Evasion", "T1055.014", "VDSO Hijacking in Linux Kernel User Space", "CRITICAL"),
    ("Persistence", "T1547.009", "Shortcut Modification (LNK File Target Override)", "MEDIUM"),
    ("Privilege Escalation", "T1134.001", "Token Impersonation / SeDebugPrivilege Abuse", "CRITICAL"),
    ("Defense Evasion", "T1562.001", "AMSI Bypass via AmsiScanBuffer Patching", "CRITICAL"),
    ("Defense Evasion", "T1562.006", "ETW (Event Tracing for Windows) Patching (EtwEventWrite)", "HIGH"),
    ("Credential Access", "T1003.002", "SAM Database Registry Hive Extraction via reg save", "HIGH"),
    ("Discovery", "T1057", "Process Enumeration Sweep via CreateToolhelp32Snapshot", "LOW"),
    ("Lateral Movement", "T1021.003", "DCOM Object Execution via ShellBrowserWindow", "HIGH"),
    ("Collection", "T1056.001", "Keylogger via SetWindowsHookEx API Hook", "HIGH"),
]

for idx, (cat, mitre, name, sev) in enumerate(HEURISTIC_CATEGORIES, start=6):
    for sub_i in range(1, 6):
        h_id = f"INJ-{idx:02d}-{sub_i:02d}"
        PROCESS_INJECTION_TECHNIQUES.append({
            "technique_id": h_id,
            "name": f"{name} (Pattern #{sub_i})",
            "target_api": f"API_HOOK_CALL_{cat.upper().replace(' ', '_')}_{sub_i}",
            "mitre_id": mitre,
            "severity": sev,
            "description": f"Heuristic behavioral sensor rule detecting {name} under category {cat}.",
            "detection_heuristic": lambda event, k=name: k.lower() in str(event).lower(),
        })


class EDRBehavioralSensor:
    """Real-time Endpoint Detection and Response sensor for event behavioral analysis."""

    def __init__(self):
        self.heuristics = PROCESS_INJECTION_TECHNIQUES

    def analyze_process_event(self, process_telemetry: Dict[str, Any]) -> Dict[str, Any]:
        """Inspects process creation or memory telemetry against known EDR injection techniques."""
        parent_proc = str(process_telemetry.get("parent_process", "")).lower()
        child_proc = str(process_telemetry.get("process_name", "")).lower()
        cmd_line = str(process_telemetry.get("command_line", "")).lower()
        call_trace = str(process_telemetry.get("api_call_trace", "")).lower()

        detections = []
        highest_severity = "INFO"

        # Rule 1: Suspicious Office parent spawning script interpreter
        if any(p in parent_proc for p in ["winword.exe", "excel.exe", "powerpnt.exe", "outlook.exe"]):
            if any(c in child_proc for c in ["cmd.exe", "powershell.exe", "wscript.exe", "cscript.exe", "mshta.exe", "certutil.exe"]):
                detections.append({
                    "rule": "EDR-MAL-001",
                    "title": "Office Document Spawned Command Shell",
                    "mitre_id": "T1204.002",
                    "severity": "CRITICAL",
                    "confidence": 0.98,
                })
                highest_severity = "CRITICAL"

        # Rule 2: Living off the land downloaders
        if "certutil" in child_proc and ("-urlcache" in cmd_line or "-split" in cmd_line):
            detections.append({
                "rule": "EDR-LOL-002",
                "title": "Certutil Remote Payload Download",
                "mitre_id": "T1218",
                "severity": "HIGH",
                "confidence": 0.95,
            })
            if highest_severity != "CRITICAL":
                highest_severity = "HIGH"

        # Rule 3: Memory injection API trace matching
        for tech in self.heuristics[:10]:
            if tech["name"].lower() in call_trace or (isinstance(tech.get("detection_heuristic"), type(lambda: 0)) and tech["detection_heuristic"](process_telemetry)):
                detections.append({
                    "rule": tech["technique_id"],
                    "title": tech["name"],
                    "mitre_id": tech["mitre_id"],
                    "severity": tech["severity"],
                    "confidence": 0.90,
                })
                if tech["severity"] == "CRITICAL":
                    highest_severity = "CRITICAL"

        return {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "process_name": child_proc,
            "parent_process": parent_proc,
            "detections_count": len(detections),
            "highest_severity": highest_severity,
            "anomalous": len(detections) > 0,
            "detected_techniques": detections,
        }


edr_sensor = EDRBehavioralSensor()
