"""
detectors/suspicious_process.py
---------------------------------
Detects suspicious process creation - specifically "LOLBins" (Living Off
the Land Binaries). These are legitimate, Microsoft-signed Windows
executables that attackers abuse to run malicious code while looking
like normal system activity.

"""

from mitre_mapping import MITRE

NATIVE_PROCESS_CREATE_EVENT_ID = 4688
SYSMON_PROCESS_CREATE_EVENT_ID = 1

# binary name (lowercase) -> substrings in the command line that make it suspicious
LOLBIN_RULES = {
    "regsvr32.exe": ["scrobj.dll", "http://", "https://", "/i:"],
    "rundll32.exe": ["javascript:", "http://", "https://", ".dll,"],
    "mshta.exe": ["http://", "https://", "vbscript:", "javascript:"],
    "certutil.exe": ["-urlcache", "-decode", "http://", "https://"],
    "powershell.exe": ["-enc", "-encodedcommand", "downloadstring", "-nop", "-w hidden", "iex"],
    "wmic.exe": ["process call create", "/node:"],
    "cmd.exe": ["/c powershell", "certutil", "bitsadmin"],
}

# Attackers commonly RENAME a LOLBin (e.g. regsvr32.exe -> jabber.exe) so
# process-name matching above is skipped entirely. But the command-line
# SYNTAX of that binary rarely changes, because the renamed copy still
# behaves like the original tool. These signature patterns catch that -
# they run against every process regardless of what the binary is called.
RENAMED_BINARY_SIGNATURES = {
    "regsvr32-style scriptlet load (/i: + remote URL)": lambda cl: "/i:http" in cl,
    "regsvr32-style /u /s silent unregister+load": lambda cl: "/u" in cl.split() and "/s" in cl.split() and "/i:" in cl,
    "mshta-style inline script execution": lambda cl: "vbscript:" in cl or "javascript:" in cl,
}


def _get_process_name_and_cmdline(event):
    """Native (4688) and Sysmon (1) events use different field names for the same data."""
    if event.get("event_id") == NATIVE_PROCESS_CREATE_EVENT_ID:
        path = event.get("NewProcessName", "") or ""
        cmdline = event.get("CommandLine", "") or ""
    else:  # Sysmon
        path = event.get("Image", "") or ""
        cmdline = event.get("CommandLine", "") or ""
    return path, cmdline


def detect(events):
    findings = []

    for e in events:
        if e.get("event_id") not in (NATIVE_PROCESS_CREATE_EVENT_ID, SYSMON_PROCESS_CREATE_EVENT_ID):
            continue

        path, cmdline = _get_process_name_and_cmdline(e)
        if not path:
            continue

        binary_name = path.lower().split("\\")[-1]
        cmdline_lower = cmdline.lower()

        if binary_name in LOLBIN_RULES:
            matched = [p for p in LOLBIN_RULES[binary_name] if p in cmdline_lower]
            if matched:
                findings.append({
                    "detection": f"Suspicious LOLBin Execution: {binary_name}",
                    "mitre": MITRE["suspicious_process"],
                    "process": path,
                    "command_line": cmdline,
                    "matched_patterns": matched,
                    "parent_process": e.get("ParentImage") or e.get("ParentProcessName"),
                    "user": e.get("User") or e.get("SubjectUserName"),
                    "time": e.get("time"),
                    "computer": e.get("computer"),
                    "severity": "High",
                })
                continue  # already flagged by name match, skip signature check below

        # Name didn't match a known LOLBin - check if the command-line SYNTAX
        # still gives it away (renamed-binary evasion, see module docstring)
        for signature_name, is_match in RENAMED_BINARY_SIGNATURES.items():
            if is_match(cmdline_lower):
                findings.append({
                    "detection": f"Suspicious LOLBin Execution (renamed binary): {signature_name}",
                    "mitre": MITRE["suspicious_process"],
                    "process": path,
                    "process_appears_as": binary_name,
                    "command_line": cmdline,
                    "matched_signature": signature_name,
                    "parent_process": e.get("ParentImage") or e.get("ParentProcessName"),
                    "user": e.get("User") or e.get("SubjectUserName"),
                    "time": e.get("time"),
                    "computer": e.get("computer"),
                    "severity": "High",
                    "note": "Binary name does not match known LOLBin names, but command-line syntax matches a known LOLBin pattern - likely renamed to evade detection.",
                })
                break

    return findings
