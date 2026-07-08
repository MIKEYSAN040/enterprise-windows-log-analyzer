"""
mitre_mapping.py
-----------------
One shared place that maps each detection type to its MITRE ATT&CK technique.
Every detector imports from here instead of hardcoding technique IDs, so if
MITRE updates a technique ID you only fix it once.
"""

MITRE = {
    "brute_force": {
        "technique_id": "T1110",
        "technique_name": "Brute Force",
        "tactic": "Credential Access",
    },
    "privilege_escalation": {
        "technique_id": "T1078.003",
        "technique_name": "Valid Accounts: Local Accounts / Privilege Use",
        "tactic": "Privilege Escalation",
    },
    "persistence_run_key": {
        "technique_id": "T1547.001",
        "technique_name": "Registry Run Keys / Startup Folder",
        "tactic": "Persistence",
    },
    "persistence_scheduled_task": {
        "technique_id": "T1053.005",
        "technique_name": "Scheduled Task",
        "tactic": "Persistence",
    },
    "persistence_new_service": {
        "technique_id": "T1543.003",
        "technique_name": "Create or Modify System Process: Windows Service",
        "tactic": "Persistence",
    },
    "suspicious_process": {
        "technique_id": "T1218",
        "technique_name": "System Binary Proxy Execution (LOLBins)",
        "tactic": "Defense Evasion / Execution",
    },
}
