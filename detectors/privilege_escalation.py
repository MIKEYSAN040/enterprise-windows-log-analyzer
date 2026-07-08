"""
detectors/privilege_escalation.py
-----------------------------------
Detects signs that an account gained more power than it should have.

We watch three Event IDs:
  4672 - Special privileges assigned to new logon (SeDebugPrivilege etc.)
         This fires whenever an admin-equivalent account logs on, so we
         only flag it for non-obvious accounts (filtering out SYSTEM).
  4728 - A member was added to a security-enabled GLOBAL group
  4732 - A member was added to a security-enabled LOCAL group
         (4732 is the one that matters most - it's how attackers add
          themselves to local "Administrators")
"""

from mitre_mapping import MITRE

SPECIAL_PRIVS_EVENT_ID = 4672
GROUP_ADD_GLOBAL_EVENT_ID = 4728
GROUP_ADD_LOCAL_EVENT_ID = 4732
PRIVILEGE_ADJUSTED_EVENT_ID = 4703  # "A user right was adjusted"

# Built-in accounts that ALWAYS get 4672 on every logon - not interesting
NOISY_SYSTEM_ACCOUNTS = {"SYSTEM", "LOCAL SERVICE", "NETWORK SERVICE"}

SENSITIVE_GROUPS = {"administrators", "domain admins", "enterprise admins", "remote desktop users"}

# Privileges that are rarely needed and heavily abused by credential-dumping
# tools like Mimikatz (SeDebugPrivilege lets a process read another
# process's memory - including LSASS, where passwords live)
DANGEROUS_PRIVILEGES = {"SeDebugPrivilege", "SeTcbPrivilege", "SeLoadDriverPrivilege", "SeImpersonatePrivilege"}


def detect(events):
    findings = []

    for e in events:
        eid = e.get("event_id")

        if eid == SPECIAL_PRIVS_EVENT_ID:
            account = e.get("SubjectUserName", "UNKNOWN")
            if account.upper() not in NOISY_SYSTEM_ACCOUNTS and not account.endswith("$"):
                findings.append({
                    "detection": "Special Privileges Assigned",
                    "mitre": MITRE["privilege_escalation"],
                    "account": account,
                    "privileges": e.get("PrivilegeList"),
                    "time": e.get("time"),
                    "computer": e.get("computer"),
                    "severity": "Medium",
                })

        elif eid == PRIVILEGE_ADJUSTED_EVENT_ID:
            enabled = e.get("EnabledPrivilegeList", "") or ""
            hit = [p for p in DANGEROUS_PRIVILEGES if p in enabled]
            if hit:
                findings.append({
                    "detection": "Dangerous Privilege Explicitly Enabled",
                    "mitre": MITRE["privilege_escalation"],
                    "account": e.get("SubjectUserName"),
                    "process": e.get("ProcessName"),
                    "privileges_enabled": hit,
                    "time": e.get("time"),
                    "computer": e.get("computer"),
                    "severity": "High",
                    "note": "SeDebugPrivilege in particular is commonly enabled by credential-dumping tools (e.g. Mimikatz) to read LSASS memory.",
                })

        elif eid in (GROUP_ADD_GLOBAL_EVENT_ID, GROUP_ADD_LOCAL_EVENT_ID):
            group_name = (e.get("TargetUserName") or "").lower()
            if any(sensitive in group_name for sensitive in SENSITIVE_GROUPS):
                findings.append({
                    "detection": "Account Added to Privileged Group",
                    "mitre": MITRE["privilege_escalation"],
                    "account_added": e.get("MemberName", "").strip("%{}") or e.get("MemberSid"),
                    "group": e.get("TargetUserName"),
                    "added_by": e.get("SubjectUserName"),
                    "time": e.get("time"),
                    "computer": e.get("computer"),
                    "severity": "High",
                })

    return findings
