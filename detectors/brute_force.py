"""
detectors/brute_force.py
-------------------------
Detects brute force login attempts.

Logic (this is exactly how a SOC analyst would eyeball it in a SIEM):
1. Filter all events down to Event ID 4625 (An account failed to log on).
2. Group the failures by (target account, source), because 5 failed
   logons for 5 DIFFERENT accounts is not brute force, but 5 failures
   for the SAME account is.
3. If the number of failures for one account crosses a threshold within
   a time window, flag it as brute force.

Threshold and window are configurable so you can tune false positives.
"""

from collections import defaultdict
from datetime import timedelta
from mitre_mapping import MITRE

FAILED_LOGON_EVENT_ID = 4625
DEFAULT_THRESHOLD = 5          # number of failures
DEFAULT_WINDOW_MINUTES = 10    # time window to count them in


def detect(events, threshold=DEFAULT_THRESHOLD, window_minutes=DEFAULT_WINDOW_MINUTES):
    findings = []

    failures = [e for e in events if e.get("event_id") == FAILED_LOGON_EVENT_ID and e.get("time")]

    # Group failed attempts by the account being targeted
    by_account = defaultdict(list)
    for e in failures:
        account = e.get("TargetUserName", "UNKNOWN")
        by_account[account].append(e)

    window = timedelta(minutes=window_minutes)

    for account, attempts in by_account.items():
        attempts.sort(key=lambda e: e["time"])

        # Sliding window: for each attempt, count how many other attempts
        # for this account fall inside the next `window_minutes`.
        for i, start_event in enumerate(attempts):
            window_end = start_event["time"] + window
            burst = [a for a in attempts[i:] if a["time"] <= window_end]

            if len(burst) >= threshold:
                findings.append({
                    "detection": "Brute Force Attempt",
                    "mitre": MITRE["brute_force"],
                    "target_account": account,
                    "attempt_count": len(burst),
                    "window_minutes": window_minutes,
                    "first_attempt": burst[0]["time"],
                    "last_attempt": burst[-1]["time"],
                    "source_workstation": burst[0].get("WorkstationName"),
                    "source_ip": burst[0].get("IpAddress"),
                    "computer": burst[0].get("computer"),
                    "severity": "High",
                })
                break  # one finding per account is enough, don't spam duplicates

    return findings
