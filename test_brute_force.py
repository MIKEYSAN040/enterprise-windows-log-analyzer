"""
test_brute_force.py
---------------------
The real EVTX-ATTACK-SAMPLES file only has ONE failed logon (4625) event,
which correctly does NOT trigger brute force (that's the point - 1 failure
isn't an attack). To prove the brute force detector actually works, this
script builds a small synthetic set of 4625 events in memory - 6 failed
logons against the same account within 2 minutes - and runs it through
the same detector used in main.py.

Run: python3 test_brute_force.py
"""

from datetime import datetime, timedelta
from detectors import brute_force

base_time = datetime(2026, 1, 1, 9, 0, 0)

synthetic_events = [
    {
        "event_id": 4625,
        "time": base_time + timedelta(seconds=15 * i),
        "computer": "DC01",
        "TargetUserName": "administrator",
        "WorkstationName": "KALI-ATTACKER",
        "IpAddress": "10.0.0.99",
    }
    for i in range(6)
]

findings = brute_force.detect(synthetic_events)

print(f"Findings: {len(findings)}")
for f in findings:
    print(f)
