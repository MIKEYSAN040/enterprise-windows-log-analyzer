# Enterprise Windows Log Analyzer

A Python tool that parses Windows Event Logs (.evtx) and detects four categories
of attacker behavior, mapped to MITRE ATT&CK: **brute force**, **privilege
escalation**, **persistence**, and **suspicious process execution (LOLBins)**.

Detection logic was validated against real attack telemetry from
[EVTX-ATTACK-SAMPLES](https://github.com/sbousseaden/EVTX-ATTACK-SAMPLES),
a public dataset of Windows/Sysmon logs captured during actual adversary
technique execution.

## Detections

| Category | Event IDs Used | MITRE Technique |
|---|---|---|
| Brute Force | 4625 (failed logon) | T1110 |
| Privilege Escalation | 4672, 4703, 4728, 4732 | T1078.003 |
| Persistence | 4698, 7045, Sysmon 13 | T1547.001 / T1053.005 / T1543.003 |
| Suspicious Process (LOLBins) | 4688, Sysmon 1 | T1218 |

The suspicious-process detector also catches **renamed LOLBins** — attackers
often rename tools like `regsvr32.exe` to evade name-based detection, but the
command-line syntax they need to use rarely changes. See
`detectors/suspicious_process.py` for details.


## Setup

```bash
pip install -r requirements.txt
```

## Usage

```bash
python3 main.py --logs sample_logs/*.evtx --output output/report.xlsx
```

Pass any number of `.evtx` files or glob patterns. The tool prints a summary
to the console and writes a multi-sheet Excel report (one sheet per detection
category, plus a summary sheet) to the output path.

## Why these specific detections

Each detector encodes logic a SOC L1 analyst applies manually when triaging
alerts in a SIEM — grouping failed logons by account within a time window,
flagging privileged-group membership changes, watching for registry/service/
scheduled-task persistence, and matching known LOLBin abuse patterns. 
