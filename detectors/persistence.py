

from mitre_mapping import MITRE

SCHEDULED_TASK_EVENT_ID = 4698
NEW_SERVICE_EVENT_ID = 7045
SYSMON_REGISTRY_EVENT_ID = 13

RUN_KEY_PATTERNS = ["\\run\\", "\\runonce\\", "currentversion\\run"]


def detect(events):
    findings = []

    for e in events:
        eid = e.get("event_id")

        if eid == SCHEDULED_TASK_EVENT_ID:
            findings.append({
                "detection": "Scheduled Task Created",
                "mitre": MITRE["persistence_scheduled_task"],
                "task_name": e.get("TaskName"),
                "created_by": e.get("SubjectUserName"),
                "time": e.get("time"),
                "computer": e.get("computer"),
                "severity": "Medium",
            })

        elif eid == NEW_SERVICE_EVENT_ID:
            findings.append({
                "detection": "New Service Installed",
                "mitre": MITRE["persistence_new_service"],
                "service_name": e.get("ServiceName"),
                "image_path": e.get("ImagePath"),
                "service_type": e.get("ServiceType"),
                "time": e.get("time"),
                "computer": e.get("computer"),
                "severity": "Medium",
            })

        elif eid == SYSMON_REGISTRY_EVENT_ID:
            target = (e.get("TargetObject") or "").lower()
            if any(pattern in target for pattern in RUN_KEY_PATTERNS):
                findings.append({
                    "detection": "Registry Run Key Modified",
                    "mitre": MITRE["persistence_run_key"],
                    "registry_path": e.get("TargetObject"),
                    "value_set": e.get("Details"),
                    "process": e.get("Image"),
                    "time": e.get("time"),
                    "computer": e.get("computer"),
                    "severity": "High",
                })

    return findings
