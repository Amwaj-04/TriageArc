from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta


@dataclass(frozen=True)
class Detection:
    rule_id: str
    title: str
    severity: str
    summary: str
    rationale: str
    mitre_technique: str
    mitre_name: str
    event_ids: tuple[int, ...]
    first_seen: str
    last_seen: str
    host: str | None = None
    username: str | None = None
    source_ip: str | None = None
    confidence: int = 80


RULES = {
    "AUTH-001": {
        "title": "Repeated authentication failures",
        "description": "Five or more failed logins for the same user and source within 10 minutes.",
        "severity": "HIGH",
        "mitre_technique": "T1110.001",
        "mitre_name": "Password Guessing",
    },
    "AUTH-002": {
        "title": "Successful login after repeated failures",
        "description": "A successful login follows at least three failures from the same source for the same user within 15 minutes.",
        "severity": "HIGH",
        "mitre_technique": "T1078",
        "mitre_name": "Valid Accounts",
    },
    "PROC-001": {
        "title": "Suspicious PowerShell execution",
        "description": "PowerShell uses a command pattern commonly associated with execution or download activity.",
        "severity": "HIGH",
        "mitre_technique": "T1059.001",
        "mitre_name": "PowerShell",
    },
    "IAM-001": {
        "title": "New privileged account",
        "description": "A newly created account is immediately granted an administrative role.",
        "severity": "CRITICAL",
        "mitre_technique": "T1098",
        "mitre_name": "Account Manipulation",
    },
    "DATA-001": {
        "title": "Sensitive file access outside normal pattern",
        "description": "A user accesses a sensitive file from a host not associated with their normal workstation pattern.",
        "severity": "MEDIUM",
        "mitre_technique": "T1005",
        "mitre_name": "Data from Local System",
    },
}


def parse_ts(value: str) -> datetime:
    return datetime.fromisoformat(value.replace("Z", "+00:00"))


def _base_detection(rule_id, event, event_ids, summary, rationale, confidence=None, related_events=None):
    rule = RULES[rule_id]
    timestamp_events = related_events or [event]
    timestamps = [item["timestamp"] for item in timestamp_events if item.get("timestamp")] or [event["timestamp"]]
    return Detection(
        rule_id=rule_id,
        title=rule["title"],
        severity=rule["severity"],
        summary=summary,
        rationale=rationale,
        mitre_technique=rule["mitre_technique"],
        mitre_name=rule["mitre_name"],
        event_ids=tuple(event_ids),
        first_seen=min(timestamps),
        last_seen=max(timestamps),
        host=event.get("host"),
        username=event.get("username"),
        source_ip=event.get("source_ip"),
        confidence=confidence or (92 if rule_id.startswith("AUTH") else 88),
    )


def detect_auth_failures(events: list[dict]) -> list[Detection]:
    failures = [e for e in events if e["event_type"] == "authentication" and e["status"] == "failure"]
    failures.sort(key=lambda e: e["timestamp"])
    detections = []
    for i, event in enumerate(failures):
        window_end = parse_ts(event["timestamp"]) + timedelta(minutes=10)
        group = [
            candidate for candidate in failures[i:]
            if candidate["username"] == event["username"]
            and candidate["source_ip"] == event["source_ip"]
            and parse_ts(candidate["timestamp"]) <= window_end
        ]
        if len(group) >= 5:
            ids = [item["id"] for item in group]
            detections.append(_base_detection(
                "AUTH-001", event, ids,
                f"{len(group)} failed authentication attempts targeted {event['username']} from {event['source_ip']} within 10 minutes.",
                "The failure count crosses the rule threshold and the attempts share the same account and source.",
                95, group,
            ))
            break
    return detections


def detect_success_after_failures(events: list[dict]) -> list[Detection]:
    ordered = sorted(events, key=lambda e: e["timestamp"])
    detections = []
    for event in ordered:
        if event["event_type"] != "authentication" or event["status"] != "success":
            continue
        cutoff = parse_ts(event["timestamp"]) - timedelta(minutes=15)
        failures = [
            candidate for candidate in ordered
            if candidate["event_type"] == "authentication"
            and candidate["status"] == "failure"
            and candidate["username"] == event["username"]
            and candidate["source_ip"] == event["source_ip"]
            and cutoff <= parse_ts(candidate["timestamp"]) < parse_ts(event["timestamp"])
        ]
        if len(failures) >= 3:
            ids = [item["id"] for item in failures] + [event["id"]]
            detections.append(_base_detection(
                "AUTH-002", event, ids,
                f"A successful login for {event['username']} followed {len(failures)} failures from {event['source_ip']}.",
                "A success immediately following repeated failures is more actionable than the failure burst alone and should be reviewed for credential abuse.",
                96, failures + [event],
            ))
    return detections


def detect_powershell(events: list[dict]) -> list[Detection]:
    indicators = ("-enc", "encodedcommand", "downloadstring", "invoke-webrequest", "iex ", "bypass", "frombase64string")
    detections = []
    for event in events:
        command = (event.get("command_line") or "").lower()
        if event["process_name"] and event["process_name"].lower() in {"powershell.exe", "pwsh.exe"} and any(i in command for i in indicators):
            matched = [i for i in indicators if i in command]
            detections.append(_base_detection(
                "PROC-001", event, [event["id"]],
                f"PowerShell executed a command containing suspicious execution indicators: {', '.join(matched)}.",
                "The rule is triggered by explicit command-line indicators rather than the presence of PowerShell alone.",
                91,
            ))
    return detections


def detect_privileged_account(events: list[dict]) -> list[Detection]:
    created = {e.get("username"): e for e in events if e["event_type"] == "account" and e["action"] == "created"}
    detections = []
    for event in events:
        if event["event_type"] == "privilege" and event["action"] == "admin_granted" and event.get("username") in created:
            account_event = created[event["username"]]
            if timedelta(0) <= parse_ts(event["timestamp"]) - parse_ts(account_event["timestamp"]) <= timedelta(minutes=30):
                detections.append(_base_detection(
                    "IAM-001", event, [account_event["id"], event["id"]],
                    f"Account {event['username']} was created and granted administrative privilege within 30 minutes.",
                    "The two events form a direct privilege-establishment sequence for a newly created account.",
                    97, [account_event, event],
                ))
    return detections


def detect_sensitive_access(events: list[dict]) -> list[Detection]:
    normal_hosts = {"analyst01": "ws-hr-01", "analyst02": "ws-fin-01", "admin01": "admin-ws-01"}
    detections = []
    for event in events:
        if event["event_type"] != "file_access" or event["action"] != "read":
            continue
        if event.get("target") not in {"payroll.xlsx", "customer_export.csv", "finance_forecast.xlsx"}:
            continue
        expected = normal_hosts.get(event.get("username"))
        if expected and event.get("host") != expected:
            detections.append(_base_detection(
                "DATA-001", event, [event["id"]],
                f"{event['username']} accessed {event['target']} from {event['host']}, outside the expected workstation pattern.",
                f"The user is associated with {expected}, but the sensitive file was accessed from {event['host']}.",
                84,
            ))
    return detections


def run_detections(events: list[dict]) -> list[Detection]:
    detections: list[Detection] = []
    for detector in (
        detect_auth_failures,
        detect_success_after_failures,
        detect_powershell,
        detect_privileged_account,
        detect_sensitive_access,
    ):
        detections.extend(detector(events))
    return detections
