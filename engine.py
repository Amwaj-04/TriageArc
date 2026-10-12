from __future__ import annotations

import json
from datetime import datetime, timezone
from uuid import uuid4

from database import get_connection, init_db, row_to_dict
from rules import run_detections


def _now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def load_events() -> list[dict]:
    init_db()
    with get_connection() as conn:
        rows = conn.execute("SELECT * FROM events ORDER BY timestamp, id").fetchall()
    return [row_to_dict(row) for row in rows]


def serialize_alert(row) -> dict:
    item = row_to_dict(row)
    item["related_event_ids"] = json.loads(item["related_event_ids"])
    return item


def create_alerts() -> list[dict]:
    events = load_events()
    detections = run_detections(events)
    with get_connection() as conn:
        existing = {row["rule_id"] + ":" + row["summary"] for row in conn.execute("SELECT rule_id, summary FROM alerts")}
        for detection in detections:
            key = detection.rule_id + ":" + detection.summary
            if key in existing:
                continue
            uid = f"ALT-{uuid4().hex[:8].upper()}"
            conn.execute(
                """INSERT INTO alerts
                (alert_uid, rule_id, title, severity, status, verdict, confidence,
                 created_at, first_seen, last_seen, host, username, source_ip,
                 summary, rationale, mitre_technique, mitre_name, related_event_ids, response_note)
                VALUES (?, ?, ?, ?, 'NEW', NULL, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, NULL)""",
                (uid, detection.rule_id, detection.title, detection.severity,
                 detection.confidence, _now(), detection.first_seen, detection.last_seen,
                 detection.host, detection.username, detection.source_ip,
                 detection.summary, detection.rationale, detection.mitre_technique,
                 detection.mitre_name, json.dumps(detection.event_ids)),
            )
            existing.add(key)
        conn.commit()
    return list_alerts()


def list_alerts(status: str | None = None) -> list[dict]:
    init_db()
    query = "SELECT * FROM alerts"
    params = []
    if status:
        query += " WHERE status = ?"
        params.append(status.upper())
    query += " ORDER BY CASE severity WHEN 'CRITICAL' THEN 1 WHEN 'HIGH' THEN 2 WHEN 'MEDIUM' THEN 3 ELSE 4 END, created_at DESC"
    with get_connection() as conn:
        rows = conn.execute(query, params).fetchall()
    return [serialize_alert(row) for row in rows]


def get_alert(alert_uid: str) -> dict | None:
    init_db()
    with get_connection() as conn:
        row = conn.execute("SELECT * FROM alerts WHERE alert_uid = ?", (alert_uid,)).fetchone()
    return serialize_alert(row) if row else None


def get_events_for_alert(alert: dict) -> list[dict]:
    ids = alert.get("related_event_ids") or []
    if not ids:
        return []
    placeholders = ",".join("?" for _ in ids)
    with get_connection() as conn:
        rows = conn.execute(f"SELECT * FROM events WHERE id IN ({placeholders}) ORDER BY timestamp, id", ids).fetchall()
    return [row_to_dict(row) for row in rows]


def triage_alert(alert_uid: str, payload: dict) -> dict | None:
    allowed_status = {"NEW", "IN_REVIEW", "ESCALATED", "CLOSED"}
    allowed_verdict = {"BENIGN", "SUSPICIOUS", "MALICIOUS"}
    status_raw = payload.get("status", "IN_REVIEW")
    if not isinstance(status_raw, str):
        raise ValueError("Status must be text")
    status = status_raw.strip().upper()
    if status not in allowed_status:
        raise ValueError("Invalid alert status")
    verdict = payload.get("verdict")
    if verdict is not None:
        if not isinstance(verdict, str):
            raise ValueError("Verdict must be text")
        verdict = verdict.strip().upper()
        if verdict not in allowed_verdict:
            raise ValueError("Invalid verdict")
    confidence = payload.get("confidence")
    if confidence is not None and (type(confidence) is not int or not 0 <= confidence <= 100):
        raise ValueError("Confidence must be an integer from 0 to 100")
    response_note = payload.get("response_note")
    if response_note is not None:
        if not isinstance(response_note, str):
            raise ValueError("Response note must be text")
        response_note = response_note.strip()
        if len(response_note) > 2000:
            raise ValueError("Response note must be 2000 characters or fewer")
    with get_connection() as conn:
        cursor = conn.execute(
            "UPDATE alerts SET status = ?, verdict = COALESCE(?, verdict), confidence = COALESCE(?, confidence), response_note = COALESCE(?, response_note) WHERE alert_uid = ?",
            (status, verdict, confidence, response_note, alert_uid),
        )
        conn.commit()
        if cursor.rowcount == 0:
            return None
    return get_alert(alert_uid)


def stats() -> dict:
    alerts = list_alerts()
    return {
        "events": len(load_events()), "alerts": len(alerts),
        "new": sum(a["status"] == "NEW" for a in alerts),
        "in_review": sum(a["status"] == "IN_REVIEW" for a in alerts),
        "escalated": sum(a["status"] == "ESCALATED" for a in alerts),
        "closed": sum(a["status"] == "CLOSED" for a in alerts),
        "critical": sum(a["severity"] == "CRITICAL" for a in alerts),
        "high": sum(a["severity"] == "HIGH" for a in alerts),
        "medium": sum(a["severity"] == "MEDIUM" for a in alerts),
    }
