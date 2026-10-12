from __future__ import annotations

from database import clear_db, get_connection, init_db
from engine import create_alerts

EVENTS = [
    # Brute-force burst + successful login.
    ("EVT-1001", "2026-10-08T07:12:00Z", "identity", "dc-01", "analyst02", "185.44.72.19", "authentication", "login", "failure", None, None, None, "Invalid password"),
    ("EVT-1002", "2026-10-08T07:13:10Z", "identity", "dc-01", "analyst02", "185.44.72.19", "authentication", "login", "failure", None, None, None, "Invalid password"),
    ("EVT-1003", "2026-10-08T07:14:02Z", "identity", "dc-01", "analyst02", "185.44.72.19", "authentication", "login", "failure", None, None, None, "Invalid password"),
    ("EVT-1004", "2026-10-08T07:15:41Z", "identity", "dc-01", "analyst02", "185.44.72.19", "authentication", "login", "failure", None, None, None, "Invalid password"),
    ("EVT-1005", "2026-10-08T07:16:33Z", "identity", "dc-01", "analyst02", "185.44.72.19", "authentication", "login", "failure", None, None, None, "Invalid password"),
    ("EVT-1006", "2026-10-08T07:17:05Z", "identity", "dc-01", "analyst02", "185.44.72.19", "authentication", "login", "success", None, None, None, "Interactive login succeeded"),
    # Benign failures that should not alert.
    ("EVT-1010", "2026-10-08T08:10:00Z", "identity", "dc-01", "analyst01", "10.20.1.44", "authentication", "login", "failure", None, None, None, "Invalid password"),
    ("EVT-1011", "2026-10-08T08:10:45Z", "identity", "dc-01", "analyst01", "10.20.1.44", "authentication", "login", "failure", None, None, None, "Invalid password"),
    # PowerShell.
    ("EVT-1020", "2026-10-08T09:21:10Z", "endpoint", "ws-fin-01", "analyst02", "10.20.3.25", "process", "execute", "success", "powershell.exe", "powershell.exe -NoProfile -ExecutionPolicy Bypass -EncodedCommand SQBFAFgA", None, "PowerShell execution"),
    # New account then privilege.
    ("EVT-1030", "2026-10-08T10:04:00Z", "identity", "dc-01", "svc-backup2", "10.20.0.15", "account", "created", "success", None, None, None, "Account created by administrator"),
    ("EVT-1031", "2026-10-08T10:12:00Z", "identity", "dc-01", "svc-backup2", "10.20.0.15", "privilege", "admin_granted", "success", None, None, "Domain Admins", "Administrative group membership granted"),
    # Sensitive file from unexpected workstation.
    ("EVT-1040", "2026-10-08T11:33:00Z", "file-server", "ws-sales-07", "analyst02", "10.20.7.81", "file_access", "read", "success", None, None, "customer_export.csv", "Sensitive customer export opened"),
    # Normal sensitive file access; no alert.
    ("EVT-1041", "2026-10-08T11:35:00Z", "file-server", "ws-fin-01", "analyst02", "10.20.3.25", "file_access", "read", "success", None, None, "finance_forecast.xlsx", "Expected finance file access"),
]


def seed() -> None:
    clear_db()
    init_db()
    with get_connection() as conn:
        conn.executemany(
            """INSERT INTO events
            (event_uid, timestamp, source, host, username, source_ip, event_type, action, status, process_name, command_line, target, detail)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            EVENTS,
        )
        conn.commit()
    alerts = create_alerts()
    print(f"Seeded {len(EVENTS)} events and generated {len(alerts)} alerts.")


if __name__ == "__main__":
    seed()
