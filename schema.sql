CREATE TABLE IF NOT EXISTS events (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    event_uid TEXT NOT NULL UNIQUE,
    timestamp TEXT NOT NULL,
    source TEXT NOT NULL,
    host TEXT NOT NULL,
    username TEXT,
    source_ip TEXT,
    event_type TEXT NOT NULL,
    action TEXT NOT NULL,
    status TEXT,
    process_name TEXT,
    command_line TEXT,
    target TEXT,
    detail TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS alerts (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    alert_uid TEXT NOT NULL UNIQUE,
    rule_id TEXT NOT NULL,
    title TEXT NOT NULL,
    severity TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'NEW',
    verdict TEXT,
    confidence INTEGER,
    created_at TEXT NOT NULL,
    first_seen TEXT NOT NULL,
    last_seen TEXT NOT NULL,
    host TEXT,
    username TEXT,
    source_ip TEXT,
    summary TEXT NOT NULL,
    rationale TEXT NOT NULL,
    mitre_technique TEXT,
    mitre_name TEXT,
    related_event_ids TEXT NOT NULL DEFAULT '[]',
    response_note TEXT
);

CREATE INDEX IF NOT EXISTS idx_events_timestamp ON events(timestamp);
CREATE INDEX IF NOT EXISTS idx_events_username ON events(username);
CREATE INDEX IF NOT EXISTS idx_alerts_status ON alerts(status);
CREATE INDEX IF NOT EXISTS idx_alerts_severity ON alerts(severity);
