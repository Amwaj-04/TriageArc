from database import clear_db, get_connection, init_db
from engine import list_alerts, stats
from rules import run_detections
from seed import EVENTS


def main():
    detections = run_detections([
        {
            "id": i + 1,
            "event_uid": row[0],
            "timestamp": row[1],
            "source": row[2],
            "host": row[3],
            "username": row[4],
            "source_ip": row[5],
            "event_type": row[6],
            "action": row[7],
            "status": row[8],
            "process_name": row[9],
            "command_line": row[10],
            "target": row[11],
            "detail": row[12],
        }
        for i, row in enumerate(EVENTS)
    ])
    assert [d.rule_id for d in detections] == ["AUTH-001", "AUTH-002", "PROC-001", "IAM-001", "DATA-001"]

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

    from engine import create_alerts
    create_alerts()
    result = stats()
    assert result["events"] == 13, result
    assert result["alerts"] == 5, result
    assert result["new"] == 5, result
    assert result["critical"] == 1, result
    assert result["high"] == 3, result
    assert result["medium"] == 1, result
    print("FOUNDATION CHECK: PASS")
    print(result)
    for alert in list_alerts():
        print(f"PASS | {alert['rule_id']} | {alert['severity']} | {alert['title']}")


if __name__ == "__main__":
    main()
