from __future__ import annotations

import os
import re
import secrets
from datetime import timedelta
from pathlib import Path
from uuid import uuid4

from flask import Flask, g, jsonify, render_template, request, session

import database
from database import init_db
from engine import get_alert, get_events_for_alert, list_alerts, load_events, stats, triage_alert
from seed import seed

def load_session_secret() -> str:
    configured = os.environ.get("TRIAGEARC_SECRET_KEY")
    if configured:
        return configured
    # Keep local browser workspaces stable across app restarts without committing
    # a secret. Hosted deployments should set TRIAGEARC_SECRET_KEY explicitly.
    secret_path = Path(database.DB_PATH).parent / "triagearc_session_secret.key"
    secret_path.parent.mkdir(parents=True, exist_ok=True)
    try:
        value = secret_path.read_text(encoding="utf-8").strip()
        if len(value) >= 64:
            return value
    except OSError:
        pass
    value = secrets.token_hex(32)
    try:
        secret_path.write_text(value, encoding="utf-8")
    except OSError:
        # Read-only deployments can still start; sessions may not survive restart.
        pass
    return value


app = Flask(__name__)
app.config["SECRET_KEY"] = load_session_secret()
app.config["JSON_SORT_KEYS"] = False
app.config["SESSION_COOKIE_HTTPONLY"] = True
app.config["SESSION_COOKIE_SAMESITE"] = "Lax"
app.config["SESSION_COOKIE_SECURE"] = os.environ.get("TRIAGEARC_COOKIE_SECURE", "").lower() in {"1", "true", "yes"}
app.config["PERMANENT_SESSION_LIFETIME"] = timedelta(days=7)


@app.before_request
def select_browser_workspace():
    """Route each browser session to its own synthetic-data workspace."""
    workspace_id = session.get("workspace_id")
    if not isinstance(workspace_id, str) or not re.fullmatch(r"[0-9a-f]{32}", workspace_id):
        workspace_id = uuid4().hex
        session["workspace_id"] = workspace_id
    session.permanent = True
    g.triagearc_db_path = Path(database_path_root()) / "workspaces" / f"{workspace_id}.db"


def database_path_root() -> Path:
    # Respect TRIAGEARC_DB_PATH for test/CLI deployments; normal installs use data/.
    from database import DB_PATH
    return Path(DB_PATH).parent


@app.get("/")
def home():
    init_db()
    # Seed an empty database only. Refreshing the page never overwrites analyst work.
    if not list_alerts():
        seed()
    return render_template("index.html")


@app.get("/api/health")
def health():
    init_db()
    return jsonify({"status": "ok", "service": "TriageArc", "mode": "synthetic-lab"})


@app.get("/api/events")
def events():
    return jsonify({"events": load_events()})


@app.get("/api/alerts")
def alerts():
    status = request.args.get("status")
    allowed = {"NEW", "IN_REVIEW", "ESCALATED", "CLOSED"}
    if status and status.upper() not in allowed:
        return jsonify({"error": "Invalid status filter"}), 400
    return jsonify({"alerts": list_alerts(status)})


@app.get("/api/alerts/<alert_uid>")
def alert_detail(alert_uid: str):
    alert = get_alert(alert_uid)
    if not alert:
        return jsonify({"error": "Alert not found"}), 404
    return jsonify({"alert": alert, "events": get_events_for_alert(alert)})


@app.post("/api/alerts/<alert_uid>/triage")
def update_alert(alert_uid: str):
    payload = request.get_json(silent=True)
    if not isinstance(payload, dict):
        return jsonify({"error": "JSON body is required"}), 400
    try:
        alert = triage_alert(alert_uid, payload)
    except ValueError as exc:
        return jsonify({"error": str(exc)}), 400
    if not alert:
        return jsonify({"error": "Alert not found"}), 404
    return jsonify({"alert": alert})


@app.get("/api/stats")
def dashboard_stats():
    return jsonify(stats())


@app.post("/api/demo/reset")
def demo_reset():
    # seed() only touches the current browser's workspace database.
    seed()
    return jsonify({"message": "This browser workspace was reset", "stats": stats()})


@app.post("/api/demo/run")
def demo_run():
    # A scenario reload resets only the current browser's workspace.
    seed()
    return jsonify({"message": "Synthetic scenario reloaded in this browser workspace", "stats": stats(), "alerts": list_alerts()})


@app.errorhandler(404)
def not_found(_error):
    if request.path.startswith("/api/"):
        return jsonify({"error": "Route not found"}), 404
    return "Page not found", 404


if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5000, debug=False)
