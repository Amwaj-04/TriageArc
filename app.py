from __future__ import annotations

from flask import Flask, jsonify, render_template, request

from database import init_db
from engine import get_alert, get_events_for_alert, list_alerts, load_events, stats, triage_alert
from seed import seed

app = Flask(__name__)
app.config["JSON_SORT_KEYS"] = False


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
    seed()
    return jsonify({"message": "Synthetic demo reset", "stats": stats()})


@app.post("/api/demo/run")
def demo_run():
    seed()
    return jsonify({"message": "Synthetic demo scenario loaded", "stats": stats(), "alerts": list_alerts()})


@app.errorhandler(404)
def not_found(_error):
    if request.path.startswith("/api/"):
        return jsonify({"error": "Route not found"}), 404
    return "Page not found", 404


if __name__ == "__main__":
    init_db()
    if not list_alerts():
        seed()
    app.run(host="127.0.0.1", port=5000, debug=False)
