import os
import re
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

import app as app_module
import database
from seed import seed


class ApiTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.original_db_path = database.DB_PATH
        cls.temp_dir = tempfile.TemporaryDirectory(prefix="triagearc-tests-")
        database.DB_PATH = Path(cls.temp_dir.name) / "test.db"
        app_module.app.config.update(TESTING=True, SECRET_KEY="triagearc-test-secret-key")
        cls.client = app_module.app.test_client()
        # Initialize the default browser workspace through the same request path as users.
        response = cls.client.get("/")
        if response.status_code != 200:
            raise RuntimeError("Could not initialize test workspace")

    @classmethod
    def tearDownClass(cls):
        database.DB_PATH = cls.original_db_path
        cls.temp_dir.cleanup()

    def test_home_serves_console(self):
        response = self.client.get("/")
        self.assertEqual(response.status_code, 200)
        self.assertIn(b"TriageArc", response.data)
        self.assertIn(b"Alert queue", response.data)

    def test_health(self):
        response = self.client.get("/api/health")
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json["status"], "ok")

    def test_seed_generates_expected_alert_count(self):
        response = self.client.get("/api/alerts")
        self.assertEqual(response.status_code, 200)
        self.assertEqual(len(response.json["alerts"]), 5)

    def test_alert_detail_includes_linked_events(self):
        alert = self.client.get("/api/alerts").json["alerts"][0]
        response = self.client.get(f"/api/alerts/{alert['alert_uid']}")
        self.assertEqual(response.status_code, 200)
        self.assertGreaterEqual(len(response.json["events"]), 1)

    def test_alert_can_be_triaged(self):
        alerts = self.client.get("/api/alerts").json["alerts"]
        alert_uid = alerts[0]["alert_uid"]
        response = self.client.post(f"/api/alerts/{alert_uid}/triage", json={"status": "IN_REVIEW", "verdict": "SUSPICIOUS", "confidence": 90, "response_note": "Review identity telemetry."})
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json["alert"]["status"], "IN_REVIEW")
        self.assertEqual(response.json["alert"]["verdict"], "SUSPICIOUS")

    def test_invalid_triage_is_rejected(self):
        alert_uid = self.client.get("/api/alerts").json["alerts"][0]["alert_uid"]
        for payload in ({"status": "WHAT"}, {"confidence": True}, {"confidence": 101}, {"status": []}, {"response_note": {"x": 1}}):
            with self.subTest(payload=payload):
                response = self.client.post(f"/api/alerts/{alert_uid}/triage", json=payload)
                self.assertEqual(response.status_code, 400)


    def test_browser_workspaces_are_isolated(self):
        first_alert = self.client.get("/api/alerts").json["alerts"][0]
        response = self.client.post(
            f"/api/alerts/{first_alert['alert_uid']}/triage",
            json={"status": "CLOSED", "verdict": "SUSPICIOUS", "confidence": 97,
                  "response_note": "Validated in the first browser workspace."},
        )
        self.assertEqual(response.status_code, 200)

        second_client = app_module.app.test_client()
        second_home = second_client.get("/")
        self.assertEqual(second_home.status_code, 200)
        second_alerts = second_client.get("/api/alerts").json["alerts"]
        matching = next(a for a in second_alerts if a["rule_id"] == first_alert["rule_id"])
        self.assertEqual(matching["status"], "NEW")
        self.assertIsNone(matching["verdict"])
        self.assertIsNone(matching["response_note"])

    def test_demo_reset_only_resets_current_workspace(self):
        second_client = app_module.app.test_client()
        second_client.get("/")
        first_alert = self.client.get("/api/alerts").json["alerts"][0]
        self.client.post(f"/api/alerts/{first_alert['alert_uid']}/triage", json={"status": "CLOSED"})
        self.client.post("/api/demo/reset", json={})
        refreshed_second = second_client.get("/api/alerts").json["alerts"]
        matching = next(a for a in refreshed_second if a["rule_id"] == first_alert["rule_id"])
        self.assertEqual(matching["status"], "NEW")

    def test_invalid_filter_is_rejected(self):
        self.assertEqual(self.client.get("/api/alerts?status=BAD").status_code, 400)


    def test_page_references_only_existing_static_assets(self):
        html = self.client.get("/").get_data(as_text=True)
        paths = set(re.findall(r'(?:href|src)="(/static/[^"]+)"', html))
        self.assertTrue({"/static/styles.css", "/static/app.js", "/static/favicon.ico",
                         "/static/triagearc-mark.png", "/static/triagearc-mark-light.png"} <= paths)
        for path in sorted(paths):
            with self.subTest(path=path):
                response = self.client.get(path)
                self.assertEqual(response.status_code, 200)
                response.close()

    def test_unknown_api_route_returns_json_404(self):
        response = self.client.get("/api/nope")
        self.assertEqual(response.status_code, 404)
        self.assertIn("error", response.json)


class FoundationCheckSafetyTests(unittest.TestCase):
    def test_check_foundation_does_not_touch_the_configured_database(self):
        root = Path(__file__).resolve().parent.parent
        with tempfile.TemporaryDirectory(prefix="triagearc-safety-") as tmp:
            db_file = Path(tmp) / "analyst.db"
            original = database.DB_PATH
            database.DB_PATH = db_file
            try:
                seed()
            finally:
                database.DB_PATH = original
            before = db_file.read_bytes()
            result = subprocess.run([sys.executable, str(root / "check_foundation.py")], cwd=root, capture_output=True, text=True,
                                    env={**os.environ, "TRIAGEARC_DB_PATH": str(db_file)})
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertIn("FOUNDATION CHECK: PASS", result.stdout)
            self.assertEqual(db_file.read_bytes(), before)


if __name__ == "__main__":
    unittest.main()
