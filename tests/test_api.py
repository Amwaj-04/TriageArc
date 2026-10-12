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
        seed()
        app_module.app.config.update(TESTING=True)
        cls.client = app_module.app.test_client()

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

    def test_invalid_filter_is_rejected(self):
        self.assertEqual(self.client.get("/api/alerts?status=BAD").status_code, 400)


if __name__ == "__main__":
    unittest.main()
