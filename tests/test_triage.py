import tempfile
import unittest
from pathlib import Path

import app as app_module
import database
import engine
from flask import g


class TriageSemanticsTests(unittest.TestCase):
    """Partial updates, intentional clearing, and validation of triage_alert."""

    def setUp(self):
        self.original_db_path = database.DB_PATH
        self.temp_dir = tempfile.TemporaryDirectory(prefix="triagearc-triage-")
        database.DB_PATH = Path(self.temp_dir.name) / "triage.db"
        app_module.app.config.update(TESTING=True)
        self.client = app_module.app.test_client()

        # Initialize and seed the same per-browser workspace used by real requests.
        home = self.client.get("/")
        self.assertEqual(home.status_code, 200)
        with self.client.session_transaction() as browser_session:
            workspace_id = browser_session["workspace_id"]
        self.workspace_db_path = (
            Path(database.DB_PATH).parent / "workspaces" / f"{workspace_id}.db"
        )
        alerts_response = self.client.get("/api/alerts")
        self.assertEqual(alerts_response.status_code, 200)
        self.uid = alerts_response.json["alerts"][0]["alert_uid"]
        self.url = f"/api/alerts/{self.uid}/triage"
        self.full = {"status": "CLOSED", "verdict": "BENIGN", "confidence": 40, "response_note": "Checked with owner."}
        self.assertEqual(self.client.post(self.url, json=self.full).status_code, 200)

    def tearDown(self):
        database.DB_PATH = self.original_db_path
        self.temp_dir.cleanup()

    def post(self, payload):
        return self.client.post(self.url, json=payload)

    def test_note_only_update_keeps_everything_else(self):
        alert = self.post({"response_note": "New note"}).json["alert"]
        self.assertEqual(alert["status"], "CLOSED")
        self.assertEqual(alert["verdict"], "BENIGN")
        self.assertEqual(alert["confidence"], 40)
        self.assertEqual(alert["response_note"], "New note")

    def test_status_only_update_keeps_verdict_confidence_note(self):
        alert = self.post({"status": "ESCALATED"}).json["alert"]
        self.assertEqual(alert["status"], "ESCALATED")
        self.assertEqual(alert["verdict"], "BENIGN")
        self.assertEqual(alert["confidence"], 40)
        self.assertEqual(alert["response_note"], "Checked with owner.")

    def test_confidence_kept_when_omitted_and_zero_is_valid(self):
        self.assertEqual(self.post({"verdict": "MALICIOUS"}).json["alert"]["confidence"], 40)
        self.assertEqual(self.post({"confidence": 0}).json["alert"]["confidence"], 0)

    def test_verdict_can_be_cleared_with_null_or_empty(self):
        self.assertIsNone(self.post({"verdict": None}).json["alert"]["verdict"])
        self.post({"verdict": "SUSPICIOUS"})
        self.assertIsNone(self.post({"verdict": ""}).json["alert"]["verdict"])

    def test_note_can_be_cleared_with_null_empty_or_blank(self):
        for cleared in (None, "", "   "):
            with self.subTest(value=cleared):
                self.post({"response_note": "again"})
                self.assertIsNone(self.post({"response_note": cleared}).json["alert"]["response_note"])

    def test_clearing_does_not_touch_other_fields(self):
        alert = self.post({"verdict": None, "response_note": None}).json["alert"]
        self.assertEqual((alert["status"], alert["confidence"]), ("CLOSED", 40))

    def test_ui_style_full_payload_round_trip(self):
        # Exactly what static/app.js sends when the analyst picks "Not set" and empties the note.
        alert = self.post({"status": "IN_REVIEW", "verdict": None, "confidence": 85, "response_note": ""}).json["alert"]
        self.assertEqual((alert["status"], alert["verdict"], alert["confidence"], alert["response_note"]),
                         ("IN_REVIEW", None, 85, None))

    def test_case_and_whitespace_are_normalised(self):
        alert = self.post({"status": " in_review ", "verdict": " suspicious "}).json["alert"]
        self.assertEqual((alert["status"], alert["verdict"]), ("IN_REVIEW", "SUSPICIOUS"))

    def test_null_status_or_confidence_is_rejected(self):
        for payload in ({"status": None}, {"confidence": None}):
            with self.subTest(payload=payload):
                self.assertEqual(self.post(payload).status_code, 400)

    def test_invalid_values_rejected_and_stored_data_unchanged(self):
        bad = ({"verdict": "MAYBE"}, {"verdict": 3}, {"confidence": "50"}, {"confidence": 50.5},
               {"confidence": -1}, {"response_note": "x" * 2001}, {"status": ""})
        for payload in bad:
            with self.subTest(payload=payload):
                self.assertEqual(self.post(payload).status_code, 400)
        alert = self.client.get(f"/api/alerts/{self.uid}").json["alert"]
        self.assertEqual((alert["status"], alert["verdict"], alert["confidence"], alert["response_note"]),
                         ("CLOSED", "BENIGN", 40, "Checked with owner."))

    def test_note_at_limit_is_accepted(self):
        self.assertEqual(self.post({"response_note": "x" * 2000}).status_code, 200)

    def test_unknown_alert_returns_404_for_partial_and_full_payloads(self):
        for payload in ({"response_note": "x"}, {"status": "CLOSED"}, {}):
            with self.subTest(payload=payload):
                response = self.client.post("/api/alerts/ALT-NOPE0000/triage", json=payload)
                self.assertEqual(response.status_code, 404)

    def test_non_object_body_is_rejected(self):
        self.assertEqual(self.client.post(self.url, json=["x"]).status_code, 400)
        self.assertEqual(self.client.post(self.url, data="nope", content_type="text/plain").status_code, 400)

    def test_rerunning_detection_does_not_overwrite_analyst_work(self):
        # Run detection against this browser's workspace without resetting it.
        with app_module.app.test_request_context("/"):
            g.triagearc_db_path = self.workspace_db_path
            engine.create_alerts()
        alert = self.client.get(f"/api/alerts/{self.uid}").json["alert"]
        self.assertEqual((alert["status"], alert["verdict"], alert["response_note"]),
                         ("CLOSED", "BENIGN", "Checked with owner."))
        self.assertEqual(len(self.client.get("/api/alerts").json["alerts"]), 5)


    def test_empty_payload_is_a_no_op_for_known_alert(self):
        response = self.post({})
        self.assertEqual(response.status_code, 200)
        alert = response.json["alert"]
        self.assertEqual((alert["status"], alert["verdict"], alert["confidence"], alert["response_note"]),
                         ("CLOSED", "BENIGN", 40, "Checked with owner."))

    def test_one_invalid_field_prevents_the_whole_update(self):
        self.assertEqual(self.post({"status": "NEW", "verdict": "MAYBE", "response_note": "should not land"}).status_code, 400)
        alert = self.client.get(f"/api/alerts/{self.uid}").json["alert"]
        self.assertEqual((alert["status"], alert["response_note"]), ("CLOSED", "Checked with owner."))

    def test_note_is_trimmed_when_saved(self):
        self.assertEqual(self.post({"response_note": "  spaced  "}).json["alert"]["response_note"], "spaced")


if __name__ == "__main__":
    unittest.main()
