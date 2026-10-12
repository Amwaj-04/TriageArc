import unittest

from rules import (
    detect_auth_failures,
    detect_powershell,
    detect_privileged_account,
    detect_sensitive_access,
    detect_success_after_failures,
)


class DetectionRuleTests(unittest.TestCase):
    def test_bruteforce_threshold_is_five(self):
        events = [
            {"id": i, "timestamp": f"2026-10-08T07:0{i}:00+00:00", "event_type": "authentication", "status": "failure", "username": "a", "source_ip": "1.2.3.4", "host": "dc-01"}
            for i in range(1, 6)
        ]
        self.assertEqual(len(detect_auth_failures(events)), 1)

    def test_four_failures_do_not_alert(self):
        events = [
            {"id": i, "timestamp": f"2026-10-08T07:0{i}:00+00:00", "event_type": "authentication", "status": "failure", "username": "a", "source_ip": "1.2.3.4", "host": "dc-01"}
            for i in range(1, 5)
        ]
        self.assertEqual(detect_auth_failures(events), [])

    def test_success_after_failures(self):
        events = [
            {"id": 1, "timestamp": "2026-10-08T07:01:00+00:00", "event_type": "authentication", "status": "failure", "username": "a", "source_ip": "1.2.3.4", "host": "dc-01"},
            {"id": 2, "timestamp": "2026-10-08T07:02:00+00:00", "event_type": "authentication", "status": "failure", "username": "a", "source_ip": "1.2.3.4", "host": "dc-01"},
            {"id": 3, "timestamp": "2026-10-08T07:03:00+00:00", "event_type": "authentication", "status": "failure", "username": "a", "source_ip": "1.2.3.4", "host": "dc-01"},
            {"id": 4, "timestamp": "2026-10-08T07:04:00+00:00", "event_type": "authentication", "status": "success", "username": "a", "source_ip": "1.2.3.4", "host": "dc-01"},
        ]
        self.assertEqual(len(detect_success_after_failures(events)), 1)

    def test_powershell_requires_indicator(self):
        base = {"id": 1, "timestamp": "2026-10-08T07:01:00+00:00", "event_type": "process", "process_name": "powershell.exe", "host": "ws-01", "username": "a", "source_ip": "10.0.0.1"}
        benign = {**base, "command_line": "powershell.exe -NoProfile Get-Date"}
        suspicious = {**base, "command_line": "powershell.exe -ExecutionPolicy Bypass -EncodedCommand AAA"}
        self.assertEqual(detect_powershell([benign]), [])
        self.assertEqual(len(detect_powershell([suspicious])), 1)

    def test_new_admin_account_is_correlated(self):
        events = [
            {"id": 1, "timestamp": "2026-10-08T10:00:00+00:00", "event_type": "account", "action": "created", "username": "newsvc", "host": "dc-01", "source_ip": "10.0.0.1"},
            {"id": 2, "timestamp": "2026-10-08T10:10:00+00:00", "event_type": "privilege", "action": "admin_granted", "username": "newsvc", "host": "dc-01", "source_ip": "10.0.0.1"},
        ]
        self.assertEqual(len(detect_privileged_account(events)), 1)

    def test_sensitive_access_outside_expected_host(self):
        event = {"id": 1, "timestamp": "2026-10-08T11:00:00+00:00", "event_type": "file_access", "action": "read", "username": "analyst02", "host": "ws-sales-07", "source_ip": "10.0.0.1", "target": "customer_export.csv"}
        self.assertEqual(len(detect_sensitive_access([event])), 1)


if __name__ == "__main__":
    unittest.main()
