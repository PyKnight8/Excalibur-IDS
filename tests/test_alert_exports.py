from pathlib import Path
from tempfile import TemporaryDirectory
import csv
import io
import json
import sqlite3
import unittest

from excalibur.dashboard.app import create_app
from excalibur.database import Database


class AlertExportTest(unittest.TestCase):
    def setUp(self):
        self.temp_dir = TemporaryDirectory()
        self.db_path = Path(self.temp_dir.name) / "alerts.sqlite"
        self.database = Database(self.db_path)
        self.database.create_alert(
            "2026-06-08T10:00:00+00:00",
            "Medium",
            "Possible Port Scan",
            "Source IP 10.0.0.10 contacted 20 unique destination ports.",
            source_ip="10.0.0.10",
            destination_ip="10.0.0.1",
            context={"unique_dst_ports": 20, "window_seconds": 60},
        )

    def tearDown(self):
        self.database.close()
        self.temp_dir.cleanup()

    def test_alert_csv_export_returns_alert_data(self):
        response = create_app(self.db_path).test_client().get("/alerts/export.csv")
        rows = list(csv.DictReader(io.StringIO(response.get_data(as_text=True))))

        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.content_type, "text/csv; charset=utf-8")
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["severity"], "Medium")
        self.assertEqual(rows[0]["title"], "Possible Port Scan")
        self.assertEqual(rows[0]["source_ip"], "10.0.0.10")
        self.assertEqual(rows[0]["destination_ip"], "10.0.0.1")
        self.assertEqual(json.loads(rows[0]["context_json"])["unique_dst_ports"], 20)

    def test_alert_json_export_returns_alert_data(self):
        response = create_app(self.db_path).test_client().get("/alerts/export.json")
        payload = response.get_json()

        self.assertEqual(response.status_code, 200)
        self.assertEqual(len(payload), 1)
        self.assertEqual(payload[0]["severity"], "Medium")
        self.assertEqual(payload[0]["title"], "Possible Port Scan")
        self.assertEqual(payload[0]["source_ip"], "10.0.0.10")
        self.assertEqual(payload[0]["destination_ip"], "10.0.0.1")
        self.assertEqual(payload[0]["context"]["window_seconds"], 60)
        self.assertEqual(self.database.count_alerts(), 1)

    def test_alerts_page_shows_source_destination_and_detail_evidence(self):
        client = create_app(self.db_path).test_client()

        response = client.get("/alerts")
        html = response.get_data(as_text=True)
        detail_response = client.get("/alerts/1")
        detail_html = detail_response.get_data(as_text=True)

        self.assertEqual(response.status_code, 200)
        self.assertIn("Source", html)
        self.assertIn("Destination", html)
        self.assertIn("10.0.0.10", html)
        self.assertIn("10.0.0.1", html)
        self.assertEqual(detail_response.status_code, 200)
        self.assertIn("Detection Evidence", detail_html)
        self.assertIn("Observed Unique Ports", detail_html)
        self.assertIn("20", detail_html)

    def test_alert_detail_missing_returns_404(self):
        response = create_app(self.db_path).test_client().get("/alerts/999")

        self.assertEqual(response.status_code, 404)

    def test_alert_details_api_returns_rule_metadata_evidence_and_related_activity(self):
        self.database.log_dns_query(
            "2026-06-08T10:00:01+00:00",
            "10.0.0.10",
            "10.0.0.53",
            "example.org",
            "A",
            "NOERROR",
        )
        self.database.log_traffic(
            "2026-06-08T10:00:02+00:00",
            "10.0.0.10",
            "10.0.0.20",
            "TCP",
            12345,
            445,
            60,
        )
        self.database.create_alert(
            "2026-06-08T10:00:03+00:00",
            "High",
            "SMB Recon Activity",
            "Source contacted many hosts via SMB.",
            source_ip="10.0.0.10",
            destination_ip="10.0.0.20",
            context={
                "rule": {
                    "name": "SMB Recon",
                    "pack": "recon.yaml",
                    "tags": ["recon", "smb", "mitre:T1595"],
                    "event_type": "packet",
                    "thresholds": {"unique_dst_ips": 20},
                    "window_seconds": 60,
                },
                "evidence": {
                    "observed": {"unique_dst_ips": 37},
                    "thresholds": {"unique_dst_ips": 20},
                    "window_seconds": 60,
                },
            },
        )

        response = create_app(self.db_path).test_client().get("/api/alerts/2/details")
        payload = response.get_json()

        self.assertEqual(response.status_code, 200)
        self.assertEqual(payload["rule"]["name"], "SMB Recon")
        self.assertEqual(payload["rule"]["pack"], "recon.yaml")
        self.assertIn("mitre:T1595", payload["rule"]["tags"])
        self.assertEqual(payload["evidence"][0]["label"], "Observed Unique Hosts")
        self.assertEqual(payload["evidence"][0]["value"], 37)
        self.assertEqual(len(payload["related_activity"]["dns_queries"]), 1)
        self.assertEqual(len(payload["related_activity"]["traffic"]), 1)
        self.assertEqual(len(payload["related_activity"]["alerts"]), 1)

    def test_alert_detail_page_renders_rule_metadata_and_related_activity(self):
        self.database.log_dns_query(
            "2026-06-08T10:00:01+00:00",
            "10.0.0.10",
            "10.0.0.53",
            "example.org",
            "A",
            "NOERROR",
        )
        self.database.log_traffic(
            "2026-06-08T10:00:02+00:00",
            "10.0.0.10",
            "10.0.0.20",
            "TCP",
            12345,
            445,
            60,
        )
        self.database.create_alert(
            "2026-06-08T10:00:03+00:00",
            "High",
            "SMB Recon Activity",
            "Source contacted many hosts via SMB.",
            source_ip="10.0.0.10",
            destination_ip="10.0.0.20",
            context={
                "rule": {
                    "name": "SMB Recon",
                    "pack": "recon.yaml",
                    "tags": ["recon", "smb"],
                    "event_type": "packet",
                    "thresholds": {"unique_dst_ips": 20},
                    "window_seconds": 60,
                },
                "evidence": {
                    "observed": {"unique_dst_ips": 37},
                    "thresholds": {"unique_dst_ips": 20},
                    "window_seconds": 60,
                },
            },
        )

        html = create_app(self.db_path).test_client().get("/alerts/2").get_data(as_text=True)

        self.assertIn("Alert ID", html)
        self.assertIn("Rule Information", html)
        self.assertIn("recon.yaml", html)
        self.assertIn("Observed Unique Hosts", html)
        self.assertIn("Recent DNS Queries", html)
        self.assertIn("Recent Traffic", html)

    def test_existing_alert_rows_without_context_remain_valid(self):
        legacy_path = Path(self.temp_dir.name) / "legacy-alerts.sqlite"
        connection = sqlite3.connect(legacy_path)
        connection.execute(
            """
            CREATE TABLE alerts (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT NOT NULL,
                severity TEXT NOT NULL,
                title TEXT NOT NULL,
                description TEXT
            )
            """
        )
        connection.execute(
            """
            INSERT INTO alerts (timestamp, severity, title, description)
            VALUES (?, ?, ?, ?)
            """,
            ("2026-06-08T10:00:00+00:00", "Low", "Legacy", "Old alert"),
        )
        connection.commit()
        connection.close()

        database = Database(legacy_path)
        alerts = database.get_alerts()
        database.close()

        self.assertEqual(alerts[0]["title"], "Legacy")
        self.assertIsNone(alerts[0]["source_ip"])
        self.assertIsNone(alerts[0]["destination_ip"])
        self.assertIsNone(alerts[0]["context_json"])

    def test_delete_one_alert_removes_only_that_alert(self):
        second_alert_id = self.database.create_alert(
            "2026-06-08T10:01:00+00:00",
            "High",
            "Second Alert",
            "Another alert",
        )
        self.database.add_host(
            "10.0.0.10",
            None,
            "2026-06-08T10:00:00+00:00",
            "2026-06-08T10:00:00+00:00",
        )
        client = create_app(self.db_path).test_client()

        response = client.post(f"/alerts/delete/{second_alert_id}")

        alerts = self.database.get_alerts()
        self.assertEqual(response.status_code, 302)
        self.assertEqual(len(alerts), 1)
        self.assertEqual(alerts[0]["title"], "Possible Port Scan")
        self.assertEqual(self.database.count_hosts(), 1)

    def test_clear_all_alerts_removes_only_alerts(self):
        self.database.create_alert(
            "2026-06-08T10:01:00+00:00",
            "High",
            "Second Alert",
            "Another alert",
        )
        self.database.add_host(
            "10.0.0.10",
            None,
            "2026-06-08T10:00:00+00:00",
            "2026-06-08T10:00:00+00:00",
        )
        self.database.log_traffic(
            "2026-06-08T10:00:01+00:00",
            "10.0.0.10",
            "10.0.0.1",
            "TCP",
            12345,
            80,
            60,
        )

        response = create_app(self.db_path).test_client().post("/alerts/delete-all")

        self.assertEqual(response.status_code, 302)
        self.assertEqual(self.database.count_alerts(), 0)
        self.assertEqual(self.database.count_hosts(), 1)
        self.assertEqual(self.database.count_traffic(), 1)


if __name__ == "__main__":
    unittest.main()
