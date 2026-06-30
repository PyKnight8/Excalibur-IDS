from datetime import datetime, timezone
from pathlib import Path
from tempfile import TemporaryDirectory
import os
import unittest

from excalibur.dashboard.app import create_app
from excalibur.database import Database
from excalibur.detection.domain_risk import DomainRiskAnalyzer
from excalibur.detection.signature_engine import SignatureEngine


class BrowserThreatProtectionTest(unittest.TestCase):
    def setUp(self):
        self.temp_dir = TemporaryDirectory()
        self.original_cwd = os.getcwd()
        os.chdir(self.temp_dir.name)
        self.config = {
            "browser_threat_protection": {
                "enabled": True,
                "risk_threshold": 60,
                "suspicious_tlds": ["zip", "mov", "xyz"],
                "suspicious_keywords": [
                    "login",
                    "verify",
                    "secure",
                    "account",
                    "update",
                    "wallet",
                    "reset",
                ],
            }
        }
        self.database = Database(Path(self.temp_dir.name) / "browser.sqlite", config=self.config)

    def tearDown(self):
        self.database.close()
        os.chdir(self.original_cwd)
        self.temp_dir.cleanup()

    def test_domain_scoring_marks_suspicious_keyword(self):
        analyzer = DomainRiskAnalyzer(self.config)

        result = analyzer.analyze("secure-login-account-update.example.com")

        self.assertGreaterEqual(result["risk_score"], 30)
        self.assertEqual(result["risk_level"], "Low")
        self.assertIn("suspicious keywords", "; ".join(result["reasons"]))

    def test_domain_scoring_marks_dga_like_domain(self):
        analyzer = DomainRiskAnalyzer(self.config)

        result = analyzer.analyze("xj3k9qz8m2p5v7n4k1s0.xyz")

        self.assertGreaterEqual(result["risk_score"], 80)
        self.assertEqual(result["risk_level"], "High")
        self.assertTrue(
            any("DGA-like" in reason or "randomness" in reason for reason in result["reasons"])
        )

    def test_risky_new_domain_generates_alert(self):
        timestamp = datetime(2026, 6, 10, 10, 0, tzinfo=timezone.utc).isoformat()

        self.database.log_dns_query(
            timestamp=timestamp,
            client_ip="10.0.0.10",
            dns_server_ip="10.0.0.1",
            query_name="secure-login-wallet-reset.xyz",
            query_type="A",
        )
        self.database.log_dns_query(
            timestamp=timestamp,
            client_ip="10.0.0.10",
            dns_server_ip="10.0.0.1",
            query_name="secure-login-wallet-reset.xyz",
            query_type="A",
        )

        alerts = self.database.get_alerts()
        rows, total = self.database.get_domain_risk()

        self.assertEqual(len(alerts), 1)
        self.assertEqual(alerts[0]["title"], "Suspicious Browser Domain")
        self.assertEqual(alerts[0]["source_ip"], "10.0.0.10")
        self.assertEqual(total, 1)
        self.assertEqual(rows[0]["query_count"], 2)
        self.assertIn("suspicious keywords", rows[0]["reasons"])

    def test_browser_erl_string_operators_trigger_alerts(self):
        engine = SignatureEngine(
            self.database,
            signatures={
                "signatures": [
                    {
                        "name": "Browser Keyword",
                        "enabled": True,
                        "event": "dns",
                        "match": {
                            "query_name": {
                                "contains_any": ["login", "wallet"],
                            }
                        },
                        "aggregate": {
                            "count": {"gte": 1},
                            "within_seconds": 60,
                        },
                        "alert": {
                            "severity": "Low",
                            "title": "Browser Keyword",
                            "description": "Browser keyword observed.",
                        },
                    },
                    {
                        "name": "Browser TLD",
                        "enabled": True,
                        "event": "dns",
                        "match": {
                            "query_name": {
                                "endswith_any": [".zip", ".mov"],
                            }
                        },
                        "aggregate": {
                            "count": {"gte": 1},
                            "within_seconds": 60,
                        },
                        "alert": {
                            "severity": "Low",
                            "title": "Browser TLD",
                            "description": "Browser TLD observed.",
                        },
                    },
                    {
                        "name": "DGA-like Risk",
                        "enabled": True,
                        "event": "dns",
                        "match": {
                            "risk_score": {
                                "gte": 80,
                            }
                        },
                        "aggregate": {
                            "count": {"gte": 1},
                            "within_seconds": 60,
                        },
                        "alert": {
                            "severity": "High",
                            "title": "DGA-like Risk",
                            "description": "DGA-like risk observed.",
                        },
                    },
                ]
            },
        )
        event = {
            "timestamp": datetime(2026, 6, 10, 10, 0, tzinfo=timezone.utc).isoformat(),
            "client_ip": "10.0.0.10",
            "dns_server_ip": "10.0.0.1",
            "query_name": "wallet-login-example.zip",
            "query_type": "A",
            "risk_score": 85,
            "risk_level": "High",
            "risk_reasons": "DGA-like randomness",
        }

        engine.process_dns_query(event)

        alert_titles = {alert["title"] for alert in self.database.get_alerts()}
        self.assertEqual(
            alert_titles,
            {"Browser Keyword", "Browser TLD", "DGA-like Risk"},
        )

    def test_browser_dashboard_route_renders_risky_domains(self):
        timestamp = datetime(2026, 6, 10, 10, 0, tzinfo=timezone.utc).isoformat()
        self.database.log_dns_query(
            timestamp=timestamp,
            client_ip="10.0.0.10",
            dns_server_ip="10.0.0.1",
            query_name="verify-account-update.xyz",
            query_type="A",
        )

        app = create_app(Path(self.temp_dir.name) / "browser.sqlite")
        response = app.test_client().get("/browser?search=verify")
        html = response.get_data(as_text=True)

        self.assertEqual(response.status_code, 200)
        self.assertIn("Browser Threats", html)
        self.assertIn("verify-account-update.xyz", html)
        self.assertIn("suspicious keywords", html)


if __name__ == "__main__":
    unittest.main()
