from datetime import datetime, timedelta, timezone
from contextlib import redirect_stdout
from io import BytesIO, StringIO
import json
from pathlib import Path
from tempfile import TemporaryDirectory
import unittest

from excalibur.dashboard.app import create_app
from excalibur.database import Database
from excalibur.detection.signature_engine import SignatureEngine, SignatureValidationError


class SignatureEngineTest(unittest.TestCase):
    def setUp(self):
        self.temp_dir = TemporaryDirectory()
        self.database = Database(Path(self.temp_dir.name) / "signatures.sqlite")
        self.base_time = datetime(2026, 6, 9, 10, 0, tzinfo=timezone.utc)

    def tearDown(self):
        self.database.close()
        self.temp_dir.cleanup()

    def test_exact_field_matching(self):
        engine = SignatureEngine(
            self.database,
            signatures=self._signatures(
                match={"protocol": "TCP", "dst_port": 445},
                aggregate={"count": {"gte": 2}, "within_seconds": 60},
            ),
        )

        engine.process_packet(self._packet(0, protocol="UDP", dst_port=445))
        engine.process_packet(self._packet(1, protocol="TCP", dst_port=445))
        engine.process_packet(self._packet(2, protocol="TCP", dst_port=445))

        self.assertEqual(self.database.count_alerts(), 1)

    def test_membership_matching(self):
        engine = SignatureEngine(
            self.database,
            signatures=self._signatures(
                match={"dst_port": {"in": [445, 389, 636]}},
                aggregate={"count": {"gte": 2}, "within_seconds": 60},
            ),
        )

        engine.process_packet(self._packet(0, dst_port=80))
        engine.process_packet(self._packet(1, dst_port=389))
        engine.process_packet(self._packet(2, dst_port=636))

        self.assertEqual(self.database.count_alerts(), 1)

    def test_tcp_flags_match_with_string_operators(self):
        engine = SignatureEngine(
            self.database,
            signatures=self._signatures(
                match={
                    "protocol": "TCP",
                    "tcp_flags": {
                        "in": ["S", "SA"],
                        "contains": "S",
                    },
                    "dst_port": {"lte": 10000},
                },
                aggregate={"count": {"gte": 2}, "within_seconds": 60},
            ),
        )

        engine.process_packet(self._packet(0, tcp_flags="A", dst_port=80))
        engine.process_packet(self._packet(1, tcp_flags="SA", dst_port=443))
        engine.process_packet(self._packet(2, tcp_flags="S", dst_port=10001))
        engine.process_packet(self._packet(3, tcp_flags="S", dst_port=445))

        self.assertEqual(self.database.count_alerts(), 1)

    def test_network_matching(self):
        engine = SignatureEngine(
            self.database,
            signatures=self._signatures(
                match={"src_ip": {"in_networks": ["10.0.0.0/8"]}},
                aggregate={"count": {"gte": 2}, "within_seconds": 60},
            ),
        )

        engine.process_packet(self._packet(0, src_ip="192.168.1.20"))
        engine.process_packet(self._packet(1, src_ip="10.0.0.20"))
        engine.process_packet(self._packet(2, src_ip="10.0.0.20"))

        self.assertEqual(self.database.count_alerts(), 1)

    def test_numeric_gt_matching(self):
        engine = SignatureEngine(
            self.database,
            signatures=self._signatures(
                match={"packet_size": {"gt": 1200}},
                aggregate={"count": {"gte": 2}, "within_seconds": 60},
            ),
        )

        engine.process_packet(self._packet(0, packet_size=1200))
        engine.process_packet(self._packet(1, packet_size=1201))
        engine.process_packet(self._packet(2, packet_size=1500))

        self.assertEqual(self.database.count_alerts(), 1)

    def test_numeric_gte_matching(self):
        engine = SignatureEngine(
            self.database,
            signatures=self._signatures(
                match={"dst_port": {"gte": 1024}},
                aggregate={"count": {"gte": 2}, "within_seconds": 60},
            ),
        )

        engine.process_packet(self._packet(0, dst_port=1023))
        engine.process_packet(self._packet(1, dst_port=1024))
        engine.process_packet(self._packet(2, dst_port=2048))

        self.assertEqual(self.database.count_alerts(), 1)

    def test_numeric_lt_matching(self):
        engine = SignatureEngine(
            self.database,
            signatures=self._signatures(
                match={"packet_size": {"lt": 100}},
                aggregate={"count": {"gte": 2}, "within_seconds": 60},
            ),
        )

        engine.process_packet(self._packet(0, packet_size=100))
        engine.process_packet(self._packet(1, packet_size=99))
        engine.process_packet(self._packet(2, packet_size=60))

        self.assertEqual(self.database.count_alerts(), 1)

    def test_numeric_lte_matching(self):
        engine = SignatureEngine(
            self.database,
            signatures=self._signatures(
                match={"packet_size": {"lte": 100}},
                aggregate={"count": {"gte": 2}, "within_seconds": 60},
            ),
        )

        engine.process_packet(self._packet(0, packet_size=101))
        engine.process_packet(self._packet(1, packet_size=100))
        engine.process_packet(self._packet(2, packet_size=60))

        self.assertEqual(self.database.count_alerts(), 1)

    def test_numeric_validation_rejects_non_numeric_thresholds(self):
        with self.assertRaises(SignatureValidationError) as context:
            SignatureEngine.parse(
                "signatures:\n"
                "  - name: Bad Numeric\n"
                "    enabled: true\n"
                "    event: packet\n"
                "    match:\n"
                "      packet_size:\n"
                "        gt: abc\n"
                "    aggregate:\n"
                "      count:\n"
                "        gte: 1\n"
                "      within_seconds: 60\n"
                "    alert:\n"
                "      severity: Medium\n"
                "      title: Bad Numeric\n"
                "      description: Bad numeric.\n"
            )

        self.assertIn("match operator 'gt' requires a number", str(context.exception))

    def test_string_contains_matching_is_case_insensitive(self):
        engine = SignatureEngine(
            self.database,
            signatures=self._signatures(
                event="dns",
                match={"query_name": {"contains": "login"}},
                aggregate={"count": {"gte": 2}, "within_seconds": 60},
            ),
        )

        engine.process_dns_query(self._dns(0, query_name="example.com"))
        engine.process_dns_query(self._dns(1, query_name="LOGIN.example.com"))
        engine.process_dns_query(self._dns(2, query_name="secure-login.example.com"))

        self.assertEqual(self.database.count_alerts(), 1)

    def test_quoted_string_match_values_are_unquoted(self):
        parsed = SignatureEngine.parse(
            "signatures:\n"
            "  - name: Quoted Contains\n"
            "    enabled: true\n"
            "    event: dns\n"
            "    match:\n"
            "      query_name:\n"
            "        contains: \"xn--\"\n"
            "    aggregate:\n"
            "      count:\n"
            "        gte: 1\n"
            "      within_seconds: 60\n"
            "    alert:\n"
            "      severity: Medium\n"
            "      title: Quoted Contains\n"
            "      description: Quoted contains.\n"
        )

        self.assertEqual(parsed["signatures"][0]["match"]["query_name"]["contains"], "xn--")

    def test_string_startswith_matching_is_case_insensitive(self):
        engine = SignatureEngine(
            self.database,
            signatures=self._signatures(
                event="dns",
                match={"query_name": {"startswith": "api"}},
                aggregate={"count": {"gte": 2}, "within_seconds": 60},
            ),
        )

        engine.process_dns_query(self._dns(0, query_name="www.example.com"))
        engine.process_dns_query(self._dns(1, query_name="API.example.com"))
        engine.process_dns_query(self._dns(2, query_name="api2.example.com"))

        self.assertEqual(self.database.count_alerts(), 1)

    def test_string_endswith_matching_is_case_insensitive(self):
        engine = SignatureEngine(
            self.database,
            signatures=self._signatures(
                event="dns",
                match={"query_name": {"endswith": ".xyz"}},
                aggregate={"count": {"gte": 2}, "within_seconds": 60},
            ),
        )

        engine.process_dns_query(self._dns(0, query_name="example.com"))
        engine.process_dns_query(self._dns(1, query_name="one.XYZ"))
        engine.process_dns_query(self._dns(2, query_name="two.xyz"))

        self.assertEqual(self.database.count_alerts(), 1)

    def test_regex_matching_uses_case_insensitive_search(self):
        engine = SignatureEngine(
            self.database,
            signatures=self._signatures(
                event="dns",
                match={"query_name": {"regex": ".*xn--.*"}},
                aggregate={"count": {"gte": 2}, "within_seconds": 60},
            ),
        )

        engine.process_dns_query(self._dns(0, query_name="example.com"))
        engine.process_dns_query(self._dns(1, query_name="XN--example.com"))
        engine.process_dns_query(self._dns(2, query_name="sub.xn--example.com"))

        self.assertEqual(self.database.count_alerts(), 1)

    def test_dns_rcode_exact_matching(self):
        engine = SignatureEngine(
            self.database,
            signatures=self._signatures(
                event="dns",
                match={"dns_rcode": "NXDOMAIN"},
                aggregate={"count": {"gte": 2}, "within_seconds": 60},
            ),
        )

        engine.process_dns_query(self._dns(0, dns_rcode="NOERROR"))
        engine.process_dns_query(self._dns(1, dns_rcode="NXDOMAIN"))
        engine.process_dns_query(self._dns(2, dns_rcode="NXDOMAIN"))

        self.assertEqual(self.database.count_alerts(), 1)

    def test_dns_rcode_membership_matching(self):
        engine = SignatureEngine(
            self.database,
            signatures=self._signatures(
                event="dns",
                match={"dns_rcode": {"in": ["NXDOMAIN", "SERVFAIL"]}},
                aggregate={"count": {"gte": 2}, "within_seconds": 60},
            ),
        )

        engine.process_dns_query(self._dns(0, dns_rcode="NOERROR"))
        engine.process_dns_query(self._dns(1, dns_rcode="SERVFAIL"))
        engine.process_dns_query(self._dns(2, dns_rcode="NXDOMAIN"))

        self.assertEqual(self.database.count_alerts(), 1)

    def test_nxdomain_burst_triggers_and_noerror_does_not(self):
        engine = SignatureEngine(
            self.database,
            signatures={
                "signatures": [
                    self._signature(
                        name="NXDOMAIN Burst",
                        event="dns",
                        match={"dns_rcode": "NXDOMAIN"},
                        aggregate={"count": {"gte": 50}, "within_seconds": 60},
                        cooldown_seconds=300,
                        alert={
                            "severity": "Medium",
                            "title": "Excessive NXDOMAIN Responses",
                            "description": "Client generated many failed DNS lookups.",
                        },
                    )
                ]
            },
        )

        for index in range(50):
            engine.process_dns_query(self._dns(index, dns_rcode="NOERROR"))
        self.assertEqual(self.database.count_alerts(), 0)

        for index in range(50):
            engine.process_dns_query(self._dns(index, dns_rcode="NXDOMAIN"))

        alerts = self.database.get_alerts()
        self.assertEqual(len(alerts), 1)
        self.assertEqual(alerts[0]["title"], "Excessive NXDOMAIN Responses")

    def test_nxdomain_fanout_triggers_on_unique_failed_domains(self):
        engine = SignatureEngine(
            self.database,
            signatures={
                "signatures": [
                    self._signature(
                        name="NXDOMAIN Fanout",
                        event="dns",
                        match={"dns_rcode": "NXDOMAIN"},
                        aggregate={"unique_domains": {"gte": 25}, "within_seconds": 60},
                        cooldown_seconds=300,
                        alert={
                            "severity": "High",
                            "title": "Excessive Failed Domain Lookups",
                            "description": "Client queried many unique non-existent domains.",
                        },
                    )
                ]
            },
        )

        for index in range(25):
            engine.process_dns_query(
                self._dns(index, query_name=f"missing-{index}.example", dns_rcode="NXDOMAIN")
            )

        alerts = self.database.get_alerts()
        self.assertEqual(len(alerts), 1)
        self.assertEqual(alerts[0]["title"], "Excessive Failed Domain Lookups")

    def test_quoted_regex_match_values_are_unquoted_and_unescaped(self):
        parsed = SignatureEngine.parse(
            "signatures:\n"
            "  - name: Quoted Regex\n"
            "    enabled: true\n"
            "    event: dns\n"
            "    match:\n"
            "      query_name:\n"
            "        regex: \".*\\\\.(xyz|zip)$\"\n"
            "    aggregate:\n"
            "      count:\n"
            "        gte: 1\n"
            "      within_seconds: 60\n"
            "    alert:\n"
            "      severity: Medium\n"
            "      title: Quoted Regex\n"
            "      description: Quoted regex.\n"
        )

        self.assertEqual(
            parsed["signatures"][0]["match"]["query_name"]["regex"],
            r".*\.(xyz|zip)$",
        )

    def test_regex_validation_rejects_invalid_patterns(self):
        with self.assertRaises(SignatureValidationError) as context:
            SignatureEngine.parse(
                "signatures:\n"
                "  - name: Bad Regex\n"
                "    enabled: true\n"
                "    event: dns\n"
                "    match:\n"
                "      query_name:\n"
                "        regex: [\n"
                "    aggregate:\n"
                "      count:\n"
                "        gte: 1\n"
                "      within_seconds: 60\n"
                "    alert:\n"
                "      severity: Medium\n"
                "      title: Bad Regex\n"
                "      description: Bad regex.\n"
            )

        self.assertIn("Invalid regex", str(context.exception))

    def test_not_logic_excludes_matching_clause(self):
        engine = SignatureEngine(
            self.database,
            signatures=self._signatures(
                match={
                    "protocol": "TCP",
                    "not": {"dst_port": 80},
                },
                aggregate={"count": {"gte": 2}, "within_seconds": 60},
            ),
        )

        engine.process_packet(self._packet(0, protocol="UDP", dst_port=445))
        engine.process_packet(self._packet(1, protocol="TCP", dst_port=80))
        engine.process_packet(self._packet(2, protocol="TCP", dst_port=445))
        engine.process_packet(self._packet(3, protocol="TCP", dst_port=3389))

        self.assertEqual(self.database.count_alerts(), 1)

    def test_not_logic_supports_membership(self):
        engine = SignatureEngine(
            self.database,
            signatures=self._signatures(
                match={
                    "protocol": "TCP",
                    "not": {"dst_port": {"in": [80, 443]}},
                },
                aggregate={"count": {"gte": 2}, "within_seconds": 60},
            ),
        )

        engine.process_packet(self._packet(0, dst_port=80))
        engine.process_packet(self._packet(1, dst_port=443))
        engine.process_packet(self._packet(2, dst_port=445))
        engine.process_packet(self._packet(3, dst_port=3389))

        self.assertEqual(self.database.count_alerts(), 1)

    def test_not_logic_supports_network_match(self):
        engine = SignatureEngine(
            self.database,
            signatures=self._signatures(
                match={"not": {"dst_ip": {"in_networks": ["10.0.0.0/24"]}}},
                aggregate={"count": {"gte": 2}, "within_seconds": 60},
            ),
        )

        engine.process_packet(self._packet(0, dst_ip="10.0.0.10"))
        engine.process_packet(self._packet(1, dst_ip="10.0.1.10"))
        engine.process_packet(self._packet(2, dst_ip="10.0.2.10"))

        self.assertEqual(self.database.count_alerts(), 1)

    def test_not_validation_rejects_non_mapping_body(self):
        with self.assertRaises(SignatureValidationError) as context:
            SignatureEngine.parse(
                "signatures:\n"
                "  - name: Bad Not\n"
                "    enabled: true\n"
                "    event: packet\n"
                "    match:\n"
                "      not: true\n"
                "    aggregate:\n"
                "      count:\n"
                "        gte: 1\n"
                "      within_seconds: 60\n"
                "    alert:\n"
                "      severity: Medium\n"
                "      title: Bad Not\n"
                "      description: Bad not.\n"
            )

        self.assertIn("not must be a match mapping", str(context.exception))

    def test_not_validation_rejects_nested_not(self):
        with self.assertRaises(SignatureValidationError) as context:
            SignatureEngine.parse(
                "signatures:\n"
                "  - name: Nested Not\n"
                "    enabled: true\n"
                "    event: packet\n"
                "    match:\n"
                "      not:\n"
                "        any:\n"
                "          - not:\n"
                "            dst_port: 443\n"
                "    aggregate:\n"
                "      count:\n"
                "        gte: 1\n"
                "      within_seconds: 60\n"
                "    alert:\n"
                "      severity: Medium\n"
                "      title: Nested Not\n"
                "      description: Nested not.\n"
            )

        self.assertIn("nested not blocks are not supported", str(context.exception))

    def test_count_aggregation(self):
        engine = SignatureEngine(
            self.database,
            signatures=self._signatures(
                match={"protocol": "TCP"},
                aggregate={"count": {"gte": 3}, "within_seconds": 60},
            ),
        )

        for index in range(3):
            engine.process_packet(self._packet(index))

        self.assertEqual(self.database.count_alerts(), 1)

    def test_unique_destination_ip_aggregation(self):
        engine = SignatureEngine(
            self.database,
            signatures=self._signatures(
                match={"dst_port": 445},
                aggregate={"unique_dst_ips": {"gte": 3}, "within_seconds": 60},
            ),
        )

        for index in range(3):
            engine.process_packet(self._packet(index, dst_ip=f"10.0.0.{index + 1}"))

        self.assertEqual(self.database.count_alerts(), 1)

    def test_unique_destination_port_aggregation(self):
        engine = SignatureEngine(
            self.database,
            signatures=self._signatures(
                match={"protocol": "TCP"},
                aggregate={"unique_dst_ports": {"gte": 3}, "within_seconds": 60},
            ),
        )

        for index, port in enumerate([80, 443, 445]):
            engine.process_packet(self._packet(index, dst_port=port))

        self.assertEqual(self.database.count_alerts(), 1)

    def test_unique_domain_aggregation(self):
        engine = SignatureEngine(
            self.database,
            signatures=self._signatures(
                event="dns",
                match={"query_type": "A"},
                aggregate={"unique_domains": {"gte": 3}, "within_seconds": 60},
            ),
        )

        for index in range(3):
            engine.process_dns_query(self._dns(index, query_name=f"d{index}.example"))

        self.assertEqual(self.database.count_alerts(), 1)

    def test_repeated_domain_does_not_count_as_unique(self):
        engine = SignatureEngine(
            self.database,
            signatures=self._signatures(
                event="dns",
                match={"query_type": "A"},
                aggregate={"unique_domains": {"gte": 3}, "within_seconds": 60},
            ),
        )

        for index in range(5):
            engine.process_dns_query(self._dns(index, query_name="same.example"))

        self.assertEqual(self.database.count_alerts(), 0)

    def test_window_expiration(self):
        engine = SignatureEngine(
            self.database,
            signatures=self._signatures(
                match={"protocol": "TCP"},
                aggregate={"count": {"gte": 3}, "within_seconds": 10},
            ),
        )

        engine.process_packet(self._packet(0))
        engine.process_packet(self._packet(1))
        engine.process_packet(self._packet(20))

        self.assertEqual(self.database.count_alerts(), 0)

    def test_cooldown_suppresses_duplicate_alerts_per_source(self):
        engine = SignatureEngine(
            self.database,
            signatures=self._signatures(
                aggregate={"count": {"gte": 2}, "within_seconds": 60},
                cooldown_seconds=300,
            ),
        )

        engine.process_packet(self._packet(0))
        engine.process_packet(self._packet(1))
        engine.process_packet(self._packet(2))
        engine.process_packet(self._packet(301))
        engine.process_packet(self._packet(302))

        self.assertEqual(self.database.count_alerts(), 2)

    def test_cooldown_is_applied_per_source_key(self):
        engine = SignatureEngine(
            self.database,
            signatures=self._signatures(
                aggregate={"count": {"gte": 1}, "within_seconds": 60},
                cooldown_seconds=300,
            ),
        )

        engine.process_packet(self._packet(0, src_ip="10.0.0.10"))
        engine.process_packet(self._packet(1, src_ip="10.0.0.11"))
        engine.process_packet(self._packet(2, src_ip="10.0.0.10"))

        self.assertEqual(self.database.count_alerts(), 2)

    def test_multiple_aggregate_thresholds_must_all_match(self):
        engine = SignatureEngine(
            self.database,
            signatures=self._signatures(
                aggregate={
                    "unique_dst_ips": {"gte": 3},
                    "count": {"gte": 5},
                    "within_seconds": 60,
                },
            ),
        )

        for index in range(4):
            engine.process_packet(self._packet(index, dst_ip=f"10.0.0.{index % 3 + 1}"))
        self.assertEqual(self.database.count_alerts(), 0)

        engine.process_packet(self._packet(5, dst_ip="10.0.0.3"))
        self.assertEqual(self.database.count_alerts(), 1)

    def test_or_logic_matches_any_clause_with_outer_and(self):
        engine = SignatureEngine(
            self.database,
            signatures=self._signatures(
                match={
                    "protocol": "TCP",
                    "any": [
                        {"dst_port": 445},
                        {"dst_port": 389},
                        {"dst_port": 636},
                    ],
                },
                aggregate={"count": {"gte": 2}, "within_seconds": 60},
            ),
        )

        engine.process_packet(self._packet(0, protocol="UDP", dst_port=445))
        engine.process_packet(self._packet(1, protocol="TCP", dst_port=389))
        engine.process_packet(self._packet(2, protocol="TCP", dst_port=636))

        self.assertEqual(self.database.count_alerts(), 1)

    def test_or_logic_parses_from_yaml(self):
        parsed = SignatureEngine.parse(
            "signatures:\n"
            "  - name: LDAP Any\n"
            "    enabled: true\n"
            "    event: packet\n"
            "    match:\n"
            "      protocol: TCP\n"
            "      any:\n"
            "        - dst_port: 389\n"
            "        - dst_port: 636\n"
            "    aggregate:\n"
            "      count:\n"
            "        gte: 2\n"
            "      within_seconds: 60\n"
            "    alert:\n"
            "      severity: Medium\n"
            "      title: LDAP Any\n"
            "      description: LDAP any match.\n"
        )

        self.assertEqual(parsed["signatures"][0]["match"]["any"][0]["dst_port"], 389)

    def test_all_logic_requires_every_clause(self):
        engine = SignatureEngine(
            self.database,
            signatures=self._signatures(
                match={
                    "all": [
                        {"protocol": "TCP"},
                        {"dst_port": 445},
                    ],
                },
                aggregate={"count": {"gte": 2}, "within_seconds": 60},
            ),
        )

        engine.process_packet(self._packet(0, protocol="TCP", dst_port=80))
        engine.process_packet(self._packet(1, protocol="TCP", dst_port=445))
        engine.process_packet(self._packet(2, protocol="TCP", dst_port=445))

        self.assertEqual(self.database.count_alerts(), 1)

    def test_group_by_destination_tracks_aggregates_per_destination(self):
        engine = SignatureEngine(
            self.database,
            signatures=self._signatures(
                group_by="dst_ip",
                aggregate={"unique_dst_ports": {"gte": 2}, "within_seconds": 60},
            ),
        )

        engine.process_packet(self._packet(0, dst_ip="10.0.0.1", dst_port=80))
        engine.process_packet(self._packet(1, dst_ip="10.0.0.2", dst_port=80))
        self.assertEqual(self.database.count_alerts(), 0)

        engine.process_packet(self._packet(2, dst_ip="10.0.0.1", dst_port=443))
        self.assertEqual(self.database.count_alerts(), 1)

    def test_group_by_source_keeps_aggregates_independent(self):
        engine = SignatureEngine(
            self.database,
            signatures=self._signatures(
                group_by="src_ip",
                aggregate={"unique_dst_ports": {"gte": 2}, "within_seconds": 60},
            ),
        )

        engine.process_packet(self._packet(0, src_ip="10.0.0.10", dst_port=80))
        engine.process_packet(self._packet(1, src_ip="10.0.0.11", dst_port=443))
        self.assertEqual(self.database.count_alerts(), 0)

        engine.process_packet(self._packet(2, src_ip="10.0.0.10", dst_port=443))
        self.assertEqual(self.database.count_alerts(), 1)

    def test_group_by_validation_rejects_unknown_values(self):
        with self.assertRaises(SignatureValidationError) as context:
            SignatureEngine.parse(
                "signatures:\n"
                "  - name: Bad Group\n"
                "    enabled: true\n"
                "    event: packet\n"
                "    group_by: client_ip\n"
                "    aggregate:\n"
                "      count:\n"
                "        gte: 2\n"
                "      within_seconds: 60\n"
                "    alert:\n"
                "      severity: Medium\n"
                "      title: Bad Group\n"
                "      description: Bad group.\n"
            )

        self.assertIn("group_by must be one of", str(context.exception))

    def test_tags_are_optional_metadata_on_compiled_rules(self):
        engine = SignatureEngine(
            self.database,
            signatures=self._signatures(tags=["recon", "smb", "mitre:T1595"]),
        )

        self.assertEqual(engine.rules[0].tags, ["recon", "smb", "mitre:T1595"])

    def test_exclude_source_ip_prevents_aggregation_for_rule(self):
        engine = SignatureEngine(
            self.database,
            signatures=self._signatures(
                exclude={"src_ip": ["10.0.0.10"]},
                aggregate={"count": {"gte": 2}, "within_seconds": 60},
            ),
        )

        engine.process_packet(self._packet(0, src_ip="10.0.0.10"))
        engine.process_packet(self._packet(1, src_ip="10.0.0.10"))
        engine.process_packet(self._packet(2, src_ip="10.0.0.20"))
        engine.process_packet(self._packet(3, src_ip="10.0.0.20"))

        self.assertEqual(self.database.count_alerts(), 1)
        self.assertEqual(len(engine.rules[0].events_by_key["10.0.0.10"]), 0)

    def test_exclude_destination_ip_prevents_aggregation_for_rule(self):
        engine = SignatureEngine(
            self.database,
            signatures=self._signatures(
                exclude={"dst_ip": ["10.0.0.1"]},
                aggregate={"count": {"gte": 2}, "within_seconds": 60},
            ),
        )

        engine.process_packet(self._packet(0, dst_ip="10.0.0.1"))
        engine.process_packet(self._packet(1, dst_ip="10.0.0.1"))
        engine.process_packet(self._packet(2, dst_ip="10.0.0.2"))
        engine.process_packet(self._packet(3, dst_ip="10.0.0.2"))

        self.assertEqual(self.database.count_alerts(), 1)

    def test_exclude_network_prevents_aggregation_for_rule(self):
        engine = SignatureEngine(
            self.database,
            signatures=self._signatures(
                exclude={"dst_ip": ["10.0.0.0/24"]},
                aggregate={"count": {"gte": 2}, "within_seconds": 60},
            ),
        )

        engine.process_packet(self._packet(0, dst_ip="10.0.0.10"))
        engine.process_packet(self._packet(1, dst_ip="10.0.0.11"))
        engine.process_packet(self._packet(2, dst_ip="10.0.1.10"))
        engine.process_packet(self._packet(3, dst_ip="10.0.1.10"))

        self.assertEqual(self.database.count_alerts(), 1)

    def test_exclude_ports_prevent_aggregation_for_rule(self):
        engine = SignatureEngine(
            self.database,
            signatures=self._signatures(
                match={"protocol": "TCP"},
                exclude={"dst_port": [5985], "src_port": [53]},
                aggregate={"count": {"gte": 2}, "within_seconds": 60},
            ),
        )

        engine.process_packet(self._packet(0, dst_port=5985))
        engine.process_packet(self._packet(1, dst_port=443, src_port=53))
        engine.process_packet(self._packet(2, dst_port=5986))
        engine.process_packet(self._packet(3, dst_port=5986))

        self.assertEqual(self.database.count_alerts(), 1)

    def test_exclude_is_rule_specific(self):
        signatures = {
            "signatures": [
                self._signature(
                    name="Excluded Rule",
                    exclude={"dst_ip": ["10.0.0.1"]},
                    aggregate={"count": {"gte": 2}, "within_seconds": 60},
                ),
                self._signature(
                    name="Active Rule",
                    aggregate={"count": {"gte": 2}, "within_seconds": 60},
                ),
            ]
        }
        engine = SignatureEngine(self.database, signatures=signatures)

        engine.process_packet(self._packet(0, dst_ip="10.0.0.1"))
        engine.process_packet(self._packet(1, dst_ip="10.0.0.1"))

        alerts = self.database.get_alerts()
        self.assertEqual(len(alerts), 1)
        self.assertEqual(alerts[0]["title"], "Active Rule")

    def test_exclude_parses_from_yaml_and_is_preserved_on_save(self):
        parsed = SignatureEngine.parse(
            "signatures:\n"
            "  - name: WinRM Activity\n"
            "    enabled: true\n"
            "    event: packet\n"
            "    match:\n"
            "      protocol: TCP\n"
            "      dst_port:\n"
            "        in:\n"
            "          - 5985\n"
            "          - 5986\n"
            "    exclude:\n"
            "      dst_ip:\n"
            "        - 10.0.2.13\n"
            "      src_ip:\n"
            "        - 10.0.2.0/24\n"
            "      dst_port:\n"
            "        - 5985\n"
            "    aggregate:\n"
            "      count:\n"
            "        gte: 20\n"
            "      within_seconds: 60\n"
            "    alert:\n"
            "      severity: High\n"
            "      title: WinRM Activity Detected\n"
            "      description: Significant WinRM traffic observed.\n"
        )
        saved = SignatureEngine.to_yaml(parsed)

        self.assertEqual(parsed["signatures"][0]["exclude"]["dst_ip"], ["10.0.2.13"])
        self.assertIn("exclude:", saved)
        self.assertIn("10.0.2.0/24", saved)

    def test_exclude_validation_rejects_unknown_fields(self):
        with self.assertRaises(SignatureValidationError) as context:
            SignatureEngine.parse(
                "signatures:\n"
                "  - name: Bad Exclude\n"
                "    enabled: true\n"
                "    event: packet\n"
                "    exclude:\n"
                "      query_name:\n"
                "        - example.com\n"
                "    aggregate:\n"
                "      count:\n"
                "        gte: 1\n"
                "      within_seconds: 60\n"
                "    alert:\n"
                "      severity: Medium\n"
                "      title: Bad Exclude\n"
                "      description: Bad exclude.\n"
            )

        self.assertIn("Unknown exclude field", str(context.exception))

    def test_exclude_validation_rejects_invalid_networks(self):
        with self.assertRaises(SignatureValidationError) as context:
            SignatureEngine.parse(
                "signatures:\n"
                "  - name: Bad Network\n"
                "    enabled: true\n"
                "    event: packet\n"
                "    exclude:\n"
                "      dst_ip:\n"
                "        - not-a-network\n"
                "    aggregate:\n"
                "      count:\n"
                "        gte: 1\n"
                "      within_seconds: 60\n"
                "    alert:\n"
                "      severity: Medium\n"
                "      title: Bad Network\n"
                "      description: Bad network.\n"
            )

        self.assertIn("Invalid exclude IP or network", str(context.exception))

    def test_rule_statistics_track_hits_alerts_and_last_triggered(self):
        engine = SignatureEngine(
            self.database,
            signatures=self._signatures(
                aggregate={"count": {"gte": 1}, "within_seconds": 60},
                cooldown_seconds=300,
            ),
        )

        engine.process_packet(self._packet(0))
        engine.process_packet(self._packet(1))
        engine.process_packet(self._packet(2))
        stats = self.database.get_rule_stats()[0]

        self.assertEqual(stats["rule_name"], "Test Signature")
        self.assertEqual(stats["hits"], 3)
        self.assertEqual(stats["alerts_generated"], 1)
        self.assertEqual(stats["last_triggered"], self._packet(2)["timestamp"])

    def test_rule_packs_load_all_yaml_files(self):
        rules_dir = Path(self.temp_dir.name) / "rules"
        rules_dir.mkdir()
        (rules_dir / "recon.yaml").write_text(
            "signatures:\n"
            "  - name: Pack Recon\n"
            "    enabled: true\n"
            "    event: packet\n"
            "    tags:\n"
            "      - recon\n"
            "    aggregate:\n"
            "      count:\n"
            "        gte: 1\n"
            "      within_seconds: 60\n"
            "    alert:\n"
            "      severity: Medium\n"
            "      title: Pack Recon\n"
            "      description: Pack recon.\n",
            encoding="utf-8",
        )
        (rules_dir / "dns.yaml").write_text("signatures:\n", encoding="utf-8")

        engine = SignatureEngine(
            self.database,
            rules_dir=rules_dir,
        )

        rule_names = [rule.name for rule in engine.rules]
        self.assertIn("Pack Recon", rule_names)
        self.assertEqual(engine.rules[0].rule_pack, "recon.yaml")

    def test_all_empty_rule_packs_are_allowed(self):
        rules_dir = Path(self.temp_dir.name) / "rules"
        rules_dir.mkdir()
        for file_name in SignatureEngine.RULE_PACK_NAMES:
            (rules_dir / file_name).write_text("signatures:\n", encoding="utf-8")

        engine = SignatureEngine(self.database, rules_dir=rules_dir)

        self.assertEqual(engine.rules, [])

    def test_legacy_signatures_yaml_with_rules_fails_startup(self):
        rules_dir = Path(self.temp_dir.name) / "rules"
        rules_dir.mkdir()
        for file_name in SignatureEngine.RULE_PACK_NAMES:
            (rules_dir / file_name).write_text("signatures:\n", encoding="utf-8")
        legacy_path = Path(self.temp_dir.name) / "signatures.yaml"
        legacy_path.write_text(
            "signatures:\n"
            "  - name: Legacy Rule\n"
            "    enabled: true\n"
            "    event: packet\n"
            "    aggregate:\n"
            "      count:\n"
            "        gte: 1\n"
            "      within_seconds: 60\n"
            "    alert:\n"
            "      severity: Medium\n"
            "      title: Legacy Rule\n"
            "      description: Legacy rule.\n",
            encoding="utf-8",
        )
        original_cwd = Path.cwd()

        try:
            import os

            os.chdir(self.temp_dir.name)
            with self.assertRaises(SignatureValidationError) as context:
                SignatureEngine(self.database, rules_dir=rules_dir)
        finally:
            os.chdir(original_cwd)

        self.assertIn("Legacy signatures.yaml contains rules", str(context.exception))

    def test_signature_engine_inventory_lists_rule_packs_only(self):
        rules_dir = Path(self.temp_dir.name) / "rules"
        rules_dir.mkdir()
        (rules_dir / "recon.yaml").write_text(SignatureEngine.default_yaml(), encoding="utf-8")
        output = StringIO()

        with redirect_stdout(output):
            engine = SignatureEngine(
                self.database,
                rules_dir=rules_dir,
            )

        text = output.getvalue()
        self.assertIn("Legacy Signatures:", text)
        self.assertIn("* 0 rules loaded", text)
        self.assertIn("Rule Packs:", text)
        self.assertIn("* recon.yaml (1)", text)
        inventory = {
            rule_pack["path"]: rule_pack["count"]
            for rule_pack in engine.source_inventory["rule_packs"]
        }
        self.assertEqual(inventory["recon.yaml"], 1)

    def test_cooldown_validation_rejects_non_positive_values(self):
        with self.assertRaises(SignatureValidationError) as context:
            SignatureEngine.parse(
                "signatures:\n"
                "  - name: Bad Cooldown\n"
                "    enabled: true\n"
                "    event: packet\n"
                "    cooldown_seconds: 0\n"
                "    aggregate:\n"
                "      count:\n"
                "        gte: 2\n"
                "      within_seconds: 60\n"
                "    alert:\n"
                "      severity: Medium\n"
                "      title: Bad Cooldown\n"
                "      description: Bad cooldown.\n"
            )

        self.assertIn("cooldown_seconds must be a positive integer", str(context.exception))

    def test_any_validation_rejects_unknown_fields(self):
        with self.assertRaises(SignatureValidationError) as context:
            SignatureEngine.parse(
                "signatures:\n"
                "  - name: Bad Any\n"
                "    enabled: true\n"
                "    event: packet\n"
                "    match:\n"
                "      any:\n"
                "        - unique_potatoes: 1\n"
                "    aggregate:\n"
                "      count:\n"
                "        gte: 2\n"
                "      within_seconds: 60\n"
                "    alert:\n"
                "      severity: Medium\n"
                "      title: Bad Any\n"
                "      description: Bad any.\n"
            )

        self.assertIn("Unknown match field 'unique_potatoes'", str(context.exception))

    def test_rule_validation_failures_are_human_readable(self):
        with self.assertRaises(SignatureValidationError) as context:
            SignatureEngine.parse(
                "signatures:\n"
                "  - name: Broken\n"
                "    enabled: true\n"
                "    event: packet\n"
                "    aggregate:\n"
                "      unique_potatoes:\n"
                "        potato: 2\n"
                "      within_seconds: 60\n"
                "    alert:\n"
                "      severity: Medium\n"
                "      title: Broken\n"
                "      description: Broken\n"
            )

        self.assertIn("Rule 'Broken'", str(context.exception))
        self.assertIn("Unknown aggregate", str(context.exception))

    def test_missing_alert_section_is_rejected(self):
        with self.assertRaises(SignatureValidationError) as context:
            SignatureEngine.parse(
                "signatures:\n"
                "  - name: Missing Alert\n"
                "    enabled: true\n"
                "    event: packet\n"
                "    aggregate:\n"
                "      count:\n"
                "        gte: 2\n"
                "      within_seconds: 60\n"
            )

        self.assertIn("Missing alert section", str(context.exception))

    def test_unknown_aggregate_operator_is_rejected(self):
        with self.assertRaises(SignatureValidationError) as context:
            SignatureEngine.parse(
                "signatures:\n"
                "  - name: Bad Operator\n"
                "    enabled: true\n"
                "    event: packet\n"
                "    aggregate:\n"
                "      count:\n"
                "        potato: 2\n"
                "      within_seconds: 60\n"
                "    alert:\n"
                "      severity: Medium\n"
                "      title: Bad Operator\n"
                "      description: Bad Operator\n"
            )

        self.assertIn("Unknown aggregate operator 'potato'", str(context.exception))

    def test_alert_generation_uses_signature_alert_fields(self):
        engine = SignatureEngine(
            self.database,
            signatures=self._signatures(
                alert={
                    "severity": "High",
                    "title": "SMB Recon Activity",
                    "description": "Source contacted many hosts via SMB.",
                },
                aggregate={"count": {"gte": 1}, "within_seconds": 60},
            ),
        )

        engine.process_packet(self._packet(0))
        alert = self.database.get_alerts()[0]

        self.assertEqual(alert["severity"], "High")
        self.assertEqual(alert["title"], "SMB Recon Activity")
        self.assertEqual(alert["description"], "Source contacted many hosts via SMB.")
        self.assertEqual(alert["source_ip"], "10.0.0.10")
        self.assertEqual(alert["destination_ip"], "10.0.0.1")
        context = json.loads(alert["context_json"])
        self.assertEqual(context["rule"]["name"], "Test Signature")
        self.assertEqual(context["rule"]["pack"], "rules/*.yaml")
        self.assertEqual(context["rule"]["thresholds"]["count"], 1)
        self.assertEqual(context["evidence"]["observed"]["count"], 1)
        self.assertEqual(context["evidence"]["window_seconds"], 60)

    def test_group_by_source_sets_alert_source_and_context(self):
        engine = SignatureEngine(
            self.database,
            signatures=self._signatures(
                group_by="src_ip",
                aggregate={"unique_dst_ips": {"gte": 2}, "within_seconds": 60},
            ),
        )

        engine.process_packet(self._packet(0, src_ip="10.0.0.20", dst_ip="10.0.0.1"))
        engine.process_packet(self._packet(1, src_ip="10.0.0.20", dst_ip="10.0.0.2"))
        alert = self.database.get_alerts()[0]
        context = json.loads(alert["context_json"])

        self.assertEqual(alert["source_ip"], "10.0.0.20")
        self.assertIsNone(alert["destination_ip"])
        self.assertEqual(context["rule"]["name"], "Test Signature")
        self.assertEqual(context["rule"]["pack"], "rules/*.yaml")
        self.assertEqual(context["rule"]["thresholds"]["unique_dst_ips"], 2)
        self.assertEqual(context["evidence"]["observed"]["group_by"], "src_ip")
        self.assertEqual(context["evidence"]["observed"]["unique_dst_ips"], 2)

    def test_group_by_destination_sets_alert_destination_and_context(self):
        engine = SignatureEngine(
            self.database,
            signatures=self._signatures(
                group_by="dst_ip",
                aggregate={"unique_dst_ports": {"gte": 2}, "within_seconds": 60},
            ),
        )

        engine.process_packet(self._packet(0, dst_ip="10.0.0.50", dst_port=5985))
        engine.process_packet(self._packet(1, dst_ip="10.0.0.50", dst_port=5986))
        alert = self.database.get_alerts()[0]
        context = json.loads(alert["context_json"])

        self.assertIsNone(alert["source_ip"])
        self.assertEqual(alert["destination_ip"], "10.0.0.50")
        self.assertEqual(context["rule"]["name"], "Test Signature")
        self.assertEqual(context["rule"]["pack"], "rules/*.yaml")
        self.assertEqual(context["rule"]["thresholds"]["unique_dst_ports"], 2)
        self.assertEqual(context["evidence"]["observed"]["group_by"], "dst_ip")
        self.assertEqual(context["evidence"]["observed"]["unique_dst_ports"], 2)

    def test_disabled_rules_do_not_run(self):
        engine = SignatureEngine(
            self.database,
            signatures=self._signatures(
                enabled=False,
                aggregate={"count": {"gte": 1}, "within_seconds": 60},
            ),
        )

        engine.process_packet(self._packet(0))

        self.assertEqual(engine.rules, [])
        self.assertEqual(self.database.count_alerts(), 0)

    def test_rules_pack_editor_validates_before_saving(self):
        rules_dir = Path(self.temp_dir.name) / "rules"
        rules_dir.mkdir()
        recon_path = rules_dir / "recon.yaml"
        recon_path.write_text(SignatureEngine.default_yaml(), encoding="utf-8")
        app = create_app(
            Path(self.temp_dir.name) / "dashboard.sqlite",
            rule_packs_path=rules_dir,
        )
        invalid_text = (
            "signatures:\n"
            "  - name: Broken\n"
            "    enabled: true\n"
            "    event: packet\n"
            "    match:\n"
            "      unique_potatoes: 1\n"
            "    aggregate:\n"
            "      count:\n"
            "        gte: 1\n"
            "      within_seconds: 60\n"
            "    alert:\n"
            "      severity: Medium\n"
            "      title: Broken\n"
            "      description: Broken\n"
        )

        response = app.test_client().post(
            "/rules/save",
            data={"pack": "recon", "pack_yaml": invalid_text},
        )

        self.assertEqual(response.status_code, 200)
        self.assertIn("Unknown match field", response.get_data(as_text=True))
        self.assertEqual(recon_path.read_text(encoding="utf-8"), SignatureEngine.default_yaml())

    def test_rules_page_shows_packs_summary_and_validation_status(self):
        rules_dir = Path(self.temp_dir.name) / "rules"
        rules_dir.mkdir()
        (rules_dir / "recon.yaml").write_text(
            "signatures:\n"
            "  - name: Enabled Rule\n"
            "    enabled: true\n"
            "    event: packet\n"
            "    aggregate:\n"
            "      count:\n"
            "        gte: 1\n"
            "      within_seconds: 60\n"
            "    alert:\n"
            "      severity: Medium\n"
            "      title: Enabled\n"
            "      description: Enabled\n"
            "  - name: Disabled Rule\n"
            "    enabled: false\n"
            "    event: packet\n"
            "    aggregate:\n"
            "      count:\n"
            "        gte: 1\n"
            "      within_seconds: 60\n"
            "    alert:\n"
            "      severity: Low\n"
            "      title: Disabled\n"
            "      description: Disabled\n",
            encoding="utf-8",
        )
        app = create_app(
            Path(self.temp_dir.name) / "dashboard.sqlite",
            rule_packs_path=rules_dir,
        )

        response = app.test_client().get("/rules?pack=recon")
        html = response.get_data(as_text=True)

        self.assertEqual(response.status_code, 200)
        self.assertIn("Rule Management", html)
        self.assertIn("Total Rules", html)
        self.assertIn(">2<", html)
        self.assertIn("Recon valid", html)
        self.assertIn("Enabled Rule", html)
        self.assertIn("Disabled Rule", html)
        self.assertIn('id="rule-editor"', html)
        self.assertIn('name="pack_yaml"', html)
        self.assertIn("Format YAML", html)
        self.assertIn("Insert template", html)

    def test_rules_routes_resolve_relative_rule_pack_dir_from_config_path(self):
        deploy_root = Path(self.temp_dir.name) / "opt" / "Excalibur"
        deploy_root.mkdir(parents=True)
        config_path = deploy_root / "config.yaml"
        config_path.write_text("general:\n  timezone: Asia/Amman\n", encoding="utf-8")
        rules_dir = deploy_root / "rules"
        rules_dir.mkdir()
        recon_path = rules_dir / "recon.yaml"
        recon_path.write_text(SignatureEngine.default_yaml(), encoding="utf-8")
        db_path = deploy_root / "dashboard.sqlite"
        app = create_app(
            db_path,
            config_path=config_path,
            rule_packs_path="rules",
        )

        export_response = app.test_client().get("/rules/export/recon")

        self.assertEqual(export_response.status_code, 200)
        self.assertEqual(export_response.get_data(as_text=True), SignatureEngine.default_yaml())

        imported_text = SignatureEngine.default_yaml().replace("SMB Recon", "Deployed Recon")
        import_response = app.test_client().post(
            "/rules/import",
            data={
                "pack": "recon",
                "pack_file": (BytesIO(imported_text.encode("utf-8")), "recon.yaml"),
            },
            content_type="multipart/form-data",
        )

        self.assertEqual(import_response.status_code, 302)
        self.assertEqual(recon_path.read_text(encoding="utf-8"), imported_text)

    def test_rules_page_displays_invalid_pack_without_crashing(self):
        rules_dir = Path(self.temp_dir.name) / "rules"
        rules_dir.mkdir()
        (rules_dir / "recon.yaml").write_text(
            "signatures:\n"
            "  - name: Broken Rule\n"
            "    enabled: true\n"
            "    event: packet\n"
            "    aggregate:\n"
            "      unique_potatoes:\n"
            "        gte: 1\n"
            "      within_seconds: 60\n"
            "    alert:\n"
            "      severity: Medium\n"
            "      title: Broken\n"
            "      description: Broken.\n",
            encoding="utf-8",
        )
        app = create_app(
            Path(self.temp_dir.name) / "dashboard.sqlite",
            rule_packs_path=rules_dir,
        )

        response = app.test_client().get("/rules?pack=recon")
        html = response.get_data(as_text=True)

        self.assertEqual(response.status_code, 200)
        self.assertIn("Validation failed", html)
        self.assertIn("Unknown aggregate", html)

    def test_rules_save_route_persists_valid_pack_yaml(self):
        rules_dir = Path(self.temp_dir.name) / "rules"
        rules_dir.mkdir()
        recon_path = rules_dir / "recon.yaml"
        recon_path.write_text(SignatureEngine.default_yaml(), encoding="utf-8")
        app = create_app(
            Path(self.temp_dir.name) / "dashboard.sqlite",
            rule_packs_path=rules_dir,
        )
        valid_text = SignatureEngine.default_yaml().replace("SMB Recon", "SMB Recon Updated")

        response = app.test_client().post(
            "/rules/save",
            data={"pack": "recon", "pack_yaml": valid_text},
        )

        self.assertEqual(response.status_code, 302)
        self.assertEqual(recon_path.read_text(encoding="utf-8"), valid_text)

    def test_rules_export_route_downloads_selected_pack_yaml(self):
        rules_dir = Path(self.temp_dir.name) / "rules"
        rules_dir.mkdir()
        recon_path = rules_dir / "recon.yaml"
        recon_path.write_text(SignatureEngine.default_yaml(), encoding="utf-8")
        app = create_app(
            Path(self.temp_dir.name) / "dashboard.sqlite",
            rule_packs_path=rules_dir,
        )

        response = app.test_client().get("/rules/export/recon")

        self.assertEqual(response.status_code, 200)
        self.assertIn("attachment; filename=recon.yaml", response.headers["Content-Disposition"])
        self.assertEqual(response.get_data(as_text=True), SignatureEngine.default_yaml())

    def test_rules_import_route_persists_valid_pack_yaml(self):
        rules_dir = Path(self.temp_dir.name) / "rules"
        rules_dir.mkdir()
        recon_path = rules_dir / "recon.yaml"
        recon_path.write_text(SignatureEngine.default_yaml(), encoding="utf-8")
        app = create_app(
            Path(self.temp_dir.name) / "dashboard.sqlite",
            rule_packs_path=rules_dir,
        )
        valid_text = SignatureEngine.default_yaml().replace("SMB Recon", "Imported Recon")

        response = app.test_client().post(
            "/rules/import",
            data={
                "pack": "recon",
                "pack_file": (BytesIO(valid_text.encode("utf-8")), "recon.yaml"),
            },
            content_type="multipart/form-data",
        )

        self.assertEqual(response.status_code, 302)
        self.assertIn("/rules?pack=recon&imported=1", response.headers["Location"])
        self.assertEqual(recon_path.read_text(encoding="utf-8"), valid_text)

    def test_rules_import_route_rejects_invalid_yaml(self):
        rules_dir = Path(self.temp_dir.name) / "rules"
        rules_dir.mkdir()
        recon_path = rules_dir / "recon.yaml"
        recon_path.write_text(SignatureEngine.default_yaml(), encoding="utf-8")
        app = create_app(
            Path(self.temp_dir.name) / "dashboard.sqlite",
            rule_packs_path=rules_dir,
        )
        invalid_text = (
            "signatures:\n"
            "  - name: Broken\n"
            "    enabled: true\n"
            "    event: packet\n"
            "    match:\n"
            "      unique_potatoes: 1\n"
            "    aggregate:\n"
            "      count:\n"
            "        gte: 1\n"
            "      within_seconds: 60\n"
            "    alert:\n"
            "      severity: Medium\n"
            "      title: Broken\n"
            "      description: Broken\n"
        )

        response = app.test_client().post(
            "/rules/import",
            data={
                "pack": "recon",
                "pack_file": (BytesIO(invalid_text.encode("utf-8")), "recon.yaml"),
            },
            content_type="multipart/form-data",
        )

        self.assertEqual(response.status_code, 200)
        self.assertIn("Unknown match field", response.get_data(as_text=True))
        self.assertEqual(recon_path.read_text(encoding="utf-8"), SignatureEngine.default_yaml())

    def test_rules_format_route_returns_formatted_yaml(self):
        rules_dir = Path(self.temp_dir.name) / "rules"
        rules_dir.mkdir()
        app = create_app(
            Path(self.temp_dir.name) / "dashboard.sqlite",
            rule_packs_path=rules_dir,
        )
        inflated_text = (
            "signatures:\n"
            "\n"
            "  - name: SMB Recon\n"
            "\n"
            "    enabled: true\n"
            "\n"
            "    event: packet\n"
            "\n"
            "    match:\n"
            "\n"
            "      protocol: TCP\n"
            "\n"
            "      dst_port: 445\n"
            "\n"
            "    aggregate:\n"
            "\n"
            "      unique_dst_ips:\n"
            "\n"
            "        gte: 20\n"
            "\n"
            "      within_seconds: 60\n"
            "\n"
            "    alert:\n"
            "\n"
            "      severity: High\n"
            "\n"
            "      title: SMB Recon Activity\n"
            "\n"
            "      description: Source contacted many hosts via SMB.\n"
        )

        response = app.test_client().post(
            "/rules/format",
            data={"pack": "recon", "pack_yaml": inflated_text},
        )
        payload = response.get_json()

        self.assertEqual(response.status_code, 200)
        self.assertTrue(payload["ok"])
        self.assertEqual(payload["formatted"], SignatureEngine.default_yaml())

    def test_rules_format_route_rejects_invalid_yaml(self):
        rules_dir = Path(self.temp_dir.name) / "rules"
        rules_dir.mkdir()
        app = create_app(
            Path(self.temp_dir.name) / "dashboard.sqlite",
            rule_packs_path=rules_dir,
        )

        response = app.test_client().post(
            "/rules/format",
            data={
                "pack": "recon",
                "pack_yaml": (
                    "signatures:\n"
                    "  - name: Broken\n"
                    "    enabled: true\n"
                    "    event: packet\n"
                    "    match:\n"
                    "      unique_potatoes: 1\n"
                    "    aggregate:\n"
                    "      count:\n"
                    "        gte: 1\n"
                    "      within_seconds: 60\n"
                    "    alert:\n"
                    "      severity: Medium\n"
                    "      title: Broken\n"
                    "      description: Broken\n"
                ),
            },
        )
        payload = response.get_json()

        self.assertEqual(response.status_code, 400)
        self.assertFalse(payload["ok"])
        self.assertIn("Unknown match field", payload["error"])

    def test_signature_save_formatting_is_stable(self):
        rules_dir = Path(self.temp_dir.name) / "rules"
        rules_dir.mkdir()
        recon_path = rules_dir / "recon.yaml"
        inflated_text = (
            "signatures:\n"
            "\n"
            "  - name: SMB Recon\n"
            "\n"
            "    enabled: true\n"
            "\n"
            "    event: packet\n"
            "\n"
            "    match:\n"
            "\n"
            "      protocol: TCP\n"
            "\n"
            "      dst_port: 445\n"
            "\n"
            "    aggregate:\n"
            "\n"
            "      unique_dst_ips:\n"
            "\n"
            "        gte: 20\n"
            "\n"
            "      within_seconds: 60\n"
            "\n"
            "    alert:\n"
            "\n"
            "      severity: High\n"
            "\n"
            "      title: SMB Recon Activity\n"
            "\n"
            "      description: Source contacted many hosts via SMB.\n"
        )
        recon_path.write_text(inflated_text, encoding="utf-8")
        app = create_app(
            Path(self.temp_dir.name) / "dashboard.sqlite",
            rule_packs_path=rules_dir,
        )
        client = app.test_client()

        loaded_text = client.get("/rules?pack=recon").get_data(as_text=True)
        self.assertIn("SMB Recon", loaded_text)
        client.post("/rules/save", data={"pack": "recon", "pack_yaml": inflated_text})
        first_saved = recon_path.read_text(encoding="utf-8")
        reloaded_text = recon_path.read_text(encoding="utf-8")
        client.post("/rules/save", data={"pack": "recon", "pack_yaml": reloaded_text})
        second_saved = recon_path.read_text(encoding="utf-8")

        self.assertEqual(first_saved, SignatureEngine.default_yaml())
        self.assertEqual(second_saved, first_saved)
        self.assertNotIn("\n\n", second_saved)

    def test_rules_toggle_updates_pack_yaml(self):
        rules_dir = Path(self.temp_dir.name) / "rules"
        rules_dir.mkdir()
        recon_path = rules_dir / "recon.yaml"
        recon_path.write_text(SignatureEngine.default_yaml(), encoding="utf-8")
        app = create_app(
            Path(self.temp_dir.name) / "dashboard.sqlite",
            rule_packs_path=rules_dir,
        )

        response = app.test_client().post(
            "/rules/toggle/recon/0",
            follow_redirects=True,
        )
        parsed = SignatureEngine.parse(recon_path.read_text(encoding="utf-8"))
        html = response.get_data(as_text=True)

        self.assertEqual(response.status_code, 200)
        self.assertFalse(parsed["signatures"][0]["enabled"])
        self.assertIn("Rule updated. Restart sensor for changes to take effect.", html)
        self.assertIn("Restart Sensor", html)

    def test_rules_toggle_enables_rule_and_marks_restart_required(self):
        rules_dir = Path(self.temp_dir.name) / "rules"
        rules_dir.mkdir()
        recon_path = rules_dir / "recon.yaml"
        parsed = SignatureEngine.parse(SignatureEngine.default_yaml())
        parsed["signatures"][0]["enabled"] = False
        recon_path.write_text(SignatureEngine.to_yaml(parsed), encoding="utf-8")
        app = create_app(
            Path(self.temp_dir.name) / "dashboard.sqlite",
            rule_packs_path=rules_dir,
        )

        response = app.test_client().post(
            "/rules/toggle/recon/0",
            follow_redirects=True,
        )
        updated = SignatureEngine.parse(recon_path.read_text(encoding="utf-8"))
        html = response.get_data(as_text=True)

        self.assertEqual(response.status_code, 200)
        self.assertTrue(updated["signatures"][0]["enabled"])
        self.assertIn("Rule updated. Restart sensor for changes to take effect.", html)
        self.assertIn("Restart Sensor", html)

    def test_rule_detail_page_shows_runtime_metadata_and_yaml(self):
        rules_dir = Path(self.temp_dir.name) / "rules"
        rules_dir.mkdir()
        (rules_dir / "recon.yaml").write_text(SignatureEngine.default_yaml(), encoding="utf-8")
        db_path = Path(self.temp_dir.name) / "dashboard.sqlite"
        database = Database(db_path)
        database.record_rule_hit("SMB Recon", "2026-06-09T10:00:00+00:00")
        database.record_rule_alert("SMB Recon", "2026-06-09T10:00:00+00:00")
        database.close()
        app = create_app(db_path, rule_packs_path=rules_dir)

        response = app.test_client().get("/rules/recon/0")
        html = response.get_data(as_text=True)

        self.assertEqual(response.status_code, 200)
        self.assertIn("SMB Recon", html)
        self.assertIn("High", html)
        self.assertIn("Hits", html)
        self.assertIn("Rule YAML", html)

    def test_dashboard_shows_rules_summary_widget(self):
        rules_dir = Path(self.temp_dir.name) / "rules"
        rules_dir.mkdir()
        (rules_dir / "recon.yaml").write_text(SignatureEngine.default_yaml(), encoding="utf-8")
        db_path = Path(self.temp_dir.name) / "dashboard.sqlite"
        database = Database(db_path)
        database.record_rule_hit("SMB Recon", "2026-06-09T10:00:00+00:00")
        database.close()
        app = create_app(db_path, rule_packs_path=rules_dir)

        response = app.test_client().get("/")
        html = response.get_data(as_text=True)

        self.assertEqual(response.status_code, 200)
        self.assertIn("Top Triggered Rules", html)
        self.assertIn("Most Active Detections", html)
        self.assertIn("SMB Recon", html)

    def test_legacy_settings_signatures_route_redirects(self):
        app = create_app(Path(self.temp_dir.name) / "dashboard.sqlite")

        response = app.test_client().get("/settings/signatures")

        self.assertEqual(response.status_code, 302)
        self.assertIn("/rules", response.headers["Location"])

    def test_legacy_signatures_route_redirects_to_rules(self):
        app = create_app(Path(self.temp_dir.name) / "dashboard.sqlite")

        response = app.test_client().get("/signatures")

        self.assertEqual(response.status_code, 302)
        self.assertIn("/rules", response.headers["Location"])

    def _signatures(
        self,
        match=None,
        aggregate=None,
        event="packet",
        enabled=True,
        alert=None,
        cooldown_seconds=None,
        group_by=None,
        tags=None,
        exclude=None,
    ):
        return {
            "signatures": [
                self._signature(
                    name="Test Signature",
                    match=match,
                    aggregate=aggregate,
                    event=event,
                    enabled=enabled,
                    alert=alert,
                    cooldown_seconds=cooldown_seconds,
                    group_by=group_by,
                    tags=tags,
                    exclude=exclude,
                )
            ]
        }

    def _signature(
        self,
        name="Test Signature",
        match=None,
        aggregate=None,
        event="packet",
        enabled=True,
        alert=None,
        cooldown_seconds=None,
        group_by=None,
        tags=None,
        exclude=None,
    ):
        signature = {
            "name": name,
            "enabled": enabled,
            "event": event,
            "match": match or {},
            "aggregate": aggregate or {"count": {"gte": 1}, "within_seconds": 60},
            "alert": alert
            or {
                "severity": "Medium",
                "title": name,
                "description": "Synthetic signature alert.",
            },
        }
        if cooldown_seconds is not None:
            signature["cooldown_seconds"] = cooldown_seconds
        if group_by is not None:
            signature["group_by"] = group_by
        if tags is not None:
            signature["tags"] = tags
        if exclude is not None:
            signature["exclude"] = exclude
        return signature

    def _packet(
        self,
        seconds,
        src_ip="10.0.0.10",
        dst_ip="10.0.0.1",
        protocol="TCP",
        dst_port=445,
        src_port=None,
        packet_size=60,
        tcp_flags=None,
    ):
        packet = {
            "timestamp": (self.base_time + timedelta(seconds=seconds)).isoformat(),
            "src_ip": src_ip,
            "dst_ip": dst_ip,
            "src_port": src_port if src_port is not None else 50000 + seconds,
            "dst_port": dst_port,
            "protocol": protocol,
            "packet_size": packet_size,
        }
        if tcp_flags is not None:
            packet["tcp_flags"] = tcp_flags
        return packet

    def _dns(self, seconds, query_name="example.com", query_type="A", dns_rcode=None):
        dns_event = {
            "timestamp": (self.base_time + timedelta(seconds=seconds)).isoformat(),
            "client_ip": "10.0.0.10",
            "dns_server_ip": "10.0.0.1",
            "query_name": query_name,
            "query_type": query_type,
        }
        if dns_rcode is not None:
            dns_event["dns_rcode"] = dns_rcode
        return dns_event


if __name__ == "__main__":
    unittest.main()
