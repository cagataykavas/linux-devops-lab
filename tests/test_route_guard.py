from __future__ import annotations

import json
import os
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout
from io import StringIO
from pathlib import Path

from route_guard import (
    ValidationError,
    load_json,
    main,
    parse_policy,
    parse_routes,
    verify,
)


class RouteGuardTests(unittest.TestCase):
    def test_longest_prefix_beats_default_route(self) -> None:
        routes = parse_routes(
            [
                {"dst": "default", "dev": "eth0", "gateway": "192.0.2.1"},
                {"dst": "203.0.113.0/24", "dev": "wg0", "metric": 50},
            ]
        )
        policy = parse_policy(
            {
                "destinations": [
                    {
                        "name": "artifact-store",
                        "address": "203.0.113.10",
                        "allowed_devices": ["wg0"],
                    }
                ]
            }
        )

        report = verify(routes, policy)

        self.assertTrue(report["ok"])
        self.assertEqual(report["checks"][0]["route"]["destination"], "203.0.113.0/24")

    def test_lower_metric_wins_for_same_prefix(self) -> None:
        routes = parse_routes(
            [
                {"dst": "10.0.0.0/8", "dev": "eth0", "metric": 200},
                {"dst": "10.0.0.0/8", "dev": "eth1", "metric": 100},
            ]
        )
        policy = parse_policy(
            {
                "destinations": [
                    {"name": "service", "address": "10.2.3.4", "allowed_devices": ["eth1"]}
                ]
            }
        )

        self.assertTrue(verify(routes, policy)["ok"])

    def test_rejects_unapproved_gateway(self) -> None:
        routes = parse_routes(
            [{"dst": "default", "dev": "eth0", "gateway": "192.0.2.99"}]
        )
        policy = parse_policy(
            {
                "destinations": [
                    {
                        "name": "internet",
                        "address": "198.51.100.4",
                        "allowed_devices": ["eth0"],
                        "allowed_gateways": ["192.0.2.1"],
                    }
                ]
            }
        )

        report = verify(routes, policy)

        self.assertFalse(report["ok"])
        self.assertIn("not approved", report["checks"][0]["reason"])

    def test_terminal_more_specific_route_fails_closed(self) -> None:
        routes = parse_routes(
            [
                {"dst": "default", "dev": "eth0", "gateway": "192.0.2.1"},
                {"dst": "198.51.100.0/24", "type": "blackhole"},
            ]
        )
        policy = parse_policy(
            {
                "destinations": [
                    {
                        "name": "dependency",
                        "address": "198.51.100.8",
                        "allowed_devices": ["eth0"],
                    }
                ]
            }
        )

        report = verify(routes, policy)

        self.assertFalse(report["ok"])
        self.assertEqual(report["checks"][0]["reason"], "selected route is blackhole")

    def test_ipv6_default_route(self) -> None:
        routes = parse_routes(
            [{"dst": "default", "dev": "eth0", "gateway": "2001:db8::1"}]
        )
        policy = parse_policy(
            {
                "destinations": [
                    {
                        "name": "v6-service",
                        "address": "2001:db8:ffff::10",
                        "allowed_devices": ["eth0"],
                        "allowed_gateways": ["2001:db8::1"],
                    }
                ]
            }
        )

        self.assertTrue(verify(routes, policy)["ok"])

    def test_equal_precedence_routes_are_ambiguous(self) -> None:
        routes = parse_routes(
            [
                {"dst": "10.0.0.0/8", "dev": "eth0", "metric": 10},
                {"dst": "10.0.0.0/8", "dev": "eth1", "metric": 10},
            ]
        )
        policy = parse_policy(
            {
                "destinations": [
                    {"name": "service", "address": "10.1.2.3", "allowed_devices": ["eth0"]}
                ]
            }
        )

        report = verify(routes, policy)

        self.assertFalse(report["ok"])
        self.assertIn("ambiguous", report["checks"][0]["reason"])

    def test_no_matching_family_reports_failure(self) -> None:
        routes = parse_routes(
            [{"dst": "default", "dev": "eth0", "gateway": "192.0.2.1"}]
        )
        policy = parse_policy(
            {
                "destinations": [
                    {"name": "v6", "address": "2001:db8::5", "allowed_devices": ["eth0"]}
                ]
            }
        )

        self.assertEqual(verify(routes, policy)["checks"][0]["reason"], "no matching route")

    def test_rejects_non_main_route_table(self) -> None:
        with self.assertRaisesRegex(ValidationError, "main/254"):
            parse_routes([{"dst": "10.0.0.0/8", "dev": "eth0", "table": 100}])

    def test_default_without_gateway_requires_family(self) -> None:
        with self.assertRaisesRegex(ValidationError, "family"):
            parse_routes([{"dst": "default", "dev": "eth0"}])

    def test_rejects_duplicate_json_keys(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "routes.json"
            path.write_text('[{"dst":"default","dst":"10.0.0.0/8"}]', encoding="utf-8")

            with self.assertRaisesRegex(ValidationError, "duplicate JSON key"):
                load_json(path)

    def test_rejects_symlink_input(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            target = Path(directory) / "target.json"
            target.write_text("[]", encoding="utf-8")
            link = Path(directory) / "routes.json"
            os.symlink(target, link)

            with self.assertRaisesRegex(ValidationError, "non-symlink"):
                load_json(link)

    def test_report_is_json_serializable(self) -> None:
        routes = parse_routes([{"dst": "127.0.0.0/8", "dev": "lo"}])
        policy = parse_policy(
            {
                "destinations": [
                    {"name": "local", "address": "127.0.0.1", "allowed_devices": ["lo"]}
                ]
            }
        )

        encoded = json.dumps(verify(routes, policy), sort_keys=True)

        self.assertIn('"ok": true', encoded)

    def test_cli_returns_nonzero_for_policy_violation(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            routes_path = Path(directory) / "routes.json"
            policy_path = Path(directory) / "policy.json"
            routes_path.write_text(
                json.dumps([{"dst": "default", "dev": "eth0", "gateway": "192.0.2.1"}]),
                encoding="utf-8",
            )
            policy_path.write_text(
                json.dumps(
                    {
                        "destinations": [
                            {
                                "name": "service",
                                "address": "203.0.113.10",
                                "allowed_devices": ["wg0"],
                            }
                        ]
                    }
                ),
                encoding="utf-8",
            )
            stdout = StringIO()
            stderr = StringIO()

            with redirect_stdout(stdout), redirect_stderr(stderr):
                exit_code = main(["--routes", str(routes_path), "--policy", str(policy_path)])

        self.assertEqual(exit_code, 2)
        self.assertFalse(json.loads(stdout.getvalue())["ok"])
        self.assertEqual(stderr.getvalue(), "")


if __name__ == "__main__":
    unittest.main()
