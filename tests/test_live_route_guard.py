from __future__ import annotations

import json
import os
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest.mock import Mock

from live_route_guard import (
    LookupError,
    audit_live_routes,
    parse_kernel_route,
    validate_ip_command,
)
from route_guard import ValidationError, parse_policy


def _policy(*, device: str = "wg0", gateway: str = "192.0.2.1"):
    return parse_policy(
        {
            "destinations": [
                {
                    "name": "artifact-store",
                    "address": "203.0.113.10",
                    "allowed_devices": [device],
                    "allowed_gateways": [gateway],
                }
            ]
        }
    )


def _completed(
    payload: object, returncode: int = 0
) -> subprocess.CompletedProcess[str]:
    return subprocess.CompletedProcess(
        args=[],
        returncode=returncode,
        stdout=json.dumps(payload),
        stderr="suppressed diagnostic",
    )


class LiveRouteGuardTests(unittest.TestCase):
    def test_admits_actual_policy_route_and_records_custom_table(self) -> None:
        runner = Mock(
            return_value=_completed(
                [
                    {
                        "dst": "203.0.113.10",
                        "gateway": "192.0.2.1",
                        "dev": "wg0",
                        "prefsrc": "192.0.2.20",
                        "table": 100,
                    }
                ]
            )
        )

        report = audit_live_routes(_policy(), runner=runner)

        self.assertTrue(report["ok"])
        self.assertEqual(report["mode"], "kernel-route-get")
        self.assertEqual(report["checks"][0]["route"]["table"], 100)
        runner.assert_called_once_with(
            ("/usr/bin/ip", "-j", "route", "get", "203.0.113.10"),
            capture_output=True,
            check=False,
            env={"LC_ALL": "C", "PATH": "/usr/bin:/bin"},
            text=True,
            timeout=2.0,
        )

    def test_rejects_unapproved_actual_device(self) -> None:
        runner = Mock(
            return_value=_completed(
                [
                    {
                        "dst": "203.0.113.10",
                        "gateway": "192.0.2.1",
                        "dev": "eth0",
                    }
                ]
            )
        )

        report = audit_live_routes(_policy(), runner=runner)

        self.assertFalse(report["ok"])
        self.assertIn("not approved", report["checks"][0]["reason"])

    def test_command_failure_does_not_expose_stderr(self) -> None:
        runner = Mock(return_value=_completed([], returncode=2))

        report = audit_live_routes(_policy(), runner=runner)

        self.assertFalse(report["ok"])
        self.assertEqual(
            report["checks"][0]["reason"], "kernel route lookup exited non-zero"
        )
        self.assertNotIn("suppressed", json.dumps(report))

    def test_timeout_is_a_bounded_failure(self) -> None:
        runner = Mock(side_effect=subprocess.TimeoutExpired(["ip"], 2.0))

        report = audit_live_routes(_policy(), runner=runner)

        self.assertFalse(report["ok"])
        self.assertIn("deadline", report["checks"][0]["reason"])

    def test_rejects_mismatched_destination(self) -> None:
        with self.assertRaisesRegex(LookupError, "does not match"):
            parse_kernel_route(
                '[{"dst":"203.0.113.11","dev":"wg0"}]',
                _policy()[0].address,
            )

    def test_rejects_multiple_or_duplicate_route_evidence(self) -> None:
        address = _policy()[0].address
        with self.assertRaisesRegex(LookupError, "exactly one"):
            parse_kernel_route(
                '[{"dst":"203.0.113.10","dev":"wg0"},{"dst":"203.0.113.10","dev":"eth0"}]',
                address,
            )
        with self.assertRaisesRegex(LookupError, "duplicate JSON"):
            parse_kernel_route(
                '[{"dst":"203.0.113.10","dev":"wg0","dev":"eth0"}]',
                address,
            )

    def test_rejects_invalid_timeout_contract(self) -> None:
        for value in (True, 0.0, 10.1):
            with self.subTest(value=value), self.assertRaises(ValidationError):
                audit_live_routes(_policy(), timeout_seconds=value)
        with self.assertRaisesRegex(ValidationError, "must be boolean"):
            audit_live_routes(_policy(), explain_rejections="yes")

    def test_rejects_terminal_route(self) -> None:
        runner = Mock(
            return_value=_completed(
                [{"dst": "203.0.113.10", "dev": "lo", "type": "unreachable"}]
            )
        )

        report = audit_live_routes(_policy(), runner=runner)

        self.assertFalse(report["ok"])
        self.assertIn("unreachable", report["checks"][0]["reason"])

    def test_explicit_ip_command_path_is_preserved(self) -> None:
        runner = Mock(
            return_value=_completed(
                [{"dst": "203.0.113.10", "gateway": "192.0.2.1", "dev": "wg0"}]
            )
        )

        report = audit_live_routes(
            _policy(),
            ip_command=Path("/opt/iproute2/ip"),
            runner=runner,
        )

        self.assertTrue(report["ok"])
        self.assertEqual(runner.call_args.args[0][0], "/opt/iproute2/ip")

    def test_ip_command_must_be_absolute_regular_and_executable(self) -> None:
        with self.assertRaisesRegex(ValidationError, "absolute"):
            validate_ip_command(Path("ip"))

        with tempfile.TemporaryDirectory() as directory:
            executable = Path(directory) / "ip"
            executable.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
            executable.chmod(0o700)
            self.assertEqual(validate_ip_command(executable), executable)

            link = Path(directory) / "ip-link"
            os.symlink(executable, link)
            with self.assertRaisesRegex(ValidationError, "non-symlink"):
                validate_ip_command(link)

    def test_rejection_diagnostics_are_opt_in_and_nexthop_scoped(self) -> None:
        route = _completed(
            [
                {
                    "dst": "203.0.113.10",
                    "gateway": "192.0.2.1",
                    "dev": "eth0",
                    "nhid": 42,
                }
            ]
        )
        runner = Mock(
            side_effect=[
                route,
                _completed(
                    [
                        {
                            "priority": 100,
                            "src": "10.0.0.0/8",
                            "table": 100,
                        }
                    ]
                ),
                _completed(
                    [
                        {
                            "id": 42,
                            "dev": "eth0",
                            "via": {"family": "inet", "addr": "192.0.2.1"},
                        }
                    ]
                ),
            ]
        )

        report = audit_live_routes(_policy(), explain_rejections=True, runner=runner)

        self.assertFalse(report["ok"])
        diagnostics = report["checks"][0]["diagnostics"]
        self.assertEqual(diagnostics["status"], "complete")
        self.assertEqual(diagnostics["nexthop"]["id"], 42)
        self.assertNotIn("10.0.0.0", json.dumps(diagnostics))
        self.assertNotIn("192.0.2.1", json.dumps(diagnostics))
        self.assertEqual(runner.call_count, 3)

    def test_passing_route_never_collects_diagnostics(self) -> None:
        runner = Mock(
            return_value=_completed(
                [
                    {
                        "dst": "203.0.113.10",
                        "gateway": "192.0.2.1",
                        "dev": "wg0",
                    }
                ]
            )
        )

        report = audit_live_routes(_policy(), explain_rejections=True, runner=runner)

        self.assertTrue(report["ok"])
        self.assertIsNone(report["checks"][0]["diagnostics"])
        self.assertEqual(runner.call_count, 1)


if __name__ == "__main__":
    unittest.main()
