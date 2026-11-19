from __future__ import annotations

import json
import subprocess
import unittest
from pathlib import Path
from unittest.mock import Mock

from route_explain import (
    DiagnosticError,
    RouteDiagnosticCollector,
    collect_route_diagnostics,
    parse_nexthop_summary,
    parse_rule_summaries,
)


def _completed(
    payload: object, returncode: int = 0
) -> subprocess.CompletedProcess[str]:
    return subprocess.CompletedProcess(
        args=[],
        returncode=returncode,
        stdout=json.dumps(payload),
        stderr="secret command diagnostic",
    )


class RouteExplainTests(unittest.TestCase):
    def test_rule_summary_omits_selector_values_and_unknown_values(self) -> None:
        summaries = parse_rule_summaries(
            json.dumps(
                [
                    {
                        "priority": 100,
                        "src": "10.23.0.0/16",
                        "fwmark": "0x2/0xff",
                        "table": "main",
                        "protocol": "boot",
                        "opaque": "must-not-appear",
                    }
                ]
            )
        )

        self.assertEqual(
            summaries,
            [
                {
                    "action": "lookup",
                    "priority": 100,
                    "selector_fields": ["fwmark", "src"],
                    "table": 254,
                    "unreported_field_count": 1,
                }
            ],
        )
        self.assertNotIn("10.23", json.dumps(summaries))
        self.assertNotIn("0x2", json.dumps(summaries))
        self.assertNotIn("must-not-appear", json.dumps(summaries))

    def test_rule_summary_rejects_duplicate_fields_and_excess_entries(self) -> None:
        with self.assertRaisesRegex(DiagnosticError, "duplicate JSON"):
            parse_rule_summaries('[{"priority":1,"priority":2}]')
        with self.assertRaisesRegex(DiagnosticError, "exceeds 256"):
            parse_rule_summaries(json.dumps([{}] * 257))

    def test_nexthop_summary_omits_gateway_address(self) -> None:
        summary = parse_nexthop_summary(
            json.dumps(
                [
                    {
                        "id": 42,
                        "dev": "eth0",
                        "via": {"family": "inet", "addr": "192.0.2.1"},
                        "protocol": "static",
                    }
                ]
            ),
            42,
        )

        self.assertEqual(summary["mode"], "device")
        self.assertEqual(summary["gateway_family"], "inet")
        self.assertNotIn("192.0.2.1", json.dumps(summary))

    def test_nexthop_group_requires_unique_bounded_members(self) -> None:
        summary = parse_nexthop_summary(
            '[{"id":50,"group":[{"id":51,"weight":2},{"id":52}]}]',
            50,
        )
        self.assertEqual(
            summary["members"], [{"id": 51, "weight": 2}, {"id": 52, "weight": 1}]
        )
        with self.assertRaisesRegex(DiagnosticError, "duplicate member"):
            parse_nexthop_summary('[{"id":50,"group":[{"id":51},{"id":51}]}]', 50)

    def test_collector_uses_fixed_commands_and_suppresses_stderr(self) -> None:
        runner = Mock(
            side_effect=[
                _completed([{"priority": 32766, "src": "all", "table": "main"}]),
                _completed([], returncode=2),
            ]
        )

        report = collect_route_diagnostics(
            ip_command=Path("/usr/bin/ip"),
            timeout_seconds=1.5,
            nexthop_id=42,
            runner=runner,
        )

        self.assertEqual(report["status"], "partial")
        self.assertEqual(report["errors"], ["nexthop lookup exited non-zero"])
        self.assertNotIn("secret", json.dumps(report))
        self.assertEqual(
            runner.call_args_list[0].args[0],
            ("/usr/bin/ip", "-j", "rule", "show"),
        )
        self.assertEqual(
            runner.call_args_list[1].args[0],
            ("/usr/bin/ip", "-j", "nexthop", "get", "id", "42"),
        )
        for call in runner.call_args_list:
            self.assertEqual(
                call.kwargs["env"], {"LC_ALL": "C", "PATH": "/usr/bin:/bin"}
            )
            self.assertEqual(call.kwargs["timeout"], 1.5)

    def test_collector_reuses_rule_and_nexthop_evidence(self) -> None:
        runner = Mock(
            side_effect=[
                _completed([{"priority": 32766, "table": "main"}]),
                _completed([{"id": 42, "dev": "eth0"}]),
            ]
        )
        collector = RouteDiagnosticCollector(
            ip_command=Path("/usr/bin/ip"),
            timeout_seconds=2.0,
            runner=runner,
        )

        first = collector.collect(42)
        second = collector.collect(42)

        self.assertEqual(first, second)
        self.assertEqual(runner.call_count, 2)


if __name__ == "__main__":
    unittest.main()
