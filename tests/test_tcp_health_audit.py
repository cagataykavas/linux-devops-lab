from __future__ import annotations

import json
import stat
import tempfile
import unittest
from datetime import UTC, datetime, timedelta
from pathlib import Path
from unittest.mock import patch

from tcp_health_audit import (
    TcpHealthPolicy,
    TcpSnapshot,
    _read_bounded_text,
    _write_atomic,
    capture_snapshot,
    evaluate_tcp_health,
    main,
    parse_tcp_counters,
)

BOOT_ID = "12345678-1234-1234-1234-123456789abc"


def snmp_text(out_segments: int, retransmitted: int, resets: int) -> str:
    return (
        "Ip: Forwarding DefaultTTL\n"
        "Ip: 2 64\n"
        "Tcp: RtoAlgorithm OutSegs RetransSegs EstabResets\n"
        f"Tcp: 1 {out_segments} {retransmitted} {resets}\n"
    )


def snapshot(
    *,
    monotonic_ns: int,
    out_segments: int,
    retransmitted_segments: int,
    established_resets: int,
    boot_id: str = BOOT_ID,
) -> TcpSnapshot:
    instant = datetime(2026, 1, 1, tzinfo=UTC) + timedelta(
        seconds=monotonic_ns / 1_000_000_000
    )
    return TcpSnapshot(
        boot_id=boot_id,
        captured_at=instant.isoformat().replace("+00:00", "Z"),
        monotonic_ns=monotonic_ns,
        out_segments=out_segments,
        retransmitted_segments=retransmitted_segments,
        established_resets=established_resets,
    )


class TcpCounterParsingTests(unittest.TestCase):
    def test_parses_required_tcp_counters(self) -> None:
        self.assertEqual(
            parse_tcp_counters(snmp_text(1_000, 12, 3)),
            {"OutSegs": 1_000, "RetransSegs": 12, "EstabResets": 3},
        )

    def test_rejects_missing_or_misaligned_tcp_evidence(self) -> None:
        with self.assertRaisesRegex(ValueError, "exactly one"):
            parse_tcp_counters("Ip: Forwarding\nIp: 2\n")
        with self.assertRaisesRegex(ValueError, "aligned"):
            parse_tcp_counters("Tcp: OutSegs RetransSegs\nTcp: 1\n")

    def test_rejects_duplicate_and_non_decimal_counters(self) -> None:
        duplicate = "Tcp: OutSegs OutSegs RetransSegs EstabResets\nTcp: 1 2 3 4\n"
        with self.assertRaisesRegex(ValueError, "unique"):
            parse_tcp_counters(duplicate)
        with self.assertRaisesRegex(ValueError, "unsigned decimal"):
            parse_tcp_counters(snmp_text(10, -1, 0))


class TcpHealthEvaluationTests(unittest.TestCase):
    def setUp(self) -> None:
        self.policy = TcpHealthPolicy(
            sample_seconds=10,
            minimum_out_segments=100,
            maximum_retransmission_ratio=0.02,
            maximum_established_resets_per_second=0.5,
        )
        self.first = snapshot(
            monotonic_ns=1_000_000_000,
            out_segments=1_000,
            retransmitted_segments=10,
            established_resets=5,
        )

    def test_passes_healthy_window(self) -> None:
        second = snapshot(
            monotonic_ns=11_000_000_000,
            out_segments=2_000,
            retransmitted_segments=20,
            established_resets=7,
        )
        report = evaluate_tcp_health(self.first, second, self.policy)
        self.assertEqual(report.decision, "pass")
        self.assertAlmostEqual(report.retransmission_ratio or 0, 0.01)
        self.assertAlmostEqual(report.established_resets_per_second, 0.2)
        self.assertEqual(len(report.evidence_digest), 64)

    def test_rejects_retransmission_and_reset_pressure(self) -> None:
        second = snapshot(
            monotonic_ns=11_000_000_000,
            out_segments=2_000,
            retransmitted_segments=60,
            established_resets=15,
        )
        report = evaluate_tcp_health(self.first, second, self.policy)
        self.assertEqual(report.decision, "fail")
        self.assertEqual(
            report.finding_codes,
            (
                "retransmission_ratio_exceeded",
                "established_reset_rate_exceeded",
            ),
        )

    def test_reports_insufficient_traffic_separately(self) -> None:
        second = snapshot(
            monotonic_ns=11_000_000_000,
            out_segments=1_050,
            retransmitted_segments=10,
            established_resets=5,
        )
        report = evaluate_tcp_health(self.first, second, self.policy)
        self.assertEqual(report.decision, "insufficient_evidence")
        self.assertEqual(report.finding_codes, ("insufficient_outbound_traffic",))

    def test_rejects_boot_boundary_counter_regression_and_bad_interval(self) -> None:
        with self.assertRaisesRegex(ValueError, "boot boundary"):
            evaluate_tcp_health(
                self.first,
                snapshot(
                    monotonic_ns=11_000_000_000,
                    out_segments=2_000,
                    retransmitted_segments=20,
                    established_resets=7,
                    boot_id="aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa",
                ),
                self.policy,
            )
        with self.assertRaisesRegex(ValueError, "regressed"):
            evaluate_tcp_health(
                self.first,
                snapshot(
                    monotonic_ns=11_000_000_000,
                    out_segments=999,
                    retransmitted_segments=20,
                    established_resets=7,
                ),
                self.policy,
            )
        with self.assertRaisesRegex(ValueError, "interval"):
            evaluate_tcp_health(
                self.first,
                snapshot(
                    monotonic_ns=2_000_000_000,
                    out_segments=2_000,
                    retransmitted_segments=20,
                    established_resets=7,
                ),
                self.policy,
            )

    def test_digest_is_deterministic_and_policy_bound(self) -> None:
        second = snapshot(
            monotonic_ns=11_000_000_000,
            out_segments=2_000,
            retransmitted_segments=20,
            established_resets=7,
        )
        first_report = evaluate_tcp_health(self.first, second, self.policy)
        second_report = evaluate_tcp_health(self.first, second, self.policy)
        changed_policy_report = evaluate_tcp_health(
            self.first,
            second,
            TcpHealthPolicy(
                sample_seconds=10,
                minimum_out_segments=100,
                maximum_retransmission_ratio=0.03,
                maximum_established_resets_per_second=0.5,
            ),
        )
        self.assertEqual(first_report.evidence_digest, second_report.evidence_digest)
        self.assertNotEqual(
            first_report.evidence_digest, changed_policy_report.evidence_digest
        )


class TcpHealthIoTests(unittest.TestCase):
    def test_capture_reads_bounded_files_and_clocks(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            snmp_path = root / "snmp"
            boot_path = root / "boot_id"
            snmp_path.write_text(snmp_text(20, 2, 1), encoding="ascii")
            boot_path.write_text(f"{BOOT_ID}\n", encoding="ascii")
            result = capture_snapshot(
                snmp_path,
                boot_path,
                monotonic_ns=lambda: 123,
                wall_clock=lambda: datetime(2026, 1, 1, tzinfo=UTC),
            )
        self.assertEqual(result.monotonic_ns, 123)
        self.assertEqual(result.out_segments, 20)

    def test_bounded_reader_rejects_symlink(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            target = root / "target"
            link = root / "link"
            target.write_text("evidence", encoding="ascii")
            link.symlink_to(target)
            with self.assertRaises(OSError):
                _read_bounded_text(link)

    def test_atomic_report_is_private(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "report.json"
            _write_atomic(output, {"decision": "pass"})
            self.assertEqual(json.loads(output.read_text()), {"decision": "pass"})
            self.assertEqual(stat.S_IMODE(output.stat().st_mode), 0o600)

    def test_cli_maps_pass_and_invalid_evidence_to_distinct_exits(self) -> None:
        first = snapshot(
            monotonic_ns=1_000_000_000,
            out_segments=1_000,
            retransmitted_segments=10,
            established_resets=5,
        )
        second = snapshot(
            monotonic_ns=6_000_000_000,
            out_segments=2_000,
            retransmitted_segments=15,
            established_resets=6,
        )
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "report.json"
            with (
                patch("tcp_health_audit.capture_snapshot", side_effect=[first, second]),
                patch("tcp_health_audit.time.sleep"),
            ):
                self.assertEqual(main(["--output", str(output)]), 0)
            self.assertEqual(json.loads(output.read_text())["decision"], "pass")
            missing_output = Path(directory) / "missing.json"
            self.assertEqual(
                main(
                    [
                        "--output",
                        str(missing_output),
                        "--snmp-path",
                        str(Path(directory) / "does-not-exist"),
                    ]
                ),
                3,
            )
            self.assertFalse(missing_output.exists())


class TcpHealthPolicyTests(unittest.TestCase):
    def test_invalid_policy_values_fail_closed(self) -> None:
        invalid = (
            {"sample_seconds": 0},
            {"minimum_out_segments": 0},
            {"maximum_retransmission_ratio": float("nan")},
            {"maximum_established_resets_per_second": -1},
        )
        for kwargs in invalid:
            with self.subTest(kwargs=kwargs), self.assertRaises(ValueError):
                TcpHealthPolicy(**kwargs)


if __name__ == "__main__":
    unittest.main()
