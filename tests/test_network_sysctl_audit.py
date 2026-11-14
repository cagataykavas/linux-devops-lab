from __future__ import annotations

import io
import json
import stat
import tempfile
import unittest
from contextlib import redirect_stderr
from datetime import UTC, datetime, timedelta
from pathlib import Path

from network_sysctl_audit import (
    AuditInputError,
    canonical_sha256,
    collect_snapshot,
    evaluate,
    main,
    parse_json,
    parse_policy,
    parse_snapshot,
    read_bounded,
    write_json,
)

NOW = datetime(2026, 11, 14, 7, 0, tzinfo=UTC)
KEYS = {
    "net/ipv4/ip_forward": [0],
    "net/ipv4/tcp_syncookies": [1],
    "net/ipv4/conf/eth0/rp_filter": [1, 2],
}


def policy_document(expectations: dict[str, list[int]] | None = None) -> dict:
    values = expectations or KEYS
    return {
        "schema_version": 1,
        "maximum_snapshot_age_seconds": 300,
        "maximum_future_skew_seconds": 5,
        "expectations": [
            {"key": key, "allowed_values": allowed} for key, allowed in values.items()
        ],
    }


def snapshot_document(
    values: dict[str, int] | None = None, captured_at: datetime = NOW
) -> dict:
    return {
        "schema_version": 1,
        "captured_at": captured_at.isoformat().replace("+00:00", "Z"),
        "values": values or {key: allowed[0] for key, allowed in KEYS.items()},
    }


class NetworkSysctlAuditTests(unittest.TestCase):
    def test_duplicate_json_key_is_rejected(self) -> None:
        with self.assertRaisesRegex(AuditInputError, "duplicate JSON key"):
            parse_json(b'{"schema_version":1,"schema_version":1}')

    def test_non_finite_policy_is_rejected(self) -> None:
        document = policy_document()
        document["maximum_snapshot_age_seconds"] = float("nan")
        with self.assertRaisesRegex(AuditInputError, "must be finite"):
            parse_policy(document)

    def test_unsupported_or_traversing_key_is_rejected(self) -> None:
        for key in ("kernel/randomize_va_space", "net/ipv4/conf/../accept_redirects"):
            with (
                self.subTest(key=key),
                self.assertRaisesRegex(
                    AuditInputError, "unsupported|invalid interface"
                ),
            ):
                parse_policy(policy_document({key: [0]}))

    def test_policy_normalization_is_order_independent(self) -> None:
        first = parse_policy(policy_document(KEYS))
        second = parse_policy(policy_document(dict(reversed(list(KEYS.items())))))
        self.assertEqual(
            canonical_sha256(first.as_dict()), canonical_sha256(second.as_dict())
        )

    def test_snapshot_requires_exact_policy_key_set(self) -> None:
        policy = parse_policy(policy_document())
        missing = snapshot_document({"net/ipv4/ip_forward": 0})
        with self.assertRaisesRegex(AuditInputError, "missing expected keys"):
            parse_snapshot(missing, policy)
        extra = snapshot_document()
        extra["values"]["net/ipv6/conf/all/forwarding"] = 0
        with self.assertRaisesRegex(AuditInputError, "unexpected keys"):
            parse_snapshot(extra, policy)

    def test_healthy_snapshot_is_admitted_with_commitments(self) -> None:
        policy = parse_policy(policy_document())
        snapshot = parse_snapshot(snapshot_document(), policy)
        report = evaluate(policy, snapshot, now=NOW + timedelta(seconds=10))
        self.assertTrue(report["ok"])
        self.assertEqual(report["checked_expectations"], 3)
        self.assertEqual(len(report["policy_sha256"]), 64)
        self.assertEqual(len(report["snapshot_sha256"]), 64)

    def test_value_drift_is_rejected_with_stable_evidence(self) -> None:
        policy = parse_policy(policy_document())
        values = {key: allowed[0] for key, allowed in KEYS.items()}
        values["net/ipv4/ip_forward"] = 1
        snapshot = parse_snapshot(snapshot_document(values), policy)
        report = evaluate(policy, snapshot, now=NOW)
        self.assertFalse(report["ok"])
        self.assertEqual(
            report["violations"],
            [
                {
                    "code": "value_not_allowed",
                    "key": "net/ipv4/ip_forward",
                    "actual": 1,
                    "allowed_values": [0],
                }
            ],
        )

    def test_stale_and_future_snapshots_are_rejected(self) -> None:
        policy = parse_policy(policy_document())
        stale = parse_snapshot(
            snapshot_document(captured_at=NOW - timedelta(seconds=301)), policy
        )
        future = parse_snapshot(
            snapshot_document(captured_at=NOW + timedelta(seconds=6)), policy
        )
        self.assertEqual(
            evaluate(policy, stale, now=NOW)["violations"][0]["code"], "snapshot_stale"
        )
        self.assertEqual(
            evaluate(policy, future, now=NOW)["violations"][0]["code"],
            "snapshot_from_future",
        )

    def test_collection_reads_only_requested_proc_files(self) -> None:
        policy = parse_policy(policy_document())
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            for key, allowed in KEYS.items():
                path = root / key
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_text(f"{allowed[0]}\n", encoding="ascii")
            snapshot = collect_snapshot(policy, root, now=NOW)
        self.assertEqual(
            snapshot.values, {key: allowed[0] for key, allowed in KEYS.items()}
        )

    def test_collection_rejects_noncanonical_value(self) -> None:
        policy = parse_policy(policy_document({"net/ipv4/ip_forward": [0]}))
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "net/ipv4/ip_forward"
            path.parent.mkdir(parents=True)
            path.write_text("00\n", encoding="ascii")
            with self.assertRaisesRegex(AuditInputError, "not canonical"):
                collect_snapshot(policy, Path(temporary), now=NOW)

    def test_collection_rejects_symlinked_intermediate_directory(self) -> None:
        policy = parse_policy(policy_document({"net/ipv4/ip_forward": [0]}))
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            outside = root / "outside"
            (outside / "ipv4").mkdir(parents=True)
            (outside / "ipv4/ip_forward").write_text("0", encoding="ascii")
            (root / "net").symlink_to(outside, target_is_directory=True)
            with self.assertRaisesRegex(AuditInputError, "trusted directories"):
                collect_snapshot(policy, root, now=NOW)

    def test_bounded_reader_rejects_symlink(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            target = root / "target"
            target.write_text("0", encoding="ascii")
            link = root / "link"
            link.symlink_to(target)
            with self.assertRaisesRegex(AuditInputError, "non-symlink"):
                read_bounded(link)

    def test_atomic_output_has_private_permissions(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            output = Path(temporary) / "evidence.json"
            write_json({"ok": True}, output)
            self.assertEqual(stat.S_IMODE(output.stat().st_mode), 0o600)
            self.assertEqual(json.loads(output.read_text())["ok"], True)

    def test_cli_separates_success_policy_failure_and_invalid_input(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            policy_path = root / "policy.json"
            snapshot_path = root / "snapshot.json"
            output_path = root / "report.json"
            policy_path.write_text(json.dumps(policy_document()), encoding="utf-8")
            snapshot_path.write_text(
                json.dumps(snapshot_document(captured_at=datetime.now(UTC))),
                encoding="utf-8",
            )
            args = [
                "verify",
                "--policy",
                str(policy_path),
                "--snapshot",
                str(snapshot_path),
                "--output",
                str(output_path),
            ]
            self.assertEqual(main(args), 0)
            stale = snapshot_document(captured_at=NOW)
            snapshot_path.write_text(json.dumps(stale), encoding="utf-8")
            self.assertEqual(main(args), 3)
            snapshot_path.write_text("{}", encoding="utf-8")
            self.assertEqual(main(args), 2)
            self.assertEqual(
                json.loads(output_path.read_text())["error"],
                "invalid_or_unreadable_input",
            )

    def test_collect_cli_creates_complete_snapshot(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            proc_root = root / "proc"
            policy_path = root / "policy.json"
            output_path = root / "snapshot.json"
            policy_path.write_text(json.dumps(policy_document()), encoding="utf-8")
            for key, allowed in KEYS.items():
                path = proc_root / key
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_text(str(allowed[0]), encoding="ascii")
            self.assertEqual(
                main(
                    [
                        "collect",
                        "--policy",
                        str(policy_path),
                        "--proc-root",
                        str(proc_root),
                        "--output",
                        str(output_path),
                    ]
                ),
                0,
            )
            self.assertEqual(
                set(json.loads(output_path.read_text())["values"]), set(KEYS)
            )

    def test_cli_output_failure_returns_operational_error(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            policy_path = root / "policy.json"
            snapshot_path = root / "snapshot.json"
            blocked_parent = root / "not-a-directory"
            policy_path.write_text(json.dumps(policy_document()), encoding="utf-8")
            snapshot_path.write_text(
                json.dumps(snapshot_document(captured_at=datetime.now(UTC))),
                encoding="utf-8",
            )
            blocked_parent.write_text("blocked", encoding="utf-8")
            error = io.StringIO()
            with redirect_stderr(error):
                self.assertEqual(
                    main(
                        [
                            "verify",
                            "--policy",
                            str(policy_path),
                            "--snapshot",
                            str(snapshot_path),
                            "--output",
                            str(blocked_parent / "report.json"),
                        ]
                    ),
                    2,
                )
            self.assertIn("could not write", error.getvalue())

    def test_output_replaces_existing_file_without_following_it(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            target = root / "target"
            target.write_text("protected", encoding="utf-8")
            output = root / "report"
            output.symlink_to(target)
            write_json({"ok": True}, output)
            self.assertEqual(target.read_text(), "protected")
            self.assertFalse(output.is_symlink())


if __name__ == "__main__":
    unittest.main()
