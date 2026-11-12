from __future__ import annotations

import contextlib
import io
import json
import tempfile
import unittest
from pathlib import Path

from listener_audit import (
    AuditInputError,
    ListenerKey,
    POLICY_LIMIT_BYTES,
    PolicyRule,
    audit_listeners,
    load_policy,
    main,
    parse_proc_net,
)

HEADER = "  sl  local_address rem_address st tx_queue rx_queue tr tm->when retrnsmt uid timeout inode\n"
TCP6_HEADER = "  sl  local_address remote_address st tx_queue rx_queue tr tm->when retrnsmt uid timeout inode\n"


def proc_row(
    local: str,
    *,
    family: str = "ipv4",
    state: str = "0A",
    uid: int = 1000,
    slot: int = 0,
    inode: int = 12345,
) -> str:
    remote = "00000000:0000" if family == "ipv4" else f"{'0' * 32}:0000"
    return (
        f"{slot}: {local} {remote} {state} 00000000:00000000 "
        f"00:00000000 00000000 {uid} 0 {inode}\n"
    )


def policy_rule(
    *,
    family: str = "ipv4",
    address: str = "127.0.0.1",
    port: int = 8000,
    uid: int = 1000,
    minimum: int = 1,
    maximum: int = 1,
) -> PolicyRule:
    return PolicyRule(
        ListenerKey(family, address, port, uid),
        min_instances=minimum,
        max_instances=maximum,
    )


class ListenerAuditTests(unittest.TestCase):
    def test_decodes_ipv4_and_ipv6_kernel_byte_order(self) -> None:
        tcp4 = (HEADER + proc_row("0100007F:1F40")).encode()
        tcp6 = (
            TCP6_HEADER
            + proc_row(
                "00000000000000000000000001000000:01BB",
                family="ipv6",
            )
        ).encode()

        ipv4 = parse_proc_net(tcp4, "ipv4")
        ipv6 = parse_proc_net(tcp6, "ipv6")

        self.assertEqual(ipv4[ListenerKey("ipv4", "127.0.0.1", 8000, 1000)], 1)
        self.assertEqual(ipv6[ListenerKey("ipv6", "::1", 443, 1000)], 1)

    def test_ignores_non_listening_connections_but_validates_rows(self) -> None:
        tcp4 = (HEADER + proc_row("0100007F:1F40", state="01")).encode()
        self.assertEqual(parse_proc_net(tcp4, "ipv4"), {})

    def test_exact_policy_passes_and_evidence_is_deterministic(self) -> None:
        tcp4 = (HEADER + proc_row("0100007F:1F40")).encode()
        first = audit_listeners(
            rules=[policy_rule()],
            policy_sha256="a" * 64,
            tcp4=tcp4,
            tcp6=TCP6_HEADER.encode(),
        )
        second = audit_listeners(
            rules=[policy_rule()],
            policy_sha256="a" * 64,
            tcp4=tcp4,
            tcp6=TCP6_HEADER.encode(),
        )

        self.assertTrue(first["passed"])
        self.assertEqual(first["evidence_sha256"], second["evidence_sha256"])
        self.assertEqual(first["listeners"][0]["exposure"], "loopback")

    def test_unexpected_wildcard_listener_fails_closed(self) -> None:
        tcp4 = (HEADER + proc_row("00000000:1F40")).encode()
        report = audit_listeners(
            rules=[],
            policy_sha256="a" * 64,
            tcp4=tcp4,
            tcp6=TCP6_HEADER.encode(),
        )

        self.assertFalse(report["passed"])
        self.assertEqual(report["findings"][0]["code"], "unexpected_listener")
        self.assertEqual(report["findings"][0]["exposure"], "wildcard")

    def test_missing_required_listener_is_reported(self) -> None:
        report = audit_listeners(
            rules=[policy_rule()],
            policy_sha256="a" * 64,
            tcp4=HEADER.encode(),
            tcp6=TCP6_HEADER.encode(),
        )

        self.assertEqual(report["findings"][0]["code"], "missing_listener")

    def test_reuseport_instance_bounds_are_enforced(self) -> None:
        tcp4 = (
            HEADER
            + proc_row("0100007F:1F40", slot=0, inode=1)
            + proc_row("0100007F:1F40", slot=1, inode=2)
        ).encode()
        passing = audit_listeners(
            rules=[policy_rule(maximum=2)],
            policy_sha256="a" * 64,
            tcp4=tcp4,
            tcp6=TCP6_HEADER.encode(),
        )
        failing = audit_listeners(
            rules=[policy_rule(maximum=1)],
            policy_sha256="a" * 64,
            tcp4=tcp4,
            tcp6=TCP6_HEADER.encode(),
        )

        self.assertTrue(passing["passed"])
        self.assertEqual(failing["findings"][0]["code"], "instance_count_out_of_range")

    def test_policy_rejects_duplicate_json_fields(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "policy.json"
            path.write_text(
                '{"schema_version":"listener-policy/v1","rules":[],"rules":[]}'
            )

            with self.assertRaisesRegex(AuditInputError, "duplicate JSON field: rules"):
                load_policy(path)

    def test_policy_rejects_family_address_mismatch(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "policy.json"
            path.write_text(
                json.dumps(
                    {
                        "schema_version": "listener-policy/v1",
                        "rules": [
                            {
                                "address": "::1",
                                "family": "ipv4",
                                "port": 8000,
                                "uid": 1000,
                            }
                        ],
                    }
                )
            )

            with self.assertRaisesRegex(AuditInputError, "does not match ipv4"):
                load_policy(path)

    def test_policy_read_is_bounded(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "policy.json"
            path.write_bytes(b" " * (POLICY_LIMIT_BYTES + 1))

            with self.assertRaisesRegex(AuditInputError, "exceeds"):
                load_policy(path)

    def test_truncated_procfs_row_is_rejected(self) -> None:
        with self.assertRaisesRegex(AuditInputError, "row 2 is truncated"):
            parse_proc_net((HEADER + "0: broken\n").encode(), "ipv4")

    def test_cli_separates_policy_failure_from_invalid_input(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            policy = root / "policy.json"
            tcp4 = root / "tcp"
            tcp6 = root / "tcp6"
            policy.write_text(
                json.dumps({"schema_version": "listener-policy/v1", "rules": []})
            )
            tcp4.write_text(HEADER + proc_row("00000000:1F40"))
            tcp6.write_text(TCP6_HEADER)
            output = io.StringIO()
            with contextlib.redirect_stdout(output):
                violation = main(
                    ["--policy", str(policy), "--tcp4", str(tcp4), "--tcp6", str(tcp6)]
                )
            tcp4.write_text("not procfs")
            with contextlib.redirect_stdout(io.StringIO()):
                invalid = main(
                    ["--policy", str(policy), "--tcp4", str(tcp4), "--tcp6", str(tcp6)]
                )
            tcp4.write_text(HEADER)
            with contextlib.redirect_stdout(io.StringIO()):
                passed = main(
                    ["--policy", str(policy), "--tcp4", str(tcp4), "--tcp6", str(tcp6)]
                )

        self.assertEqual(violation, 2)
        self.assertEqual(invalid, 3)
        self.assertEqual(passed, 0)
        self.assertEqual(
            json.loads(output.getvalue())["findings"][0]["code"], "unexpected_listener"
        )


if __name__ == "__main__":
    unittest.main()
