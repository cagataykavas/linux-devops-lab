from __future__ import annotations

import json
import stat
import tempfile
import unittest
from pathlib import Path

import link_health_audit as audit

RULE = {
    "max_rx_errors_per_second": 0.0,
    "max_tx_errors_per_second": 0.0,
    "max_rx_drop_ratio": 0.01,
    "max_tx_drop_ratio": 0.01,
    "min_rx_packets_for_ratio": 100,
    "min_tx_packets_for_ratio": 100,
    "require_operstate_up": True,
}


def snapshot(
    moment: float,
    *,
    counters: dict[str, int] | None = None,
    ifindex: int = 2,
    state: str = "up",
    boot_id: str = "boot",
    netns: int = 10,
) -> audit.Snapshot:
    values = {name: 0 for name in audit.COUNTERS}
    values.update(counters or {})
    return audit.Snapshot(
        moment,
        boot_id,
        netns,
        {"eth0": audit.InterfaceSnapshot(ifindex, state, values)},
    )


class PolicyTests(unittest.TestCase):
    def test_valid_policy_is_normalized(self) -> None:
        policy = audit.validate_policy({"version": 1, "interfaces": {"eth0": RULE}})
        self.assertEqual(policy["eth0"]["max_rx_drop_ratio"], 0.01)

    def test_unknown_rule_field_fails_closed(self) -> None:
        with self.assertRaisesRegex(audit.InvalidEvidence, "schema"):
            audit.validate_policy(
                {"version": 1, "interfaces": {"eth0": {**RULE, "ignored": True}}}
            )

    def test_fractional_packet_floor_is_rejected(self) -> None:
        with self.assertRaisesRegex(audit.InvalidEvidence, "must be an integer"):
            audit.validate_policy(
                {
                    "version": 1,
                    "interfaces": {"eth0": {**RULE, "min_rx_packets_for_ratio": 1.5}},
                }
            )

    def test_path_like_interface_name_is_rejected(self) -> None:
        with self.assertRaisesRegex(audit.InvalidEvidence, "invalid interface"):
            audit.validate_policy({"version": 1, "interfaces": {"../eth0": RULE}})


class EvaluationTests(unittest.TestCase):
    def test_healthy_window_is_admitted(self) -> None:
        before = snapshot(10)
        after = snapshot(11, counters={"rx_packets": 1000, "tx_packets": 2000})
        result = audit.evaluate_window(before, after, {"eth0": RULE}, 1.0)
        self.assertTrue(result["admitted"])
        self.assertEqual(result["interfaces"]["eth0"]["reasons"], [])

    def test_drop_ratio_and_error_rate_are_rejected(self) -> None:
        before = snapshot(10)
        after = snapshot(
            12,
            counters={
                "rx_packets": 990,
                "rx_dropped": 20,
                "tx_packets": 1000,
                "tx_errors": 1,
            },
        )
        result = audit.evaluate_window(before, after, {"eth0": RULE}, 2.0)
        self.assertFalse(result["admitted"])
        self.assertEqual(
            result["interfaces"]["eth0"]["reasons"],
            ["tx_error_rate_exceeded", "rx_drop_ratio_exceeded"],
        )

    def test_low_traffic_does_not_claim_ratio_health(self) -> None:
        after = snapshot(11, counters={"rx_packets": 2, "rx_dropped": 1})
        result = audit.evaluate_window(snapshot(10), after, {"eth0": RULE}, 1.0)
        interface = result["interfaces"]["eth0"]
        self.assertTrue(result["admitted"])
        self.assertIsNone(interface["rx_drop_ratio"])

    def test_non_up_state_is_rejected(self) -> None:
        result = audit.evaluate_window(
            snapshot(10, state="down"), snapshot(11, state="down"), {"eth0": RULE}, 1.0
        )
        self.assertEqual(result["interfaces"]["eth0"]["reasons"], ["operstate_not_up"])

    def test_counter_regression_is_invalid(self) -> None:
        with self.assertRaisesRegex(audit.InvalidEvidence, "regressed"):
            audit.evaluate_window(
                snapshot(10, counters={"rx_packets": 2}),
                snapshot(11, counters={"rx_packets": 1}),
                {"eth0": RULE},
                1.0,
            )

    def test_interface_replacement_is_invalid(self) -> None:
        with self.assertRaisesRegex(audit.InvalidEvidence, "identity changed"):
            audit.evaluate_window(
                snapshot(10), snapshot(11, ifindex=3), {"eth0": RULE}, 1.0
            )

    def test_boot_namespace_and_state_boundaries_are_invalid(self) -> None:
        cases = [
            (snapshot(11, boot_id="other"), "boot changed"),
            (snapshot(11, netns=11), "namespace changed"),
            (snapshot(11, state="down"), "operstate changed"),
        ]
        for after, message in cases:
            with (
                self.subTest(message=message),
                self.assertRaisesRegex(audit.InvalidEvidence, message),
            ):
                audit.evaluate_window(snapshot(10), after, {"eth0": RULE}, 1.0)

    def test_excess_sampling_drift_is_invalid(self) -> None:
        with self.assertRaisesRegex(audit.InvalidEvidence, "drift"):
            audit.evaluate_window(snapshot(10), snapshot(12), {"eth0": RULE}, 1.0)


class FilesystemTests(unittest.TestCase):
    def test_collects_only_fixed_interface_fields(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            sysfs = root / "sys/class/net"
            proc = root / "proc"
            interface = sysfs / "eth0"
            (interface / "statistics").mkdir(parents=True)
            (proc / "sys/kernel/random").mkdir(parents=True)
            (proc / "self/ns").mkdir(parents=True)
            (proc / "sys/kernel/random/boot_id").write_text(
                "11111111-1111-1111-1111-111111111111\n", encoding="ascii"
            )
            (proc / "self/ns/net").write_text("namespace", encoding="ascii")
            (interface / "ifindex").write_text("2\n", encoding="ascii")
            (interface / "operstate").write_text("up\n", encoding="ascii")
            for index, counter in enumerate(audit.COUNTERS):
                (interface / "statistics" / counter).write_text(
                    str(index), encoding="ascii"
                )

            result = audit.collect_snapshot(["eth0"], sysfs_root=sysfs, proc_root=proc)
            self.assertEqual(result.interfaces["eth0"].counters["tx_errors"], 5)
            self.assertEqual(result.boot_id, "11111111-1111-1111-1111-111111111111")

    def test_duplicate_policy_key_and_symlink_are_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            duplicate = root / "duplicate.json"
            duplicate.write_text('{"version":1,"version":1}', encoding="utf-8")
            with self.assertRaisesRegex(audit.InvalidEvidence, "duplicate"):
                audit._read_regular_json(duplicate)
            target = root / "target.json"
            target.write_text("{}", encoding="utf-8")
            link = root / "link.json"
            link.symlink_to(target)
            with self.assertRaisesRegex(audit.InvalidEvidence, "open policy safely"):
                audit._read_regular_json(link)

    def test_report_is_private_and_replaced_atomically(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "report.json"
            path.write_text("old", encoding="utf-8")
            audit._atomic_write_json(path, {"admitted": True})
            self.assertEqual(json.loads(path.read_text()), {"admitted": True})
            self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o600)
            self.assertEqual(
                [entry.name for entry in path.parent.iterdir()], ["report.json"]
            )


if __name__ == "__main__":
    unittest.main()
