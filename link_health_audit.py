"""Bounded, non-root audit of Linux link error and drop counters."""

from __future__ import annotations

import argparse
import fcntl
import hashlib
import json
import math
import os
import re
import socket
import stat
import struct
import tempfile
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any

MAX_POLICY_BYTES = 64 * 1024
MAX_PROC_NET_DEV_BYTES = 256 * 1024
MAX_INTERFACES = 32
MIN_INTERVAL_SECONDS = 0.05
MAX_INTERVAL_SECONDS = 60.0
MAX_SAMPLE_DRIFT_RATIO = 0.5
COUNTERS = (
    "rx_packets",
    "tx_packets",
    "rx_dropped",
    "tx_dropped",
    "rx_errors",
    "tx_errors",
)
INTERFACE_RE = re.compile(r"[A-Za-z0-9_.:-]{1,15}\Z")
RULE_FIELDS = {
    "max_rx_errors_per_second",
    "max_tx_errors_per_second",
    "max_rx_drop_ratio",
    "max_tx_drop_ratio",
    "min_rx_packets_for_ratio",
    "min_tx_packets_for_ratio",
    "require_operstate_up",
}


class InvalidEvidence(ValueError):
    """Input cannot be trusted or interpreted."""


@dataclass(frozen=True)
class InterfaceSnapshot:
    ifindex: int
    operstate: str
    counters: dict[str, int]


@dataclass(frozen=True)
class Snapshot:
    monotonic_seconds: float
    boot_id: str
    netns_inode: int
    interfaces: dict[str, InterfaceSnapshot]


def _reject_constant(value: str) -> None:
    raise InvalidEvidence(f"non-finite JSON value: {value}")


def _unique_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise InvalidEvidence(f"duplicate JSON field: {key}")
        result[key] = value
    return result


def _read_regular_json(path: Path) -> tuple[dict[str, Any], bytes]:
    try:
        descriptor = os.open(path, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW)
    except OSError as exc:
        raise InvalidEvidence(f"cannot open policy safely: {exc.strerror}") from exc
    try:
        with os.fdopen(descriptor, "rb") as handle:
            metadata = os.fstat(handle.fileno())
            if not stat.S_ISREG(metadata.st_mode):
                raise InvalidEvidence("policy must be a regular, non-symlink file")
            if metadata.st_size > MAX_POLICY_BYTES:
                raise InvalidEvidence("policy exceeds size limit")
            raw = handle.read(MAX_POLICY_BYTES + 1)
    except OSError as exc:
        raise InvalidEvidence(f"cannot read policy: {exc.strerror}") from exc
    if len(raw) > MAX_POLICY_BYTES:
        raise InvalidEvidence("policy exceeds size limit")
    try:
        value = json.loads(
            raw,
            object_pairs_hook=_unique_object,
            parse_constant=_reject_constant,
        )
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise InvalidEvidence("policy is not valid UTF-8 JSON") from exc
    if not isinstance(value, dict):
        raise InvalidEvidence("policy root must be an object")
    return value, raw


def _bounded_number(value: Any, field: str, minimum: float, maximum: float) -> float:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise InvalidEvidence(f"{field} must be numeric")
    number = float(value)
    if not math.isfinite(number) or not minimum <= number <= maximum:
        raise InvalidEvidence(f"{field} must be between {minimum} and {maximum}")
    return number


def validate_policy(value: dict[str, Any]) -> dict[str, dict[str, Any]]:
    if set(value) != {"version", "interfaces"} or value.get("version") != 1:
        raise InvalidEvidence("policy requires only version=1 and interfaces")
    interfaces = value.get("interfaces")
    if not isinstance(interfaces, dict) or not 1 <= len(interfaces) <= MAX_INTERFACES:
        raise InvalidEvidence(f"interfaces must contain 1..{MAX_INTERFACES} entries")

    normalized: dict[str, dict[str, Any]] = {}
    for name, rule in interfaces.items():
        if (
            not isinstance(name, str)
            or not INTERFACE_RE.fullmatch(name)
            or name in {".", ".."}
        ):
            raise InvalidEvidence(f"invalid interface name: {name!r}")
        if not isinstance(rule, dict) or set(rule) != RULE_FIELDS:
            raise InvalidEvidence(f"{name}: rule fields do not match the schema")
        require_up = rule["require_operstate_up"]
        if not isinstance(require_up, bool):
            raise InvalidEvidence(f"{name}: require_operstate_up must be boolean")
        normalized[name] = {
            "max_rx_errors_per_second": _bounded_number(
                rule["max_rx_errors_per_second"],
                f"{name}.max_rx_errors_per_second",
                0,
                1e9,
            ),
            "max_tx_errors_per_second": _bounded_number(
                rule["max_tx_errors_per_second"],
                f"{name}.max_tx_errors_per_second",
                0,
                1e9,
            ),
            "max_rx_drop_ratio": _bounded_number(
                rule["max_rx_drop_ratio"], f"{name}.max_rx_drop_ratio", 0, 1
            ),
            "max_tx_drop_ratio": _bounded_number(
                rule["max_tx_drop_ratio"], f"{name}.max_tx_drop_ratio", 0, 1
            ),
            "min_rx_packets_for_ratio": int(
                _bounded_number(
                    rule["min_rx_packets_for_ratio"],
                    f"{name}.min_rx_packets_for_ratio",
                    0,
                    1e12,
                )
            ),
            "min_tx_packets_for_ratio": int(
                _bounded_number(
                    rule["min_tx_packets_for_ratio"],
                    f"{name}.min_tx_packets_for_ratio",
                    0,
                    1e12,
                )
            ),
            "require_operstate_up": require_up,
        }
        for key in ("min_rx_packets_for_ratio", "min_tx_packets_for_ratio"):
            original = rule[key]
            if isinstance(original, float) and not original.is_integer():
                raise InvalidEvidence(f"{name}.{key} must be an integer")
    return normalized


def _read_small_text(path: Path, field: str, *, limit: int = 64) -> str:
    try:
        raw = path.read_bytes()
    except OSError as exc:
        raise InvalidEvidence(f"cannot read {field}: {exc.strerror}") from exc
    if len(raw) > limit:
        raise InvalidEvidence(f"{field} exceeds size limit")
    try:
        return raw.decode("ascii").strip()
    except UnicodeDecodeError as exc:
        raise InvalidEvidence(f"{field} is not ASCII") from exc


def _parse_proc_net_dev(raw: str) -> dict[str, dict[str, int]]:
    lines = raw.splitlines()
    if len(lines) < 2 or "Receive" not in lines[0] or "packets" not in lines[1]:
        raise InvalidEvidence("proc_net_dev headers are malformed")
    interfaces: dict[str, dict[str, int]] = {}
    for line in lines[2:]:
        if not line.strip():
            continue
        name_text, separator, values_text = line.rpartition(":")
        name = name_text.strip()
        values = values_text.split()
        if not separator or not INTERFACE_RE.fullmatch(name) or name in {".", ".."}:
            raise InvalidEvidence("proc_net_dev contains an invalid interface name")
        if name in interfaces:
            raise InvalidEvidence(f"proc_net_dev contains duplicate interface: {name}")
        if len(values) != 16 or any(not value.isdecimal() for value in values):
            raise InvalidEvidence(f"{name}: proc_net_dev counters are malformed")
        numbers = [int(value) for value in values]
        interfaces[name] = {
            "rx_packets": numbers[1],
            "rx_errors": numbers[2],
            "rx_dropped": numbers[3],
            "tx_packets": numbers[9],
            "tx_errors": numbers[10],
            "tx_dropped": numbers[11],
        }
    return interfaces


def _interface_identity(name: str) -> tuple[int, str]:
    try:
        ifindex = socket.if_nametoindex(name)
        request = struct.pack("16sH14x", name.encode("ascii"), 0)
        socket_type = socket.SOCK_DGRAM | getattr(socket, "SOCK_CLOEXEC", 0)
        with socket.socket(socket.AF_INET, socket_type) as control:
            response = fcntl.ioctl(control.fileno(), 0x8913, request)  # SIOCGIFFLAGS
        _, flags = struct.unpack("16sH14x", response)
    except (OSError, UnicodeEncodeError) as exc:
        detail = exc.strerror if isinstance(exc, OSError) else "non-ASCII name"
        raise InvalidEvidence(f"cannot inspect {name} identity: {detail}") from exc
    if ifindex <= 0:
        raise InvalidEvidence(f"{name}: interface index is invalid")
    if flags & 0x1 and flags & 0x40:  # IFF_UP and IFF_RUNNING
        operstate = "up"
    elif flags & 0x1:
        operstate = "lowerlayerdown"
    else:
        operstate = "down"
    return ifindex, operstate


def collect_snapshot(
    interface_names: list[str], *, proc_root: Path = Path("/proc")
) -> Snapshot:
    boot_id = _read_small_text(proc_root / "sys/kernel/random/boot_id", "boot_id")
    if not re.fullmatch(r"[0-9a-f]{8}-[0-9a-f-]{27}", boot_id):
        raise InvalidEvidence("boot_id is malformed")
    try:
        netns_inode = (proc_root / "self/ns/net").stat().st_ino
    except OSError as exc:
        raise InvalidEvidence(
            f"cannot inspect network namespace: {exc.strerror}"
        ) from exc

    identities: dict[str, tuple[int, str]] = {}
    for name in interface_names:
        if not INTERFACE_RE.fullmatch(name) or name in {".", ".."}:
            raise InvalidEvidence(f"invalid interface name: {name!r}")
        identities[name] = _interface_identity(name)
    raw_table = _read_small_text(
        proc_root / "net/dev", "proc_net_dev", limit=MAX_PROC_NET_DEV_BYTES
    )
    table = _parse_proc_net_dev(raw_table)
    interfaces: dict[str, InterfaceSnapshot] = {}
    for name in interface_names:
        if name not in table:
            raise InvalidEvidence(f"{name}: interface is absent from proc_net_dev")
        after_identity = _interface_identity(name)
        if identities[name] != after_identity:
            raise InvalidEvidence(f"{name}: interface changed while counters were read")
        interfaces[name] = InterfaceSnapshot(*identities[name], table[name])

    return Snapshot(time.monotonic(), boot_id, netns_inode, interfaces)


def evaluate_window(
    before: Snapshot,
    after: Snapshot,
    policy: dict[str, dict[str, Any]],
    requested_interval: float,
) -> dict[str, Any]:
    elapsed = after.monotonic_seconds - before.monotonic_seconds
    if before.boot_id != after.boot_id:
        raise InvalidEvidence("boot changed during sampling")
    if before.netns_inode != after.netns_inode:
        raise InvalidEvidence("network namespace changed during sampling")
    if set(before.interfaces) != set(policy) or set(after.interfaces) != set(policy):
        raise InvalidEvidence("snapshot interface set does not match policy")
    if not math.isfinite(elapsed) or elapsed <= 0:
        raise InvalidEvidence("sampling clock did not advance")
    if abs(elapsed - requested_interval) > requested_interval * MAX_SAMPLE_DRIFT_RATIO:
        raise InvalidEvidence("sampling interval drift exceeded budget")

    admitted = True
    results: dict[str, Any] = {}
    for name in sorted(policy):
        start = before.interfaces[name]
        end = after.interfaces[name]
        rule = policy[name]
        if start.ifindex != end.ifindex:
            raise InvalidEvidence(f"{name}: interface identity changed")
        if start.operstate != end.operstate:
            raise InvalidEvidence(f"{name}: operstate changed during sampling")
        deltas: dict[str, int] = {}
        for counter in COUNTERS:
            delta = end.counters[counter] - start.counters[counter]
            if delta < 0:
                raise InvalidEvidence(f"{name}.{counter}: counter regressed")
            deltas[counter] = delta

        rx_total = deltas["rx_packets"] + deltas["rx_dropped"]
        tx_total = deltas["tx_packets"] + deltas["tx_dropped"]
        rx_ratio = deltas["rx_dropped"] / rx_total if rx_total else 0.0
        tx_ratio = deltas["tx_dropped"] / tx_total if tx_total else 0.0
        rx_error_rate = deltas["rx_errors"] / elapsed
        tx_error_rate = deltas["tx_errors"] / elapsed
        reasons: list[str] = []
        if rule["require_operstate_up"] and end.operstate != "up":
            reasons.append("operstate_not_up")
        if rx_error_rate > rule["max_rx_errors_per_second"]:
            reasons.append("rx_error_rate_exceeded")
        if tx_error_rate > rule["max_tx_errors_per_second"]:
            reasons.append("tx_error_rate_exceeded")
        if (
            rx_total >= rule["min_rx_packets_for_ratio"]
            and rx_ratio > rule["max_rx_drop_ratio"]
        ):
            reasons.append("rx_drop_ratio_exceeded")
        if (
            tx_total >= rule["min_tx_packets_for_ratio"]
            and tx_ratio > rule["max_tx_drop_ratio"]
        ):
            reasons.append("tx_drop_ratio_exceeded")
        if reasons:
            admitted = False
        results[name] = {
            "ifindex": end.ifindex,
            "operstate": end.operstate,
            "deltas": deltas,
            "rx_drop_ratio": rx_ratio
            if rx_total >= rule["min_rx_packets_for_ratio"]
            else None,
            "tx_drop_ratio": tx_ratio
            if tx_total >= rule["min_tx_packets_for_ratio"]
            else None,
            "rx_errors_per_second": rx_error_rate,
            "tx_errors_per_second": tx_error_rate,
            "reasons": reasons,
        }
    return {"admitted": admitted, "elapsed_seconds": elapsed, "interfaces": results}


def _atomic_write_json(path: Path, payload: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    descriptor, temporary = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    try:
        os.fchmod(descriptor, 0o600)
        with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
            json.dump(payload, handle, sort_keys=True, separators=(",", ":"))
            handle.write("\n")
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, path)
    except Exception:
        try:
            os.unlink(temporary)
        except FileNotFoundError:
            pass
        raise


def run(args: argparse.Namespace) -> int:
    try:
        interval = _bounded_number(
            args.interval, "interval", MIN_INTERVAL_SECONDS, MAX_INTERVAL_SECONDS
        )
        raw_policy, policy_bytes = _read_regular_json(args.policy)
        policy = validate_policy(raw_policy)
        before = collect_snapshot(list(policy), proc_root=args.proc_root)
        time.sleep(interval)
        after = collect_snapshot(list(policy), proc_root=args.proc_root)
        decision = evaluate_window(before, after, policy, interval)
        report = {
            "schema_version": 1,
            "policy_sha256": hashlib.sha256(policy_bytes).hexdigest(),
            **decision,
        }
        _atomic_write_json(args.report, report)
        return 0 if decision["admitted"] else 3
    except InvalidEvidence as exc:
        print(f"invalid evidence: {exc}", file=os.sys.stderr)
        return 2
    except OSError as exc:
        print(f"audit failed: {exc.strerror}", file=os.sys.stderr)
        return 2


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--policy", type=Path, required=True)
    parser.add_argument("--report", type=Path, required=True)
    parser.add_argument("--interval", type=float, default=1.0)
    parser.add_argument(
        "--proc-root", type=Path, default=Path("/proc"), help=argparse.SUPPRESS
    )
    return parser


if __name__ == "__main__":
    raise SystemExit(run(build_parser().parse_args()))
