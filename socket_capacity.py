"""Collect and audit Linux socket-capacity evidence without privileged commands."""

from __future__ import annotations

import argparse
import hashlib
import json
import math
import os
import stat
from dataclasses import asdict, dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

SNAPSHOT_SCHEMA = "linux-socket-capacity-snapshot/v1"
REPORT_SCHEMA = "linux-socket-capacity-report/v1"
MAX_INPUT_BYTES = 64 * 1024
MAX_RESERVED_RANGES = 1024


class EvidenceError(ValueError):
    """Raised when evidence cannot be safely parsed or normalized."""


@dataclass(frozen=True)
class AuditPolicy:
    max_evidence_age_seconds: int = 300
    max_future_skew_seconds: int = 30
    min_usable_ephemeral_ports: int = 16_384
    max_ephemeral_pressure: float = 0.70
    max_conntrack_utilization: float = 0.80
    max_tcp_orphans: int = 4_096
    min_somaxconn: int = 4_096
    min_tcp_max_syn_backlog: int = 4_096
    require_syncookies: bool = True

    def __post_init__(self) -> None:
        integer_values = (
            self.max_evidence_age_seconds,
            self.max_future_skew_seconds,
            self.min_usable_ephemeral_ports,
            self.max_tcp_orphans,
            self.min_somaxconn,
            self.min_tcp_max_syn_backlog,
        )
        if any(
            isinstance(value, bool) or not isinstance(value, int) or value < 0
            for value in integer_values
        ):
            raise ValueError("integer policy thresholds must be non-negative integers")
        if self.min_usable_ephemeral_ports < 1:
            raise ValueError("min_usable_ephemeral_ports must be positive")
        for name, value in (
            ("max_ephemeral_pressure", self.max_ephemeral_pressure),
            ("max_conntrack_utilization", self.max_conntrack_utilization),
        ):
            if not math.isfinite(value) or not 0.0 <= value <= 1.0:
                raise ValueError(f"{name} must be finite and in [0, 1]")


@dataclass(frozen=True)
class Finding:
    code: str
    message: str


@dataclass(frozen=True)
class SocketSnapshot:
    captured_at: datetime
    ephemeral_first: int
    ephemeral_last: int
    reserved_ranges: tuple[tuple[int, int], ...]
    tcp_inuse: int
    tcp_orphan: int
    tcp_time_wait: int
    tcp_allocated: int
    conntrack_count: int
    conntrack_max: int
    somaxconn: int
    tcp_max_syn_backlog: int
    tcp_syncookies: int

    @classmethod
    def from_dict(cls, values: dict[str, Any]) -> SocketSnapshot:
        expected = {
            "schema_version",
            "captured_at",
            "ephemeral_port_range",
            "reserved_port_ranges",
            "tcp",
            "conntrack",
            "listen_backlog",
        }
        if set(values) != expected:
            raise EvidenceError("snapshot keys do not match the schema")
        if values["schema_version"] != SNAPSHOT_SCHEMA:
            raise EvidenceError("unsupported snapshot schema")
        captured_at = _parse_timestamp(values["captured_at"])
        port_range = _exact_mapping(
            values["ephemeral_port_range"], {"first", "last"}, "ephemeral_port_range"
        )
        tcp = _exact_mapping(values["tcp"], {"inuse", "orphan", "time_wait", "allocated"}, "tcp")
        conntrack = _exact_mapping(values["conntrack"], {"count", "max"}, "conntrack")
        backlog = _exact_mapping(
            values["listen_backlog"],
            {"somaxconn", "tcp_max_syn_backlog", "syncookies"},
            "listen_backlog",
        )
        ranges = _normalize_ranges(values["reserved_port_ranges"])
        snapshot = cls(
            captured_at=captured_at,
            ephemeral_first=_integer(port_range["first"], "ephemeral_port_range.first"),
            ephemeral_last=_integer(port_range["last"], "ephemeral_port_range.last"),
            reserved_ranges=ranges,
            tcp_inuse=_integer(tcp["inuse"], "tcp.inuse"),
            tcp_orphan=_integer(tcp["orphan"], "tcp.orphan"),
            tcp_time_wait=_integer(tcp["time_wait"], "tcp.time_wait"),
            tcp_allocated=_integer(tcp["allocated"], "tcp.allocated"),
            conntrack_count=_integer(conntrack["count"], "conntrack.count"),
            conntrack_max=_integer(conntrack["max"], "conntrack.max"),
            somaxconn=_integer(backlog["somaxconn"], "listen_backlog.somaxconn"),
            tcp_max_syn_backlog=_integer(
                backlog["tcp_max_syn_backlog"], "listen_backlog.tcp_max_syn_backlog"
            ),
            tcp_syncookies=_integer(backlog["syncookies"], "listen_backlog.syncookies"),
        )
        snapshot.validate()
        return snapshot

    def validate(self) -> None:
        if not 1 <= self.ephemeral_first <= self.ephemeral_last <= 65_535:
            raise EvidenceError("ephemeral port range must be inside [1, 65535]")
        if self.conntrack_max < 1 or self.conntrack_count > self.conntrack_max:
            raise EvidenceError("conntrack counts are inconsistent")
        if self.tcp_allocated < self.tcp_inuse:
            raise EvidenceError("TCP allocated sockets cannot be below in-use sockets")
        if self.tcp_syncookies not in {0, 1}:
            raise EvidenceError("tcp_syncookies must be 0 or 1")

    def canonical_dict(self) -> dict[str, Any]:
        return {
            "schema_version": SNAPSHOT_SCHEMA,
            "captured_at": self.captured_at.astimezone(UTC).isoformat().replace("+00:00", "Z"),
            "ephemeral_port_range": {
                "first": self.ephemeral_first,
                "last": self.ephemeral_last,
            },
            "reserved_port_ranges": [list(item) for item in self.reserved_ranges],
            "tcp": {
                "inuse": self.tcp_inuse,
                "orphan": self.tcp_orphan,
                "time_wait": self.tcp_time_wait,
                "allocated": self.tcp_allocated,
            },
            "conntrack": {"count": self.conntrack_count, "max": self.conntrack_max},
            "listen_backlog": {
                "somaxconn": self.somaxconn,
                "tcp_max_syn_backlog": self.tcp_max_syn_backlog,
                "syncookies": self.tcp_syncookies,
            },
        }


def _integer(value: Any, field: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        raise EvidenceError(f"{field} must be a non-negative integer")
    return value


def _exact_mapping(value: Any, keys: set[str], field: str) -> dict[str, Any]:
    if not isinstance(value, dict) or set(value) != keys:
        raise EvidenceError(f"{field} keys do not match the schema")
    return value


def _parse_timestamp(value: Any) -> datetime:
    if not isinstance(value, str):
        raise EvidenceError("captured_at must be an ISO-8601 string")
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as error:
        raise EvidenceError("captured_at is not valid ISO-8601") from error
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        raise EvidenceError("captured_at must include a timezone")
    return parsed.astimezone(UTC)


def _normalize_ranges(value: Any) -> tuple[tuple[int, int], ...]:
    if not isinstance(value, list) or len(value) > MAX_RESERVED_RANGES:
        raise EvidenceError("reserved_port_ranges must be a bounded list")
    ranges: list[tuple[int, int]] = []
    for index, item in enumerate(value):
        if not isinstance(item, list) or len(item) != 2:
            raise EvidenceError(f"reserved_port_ranges[{index}] must be [first, last]")
        first = _integer(item[0], f"reserved_port_ranges[{index}].first")
        last = _integer(item[1], f"reserved_port_ranges[{index}].last")
        if not 1 <= first <= last <= 65_535:
            raise EvidenceError(f"reserved_port_ranges[{index}] is outside [1, 65535]")
        ranges.append((first, last))
    ranges.sort()
    if any(
        current[0] <= previous[1] for previous, current in zip(ranges, ranges[1:], strict=False)
    ):
        raise EvidenceError("reserved port ranges must not overlap")
    return tuple(ranges)


def _read_proc(root: Path, relative: str, *, allow_empty: bool = False) -> str:
    path = root / relative
    metadata = path.stat(follow_symlinks=False)
    if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISREG(metadata.st_mode):
        raise EvidenceError(f"{relative} must be a regular, non-symlink procfs entry")
    payload = path.read_bytes()
    if len(payload) > 4_096:
        raise EvidenceError(f"{relative} exceeds the 4096-byte read budget")
    try:
        text = payload.decode("ascii").strip()
    except UnicodeDecodeError as error:
        raise EvidenceError(f"{relative} is not ASCII") from error
    if not text and not allow_empty:
        raise EvidenceError(f"{relative} is empty")
    return text


def _single_integer(root: Path, relative: str) -> int:
    raw = _read_proc(root, relative)
    try:
        value = int(raw)
    except ValueError as error:
        raise EvidenceError(f"{relative} must contain one integer") from error
    return _integer(value, relative)


def _parse_sockstat(raw: str) -> dict[str, int]:
    tcp_line = next((line for line in raw.splitlines() if line.startswith("TCP:")), None)
    if tcp_line is None:
        raise EvidenceError("net/sockstat is missing its TCP line")
    tokens = tcp_line.removeprefix("TCP:").split()
    if len(tokens) % 2:
        raise EvidenceError("net/sockstat TCP line must contain key/value pairs")
    values: dict[str, int] = {}
    for key, raw_value in zip(tokens[::2], tokens[1::2], strict=True):
        if key in values:
            raise EvidenceError(f"net/sockstat contains duplicate TCP field: {key}")
        try:
            values[key] = _integer(int(raw_value), f"net/sockstat.{key}")
        except ValueError as error:
            raise EvidenceError(f"net/sockstat field {key} is not an integer") from error
    required = {"inuse", "orphan", "tw", "alloc"}
    if not required <= values.keys():
        raise EvidenceError("net/sockstat is missing required TCP fields")
    return values


def _parse_reserved_ports(raw: str) -> tuple[tuple[int, int], ...]:
    if not raw:
        return ()
    ranges: list[list[int]] = []
    try:
        for item in raw.split(","):
            bounds = item.split("-")
            if len(bounds) == 1:
                ranges.append([int(bounds[0]), int(bounds[0])])
            elif len(bounds) == 2:
                ranges.append([int(bounds[0]), int(bounds[1])])
            else:
                raise ValueError
    except ValueError as error:
        raise EvidenceError("ip_local_reserved_ports has invalid range syntax") from error
    return _normalize_ranges(ranges)


def collect_snapshot(
    proc_root: Path = Path("/proc"), captured_at: datetime | None = None
) -> SocketSnapshot:
    port_tokens = _read_proc(proc_root, "sys/net/ipv4/ip_local_port_range").split()
    if len(port_tokens) != 2:
        raise EvidenceError("ip_local_port_range must contain exactly two integers")
    try:
        ephemeral_first, ephemeral_last = map(int, port_tokens)
    except ValueError as error:
        raise EvidenceError("ip_local_port_range must contain exactly two integers") from error
    tcp = _parse_sockstat(_read_proc(proc_root, "net/sockstat"))
    return SocketSnapshot.from_dict(
        {
            "schema_version": SNAPSHOT_SCHEMA,
            "captured_at": (captured_at or datetime.now(UTC)).isoformat(),
            "ephemeral_port_range": {"first": ephemeral_first, "last": ephemeral_last},
            "reserved_port_ranges": [
                list(item)
                for item in _parse_reserved_ports(
                    _read_proc(proc_root, "sys/net/ipv4/ip_local_reserved_ports", allow_empty=True)
                )
            ],
            "tcp": {
                "inuse": tcp["inuse"],
                "orphan": tcp["orphan"],
                "time_wait": tcp["tw"],
                "allocated": tcp["alloc"],
            },
            "conntrack": {
                "count": _single_integer(proc_root, "sys/net/netfilter/nf_conntrack_count"),
                "max": _single_integer(proc_root, "sys/net/netfilter/nf_conntrack_max"),
            },
            "listen_backlog": {
                "somaxconn": _single_integer(proc_root, "sys/net/core/somaxconn"),
                "tcp_max_syn_backlog": _single_integer(
                    proc_root, "sys/net/ipv4/tcp_max_syn_backlog"
                ),
                "syncookies": _single_integer(proc_root, "sys/net/ipv4/tcp_syncookies"),
            },
        }
    )


def _usable_ephemeral_ports(snapshot: SocketSnapshot) -> int:
    total = snapshot.ephemeral_last - snapshot.ephemeral_first + 1
    reserved = 0
    for first, last in snapshot.reserved_ranges:
        overlap_first = max(first, snapshot.ephemeral_first)
        overlap_last = min(last, snapshot.ephemeral_last)
        if overlap_first <= overlap_last:
            reserved += overlap_last - overlap_first + 1
    return total - reserved


def audit_snapshot(
    snapshot: SocketSnapshot,
    policy: AuditPolicy | None = None,
    now: datetime | None = None,
) -> dict[str, Any]:
    snapshot.validate()
    policy = policy or AuditPolicy()
    evaluated_at = (now or datetime.now(UTC)).astimezone(UTC)
    usable_ports = _usable_ephemeral_ports(snapshot)
    if usable_ports < 1:
        raise EvidenceError("reserved ranges consume the entire ephemeral port range")
    ephemeral_pressure = min(1.0, (snapshot.tcp_inuse + snapshot.tcp_time_wait) / usable_ports)
    conntrack_utilization = snapshot.conntrack_count / snapshot.conntrack_max
    findings: list[Finding] = []

    age = evaluated_at - snapshot.captured_at
    if age < -timedelta(seconds=policy.max_future_skew_seconds):
        findings.append(Finding("TIME001", "snapshot timestamp exceeds allowed future skew"))
    elif age > timedelta(seconds=policy.max_evidence_age_seconds):
        findings.append(Finding("TIME002", "snapshot is older than the evidence-age budget"))
    if usable_ports < policy.min_usable_ephemeral_ports:
        findings.append(Finding("PORT001", "usable ephemeral port capacity is below policy"))
    if ephemeral_pressure > policy.max_ephemeral_pressure:
        findings.append(Finding("PORT002", "ephemeral port pressure proxy exceeds policy"))
    if conntrack_utilization > policy.max_conntrack_utilization:
        findings.append(Finding("CT001", "conntrack utilization exceeds policy"))
    if snapshot.tcp_orphan > policy.max_tcp_orphans:
        findings.append(Finding("TCP001", "orphan socket count exceeds policy"))
    if snapshot.somaxconn < policy.min_somaxconn:
        findings.append(Finding("BACKLOG001", "somaxconn is below policy"))
    if snapshot.tcp_max_syn_backlog < policy.min_tcp_max_syn_backlog:
        findings.append(Finding("BACKLOG002", "TCP SYN backlog is below policy"))
    if policy.require_syncookies and snapshot.tcp_syncookies != 1:
        findings.append(Finding("SYN001", "TCP SYN cookies are disabled"))
    findings.sort(key=lambda item: item.code)

    snapshot_canonical = json.dumps(
        snapshot.canonical_dict(), sort_keys=True, separators=(",", ":"), allow_nan=False
    ).encode()
    report: dict[str, Any] = {
        "schema_version": REPORT_SCHEMA,
        "status": "accepted" if not findings else "rejected",
        "evaluated_at": evaluated_at.isoformat().replace("+00:00", "Z"),
        "snapshot_sha256": hashlib.sha256(snapshot_canonical).hexdigest(),
        "policy": asdict(policy),
        "metrics": {
            "usable_ephemeral_ports": usable_ports,
            "ephemeral_pressure": ephemeral_pressure,
            "conntrack_utilization": conntrack_utilization,
            "tcp_orphans": snapshot.tcp_orphan,
            "somaxconn": snapshot.somaxconn,
            "tcp_max_syn_backlog": snapshot.tcp_max_syn_backlog,
            "syncookies": snapshot.tcp_syncookies,
        },
        "findings": [asdict(item) for item in findings],
        "limitations": [
            "The ephemeral-pressure metric is a conservative host proxy, not per-destination "
            "tuple accounting.",
            "A single procfs snapshot can miss short spikes and does not include NAT gateway "
            "capacity.",
        ],
    }
    canonical = json.dumps(report, sort_keys=True, separators=(",", ":"), allow_nan=False).encode()
    report["evidence_sha256"] = hashlib.sha256(canonical).hexdigest()
    return report


def _reject_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    values: dict[str, Any] = {}
    for key, value in pairs:
        if key in values:
            raise EvidenceError(f"duplicate JSON key: {key}")
        values[key] = value
    return values


def _reject_constant(value: str) -> None:
    raise EvidenceError(f"non-finite JSON value: {value}")


def load_snapshot(path: Path) -> SocketSnapshot:
    metadata = path.stat(follow_symlinks=False)
    if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISREG(metadata.st_mode):
        raise EvidenceError("snapshot must be a regular, non-symlink file")
    if metadata.st_size > MAX_INPUT_BYTES:
        raise EvidenceError(f"snapshot exceeds the {MAX_INPUT_BYTES}-byte budget")
    try:
        values = json.loads(
            path.read_bytes(),
            object_pairs_hook=_reject_duplicate_keys,
            parse_constant=_reject_constant,
        )
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise EvidenceError("snapshot is not valid JSON") from error
    if not isinstance(values, dict):
        raise EvidenceError("snapshot root must be an object")
    return SocketSnapshot.from_dict(values)


def _atomic_write(path: Path, values: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(f".{path.name}.{os.getpid()}.tmp")
    temporary.write_text(
        json.dumps(values, indent=2, sort_keys=True, allow_nan=False) + "\n",
        encoding="utf-8",
    )
    temporary.replace(path)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Collect and audit Linux socket capacity")
    subparsers = parser.add_subparsers(dest="command", required=True)
    collect_parser = subparsers.add_parser("collect")
    collect_parser.add_argument("--proc-root", type=Path, default=Path("/proc"))
    collect_parser.add_argument("--output", type=Path, required=True)
    audit_parser = subparsers.add_parser("audit")
    audit_parser.add_argument("--input", type=Path, required=True)
    audit_parser.add_argument("--output", type=Path, required=True)
    audit_parser.add_argument("--max-ephemeral-pressure", type=float, default=0.70)
    audit_parser.add_argument("--max-conntrack-utilization", type=float, default=0.80)
    audit_parser.add_argument("--min-usable-ephemeral-ports", type=int, default=16_384)
    values = parser.parse_args(argv)
    try:
        if values.command == "collect":
            snapshot = collect_snapshot(values.proc_root)
            _atomic_write(values.output, snapshot.canonical_dict())
            print(json.dumps({"status": "collected", "output": str(values.output)}))
            return 0
        policy = AuditPolicy(
            max_ephemeral_pressure=values.max_ephemeral_pressure,
            max_conntrack_utilization=values.max_conntrack_utilization,
            min_usable_ephemeral_ports=values.min_usable_ephemeral_ports,
        )
        report = audit_snapshot(load_snapshot(values.input), policy)
        _atomic_write(values.output, report)
    except (EvidenceError, OSError, TypeError, ValueError) as error:
        print(json.dumps({"status": "malformed", "error": str(error)}))
        return 2
    print(json.dumps({"status": report["status"], "evidence_sha256": report["evidence_sha256"]}))
    return 0 if report["status"] == "accepted" else 3


if __name__ == "__main__":
    raise SystemExit(main())
