"""Bounded audit of short-window Linux TCP retransmission health."""

from __future__ import annotations

import argparse
import hashlib
import json
import math
import os
import re
import stat
import sys
import tempfile
import time
from dataclasses import asdict, dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Callable, Sequence

MAX_SOURCE_BYTES = 1_048_576
MAX_COUNTER = 2**64 - 1
REQUIRED_COUNTERS = ("OutSegs", "RetransSegs", "EstabResets")
BOOT_ID_PATTERN = re.compile(
    r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$"
)


@dataclass(frozen=True, slots=True)
class TcpHealthPolicy:
    sample_seconds: float = 5.0
    minimum_out_segments: int = 100
    maximum_retransmission_ratio: float = 0.02
    maximum_established_resets_per_second: float = 1.0

    def __post_init__(self) -> None:
        if (
            isinstance(self.sample_seconds, bool)
            or not isinstance(self.sample_seconds, (int, float))
            or not math.isfinite(self.sample_seconds)
            or not 0.1 <= self.sample_seconds <= 300.0
        ):
            raise ValueError("sample_seconds must be finite and within [0.1, 300]")
        if (
            isinstance(self.minimum_out_segments, bool)
            or not isinstance(self.minimum_out_segments, int)
            or not 1 <= self.minimum_out_segments <= 1_000_000_000
        ):
            raise ValueError("minimum_out_segments must be within [1, 1000000000]")
        if (
            isinstance(self.maximum_retransmission_ratio, bool)
            or not isinstance(self.maximum_retransmission_ratio, (int, float))
            or not math.isfinite(self.maximum_retransmission_ratio)
            or not 0.0 <= self.maximum_retransmission_ratio <= 1.0
        ):
            raise ValueError(
                "maximum_retransmission_ratio must be finite and within [0, 1]"
            )
        if (
            isinstance(self.maximum_established_resets_per_second, bool)
            or not isinstance(self.maximum_established_resets_per_second, (int, float))
            or not math.isfinite(self.maximum_established_resets_per_second)
            or not 0.0 <= self.maximum_established_resets_per_second <= 1_000_000.0
        ):
            raise ValueError(
                "maximum_established_resets_per_second must be finite and within "
                "[0, 1000000]"
            )


@dataclass(frozen=True, slots=True)
class TcpSnapshot:
    boot_id: str
    captured_at: str
    monotonic_ns: int
    out_segments: int
    retransmitted_segments: int
    established_resets: int


@dataclass(frozen=True, slots=True)
class TcpHealthReport:
    decision: str
    finding_codes: tuple[str, ...]
    elapsed_seconds: float
    out_segments: int
    retransmitted_segments: int
    established_resets: int
    retransmission_ratio: float | None
    established_resets_per_second: float
    policy: TcpHealthPolicy
    first_snapshot: TcpSnapshot
    second_snapshot: TcpSnapshot
    evidence_digest: str

    def to_dict(self) -> dict[str, object]:
        return asdict(self)


def _read_bounded_text(path: Path, maximum_bytes: int = MAX_SOURCE_BYTES) -> str:
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    descriptor = os.open(path, flags)
    try:
        metadata = os.fstat(descriptor)
        if not stat.S_ISREG(metadata.st_mode):
            raise ValueError(f"source is not a regular file: {path}")
        chunks: list[bytes] = []
        total = 0
        while total <= maximum_bytes:
            chunk = os.read(descriptor, min(65_536, maximum_bytes + 1 - total))
            if not chunk:
                break
            chunks.append(chunk)
            total += len(chunk)
        if total > maximum_bytes:
            raise ValueError(f"source exceeds {maximum_bytes} bytes: {path}")
        return b"".join(chunks).decode("ascii", errors="strict")
    finally:
        os.close(descriptor)


def parse_tcp_counters(text: str) -> dict[str, int]:
    if not isinstance(text, str):
        raise TypeError("SNMP evidence must be text")
    if len(text.encode("utf-8")) > MAX_SOURCE_BYTES:
        raise ValueError("SNMP evidence exceeds the byte limit")
    tcp_lines = [line.split() for line in text.splitlines() if line.startswith("Tcp:")]
    if len(tcp_lines) != 2:
        raise ValueError("SNMP evidence must contain exactly one TCP header/value pair")
    headers = tcp_lines[0][1:]
    values = tcp_lines[1][1:]
    if not headers or len(headers) != len(values):
        raise ValueError("TCP header and value columns must be non-empty and aligned")
    if len(headers) != len(set(headers)):
        raise ValueError("TCP counter names must be unique")

    parsed: dict[str, int] = {}
    for name in REQUIRED_COUNTERS:
        if name not in headers:
            raise ValueError(f"required TCP counter is missing: {name}")
        raw_value = values[headers.index(name)]
        if not raw_value.isdecimal():
            raise ValueError(f"TCP counter {name} must be an unsigned decimal integer")
        value = int(raw_value)
        if value > MAX_COUNTER:
            raise ValueError(f"TCP counter {name} exceeds the unsigned 64-bit range")
        parsed[name] = value
    return parsed


def capture_snapshot(
    snmp_path: Path = Path("/proc/net/snmp"),
    boot_id_path: Path = Path("/proc/sys/kernel/random/boot_id"),
    *,
    monotonic_ns: Callable[[], int] = time.monotonic_ns,
    wall_clock: Callable[[], datetime] = lambda: datetime.now(UTC),
) -> TcpSnapshot:
    counters = parse_tcp_counters(_read_bounded_text(snmp_path))
    boot_id = _read_bounded_text(boot_id_path, maximum_bytes=128).strip().lower()
    if not BOOT_ID_PATTERN.fullmatch(boot_id):
        raise ValueError("boot ID must be a canonical lowercase UUID")
    captured_at = wall_clock()
    if captured_at.tzinfo is None or captured_at.utcoffset() is None:
        raise ValueError("wall clock must return a timezone-aware datetime")
    observed_monotonic_ns = monotonic_ns()
    if (
        isinstance(observed_monotonic_ns, bool)
        or not isinstance(observed_monotonic_ns, int)
        or observed_monotonic_ns < 0
    ):
        raise ValueError("monotonic clock must return a non-negative integer")
    return TcpSnapshot(
        boot_id=boot_id,
        captured_at=captured_at.astimezone(UTC).isoformat().replace("+00:00", "Z"),
        monotonic_ns=observed_monotonic_ns,
        out_segments=counters["OutSegs"],
        retransmitted_segments=counters["RetransSegs"],
        established_resets=counters["EstabResets"],
    )


def _evidence_digest(
    first: TcpSnapshot, second: TcpSnapshot, policy: TcpHealthPolicy
) -> str:
    payload = {
        "schema_version": 1,
        "first_snapshot": asdict(first),
        "second_snapshot": asdict(second),
        "policy": asdict(policy),
    }
    canonical = json.dumps(
        payload, sort_keys=True, separators=(",", ":"), allow_nan=False
    ).encode("utf-8")
    return hashlib.sha256(canonical).hexdigest()


def evaluate_tcp_health(
    first: TcpSnapshot, second: TcpSnapshot, policy: TcpHealthPolicy
) -> TcpHealthReport:
    if not isinstance(first, TcpSnapshot) or not isinstance(second, TcpSnapshot):
        raise TypeError("first and second must be TcpSnapshot values")
    if not isinstance(policy, TcpHealthPolicy):
        raise TypeError("policy must be a TcpHealthPolicy")
    if first.boot_id != second.boot_id:
        raise ValueError("snapshots cross a host boot boundary")
    elapsed_ns = second.monotonic_ns - first.monotonic_ns
    if elapsed_ns <= 0:
        raise ValueError("snapshot monotonic time must increase")
    elapsed_seconds = elapsed_ns / 1_000_000_000
    if (
        not 0.5 * policy.sample_seconds
        <= elapsed_seconds
        <= 2.0 * policy.sample_seconds
    ):
        raise ValueError("observed sample interval is outside the policy tolerance")

    deltas = {
        "out_segments": second.out_segments - first.out_segments,
        "retransmitted_segments": (
            second.retransmitted_segments - first.retransmitted_segments
        ),
        "established_resets": second.established_resets - first.established_resets,
    }
    regressed = [name for name, value in deltas.items() if value < 0]
    if regressed:
        raise ValueError(f"TCP counters regressed: {', '.join(regressed)}")

    retransmission_ratio = (
        deltas["retransmitted_segments"] / deltas["out_segments"]
        if deltas["out_segments"]
        else None
    )
    reset_rate = deltas["established_resets"] / elapsed_seconds
    findings: list[str] = []
    if deltas["out_segments"] < policy.minimum_out_segments:
        findings.append("insufficient_outbound_traffic")
        decision = "insufficient_evidence"
    else:
        if (
            retransmission_ratio is not None
            and retransmission_ratio > policy.maximum_retransmission_ratio
        ):
            findings.append("retransmission_ratio_exceeded")
        if reset_rate > policy.maximum_established_resets_per_second:
            findings.append("established_reset_rate_exceeded")
        decision = "fail" if findings else "pass"

    return TcpHealthReport(
        decision=decision,
        finding_codes=tuple(findings),
        elapsed_seconds=elapsed_seconds,
        out_segments=deltas["out_segments"],
        retransmitted_segments=deltas["retransmitted_segments"],
        established_resets=deltas["established_resets"],
        retransmission_ratio=retransmission_ratio,
        established_resets_per_second=reset_rate,
        policy=policy,
        first_snapshot=first,
        second_snapshot=second,
        evidence_digest=_evidence_digest(first, second, policy),
    )


def sample_tcp_health(
    policy: TcpHealthPolicy,
    *,
    snmp_path: Path = Path("/proc/net/snmp"),
    boot_id_path: Path = Path("/proc/sys/kernel/random/boot_id"),
    sleeper: Callable[[float], None] | None = None,
) -> TcpHealthReport:
    first = capture_snapshot(snmp_path, boot_id_path)
    (sleeper or time.sleep)(policy.sample_seconds)
    second = capture_snapshot(snmp_path, boot_id_path)
    return evaluate_tcp_health(first, second, policy)


def _write_atomic(path: Path, payload: dict[str, object]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    descriptor, temporary_name = tempfile.mkstemp(
        prefix=f".{path.name}.", dir=path.parent
    )
    try:
        os.fchmod(descriptor, 0o600)
        with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
            json.dump(payload, handle, indent=2, sort_keys=True, allow_nan=False)
            handle.write("\n")
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary_name, path)
        directory = os.open(path.parent, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
        try:
            os.fsync(directory)
        finally:
            os.close(directory)
    except Exception:
        try:
            os.unlink(temporary_name)
        except FileNotFoundError:
            pass
        raise


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Audit short-window Linux TCP retransmission health"
    )
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--sample-seconds", type=float, default=5.0)
    parser.add_argument("--minimum-out-segments", type=int, default=100)
    parser.add_argument("--maximum-retransmission-ratio", type=float, default=0.02)
    parser.add_argument(
        "--maximum-established-resets-per-second", type=float, default=1.0
    )
    parser.add_argument("--snmp-path", type=Path, default=Path("/proc/net/snmp"))
    parser.add_argument(
        "--boot-id-path",
        type=Path,
        default=Path("/proc/sys/kernel/random/boot_id"),
    )
    args = parser.parse_args(argv)

    try:
        policy = TcpHealthPolicy(
            sample_seconds=args.sample_seconds,
            minimum_out_segments=args.minimum_out_segments,
            maximum_retransmission_ratio=args.maximum_retransmission_ratio,
            maximum_established_resets_per_second=(
                args.maximum_established_resets_per_second
            ),
        )
        report = sample_tcp_health(
            policy, snmp_path=args.snmp_path, boot_id_path=args.boot_id_path
        )
        _write_atomic(args.output, report.to_dict())
    except (OSError, TypeError, UnicodeError, ValueError) as exc:
        print(f"TCP health audit failed: {exc}", file=sys.stderr)
        return 3
    return 0 if report.decision == "pass" else 2


if __name__ == "__main__":
    raise SystemExit(main())
