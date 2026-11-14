from __future__ import annotations

import argparse
import hashlib
import json
import math
import os
import re
import stat
import sys
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

MAX_DOCUMENT_BYTES = 64 * 1024
MAX_EXPECTATIONS = 64
MAX_ALLOWED_VALUES = 8
MAX_AGE_SECONDS = 86_400.0

_IPV4_GLOBAL = re.compile(r"^net/ipv4/(?:ip_forward|tcp_syncookies)$")
_IPV4_INTERFACE = re.compile(
    r"^net/ipv4/conf/([A-Za-z0-9_.-]{1,15})/"
    r"(?:accept_redirects|send_redirects|accept_source_route|rp_filter|"
    r"route_localnet|log_martians)$"
)
_IPV6_INTERFACE = re.compile(
    r"^net/ipv6/conf/([A-Za-z0-9_.-]{1,15})/"
    r"(?:forwarding|accept_ra|accept_redirects|accept_source_route)$"
)


class AuditInputError(ValueError):
    """Raised when policy or evidence cannot be trusted."""


@dataclass(frozen=True)
class Expectation:
    key: str
    allowed_values: tuple[int, ...]


@dataclass(frozen=True)
class Policy:
    maximum_snapshot_age_seconds: float
    maximum_future_skew_seconds: float
    expectations: tuple[Expectation, ...]

    def as_dict(self) -> dict[str, Any]:
        return {
            "schema_version": 1,
            "maximum_snapshot_age_seconds": self.maximum_snapshot_age_seconds,
            "maximum_future_skew_seconds": self.maximum_future_skew_seconds,
            "expectations": [
                {"key": item.key, "allowed_values": list(item.allowed_values)}
                for item in self.expectations
            ],
        }


@dataclass(frozen=True)
class Snapshot:
    captured_at: datetime
    values: dict[str, int]

    def as_dict(self) -> dict[str, Any]:
        return {
            "schema_version": 1,
            "captured_at": self.captured_at.isoformat().replace("+00:00", "Z"),
            "values": dict(sorted(self.values.items())),
        }


def _reject_constant(value: str) -> None:
    raise AuditInputError(f"non-finite JSON constant is not allowed: {value}")


def _strict_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise AuditInputError(f"duplicate JSON key: {key}")
        result[key] = value
    return result


def parse_json(data: bytes) -> Any:
    if len(data) > MAX_DOCUMENT_BYTES:
        raise AuditInputError("document exceeds 65536 bytes")
    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise AuditInputError("document must be UTF-8") from exc
    try:
        return json.loads(
            text,
            object_pairs_hook=_strict_object,
            parse_constant=_reject_constant,
        )
    except json.JSONDecodeError as exc:
        raise AuditInputError("document is not valid JSON") from exc


def read_bounded(path: Path, *, maximum_bytes: int = MAX_DOCUMENT_BYTES) -> bytes:
    try:
        metadata = path.lstat()
    except OSError as exc:
        raise AuditInputError(f"cannot inspect input: {path}") from exc
    if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISREG(metadata.st_mode):
        raise AuditInputError(f"input must be a regular non-symlink file: {path}")
    if metadata.st_size > maximum_bytes:
        raise AuditInputError(f"input exceeds {maximum_bytes} bytes: {path}")

    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(path, flags)
    except OSError as exc:
        raise AuditInputError(f"cannot open input: {path}") from exc
    try:
        opened = os.fstat(descriptor)
        if not stat.S_ISREG(opened.st_mode) or (metadata.st_dev, metadata.st_ino) != (
            opened.st_dev,
            opened.st_ino,
        ):
            raise AuditInputError(f"input changed while opening: {path}")
        with os.fdopen(descriptor, "rb", closefd=False) as stream:
            data = stream.read(maximum_bytes + 1)
        if len(data) > maximum_bytes:
            raise AuditInputError(f"input exceeds {maximum_bytes} bytes: {path}")
        return data
    finally:
        os.close(descriptor)


def _read_proc_value(proc_root: Path, key: str) -> bytes:
    directory_flags = (
        os.O_RDONLY
        | getattr(os, "O_CLOEXEC", 0)
        | getattr(os, "O_NOFOLLOW", 0)
        | getattr(os, "O_DIRECTORY", 0)
    )
    file_flags = (
        os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    )
    descriptors: list[int] = []
    try:
        descriptors.append(os.open(proc_root, directory_flags))
        components = key.split("/")
        for component in components[:-1]:
            descriptors.append(
                os.open(component, directory_flags, dir_fd=descriptors[-1])
            )
        descriptor = os.open(components[-1], file_flags, dir_fd=descriptors[-1])
        descriptors.append(descriptor)
        if not stat.S_ISREG(os.fstat(descriptor).st_mode):
            raise AuditInputError(f"sysctl input is not a regular file: {key}")
        with os.fdopen(descriptor, "rb", closefd=False) as stream:
            data = stream.read(33)
        if len(data) > 32:
            raise AuditInputError(f"sysctl value exceeds 32 bytes: {key}")
        return data
    except OSError as exc:
        raise AuditInputError(
            f"cannot read sysctl through trusted directories: {key}"
        ) from exc
    finally:
        for descriptor in reversed(descriptors):
            os.close(descriptor)


def _require_exact_fields(
    document: dict[str, Any], fields: set[str], name: str
) -> None:
    missing = fields - document.keys()
    unknown = document.keys() - fields
    if missing:
        raise AuditInputError(f"{name} missing fields: {', '.join(sorted(missing))}")
    if unknown:
        raise AuditInputError(
            f"{name} has unknown fields: {', '.join(sorted(unknown))}"
        )


def _bounded_number(value: Any, name: str, *, allow_zero: bool) -> float:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise AuditInputError(f"{name} must be numeric")
    result = float(value)
    lower_ok = result >= 0 if allow_zero else result > 0
    if not math.isfinite(result) or not lower_ok or result > MAX_AGE_SECONDS:
        qualifier = "non-negative" if allow_zero else "positive"
        raise AuditInputError(f"{name} must be finite, {qualifier}, and at most 86400")
    return result


def _validate_key(key: Any) -> str:
    if not isinstance(key, str):
        raise AuditInputError("expectation key must be a string")
    match = _IPV4_GLOBAL.fullmatch(key)
    interface_match = _IPV4_INTERFACE.fullmatch(key) or _IPV6_INTERFACE.fullmatch(key)
    if match is None and interface_match is None:
        raise AuditInputError(f"unsupported network sysctl key: {key}")
    if interface_match is not None and interface_match.group(1) in {".", ".."}:
        raise AuditInputError(f"invalid interface component in key: {key}")
    return key


def _small_int(value: Any, name: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or not -2 <= value <= 2:
        raise AuditInputError(f"{name} must be an integer between -2 and 2")
    return value


def parse_policy(document: Any) -> Policy:
    if not isinstance(document, dict):
        raise AuditInputError("policy must be a JSON object")
    _require_exact_fields(
        document,
        {
            "schema_version",
            "maximum_snapshot_age_seconds",
            "maximum_future_skew_seconds",
            "expectations",
        },
        "policy",
    )
    if document["schema_version"] != 1:
        raise AuditInputError("unsupported policy schema_version")
    maximum_age = _bounded_number(
        document["maximum_snapshot_age_seconds"],
        "maximum_snapshot_age_seconds",
        allow_zero=False,
    )
    maximum_future = _bounded_number(
        document["maximum_future_skew_seconds"],
        "maximum_future_skew_seconds",
        allow_zero=True,
    )
    raw_expectations = document["expectations"]
    if (
        not isinstance(raw_expectations, list)
        or not 1 <= len(raw_expectations) <= MAX_EXPECTATIONS
    ):
        raise AuditInputError("expectations must contain between 1 and 64 entries")

    expectations: list[Expectation] = []
    seen: set[str] = set()
    for index, raw in enumerate(raw_expectations):
        if not isinstance(raw, dict):
            raise AuditInputError(f"expectation {index} must be an object")
        _require_exact_fields(raw, {"key", "allowed_values"}, f"expectation {index}")
        key = _validate_key(raw["key"])
        if key in seen:
            raise AuditInputError(f"duplicate expectation key: {key}")
        seen.add(key)
        allowed = raw["allowed_values"]
        if not isinstance(allowed, list) or not 1 <= len(allowed) <= MAX_ALLOWED_VALUES:
            raise AuditInputError(
                f"allowed_values for {key} must contain between 1 and 8 values"
            )
        normalized = tuple(
            sorted({_small_int(item, f"allowed value for {key}") for item in allowed})
        )
        if len(normalized) != len(allowed):
            raise AuditInputError(f"allowed_values for {key} contains duplicates")
        expectations.append(Expectation(key, normalized))
    return Policy(
        maximum_age,
        maximum_future,
        tuple(sorted(expectations, key=lambda item: item.key)),
    )


def _parse_timestamp(value: Any) -> datetime:
    if not isinstance(value, str) or len(value) > 35:
        raise AuditInputError("captured_at must be a bounded RFC 3339 timestamp")
    normalized = value[:-1] + "+00:00" if value.endswith("Z") else value
    try:
        parsed = datetime.fromisoformat(normalized)
    except ValueError as exc:
        raise AuditInputError("captured_at must be RFC 3339") from exc
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        raise AuditInputError("captured_at must include an offset")
    return parsed.astimezone(UTC)


def parse_snapshot(document: Any, policy: Policy) -> Snapshot:
    if not isinstance(document, dict):
        raise AuditInputError("snapshot must be a JSON object")
    _require_exact_fields(
        document, {"schema_version", "captured_at", "values"}, "snapshot"
    )
    if document["schema_version"] != 1:
        raise AuditInputError("unsupported snapshot schema_version")
    values = document["values"]
    if not isinstance(values, dict) or len(values) > MAX_EXPECTATIONS:
        raise AuditInputError("snapshot values must be a bounded object")
    normalized = {
        _validate_key(key): _small_int(value, f"snapshot value for {key}")
        for key, value in values.items()
    }
    expected_keys = {item.key for item in policy.expectations}
    actual_keys = set(normalized)
    if missing := expected_keys - actual_keys:
        raise AuditInputError(
            f"snapshot missing expected keys: {', '.join(sorted(missing))}"
        )
    if extra := actual_keys - expected_keys:
        raise AuditInputError(
            f"snapshot contains unexpected keys: {', '.join(sorted(extra))}"
        )
    return Snapshot(
        _parse_timestamp(document["captured_at"]), dict(sorted(normalized.items()))
    )


def canonical_sha256(document: dict[str, Any]) -> str:
    encoded = json.dumps(
        document, sort_keys=True, separators=(",", ":"), allow_nan=False
    ).encode()
    return hashlib.sha256(encoded).hexdigest()


def collect_snapshot(
    policy: Policy, proc_root: Path, *, now: datetime | None = None
) -> Snapshot:
    captured_at = (now or datetime.now(UTC)).astimezone(UTC)
    values: dict[str, int] = {}
    for expectation in policy.expectations:
        raw = _read_proc_value(proc_root, expectation.key).strip()
        try:
            text = raw.decode("ascii")
            value = int(text)
        except (UnicodeDecodeError, ValueError) as exc:
            raise AuditInputError(
                f"sysctl value is not an integer: {expectation.key}"
            ) from exc
        if text != str(value):
            raise AuditInputError(f"sysctl value is not canonical: {expectation.key}")
        values[expectation.key] = _small_int(
            value, f"sysctl value for {expectation.key}"
        )
    return Snapshot(captured_at, dict(sorted(values.items())))


def evaluate(
    policy: Policy, snapshot: Snapshot, *, now: datetime | None = None
) -> dict[str, Any]:
    assessed_at = (now or datetime.now(UTC)).astimezone(UTC)
    age_seconds = (assessed_at - snapshot.captured_at).total_seconds()
    violations: list[dict[str, Any]] = []
    if age_seconds > policy.maximum_snapshot_age_seconds:
        violations.append(
            {
                "code": "snapshot_stale",
                "age_seconds": age_seconds,
                "maximum_seconds": policy.maximum_snapshot_age_seconds,
            }
        )
    elif age_seconds < -policy.maximum_future_skew_seconds:
        violations.append(
            {
                "code": "snapshot_from_future",
                "skew_seconds": -age_seconds,
                "maximum_seconds": policy.maximum_future_skew_seconds,
            }
        )
    for expectation in policy.expectations:
        actual = snapshot.values[expectation.key]
        if actual not in expectation.allowed_values:
            violations.append(
                {
                    "code": "value_not_allowed",
                    "key": expectation.key,
                    "actual": actual,
                    "allowed_values": list(expectation.allowed_values),
                }
            )
    return {
        "schema_version": 1,
        "ok": not violations,
        "assessed_at": assessed_at.isoformat().replace("+00:00", "Z"),
        "snapshot_age_seconds": max(0.0, age_seconds),
        "checked_expectations": len(policy.expectations),
        "policy_sha256": canonical_sha256(policy.as_dict()),
        "snapshot_sha256": canonical_sha256(snapshot.as_dict()),
        "violations": violations,
    }


def write_json(document: dict[str, Any], output: Path | None) -> None:
    payload = (
        json.dumps(document, sort_keys=True, indent=2, allow_nan=False) + "\n"
    ).encode()
    if output is None:
        sys.stdout.buffer.write(payload)
        return
    output.parent.mkdir(parents=True, exist_ok=True)
    temporary = output.with_name(f".{output.name}.tmp-{os.getpid()}")
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_CLOEXEC", 0)
    descriptor = os.open(temporary, flags, 0o600)
    try:
        with os.fdopen(descriptor, "wb", closefd=False) as stream:
            stream.write(payload)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, output)
    finally:
        os.close(descriptor)
        try:
            temporary.unlink()
        except FileNotFoundError:
            pass


def _load_policy(path: Path) -> Policy:
    return parse_policy(parse_json(read_bounded(path)))


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Collect and audit Linux network sysctls"
    )
    subparsers = parser.add_subparsers(dest="command", required=True)
    collect = subparsers.add_parser(
        "collect", help="collect only policy-requested sysctls"
    )
    collect.add_argument("--policy", type=Path, required=True)
    collect.add_argument("--proc-root", type=Path, default=Path("/proc/sys"))
    collect.add_argument("--output", type=Path)
    verify = subparsers.add_parser("verify", help="verify a captured snapshot")
    verify.add_argument("--policy", type=Path, required=True)
    verify.add_argument("--snapshot", type=Path, required=True)
    verify.add_argument("--output", type=Path)
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        policy = _load_policy(args.policy)
        if args.command == "collect":
            snapshot = collect_snapshot(policy, args.proc_root)
            write_json(snapshot.as_dict(), args.output)
            return 0
        snapshot = parse_snapshot(parse_json(read_bounded(args.snapshot)), policy)
        report = evaluate(policy, snapshot)
        write_json(report, args.output)
        return 0 if report["ok"] else 3
    except (AuditInputError, OSError):
        error = {
            "schema_version": 1,
            "ok": False,
            "error": "invalid_or_unreadable_input",
        }
        try:
            write_json(error, getattr(args, "output", None))
        except OSError:
            sys.stderr.write("network sysctl audit could not write its error report\n")
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
