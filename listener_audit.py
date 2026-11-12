from __future__ import annotations

import argparse
import hashlib
import ipaddress
import json
import sys
from collections import Counter
from dataclasses import dataclass
from pathlib import Path
from typing import Any

PROC_LIMIT_BYTES = 1_048_576
POLICY_LIMIT_BYTES = 65_536
MAX_PROC_ROWS = 4_096
MAX_POLICY_RULES = 256
LISTEN_STATE = "0A"
POLICY_SCHEMA = "listener-policy/v1"
EVIDENCE_SCHEMA = "listener-audit/v1"


class AuditInputError(ValueError):
    """Raised when policy or procfs evidence is malformed or unbounded."""


@dataclass(frozen=True, order=True)
class ListenerKey:
    family: str
    address: str
    port: int
    uid: int


@dataclass(frozen=True)
class PolicyRule:
    key: ListenerKey
    min_instances: int
    max_instances: int


def _canonical_json(value: Any) -> bytes:
    return json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
        allow_nan=False,
    ).encode("ascii")


def _sha256(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def _read_bounded(path: Path, limit: int) -> bytes:
    try:
        with path.open("rb") as handle:
            data = handle.read(limit + 1)
    except OSError as exc:
        raise AuditInputError(f"cannot read {path}: {exc.strerror or exc}") from exc
    if len(data) > limit:
        raise AuditInputError(f"{path} exceeds the {limit}-byte limit")
    return data


def _pairs_without_duplicates(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise AuditInputError(f"duplicate JSON field: {key}")
        result[key] = value
    return result


def _strict_keys(value: dict[str, Any], allowed: set[str], context: str) -> None:
    unknown = sorted(set(value) - allowed)
    if unknown:
        raise AuditInputError(
            f"{context} contains unknown fields: {', '.join(unknown)}"
        )


def _bounded_integer(value: Any, *, name: str, minimum: int, maximum: int) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise AuditInputError(f"{name} must be an integer")
    if not minimum <= value <= maximum:
        raise AuditInputError(f"{name} must be between {minimum} and {maximum}")
    return value


def load_policy(path: Path) -> tuple[list[PolicyRule], str]:
    raw = _read_bounded(path, POLICY_LIMIT_BYTES)
    try:
        document = json.loads(raw, object_pairs_hook=_pairs_without_duplicates)
    except (UnicodeDecodeError, json.JSONDecodeError, RecursionError) as exc:
        raise AuditInputError(f"policy is not valid JSON: {exc}") from exc

    if not isinstance(document, dict):
        raise AuditInputError("policy must be a JSON object")
    _strict_keys(document, {"schema_version", "rules"}, "policy")
    if document.get("schema_version") != POLICY_SCHEMA:
        raise AuditInputError(f"policy schema_version must be {POLICY_SCHEMA!r}")
    raw_rules = document.get("rules")
    if not isinstance(raw_rules, list):
        raise AuditInputError("policy rules must be a list")
    if len(raw_rules) > MAX_POLICY_RULES:
        raise AuditInputError(f"policy contains more than {MAX_POLICY_RULES} rules")

    rules: list[PolicyRule] = []
    seen: set[ListenerKey] = set()
    for index, raw_rule in enumerate(raw_rules):
        context = f"rule {index}"
        if not isinstance(raw_rule, dict):
            raise AuditInputError(f"{context} must be an object")
        _strict_keys(
            raw_rule,
            {"family", "address", "port", "uid", "min_instances", "max_instances"},
            context,
        )
        family = raw_rule.get("family")
        if family not in {"ipv4", "ipv6"}:
            raise AuditInputError(f"{context} family must be 'ipv4' or 'ipv6'")
        address_value = raw_rule.get("address")
        if not isinstance(address_value, str):
            raise AuditInputError(f"{context} address must be a string")
        try:
            address = ipaddress.ip_address(address_value)
        except ValueError as exc:
            raise AuditInputError(f"{context} address is invalid") from exc
        expected_version = 4 if family == "ipv4" else 6
        if address.version != expected_version:
            raise AuditInputError(f"{context} address does not match {family}")
        if address_value != str(address):
            raise AuditInputError(
                f"{context} address must use canonical form {str(address)!r}"
            )

        port = _bounded_integer(
            raw_rule.get("port"), name=f"{context} port", minimum=1, maximum=65_535
        )
        uid = _bounded_integer(
            raw_rule.get("uid"), name=f"{context} uid", minimum=0, maximum=2**32 - 1
        )
        minimum = _bounded_integer(
            raw_rule.get("min_instances", 1),
            name=f"{context} min_instances",
            minimum=0,
            maximum=1_024,
        )
        maximum = _bounded_integer(
            raw_rule.get("max_instances", 1),
            name=f"{context} max_instances",
            minimum=0,
            maximum=1_024,
        )
        if maximum < minimum:
            raise AuditInputError(f"{context} max_instances must be >= min_instances")

        key = ListenerKey(family, str(address), port, uid)
        if key in seen:
            raise AuditInputError(
                f"duplicate policy rule for {family} {address}:{port} uid {uid}"
            )
        seen.add(key)
        rules.append(PolicyRule(key, minimum, maximum))

    normalized = {
        "schema_version": POLICY_SCHEMA,
        "rules": [
            {
                "address": rule.key.address,
                "family": rule.key.family,
                "max_instances": rule.max_instances,
                "min_instances": rule.min_instances,
                "port": rule.key.port,
                "uid": rule.key.uid,
            }
            for rule in sorted(rules, key=lambda item: item.key)
        ],
    }
    return rules, _sha256(_canonical_json(normalized))


def _decode_address(value: str, family: str) -> str:
    expected_length = 8 if family == "ipv4" else 32
    if len(value) != expected_length:
        raise AuditInputError(f"invalid {family} address width")
    try:
        packed = bytes.fromhex(value)
    except ValueError as exc:
        raise AuditInputError(f"invalid hexadecimal {family} address") from exc
    if family == "ipv4":
        packed = packed[::-1]
    else:
        packed = b"".join(
            packed[offset : offset + 4][::-1] for offset in range(0, 16, 4)
        )
    return str(ipaddress.ip_address(packed))


def _decode_endpoint(value: str, family: str) -> tuple[str, int]:
    try:
        address_hex, port_hex = value.rsplit(":", 1)
    except ValueError as exc:
        raise AuditInputError("procfs endpoint is missing its port") from exc
    if len(port_hex) != 4:
        raise AuditInputError("procfs port must contain four hexadecimal digits")
    try:
        port = int(port_hex, 16)
    except ValueError as exc:
        raise AuditInputError("procfs port is not hexadecimal") from exc
    return _decode_address(address_hex, family), port


def parse_proc_net(data: bytes, family: str) -> Counter[ListenerKey]:
    if family not in {"ipv4", "ipv6"}:
        raise AuditInputError("family must be ipv4 or ipv6")
    try:
        lines = data.decode("ascii").splitlines()
    except UnicodeDecodeError as exc:
        raise AuditInputError(f"{family} procfs evidence must be ASCII") from exc
    if not lines:
        raise AuditInputError(f"{family} procfs evidence is empty")
    header = set(lines[0].split())
    required_header = {"local_address", "st", "uid", "inode"}
    has_remote_address = "rem_address" in header or "remote_address" in header
    if not required_header.issubset(header) or not has_remote_address:
        raise AuditInputError(f"{family} procfs header is incomplete")
    rows = [line for line in lines[1:] if line.strip()]
    if len(rows) > MAX_PROC_ROWS:
        raise AuditInputError(f"{family} procfs evidence exceeds {MAX_PROC_ROWS} rows")

    listeners: Counter[ListenerKey] = Counter()
    for row_number, line in enumerate(rows, start=2):
        parts = line.split()
        if len(parts) < 10:
            raise AuditInputError(f"{family} procfs row {row_number} is truncated")
        try:
            if not parts[0].endswith(":"):
                raise ValueError
            int(parts[0][:-1])
            state = parts[3].upper()
            if len(state) != 2:
                raise ValueError
            int(state, 16)
            address, port = _decode_endpoint(parts[1], family)
            _decode_endpoint(parts[2], family)
            uid = int(parts[7])
            inode = int(parts[9])
        except (ValueError, AuditInputError) as exc:
            if isinstance(exc, AuditInputError):
                detail = str(exc)
            else:
                detail = "invalid numeric field"
            raise AuditInputError(
                f"{family} procfs row {row_number}: {detail}"
            ) from exc
        if not 0 <= uid <= 2**32 - 1 or inode < 0:
            raise AuditInputError(
                f"{family} procfs row {row_number}: uid or inode out of range"
            )
        if state == LISTEN_STATE:
            if port == 0:
                raise AuditInputError(
                    f"{family} procfs row {row_number}: listener has port zero"
                )
            listeners[ListenerKey(family, address, port, uid)] += 1
    return listeners


def _exposure(address: str) -> str:
    value = ipaddress.ip_address(address)
    if value.is_unspecified:
        return "wildcard"
    if value.is_loopback:
        return "loopback"
    if value.is_link_local:
        return "link_local"
    if value.is_global:
        return "global"
    if value.is_private:
        return "private"
    return "other"


def audit_listeners(
    *,
    rules: list[PolicyRule],
    policy_sha256: str,
    tcp4: bytes,
    tcp6: bytes,
) -> dict[str, Any]:
    actual = parse_proc_net(tcp4, "ipv4") + parse_proc_net(tcp6, "ipv6")
    expected = {rule.key: rule for rule in rules}
    listeners = [
        {
            "address": key.address,
            "exposure": _exposure(key.address),
            "family": key.family,
            "instances": instances,
            "port": key.port,
            "uid": key.uid,
        }
        for key, instances in sorted(actual.items())
    ]
    findings: list[dict[str, Any]] = []
    for key, instances in sorted(actual.items()):
        rule = expected.get(key)
        endpoint = {
            "address": key.address,
            "family": key.family,
            "port": key.port,
            "uid": key.uid,
        }
        if rule is None:
            findings.append(
                {
                    "code": "unexpected_listener",
                    "endpoint": endpoint,
                    "exposure": _exposure(key.address),
                    "instances": instances,
                }
            )
        elif not rule.min_instances <= instances <= rule.max_instances:
            findings.append(
                {
                    "actual_instances": instances,
                    "code": "instance_count_out_of_range",
                    "endpoint": endpoint,
                    "max_instances": rule.max_instances,
                    "min_instances": rule.min_instances,
                }
            )
    for key, rule in sorted(expected.items()):
        if key not in actual and rule.min_instances > 0:
            findings.append(
                {
                    "code": "missing_listener",
                    "endpoint": {
                        "address": key.address,
                        "family": key.family,
                        "port": key.port,
                        "uid": key.uid,
                    },
                    "min_instances": rule.min_instances,
                }
            )

    report: dict[str, Any] = {
        "findings": findings,
        "listeners": listeners,
        "passed": not findings,
        "policy_sha256": policy_sha256,
        "schema_version": EVIDENCE_SCHEMA,
        "sources": {
            "tcp4_sha256": _sha256(tcp4),
            "tcp6_sha256": _sha256(tcp6),
        },
    }
    report["evidence_sha256"] = _sha256(_canonical_json(report))
    return report


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Audit Linux TCP listeners against an exact, UID-bound policy."
    )
    parser.add_argument("--policy", type=Path, required=True)
    parser.add_argument("--tcp4", type=Path, default=Path("/proc/net/tcp"))
    parser.add_argument("--tcp6", type=Path, default=Path("/proc/net/tcp6"))
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        rules, policy_sha256 = load_policy(args.policy)
        tcp4 = _read_bounded(args.tcp4, PROC_LIMIT_BYTES)
        tcp6 = _read_bounded(args.tcp6, PROC_LIMIT_BYTES)
        report = audit_listeners(
            rules=rules,
            policy_sha256=policy_sha256,
            tcp4=tcp4,
            tcp6=tcp6,
        )
    except AuditInputError as exc:
        print(
            json.dumps(
                {
                    "error": {"code": "invalid_input", "detail": str(exc)},
                    "passed": False,
                    "schema_version": EVIDENCE_SCHEMA,
                },
                sort_keys=True,
            )
        )
        return 3
    print(json.dumps(report, indent=2, sort_keys=True))
    return 0 if report["passed"] else 2


if __name__ == "__main__":
    sys.exit(main())
