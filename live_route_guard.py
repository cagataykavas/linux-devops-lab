"""Verify Linux kernel route decisions against reviewed destination intent."""

from __future__ import annotations

import argparse
import ipaddress
import json
import os
import stat
import subprocess
import sys
from collections.abc import Callable, Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from route_guard import DestinationIntent, ValidationError, load_json, parse_policy

MAX_LOOKUP_BYTES = 64 * 1024
DEFAULT_IP_COMMAND = Path("/usr/bin/ip")
TABLE_ALIASES = {"default": 253, "main": 254, "local": 255}
TERMINAL_ROUTE_TYPES = {"blackhole", "prohibit", "throw", "unreachable"}


class LookupError(RuntimeError):
    """Raised when kernel route evidence cannot be trusted."""


@dataclass(frozen=True, slots=True)
class KernelRoute:
    address: ipaddress.IPv4Address | ipaddress.IPv6Address
    device: str
    gateway: ipaddress.IPv4Address | ipaddress.IPv6Address | None
    preferred_source: ipaddress.IPv4Address | ipaddress.IPv6Address | None
    table: int
    route_type: str

    def evidence(self) -> dict[str, Any]:
        return {
            "address": str(self.address),
            "device": self.device,
            "gateway": str(self.gateway) if self.gateway else None,
            "preferred_source": str(self.preferred_source)
            if self.preferred_source
            else None,
            "table": self.table,
            "type": self.route_type,
        }


Runner = Callable[..., subprocess.CompletedProcess[str]]


def _reject_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise LookupError(f"duplicate JSON field: {key}")
        result[key] = value
    return result


def _bounded_json(raw: str) -> Any:
    if len(raw.encode("utf-8")) > MAX_LOOKUP_BYTES:
        raise LookupError("kernel route output exceeds the evidence limit")
    try:
        return json.loads(
            raw,
            object_pairs_hook=_reject_duplicate_keys,
            parse_constant=lambda value: (_ for _ in ()).throw(
                LookupError(f"non-finite JSON number: {value}")
            ),
        )
    except json.JSONDecodeError as exc:
        raise LookupError("kernel route output is not valid JSON") from exc


def _parse_table(value: Any) -> int:
    if value is None:
        return 254
    if isinstance(value, bool):
        raise LookupError("kernel route table must be a name or integer")
    if isinstance(value, str):
        if value in TABLE_ALIASES:
            return TABLE_ALIASES[value]
        if value.isdecimal():
            value = int(value)
        else:
            raise LookupError("kernel route table name is unsupported")
    if not isinstance(value, int) or not 1 <= value <= 2**32 - 1:
        raise LookupError("kernel route table must be within [1, 4294967295]")
    return value


def _parse_optional_ip(
    value: Any,
    *,
    field: str,
    version: int,
) -> ipaddress.IPv4Address | ipaddress.IPv6Address | None:
    if value is None:
        return None
    if not isinstance(value, str):
        raise LookupError(f"kernel route {field} must be an IP address")
    try:
        parsed = ipaddress.ip_address(value)
    except ValueError as exc:
        raise LookupError(f"kernel route {field} must be an IP address") from exc
    if parsed.version != version:
        raise LookupError(f"kernel route {field} family differs from destination")
    return parsed


def parse_kernel_route(
    raw: str, expected: ipaddress.IPv4Address | ipaddress.IPv6Address
) -> KernelRoute:
    payload = _bounded_json(raw)
    if (
        not isinstance(payload, list)
        or len(payload) != 1
        or not isinstance(payload[0], dict)
    ):
        raise LookupError("kernel route output must contain exactly one route object")
    item = payload[0]
    destination = item.get("dst")
    if not isinstance(destination, str):
        raise LookupError("kernel route destination is missing")
    try:
        observed = ipaddress.ip_address(destination)
    except ValueError as exc:
        raise LookupError("kernel route destination must be an IP address") from exc
    if observed != expected:
        raise LookupError(
            "kernel route destination does not match the requested address"
        )

    device = item.get("dev")
    if not isinstance(device, str) or not device or device.strip() != device:
        raise LookupError("kernel route device must be a normalized non-empty string")
    route_type = item.get("type", "unicast")
    if not isinstance(route_type, str) or route_type not in {
        "unicast",
        *TERMINAL_ROUTE_TYPES,
    }:
        raise LookupError("kernel route type is unsupported")

    return KernelRoute(
        address=observed,
        device=device,
        gateway=_parse_optional_ip(
            item.get("gateway"), field="gateway", version=expected.version
        ),
        preferred_source=_parse_optional_ip(
            item.get("prefsrc"), field="preferred source", version=expected.version
        ),
        table=_parse_table(item.get("table")),
        route_type=route_type,
    )


def validate_ip_command(path: Path) -> Path:
    if not path.is_absolute():
        raise ValidationError("ip command path must be absolute")
    try:
        metadata = path.lstat()
    except OSError as exc:
        raise ValidationError(f"cannot inspect ip command: {exc}") from exc
    if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISREG(metadata.st_mode):
        raise ValidationError("ip command must be a regular, non-symlink file")
    if not os.access(path, os.X_OK):
        raise ValidationError("ip command must be executable")
    return path


def _lookup(
    intent: DestinationIntent,
    *,
    ip_command: Path,
    timeout_seconds: float,
    runner: Runner,
) -> KernelRoute:
    command: Sequence[str] = (
        str(ip_command),
        "-j",
        "route",
        "get",
        str(intent.address),
    )
    try:
        completed = runner(
            command,
            capture_output=True,
            check=False,
            env={"LC_ALL": "C", "PATH": "/usr/bin:/bin"},
            text=True,
            timeout=timeout_seconds,
        )
    except subprocess.TimeoutExpired as exc:
        raise LookupError("kernel route lookup exceeded its deadline") from exc
    except OSError as exc:
        raise LookupError("kernel route lookup could not start") from exc
    if completed.returncode != 0:
        raise LookupError("kernel route lookup exited non-zero")
    return parse_kernel_route(completed.stdout, intent.address)


def audit_live_routes(
    intents: list[DestinationIntent],
    *,
    ip_command: Path = DEFAULT_IP_COMMAND,
    timeout_seconds: float = 2.0,
    runner: Runner = subprocess.run,
) -> dict[str, Any]:
    if isinstance(timeout_seconds, bool) or not isinstance(
        timeout_seconds, (int, float)
    ):
        raise ValidationError("lookup timeout must be numeric")
    if not 0.1 <= timeout_seconds <= 10.0:
        raise ValidationError("lookup timeout must be within [0.1, 10] seconds")

    checks: list[dict[str, Any]] = []
    for intent in intents:
        try:
            route = _lookup(
                intent,
                ip_command=ip_command,
                timeout_seconds=float(timeout_seconds),
                runner=runner,
            )
        except LookupError as exc:
            checks.append(
                {
                    "address": str(intent.address),
                    "name": intent.name,
                    "reason": str(exc),
                    "route": None,
                    "status": "fail",
                }
            )
            continue

        status = "pass"
        reason = "kernel route matches approved intent"
        if route.route_type in TERMINAL_ROUTE_TYPES:
            status = "fail"
            reason = f"kernel selected a {route.route_type} route"
        elif route.device not in intent.allowed_devices:
            status = "fail"
            reason = f"device {route.device!r} is not approved"
        elif (
            intent.allowed_gateways is not None
            and route.gateway not in intent.allowed_gateways
        ):
            status = "fail"
            gateway = str(route.gateway) if route.gateway else "direct"
            reason = f"gateway {gateway!r} is not approved"
        checks.append(
            {
                "address": str(intent.address),
                "name": intent.name,
                "reason": reason,
                "route": route.evidence(),
                "status": status,
            }
        )
    return {
        "checks": checks,
        "mode": "kernel-route-get",
        "ok": bool(checks) and all(check["status"] == "pass" for check in checks),
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--policy", required=True, type=Path, help="route intent policy"
    )
    parser.add_argument("--ip-command", type=Path, default=DEFAULT_IP_COMMAND)
    parser.add_argument("--timeout-seconds", type=float, default=2.0)
    args = parser.parse_args(argv)
    try:
        intents = parse_policy(load_json(args.policy))
        ip_command = validate_ip_command(args.ip_command)
        report = audit_live_routes(
            intents,
            ip_command=ip_command,
            timeout_seconds=args.timeout_seconds,
        )
    except ValidationError as exc:
        print(f"live_route_guard: {exc}", file=sys.stderr)
        return 2
    print(json.dumps(report, indent=2, sort_keys=True))
    return 0 if report["ok"] else 2


if __name__ == "__main__":
    raise SystemExit(main())
