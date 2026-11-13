"""Fail-closed verification of Linux route snapshots against egress intent."""

from __future__ import annotations

import argparse
import ipaddress
import json
import os
import stat
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any

MAX_INPUT_BYTES = 1_048_576
MAX_ROUTES = 4_096
MAX_DESTINATIONS = 256
TERMINAL_ROUTE_TYPES = {"blackhole", "prohibit", "unreachable"}


class ValidationError(ValueError):
    """Raised when an input cannot be interpreted safely."""


def _reject_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValidationError(f"duplicate JSON key: {key}")
        result[key] = value
    return result


def load_json(path: Path) -> Any:
    """Load a bounded, regular, non-symlink JSON file with strict constants."""

    try:
        metadata = path.lstat()
    except OSError as exc:
        raise ValidationError(f"cannot inspect {path}: {exc}") from exc
    if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISREG(metadata.st_mode):
        raise ValidationError(f"input must be a regular, non-symlink file: {path}")
    if metadata.st_size > MAX_INPUT_BYTES:
        raise ValidationError(f"input exceeds {MAX_INPUT_BYTES} bytes: {path}")
    try:
        flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
        descriptor = os.open(path, flags)
        with os.fdopen(descriptor, encoding="utf-8") as handle:
            opened_metadata = os.fstat(handle.fileno())
            if not stat.S_ISREG(opened_metadata.st_mode):
                raise ValidationError(f"input must remain a regular file: {path}")
            if opened_metadata.st_size > MAX_INPUT_BYTES:
                raise ValidationError(f"input exceeds {MAX_INPUT_BYTES} bytes: {path}")
            raw = handle.read(MAX_INPUT_BYTES + 1)
        if len(raw.encode("utf-8")) > MAX_INPUT_BYTES:
            raise ValidationError(f"input exceeds {MAX_INPUT_BYTES} bytes: {path}")
        return json.loads(
            raw,
            object_pairs_hook=_reject_duplicate_keys,
            parse_constant=lambda value: (_ for _ in ()).throw(
                ValidationError(f"non-finite JSON number: {value}")
            ),
        )
    except UnicodeDecodeError as exc:
        raise ValidationError(f"input is not UTF-8: {path}") from exc
    except json.JSONDecodeError as exc:
        raise ValidationError(f"invalid JSON in {path}: {exc.msg}") from exc
    except OSError as exc:
        raise ValidationError(f"cannot safely read {path}: {exc}") from exc


def _require_string(value: Any, field: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise ValidationError(f"{field} must be a non-empty string")
    return value


@dataclass(frozen=True)
class Route:
    network: ipaddress.IPv4Network | ipaddress.IPv6Network
    device: str | None
    gateway: ipaddress.IPv4Address | ipaddress.IPv6Address | None
    metric: int
    route_type: str

    def evidence(self) -> dict[str, Any]:
        return {
            "destination": str(self.network),
            "device": self.device,
            "gateway": str(self.gateway) if self.gateway else None,
            "metric": self.metric,
            "type": self.route_type,
        }


@dataclass(frozen=True)
class DestinationIntent:
    name: str
    address: ipaddress.IPv4Address | ipaddress.IPv6Address
    allowed_devices: frozenset[str]
    allowed_gateways: frozenset[ipaddress.IPv4Address | ipaddress.IPv6Address] | None


def _parse_family(value: Any, field: str) -> int:
    if value == "inet":
        return 4
    if value == "inet6":
        return 6
    raise ValidationError(f"{field} must be 'inet' or 'inet6'")


def parse_routes(payload: Any) -> list[Route]:
    if not isinstance(payload, list):
        raise ValidationError("route snapshot must be a JSON array")
    if len(payload) > MAX_ROUTES:
        raise ValidationError(f"route snapshot exceeds {MAX_ROUTES} entries")

    routes: list[Route] = []
    for index, item in enumerate(payload):
        field = f"routes[{index}]"
        if not isinstance(item, dict):
            raise ValidationError(f"{field} must be an object")
        table = item.get("table", "main")
        if table not in ("main", 254):
            raise ValidationError(f"{field}.table must be main/254")
        destination = _require_string(item.get("dst"), f"{field}.dst")
        gateway_raw = item.get("gateway")
        if gateway_raw is not None:
            gateway_raw = _require_string(gateway_raw, f"{field}.gateway")
        try:
            gateway = ipaddress.ip_address(gateway_raw) if gateway_raw is not None else None
        except ValueError as exc:
            raise ValidationError(f"{field}.gateway is not an IP address") from exc

        if destination == "default":
            if gateway is not None:
                version = gateway.version
            else:
                version = _parse_family(item.get("family"), f"{field}.family")
            network = ipaddress.ip_network("0.0.0.0/0" if version == 4 else "::/0")
        else:
            try:
                network = ipaddress.ip_network(destination, strict=False)
            except ValueError as exc:
                raise ValidationError(f"{field}.dst is not a valid prefix") from exc
        if gateway is not None and gateway.version != network.version:
            raise ValidationError(f"{field}.gateway family differs from destination")

        metric = item.get("metric", 0)
        if isinstance(metric, bool) or not isinstance(metric, int) or metric < 0:
            raise ValidationError(f"{field}.metric must be a non-negative integer")
        route_type = item.get("type", "unicast")
        if route_type not in {"unicast", *TERMINAL_ROUTE_TYPES}:
            raise ValidationError(f"{field}.type is unsupported: {route_type}")
        device_raw = item.get("dev")
        device = _require_string(device_raw, f"{field}.dev") if device_raw is not None else None
        if route_type == "unicast" and device is None:
            raise ValidationError(f"{field}.dev is required for unicast routes")
        routes.append(Route(network, device, gateway, metric, route_type))
    return routes


def _parse_string_set(value: Any, field: str) -> frozenset[str]:
    if not isinstance(value, list) or not value:
        raise ValidationError(f"{field} must be a non-empty array")
    parsed = frozenset(_require_string(item, field) for item in value)
    if len(parsed) != len(value):
        raise ValidationError(f"{field} must not contain duplicates")
    return parsed


def parse_policy(payload: Any) -> list[DestinationIntent]:
    if not isinstance(payload, dict):
        raise ValidationError("policy must be a JSON object")
    destinations = payload.get("destinations")
    if not isinstance(destinations, list) or not destinations:
        raise ValidationError("policy.destinations must be a non-empty array")
    if len(destinations) > MAX_DESTINATIONS:
        raise ValidationError(f"policy exceeds {MAX_DESTINATIONS} destinations")

    intents: list[DestinationIntent] = []
    names: set[str] = set()
    for index, item in enumerate(destinations):
        field = f"destinations[{index}]"
        if not isinstance(item, dict):
            raise ValidationError(f"{field} must be an object")
        name = _require_string(item.get("name"), f"{field}.name")
        if name in names:
            raise ValidationError(f"duplicate destination name: {name}")
        names.add(name)
        address_raw = _require_string(item.get("address"), f"{field}.address")
        try:
            address = ipaddress.ip_address(address_raw)
        except ValueError as exc:
            raise ValidationError(f"{field}.address must be an IP address") from exc
        devices = _parse_string_set(item.get("allowed_devices"), f"{field}.allowed_devices")

        gateways_raw = item.get("allowed_gateways")
        gateways = None
        if gateways_raw is not None:
            if not isinstance(gateways_raw, list) or not gateways_raw:
                raise ValidationError(f"{field}.allowed_gateways must be a non-empty array")
            parsed_gateways = []
            for gateway_index, gateway_raw in enumerate(gateways_raw):
                gateway_raw = _require_string(
                    gateway_raw, f"{field}.allowed_gateways[{gateway_index}]"
                )
                try:
                    gateway = ipaddress.ip_address(gateway_raw)
                except ValueError as exc:
                    raise ValidationError(
                        f"{field}.allowed_gateways contains an invalid IP address"
                    ) from exc
                if gateway.version != address.version:
                    raise ValidationError(f"{field}.allowed_gateways family mismatch")
                parsed_gateways.append(gateway)
            gateways = frozenset(parsed_gateways)
            if len(gateways) != len(gateways_raw):
                raise ValidationError(f"{field}.allowed_gateways must not contain duplicates")
        intents.append(DestinationIntent(name, address, devices, gateways))
    return intents


def verify(routes: list[Route], intents: list[DestinationIntent]) -> dict[str, Any]:
    checks: list[dict[str, Any]] = []
    for intent in intents:
        candidates = [
            route
            for route in routes
            if route.network.version == intent.address.version and intent.address in route.network
        ]
        if not candidates:
            checks.append(
                {
                    "address": str(intent.address),
                    "name": intent.name,
                    "reason": "no matching route",
                    "route": None,
                    "status": "fail",
                }
            )
            continue
        best_prefix = max(route.network.prefixlen for route in candidates)
        candidates = [route for route in candidates if route.network.prefixlen == best_prefix]
        best_metric = min(route.metric for route in candidates)
        winners = [route for route in candidates if route.metric == best_metric]
        if len(winners) != 1:
            checks.append(
                {
                    "address": str(intent.address),
                    "name": intent.name,
                    "reason": "ambiguous equal-precedence routes are unsupported",
                    "route": None,
                    "status": "fail",
                }
            )
            continue
        route = winners[0]
        reason = "route matches approved intent"
        status = "pass"
        if route.route_type in TERMINAL_ROUTE_TYPES:
            reason = f"selected route is {route.route_type}"
            status = "fail"
        elif route.device not in intent.allowed_devices:
            reason = f"device {route.device!r} is not approved"
            status = "fail"
        elif intent.allowed_gateways is not None and route.gateway not in intent.allowed_gateways:
            gateway = str(route.gateway) if route.gateway else "direct"
            reason = f"gateway {gateway!r} is not approved"
            status = "fail"
        checks.append(
            {
                "address": str(intent.address),
                "name": intent.name,
                "reason": reason,
                "route": route.evidence(),
                "status": status,
            }
        )
    return {"checks": checks, "ok": all(check["status"] == "pass" for check in checks)}


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--routes", required=True, type=Path, help="ip -j route snapshot")
    parser.add_argument("--policy", required=True, type=Path, help="route intent policy")
    args = parser.parse_args(argv)
    try:
        routes = parse_routes(load_json(args.routes))
        policy = parse_policy(load_json(args.policy))
        report = verify(routes, policy)
    except ValidationError as exc:
        print(f"route_guard: {exc}", file=sys.stderr)
        return 2
    print(json.dumps(report, indent=2, sort_keys=True))
    return 0 if report["ok"] else 2


if __name__ == "__main__":
    raise SystemExit(main())
