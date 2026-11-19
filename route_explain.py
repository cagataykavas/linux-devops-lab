"""Collect bounded, privacy-reduced Linux policy-route diagnostics."""

from __future__ import annotations

import ipaddress
import json
import subprocess
from collections.abc import Callable, Sequence
from pathlib import Path
from typing import Any

MAX_EVIDENCE_BYTES = 64 * 1024
MAX_RULES = 256
MAX_NEXTHOP_MEMBERS = 64
TABLE_ALIASES = {"unspec": 0, "default": 253, "main": 254, "local": 255}
RULE_SELECTORS = {
    "dport",
    "dst",
    "fwmark",
    "fwmask",
    "iif",
    "iifname",
    "ipproto",
    "l3mdev",
    "not",
    "oif",
    "oifname",
    "sport",
    "src",
    "suppress_prefixlength",
    "tun_id",
    "uidrange",
}
RULE_EXPOSED_FIELDS = {"action", "priority", "protocol", "table", "type"}


class DiagnosticError(RuntimeError):
    """Raised when diagnostic evidence cannot be trusted."""


Runner = Callable[..., subprocess.CompletedProcess[str]]


def _reject_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise DiagnosticError(f"duplicate JSON field: {key}")
        result[key] = value
    return result


def _bounded_json(raw: str, *, label: str) -> Any:
    if len(raw.encode("utf-8")) > MAX_EVIDENCE_BYTES:
        raise DiagnosticError(f"{label} output exceeds the evidence limit")
    try:
        return json.loads(
            raw,
            object_pairs_hook=_reject_duplicate_keys,
            parse_constant=lambda value: (_ for _ in ()).throw(
                DiagnosticError(f"non-finite JSON number: {value}")
            ),
        )
    except json.JSONDecodeError as exc:
        raise DiagnosticError(f"{label} output is not valid JSON") from exc


def _optional_uint(
    value: Any,
    *,
    field: str,
    minimum: int = 0,
) -> int | None:
    if value is None:
        return None
    if isinstance(value, bool) or not isinstance(value, int):
        raise DiagnosticError(f"{field} must be an integer")
    if not minimum <= value <= 2**32 - 1:
        raise DiagnosticError(f"{field} must be within [{minimum}, 4294967295]")
    return value


def _table_id(value: Any) -> int | None:
    if value is None:
        return None
    if isinstance(value, str):
        if value in TABLE_ALIASES:
            return TABLE_ALIASES[value]
        if value.isdecimal():
            value = int(value)
        else:
            raise DiagnosticError("rule table name is unsupported")
    return _optional_uint(value, field="rule table")


def parse_rule_summaries(raw: str) -> list[dict[str, Any]]:
    """Parse rule JSON without retaining selector values or unknown fields."""

    payload = _bounded_json(raw, label="policy rule")
    if not isinstance(payload, list):
        raise DiagnosticError("policy rule output must be a JSON array")
    if len(payload) > MAX_RULES:
        raise DiagnosticError(f"policy rule output exceeds {MAX_RULES} entries")

    summaries: list[dict[str, Any]] = []
    for index, item in enumerate(payload):
        if not isinstance(item, dict):
            raise DiagnosticError(f"policy rule {index} must be an object")
        priority = _optional_uint(item.get("priority"), field="rule priority")
        action = item.get("action", item.get("type", "lookup"))
        if (
            not isinstance(action, str)
            or not action
            or len(action) > 32
            or action.strip() != action
        ):
            raise DiagnosticError("rule action must be a normalized string")

        selectors = sorted(
            field
            for field in RULE_SELECTORS
            if field in item and item[field] not in (None, False, "all")
        )
        represented = RULE_EXPOSED_FIELDS | RULE_SELECTORS
        summaries.append(
            {
                "action": action,
                "priority": priority,
                "selector_fields": selectors,
                "table": _table_id(item.get("table")),
                "unreported_field_count": len(set(item) - represented),
            }
        )
    return summaries


def _parse_via(value: Any) -> str | None:
    if value is None:
        return None
    if not isinstance(value, dict):
        raise DiagnosticError("nexthop via must be an object")
    family = value.get("family")
    address = value.get("addr")
    if family not in {"inet", "inet6"} or not isinstance(address, str):
        raise DiagnosticError("nexthop via must contain a supported family and address")
    try:
        parsed = ipaddress.ip_address(address)
    except ValueError as exc:
        raise DiagnosticError("nexthop via address is invalid") from exc
    expected_version = 4 if family == "inet" else 6
    if parsed.version != expected_version:
        raise DiagnosticError("nexthop via family and address differ")
    return family


def _parse_members(value: Any) -> list[dict[str, int]] | None:
    if value is None:
        return None
    if not isinstance(value, list) or not value:
        raise DiagnosticError("nexthop group must be a non-empty array")
    if len(value) > MAX_NEXTHOP_MEMBERS:
        raise DiagnosticError(f"nexthop group exceeds {MAX_NEXTHOP_MEMBERS} members")

    members: list[dict[str, int]] = []
    seen: set[int] = set()
    for member in value:
        if not isinstance(member, dict):
            raise DiagnosticError("nexthop group member must be an object")
        member_id = _optional_uint(
            member.get("id"), field="nexthop group member id", minimum=1
        )
        if member_id is None:
            raise DiagnosticError("nexthop group member id is required")
        if member_id in seen:
            raise DiagnosticError("nexthop group contains duplicate member ids")
        seen.add(member_id)
        weight = _optional_uint(
            member.get("weight", 1), field="nexthop group member weight", minimum=1
        )
        assert weight is not None
        members.append({"id": member_id, "weight": weight})
    return members


def parse_nexthop_summary(raw: str, expected_id: int) -> dict[str, Any]:
    """Parse one selected nexthop while omitting gateway addresses."""

    payload = _bounded_json(raw, label="nexthop")
    if (
        not isinstance(payload, list)
        or len(payload) != 1
        or not isinstance(payload[0], dict)
    ):
        raise DiagnosticError("nexthop output must contain exactly one object")
    item = payload[0]
    observed_id = _optional_uint(item.get("id"), field="nexthop id", minimum=1)
    if observed_id != expected_id:
        raise DiagnosticError("nexthop id does not match the selected route")

    device = item.get("dev")
    if device is not None and (
        not isinstance(device, str)
        or not device
        or len(device) > 64
        or device.strip() != device
    ):
        raise DiagnosticError("nexthop device must be a normalized string")
    blackhole = item.get("blackhole", False)
    if not isinstance(blackhole, bool):
        raise DiagnosticError("nexthop blackhole flag must be boolean")
    members = _parse_members(item.get("group"))
    via_family = _parse_via(item.get("via"))
    modes = sum((blackhole, members is not None, device is not None))
    if modes != 1:
        raise DiagnosticError(
            "nexthop must describe exactly one blackhole, group, or device"
        )

    represented = {"blackhole", "dev", "group", "id", "protocol", "via"}
    mode = "blackhole" if blackhole else "group" if members is not None else "device"
    return {
        "device": device,
        "gateway_family": via_family,
        "id": observed_id,
        "members": members,
        "mode": mode,
        "unreported_field_count": len(set(item) - represented),
    }


def _run_json(
    command: Sequence[str],
    *,
    label: str,
    timeout_seconds: float,
    runner: Runner,
) -> str:
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
        raise DiagnosticError(f"{label} lookup exceeded its deadline") from exc
    except OSError as exc:
        raise DiagnosticError(f"{label} lookup could not start") from exc
    if completed.returncode != 0:
        raise DiagnosticError(f"{label} lookup exited non-zero")
    return completed.stdout


class RouteDiagnosticCollector:
    """Cache one rule snapshot and each referenced nexthop per audit run."""

    def __init__(
        self,
        *,
        ip_command: Path,
        timeout_seconds: float,
        runner: Runner = subprocess.run,
    ) -> None:
        self._ip_command = ip_command
        self._timeout_seconds = timeout_seconds
        self._runner = runner
        self._rules_loaded = False
        self._rules: list[dict[str, Any]] | None = None
        self._rule_error: str | None = None
        self._nexthops: dict[int, tuple[dict[str, Any] | None, str | None]] = {}

    def _load_rules(self) -> None:
        if self._rules_loaded:
            return
        self._rules_loaded = True
        try:
            raw_rules = _run_json(
                (
                    str(self._ip_command),
                    "-j",
                    "rule",
                    "show",
                ),
                label="policy rule",
                timeout_seconds=self._timeout_seconds,
                runner=self._runner,
            )
            self._rules = parse_rule_summaries(raw_rules)
        except DiagnosticError as exc:
            self._rule_error = str(exc)

    def _load_nexthop(self, nexthop_id: int) -> None:
        if nexthop_id in self._nexthops:
            return
        try:
            raw_nexthop = _run_json(
                (
                    str(self._ip_command),
                    "-j",
                    "nexthop",
                    "get",
                    "id",
                    str(nexthop_id),
                ),
                label="nexthop",
                timeout_seconds=self._timeout_seconds,
                runner=self._runner,
            )
            summary = parse_nexthop_summary(raw_nexthop, nexthop_id)
            self._nexthops[nexthop_id] = (summary, None)
        except DiagnosticError as exc:
            self._nexthops[nexthop_id] = (None, str(exc))

    def collect(self, nexthop_id: int | None) -> dict[str, Any]:
        """Return cached rule context and the exact selected nexthop, if any."""

        self._load_rules()
        errors = [self._rule_error] if self._rule_error is not None else []
        nexthop: dict[str, Any] | None = None
        if nexthop_id is not None:
            self._load_nexthop(nexthop_id)
            nexthop, nexthop_error = self._nexthops[nexthop_id]
            if nexthop_error is not None:
                errors.append(nexthop_error)

        status = "complete"
        if errors:
            status = (
                "partial"
                if self._rules is not None or nexthop is not None
                else "unavailable"
            )
        return {
            "errors": errors,
            "nexthop": nexthop,
            "rules": self._rules,
            "status": status,
        }


def collect_route_diagnostics(
    *,
    ip_command: Path,
    timeout_seconds: float,
    nexthop_id: int | None,
    runner: Runner = subprocess.run,
) -> dict[str, Any]:
    """Collect one privacy-reduced diagnostic report."""

    return RouteDiagnosticCollector(
        ip_command=ip_command,
        timeout_seconds=timeout_seconds,
        runner=runner,
    ).collect(nexthop_id)
