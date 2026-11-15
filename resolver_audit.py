"""Offline admission control for Linux resolv.conf policy."""

from __future__ import annotations

import argparse
import ipaddress
import json
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any

SCALAR_LIMITS = {"attempts": (1, 5), "ndots": (0, 15), "timeout": (1, 30)}
DOMAIN_PATTERN = re.compile(
    r"(?=^.{1,253}\.?$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)*"
    r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.?$"
)


class EvidenceError(ValueError):
    """The resolver evidence is ambiguous or malformed."""


def _strict_integer(value: Any, field: str, *, minimum: int, maximum: int) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or not minimum <= value <= maximum:
        raise ValueError(f"{field} must be an integer from {minimum} to {maximum}")
    return value


def _domain(value: str, field: str) -> str:
    normalized = value.lower().rstrip(".")
    if not normalized or not DOMAIN_PATTERN.fullmatch(normalized):
        raise EvidenceError(f"{field} is not a valid DNS name")
    return normalized


@dataclass(frozen=True)
class ResolverConfig:
    nameservers: tuple[ipaddress.IPv4Address | ipaddress.IPv6Address, ...]
    search_domains: tuple[str, ...]
    scalar_options: dict[str, int]
    flags: tuple[str, ...]

    @classmethod
    def parse(cls, text: str) -> ResolverConfig:
        nameservers: list[ipaddress.IPv4Address | ipaddress.IPv6Address] = []
        search_domains: list[str] | None = None
        scalar_options: dict[str, int] = {}
        flags: list[str] = []

        for line_number, raw_line in enumerate(text.splitlines(), start=1):
            stripped = raw_line.strip()
            if not stripped or stripped.startswith(("#", ";")):
                continue
            parts = raw_line.split("#", 1)[0].split()
            if not parts:
                continue
            directive, values = parts[0].lower(), parts[1:]
            if directive == "nameserver":
                if len(values) != 1:
                    raise EvidenceError(f"line {line_number}: nameserver requires one address")
                try:
                    address = ipaddress.ip_address(values[0])
                except ValueError as error:
                    raise EvidenceError(
                        f"line {line_number}: nameserver must be an IP literal"
                    ) from error
                if address in nameservers:
                    raise EvidenceError(f"line {line_number}: duplicate nameserver {address}")
                nameservers.append(address)
            elif directive in {"domain", "search"}:
                if search_domains is not None:
                    raise EvidenceError(
                        f"line {line_number}: domain/search directives are ambiguous when repeated"
                    )
                if len(values) != 1 and directive == "domain":
                    raise EvidenceError(f"line {line_number}: domain requires one suffix")
                if not values:
                    raise EvidenceError(f"line {line_number}: {directive} requires a suffix")
                search_domains = [
                    _domain(value, f"line {line_number} search suffix") for value in values
                ]
            elif directive == "options":
                if not values:
                    raise EvidenceError(f"line {line_number}: options requires a value")
                for option in values:
                    key, separator, raw_value = option.partition(":")
                    key = key.lower()
                    if separator:
                        if key not in SCALAR_LIMITS or not raw_value.isdigit():
                            raise EvidenceError(
                                f"line {line_number}: unsupported scalar option {option}"
                            )
                        if key in scalar_options:
                            raise EvidenceError(f"line {line_number}: duplicate option {key}")
                        scalar_value = int(raw_value)
                        minimum, maximum = SCALAR_LIMITS[key]
                        if not minimum <= scalar_value <= maximum:
                            raise EvidenceError(
                                f"line {line_number}: {key} must be from {minimum} to {maximum}"
                            )
                        scalar_options[key] = scalar_value
                    else:
                        if not re.fullmatch(r"[a-z0-9-]+", key):
                            raise EvidenceError(f"line {line_number}: invalid option flag {option}")
                        if key in flags:
                            raise EvidenceError(f"line {line_number}: duplicate option flag {key}")
                        flags.append(key)
            else:
                raise EvidenceError(f"line {line_number}: unsupported directive {directive}")

        return cls(
            nameservers=tuple(nameservers),
            search_domains=tuple(search_domains or ()),
            scalar_options=scalar_options,
            flags=tuple(flags),
        )


@dataclass(frozen=True)
class ResolverPolicy:
    allowed_nameserver_cidrs: tuple[ipaddress.IPv4Network | ipaddress.IPv6Network, ...]
    allowed_search_suffixes: tuple[str, ...]
    allowed_option_flags: tuple[str, ...]
    max_nameservers: int
    max_ndots: int
    max_timeout_seconds: int
    max_attempts: int

    @classmethod
    def from_dict(cls, values: dict[str, Any]) -> ResolverPolicy:
        required = {
            "allowed_nameserver_cidrs",
            "allowed_option_flags",
            "allowed_search_suffixes",
            "max_attempts",
            "max_nameservers",
            "max_ndots",
            "max_timeout_seconds",
        }
        if not isinstance(values, dict) or set(values) != required:
            raise ValueError(f"policy must contain exactly: {', '.join(sorted(required))}")
        for field in (
            "allowed_nameserver_cidrs",
            "allowed_search_suffixes",
            "allowed_option_flags",
        ):
            if not isinstance(values[field], list) or not all(
                isinstance(item, str) and item for item in values[field]
            ):
                raise ValueError(f"{field} must be a list of non-empty strings")
            if len(values[field]) != len(set(values[field])):
                raise ValueError(f"{field} must not contain duplicates")
        try:
            networks = tuple(
                ipaddress.ip_network(value, strict=True)
                for value in values["allowed_nameserver_cidrs"]
            )
        except ValueError as error:
            raise ValueError("allowed_nameserver_cidrs contains an invalid network") from error
        suffixes = tuple(
            _domain(value, "allowed_search_suffixes entry")
            for value in values["allowed_search_suffixes"]
        )
        if len(suffixes) != len(set(suffixes)):
            raise ValueError("allowed_search_suffixes must not contain normalized duplicates")
        flags = tuple(value.lower() for value in values["allowed_option_flags"])
        if len(flags) != len(set(flags)):
            raise ValueError("allowed_option_flags must not contain case-insensitive duplicates")
        if any(not re.fullmatch(r"[a-z0-9-]+", flag) for flag in flags):
            raise ValueError("allowed_option_flags contains an invalid flag")
        return cls(
            allowed_nameserver_cidrs=networks,
            allowed_search_suffixes=suffixes,
            allowed_option_flags=flags,
            max_nameservers=_strict_integer(
                values["max_nameservers"], "max_nameservers", minimum=1, maximum=3
            ),
            max_ndots=_strict_integer(values["max_ndots"], "max_ndots", minimum=0, maximum=15),
            max_timeout_seconds=_strict_integer(
                values["max_timeout_seconds"],
                "max_timeout_seconds",
                minimum=1,
                maximum=30,
            ),
            max_attempts=_strict_integer(
                values["max_attempts"], "max_attempts", minimum=1, maximum=5
            ),
        )


def _suffix_allowed(domain: str, allowed: tuple[str, ...]) -> bool:
    return any(domain == suffix or domain.endswith(f".{suffix}") for suffix in allowed)


def audit(config: ResolverConfig, policy: ResolverPolicy) -> dict[str, Any]:
    findings: list[dict[str, str]] = []
    if not config.nameservers:
        findings.append({"code": "DNS001", "message": "no nameserver is configured"})
    if len(config.nameservers) > policy.max_nameservers:
        findings.append(
            {
                "code": "DNS002",
                "message": "nameserver count exceeds the admitted resolver limit",
            }
        )
    for address in config.nameservers:
        if not any(
            address.version == network.version and address in network
            for network in policy.allowed_nameserver_cidrs
        ):
            findings.append(
                {"code": "DNS003", "message": f"nameserver {address} is outside allowed CIDRs"}
            )
    for domain in config.search_domains:
        if not _suffix_allowed(domain, policy.allowed_search_suffixes):
            findings.append({"code": "DNS004", "message": f"search suffix {domain} is not allowed"})

    effective = {
        "ndots": config.scalar_options.get("ndots", 1),
        "timeout": config.scalar_options.get("timeout", 5),
        "attempts": config.scalar_options.get("attempts", 2),
    }
    limits = {
        "ndots": (policy.max_ndots, "DNS005"),
        "timeout": (policy.max_timeout_seconds, "DNS006"),
        "attempts": (policy.max_attempts, "DNS007"),
    }
    for key, value in effective.items():
        maximum, code = limits[key]
        if value > maximum:
            findings.append(
                {"code": code, "message": f"effective {key}={value} exceeds policy {maximum}"}
            )
    for flag in config.flags:
        if flag not in policy.allowed_option_flags:
            findings.append({"code": "DNS008", "message": f"option flag {flag} is not allowed"})

    findings.sort(key=lambda item: (item["code"], item["message"]))
    return {
        "status": "rejected" if findings else "accepted",
        "nameservers": [str(address) for address in config.nameservers],
        "search_domains": list(config.search_domains),
        "effective_options": effective,
        "option_flags": list(config.flags),
        "findings": findings,
    }


def main() -> None:
    parser = argparse.ArgumentParser(description="Audit Linux resolver configuration")
    parser.add_argument("--resolv-conf", default="/etc/resolv.conf")
    parser.add_argument("--policy", required=True)
    values = parser.parse_args()
    try:
        config = ResolverConfig.parse(Path(values.resolv_conf).read_text(encoding="utf-8"))
        policy_values = json.loads(Path(values.policy).read_text(encoding="utf-8"))
        report = audit(config, ResolverPolicy.from_dict(policy_values))
    except (OSError, json.JSONDecodeError, EvidenceError, ValueError) as error:
        print(json.dumps({"status": "invalid", "error": str(error)}, sort_keys=True))
        raise SystemExit(2) from error
    print(json.dumps(report, indent=2, sort_keys=True))
    if report["status"] == "rejected":
        raise SystemExit(3)


if __name__ == "__main__":
    main()
