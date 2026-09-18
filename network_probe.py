"""Layered DNS, TCP and TLS diagnostics with one end-to-end deadline."""

from __future__ import annotations

import argparse
import json
import socket
import ssl
import time
from collections.abc import Callable, Sequence
from dataclasses import asdict, dataclass
from ipaddress import ip_address
from typing import Any


@dataclass(frozen=True)
class AddressAttempt:
    address: str
    family: str
    tcp_ms: float
    tls_ms: float | None
    ok: bool
    error: str | None


@dataclass(frozen=True)
class ProbeReport:
    host: str
    port: int
    tls: bool
    dns_ms: float
    total_ms: float
    resolved_addresses: tuple[str, ...]
    attempts: tuple[AddressAttempt, ...]
    ok: bool
    failure_stage: str | None

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


Resolver = Callable[[str, int], Sequence[tuple[int, int, int, str, tuple[Any, ...]]]]
Clock = Callable[[], float]


def _default_resolver(host: str, port: int):
    return socket.getaddrinfo(host, port, type=socket.SOCK_STREAM)


def _family_name(family: int) -> str:
    if family == socket.AF_INET:
        return "ipv4"
    if family == socket.AF_INET6:
        return "ipv6"
    return str(family)


def _normalized_ip(sockaddr: tuple[Any, ...]) -> str:
    return str(ip_address(str(sockaddr[0])))


def diagnose_endpoint(
    host: str,
    port: int,
    *,
    use_tls: bool = False,
    timeout_seconds: float = 5.0,
    resolver: Resolver = _default_resolver,
    clock: Clock = time.monotonic,
    ssl_context: ssl.SSLContext | None = None,
) -> ProbeReport:
    """Resolve and try every unique address until one connection succeeds."""
    if not host or host.strip() != host:
        raise ValueError("host must be a non-empty normalized name or address")
    if not isinstance(port, int) or isinstance(port, bool) or not 1 <= port <= 65535:
        raise ValueError("port must be an integer between 1 and 65535")
    if timeout_seconds <= 0:
        raise ValueError("timeout_seconds must be positive")

    started = clock()
    deadline = started + timeout_seconds
    dns_started = clock()
    try:
        resolved = list(resolver(host, port))
    except OSError:
        finished = clock()
        return ProbeReport(
            host,
            port,
            use_tls,
            (finished - dns_started) * 1000,
            (finished - started) * 1000,
            (),
            (),
            False,
            "dns",
        )
    dns_finished = clock()

    unique: list[tuple[int, int, int, tuple[Any, ...], str]] = []
    seen: set[tuple[int, str, int]] = set()
    for family, socktype, proto, _, sockaddr in resolved:
        address = _normalized_ip(sockaddr)
        key = (family, address, int(sockaddr[1]))
        if key not in seen:
            seen.add(key)
            unique.append((family, socktype, proto, sockaddr, address))

    if not unique:
        finished = clock()
        return ProbeReport(
            host,
            port,
            use_tls,
            (dns_finished - dns_started) * 1000,
            (finished - started) * 1000,
            (),
            (),
            False,
            "dns",
        )

    attempts: list[AddressAttempt] = []
    context = ssl_context or ssl.create_default_context()
    for family, socktype, proto, sockaddr, address in unique:
        remaining = deadline - clock()
        if remaining <= 0:
            break
        tcp_started = clock()
        raw_socket: socket.socket | None = None
        try:
            raw_socket = socket.socket(family, socktype, proto)
            raw_socket.settimeout(remaining)
            raw_socket.connect(sockaddr)
            tcp_finished = clock()
            tls_ms: float | None = None
            if use_tls:
                remaining = deadline - clock()
                if remaining <= 0:
                    raise TimeoutError("deadline exhausted before TLS handshake")
                raw_socket.settimeout(remaining)
                tls_started = clock()
                with context.wrap_socket(raw_socket, server_hostname=host) as secured:
                    secured.do_handshake()
                raw_socket = None
                tls_ms = (clock() - tls_started) * 1000
            attempts.append(
                AddressAttempt(
                    address,
                    _family_name(family),
                    (tcp_finished - tcp_started) * 1000,
                    tls_ms,
                    True,
                    None,
                )
            )
            break
        except (OSError, ssl.SSLError, TimeoutError) as exc:
            attempts.append(
                AddressAttempt(
                    address,
                    _family_name(family),
                    (clock() - tcp_started) * 1000,
                    None,
                    False,
                    f"{type(exc).__name__}: {exc}",
                )
            )
        finally:
            if raw_socket is not None:
                raw_socket.close()

    finished = clock()
    ok = any(item.ok for item in attempts)
    failure_stage = None
    if not ok:
        failure_stage = "deadline" if finished >= deadline else ("tls" if use_tls else "tcp")
    return ProbeReport(
        host=host,
        port=port,
        tls=use_tls,
        dns_ms=(dns_finished - dns_started) * 1000,
        total_ms=(finished - started) * 1000,
        resolved_addresses=tuple(item[4] for item in unique),
        attempts=tuple(attempts),
        ok=ok,
        failure_stage=failure_stage,
    )


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("host")
    parser.add_argument("--port", type=int, default=443)
    parser.add_argument("--tls", action=argparse.BooleanOptionalAction, default=True)
    parser.add_argument("--timeout", type=float, default=5.0)
    args = parser.parse_args()
    report = diagnose_endpoint(
        args.host,
        args.port,
        use_tls=args.tls,
        timeout_seconds=args.timeout,
    )
    print(json.dumps(report.to_dict(), sort_keys=True))
    return 0 if report.ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
