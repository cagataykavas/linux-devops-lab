import socket
from unittest.mock import MagicMock, patch

import pytest

from network_probe import diagnose_endpoint


class Clock:
    def __init__(self):
        self.value = 0.0

    def __call__(self):
        self.value += 0.001
        return self.value


def addresses(*ips):
    rows = []
    for ip in ips:
        family = socket.AF_INET6 if ":" in ip else socket.AF_INET
        sockaddr = (ip, 443, 0, 0) if family == socket.AF_INET6 else (ip, 443)
        rows.append((family, socket.SOCK_STREAM, 6, "", sockaddr))
    return rows


def test_deduplicates_dns_and_falls_back_between_addresses():
    fake_socket = MagicMock()
    fake_socket.connect.side_effect = [OSError("refused"), None]
    with patch("network_probe.socket.socket", return_value=fake_socket):
        report = diagnose_endpoint(
            "service.example",
            443,
            use_tls=False,
            resolver=lambda host, port: addresses("192.0.2.1", "192.0.2.1", "2001:db8::1"),
            clock=Clock(),
        )

    assert report.ok is True
    assert report.resolved_addresses == ("192.0.2.1", "2001:db8::1")
    assert [item.family for item in report.attempts] == ["ipv4", "ipv6"]
    assert report.attempts[0].error.startswith("OSError")
    assert report.to_dict()["failure_stage"] is None


def test_dns_failure_is_attributed_without_connect_attempt():
    def fail(host, port):
        raise socket.gaierror("not found")

    report = diagnose_endpoint("missing.example", 443, resolver=fail, clock=Clock())
    assert report.ok is False
    assert report.failure_stage == "dns"
    assert report.attempts == ()


def test_tls_handshake_is_measured_separately():
    fake_socket = MagicMock()
    secured = MagicMock()
    secured.__enter__.return_value = secured
    context = MagicMock()
    context.wrap_socket.return_value = secured

    with patch("network_probe.socket.socket", return_value=fake_socket):
        report = diagnose_endpoint(
            "service.example",
            443,
            use_tls=True,
            resolver=lambda host, port: addresses("192.0.2.10"),
            clock=Clock(),
            ssl_context=context,
        )

    assert report.ok is True
    assert report.attempts[0].tls_ms is not None
    context.wrap_socket.assert_called_once_with(fake_socket, server_hostname="service.example")
    secured.do_handshake.assert_called_once()


def test_empty_dns_answer_fails_closed():
    report = diagnose_endpoint(
        "empty.example", 443, resolver=lambda host, port: [], clock=Clock()
    )
    assert report.ok is False
    assert report.failure_stage == "dns"


@pytest.mark.parametrize(
    "host, port, timeout",
    [("", 443, 1), (" host", 443, 1), ("host", 0, 1), ("host", 65536, 1), ("host", 443, 0)],
)
def test_rejects_invalid_policy(host, port, timeout):
    with pytest.raises(ValueError):
        diagnose_endpoint(host, port, timeout_seconds=timeout)
