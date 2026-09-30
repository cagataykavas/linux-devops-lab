from __future__ import annotations

import json
from dataclasses import replace
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

from socket_capacity import (
    MAX_INPUT_BYTES,
    AuditPolicy,
    EvidenceError,
    SocketSnapshot,
    audit_snapshot,
    collect_snapshot,
    load_snapshot,
    main,
)

NOW = datetime(2026, 9, 30, 12, 0, tzinfo=UTC)


def _snapshot(**changes) -> SocketSnapshot:
    values = {
        "captured_at": NOW - timedelta(seconds=10),
        "ephemeral_first": 20_000,
        "ephemeral_last": 60_000,
        "reserved_ranges": ((20_000, 20_999), (61_000, 62_000)),
        "tcp_inuse": 2_000,
        "tcp_orphan": 3,
        "tcp_time_wait": 4_000,
        "tcp_allocated": 2_500,
        "conntrack_count": 20_000,
        "conntrack_max": 100_000,
        "somaxconn": 4_096,
        "tcp_max_syn_backlog": 8_192,
        "tcp_syncookies": 1,
    }
    values.update(changes)
    return SocketSnapshot(**values)


def _write(root: Path, relative: str, value: str) -> None:
    path = root / relative
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(value, encoding="ascii")


def _proc_fixture(root: Path) -> None:
    _write(root, "sys/net/ipv4/ip_local_port_range", "20000 60000\n")
    _write(root, "sys/net/ipv4/ip_local_reserved_ports", "20000-20999,61000-62000\n")
    _write(
        root,
        "net/sockstat",
        "sockets: used 2500\nTCP: inuse 2000 orphan 3 tw 4000 alloc 2500 mem 50\n",
    )
    _write(root, "sys/net/netfilter/nf_conntrack_count", "20000\n")
    _write(root, "sys/net/netfilter/nf_conntrack_max", "100000\n")
    _write(root, "sys/net/core/somaxconn", "4096\n")
    _write(root, "sys/net/ipv4/tcp_max_syn_backlog", "8192\n")
    _write(root, "sys/net/ipv4/tcp_syncookies", "1\n")


def test_collector_parses_bounded_procfs_evidence(tmp_path):
    _proc_fixture(tmp_path)
    snapshot = collect_snapshot(tmp_path, NOW)
    assert snapshot == _snapshot(captured_at=NOW)
    assert snapshot.reserved_ranges == ((20_000, 20_999), (61_000, 62_000))


def test_healthy_snapshot_is_deterministic_and_accepted():
    first = audit_snapshot(_snapshot(), now=NOW)
    second = audit_snapshot(_snapshot(), now=NOW)
    assert first == second
    assert first["status"] == "accepted"
    assert first["metrics"]["usable_ephemeral_ports"] == 39_001
    assert len(first["evidence_sha256"]) == 64


@pytest.mark.parametrize(
    "snapshot,policy,code",
    [
        (_snapshot(ephemeral_last=25_000), AuditPolicy(), "PORT001"),
        (
            _snapshot(tcp_inuse=20_000, tcp_allocated=20_000, tcp_time_wait=10_000),
            AuditPolicy(),
            "PORT002",
        ),
        (_snapshot(conntrack_count=90_000), AuditPolicy(), "CT001"),
        (_snapshot(tcp_orphan=5_000), AuditPolicy(), "TCP001"),
        (_snapshot(somaxconn=128), AuditPolicy(), "BACKLOG001"),
        (_snapshot(tcp_max_syn_backlog=128), AuditPolicy(), "BACKLOG002"),
        (_snapshot(tcp_syncookies=0), AuditPolicy(), "SYN001"),
    ],
)
def test_capacity_and_kernel_guardrails_reject(snapshot, policy, code):
    report = audit_snapshot(snapshot, policy, NOW)
    assert report["status"] == "rejected"
    assert code in {finding["code"] for finding in report["findings"]}


def test_reserved_ranges_only_reduce_overlapping_ephemeral_ports():
    snapshot = _snapshot(
        ephemeral_first=10_000,
        ephemeral_last=19_999,
        reserved_ranges=((1, 100), (15_000, 15_999), (30_000, 31_000)),
    )
    policy = replace(AuditPolicy(), min_usable_ephemeral_ports=1)
    assert audit_snapshot(snapshot, policy, NOW)["metrics"]["usable_ephemeral_ports"] == 9_000


@pytest.mark.parametrize(
    "changes,match",
    [
        ({"ephemeral_first": 0}, "ephemeral port range"),
        ({"conntrack_count": 101_000}, "conntrack"),
        ({"tcp_allocated": 100}, "allocated"),
        ({"tcp_syncookies": 2}, "syncookies"),
    ],
)
def test_inconsistent_snapshot_fails_closed(changes, match):
    snapshot = _snapshot(**changes)
    with pytest.raises(EvidenceError, match=match):
        snapshot.validate()


def test_stale_future_and_naive_timestamps_are_rejected():
    assert (
        audit_snapshot(_snapshot(captured_at=NOW - timedelta(hours=1)), now=NOW)["findings"][0][
            "code"
        ]
        == "TIME002"
    )
    assert (
        audit_snapshot(_snapshot(captured_at=NOW + timedelta(minutes=1)), now=NOW)["findings"][0][
            "code"
        ]
        == "TIME001"
    )
    values = _snapshot().canonical_dict()
    values["captured_at"] = "2026-09-30T12:00:00"
    with pytest.raises(EvidenceError, match="timezone"):
        SocketSnapshot.from_dict(values)


def test_procfs_duplicate_field_and_reserved_overlap_fail_closed(tmp_path):
    _proc_fixture(tmp_path)
    _write(tmp_path, "net/sockstat", "TCP: inuse 1 inuse 2 orphan 0 tw 0 alloc 2\n")
    with pytest.raises(EvidenceError, match="duplicate"):
        collect_snapshot(tmp_path, NOW)

    _proc_fixture(tmp_path)
    _write(tmp_path, "sys/net/ipv4/ip_local_reserved_ports", "20000-21000,20500-22000")
    with pytest.raises(EvidenceError, match="overlap"):
        collect_snapshot(tmp_path, NOW)


def test_missing_symlink_and_oversized_procfs_entries_fail_closed(tmp_path):
    _proc_fixture(tmp_path)
    target = tmp_path / "real-range"
    target.write_text("20000 60000", encoding="ascii")
    path = tmp_path / "sys/net/ipv4/ip_local_port_range"
    path.unlink()
    path.symlink_to(target)
    with pytest.raises(EvidenceError, match="non-symlink"):
        collect_snapshot(tmp_path, NOW)

    path.unlink()
    _proc_fixture(tmp_path)
    _write(tmp_path, "net/sockstat", "x" * 4_097)
    with pytest.raises(EvidenceError, match="budget"):
        collect_snapshot(tmp_path, NOW)


def _write_snapshot(path: Path, snapshot: SocketSnapshot | None = None) -> None:
    path.write_text(json.dumps((snapshot or _snapshot()).canonical_dict()), encoding="utf-8")


def test_json_loader_rejects_duplicate_nonfinite_oversized_and_symlink(tmp_path):
    duplicate = tmp_path / "duplicate.json"
    duplicate.write_text('{"schema_version":"first","schema_version":"second"}', encoding="utf-8")
    with pytest.raises(EvidenceError, match="duplicate"):
        load_snapshot(duplicate)

    nonfinite = tmp_path / "nonfinite.json"
    nonfinite.write_text('{"value":NaN}', encoding="utf-8")
    with pytest.raises(EvidenceError, match="non-finite"):
        load_snapshot(nonfinite)

    oversized = tmp_path / "oversized.json"
    oversized.write_text("x" * (MAX_INPUT_BYTES + 1), encoding="utf-8")
    with pytest.raises(EvidenceError, match="budget"):
        load_snapshot(oversized)

    valid = tmp_path / "valid.json"
    linked = tmp_path / "linked.json"
    _write_snapshot(valid)
    linked.symlink_to(valid)
    with pytest.raises(EvidenceError, match="non-symlink"):
        load_snapshot(linked)


def test_cli_collect_and_audit_write_atomic_artifacts(tmp_path, monkeypatch):
    monkeypatch.setattr("socket_capacity.datetime", _FixedDateTime)
    proc_root = tmp_path / "proc"
    _proc_fixture(proc_root)
    snapshot_path = tmp_path / "snapshot.json"
    report_path = tmp_path / "nested" / "report.json"
    assert main(["collect", "--proc-root", str(proc_root), "--output", str(snapshot_path)]) == 0

    assert main(["audit", "--input", str(snapshot_path), "--output", str(report_path)]) == 0
    assert json.loads(report_path.read_text(encoding="utf-8"))["status"] == "accepted"
    assert not list(report_path.parent.glob("*.tmp"))


class _FixedDateTime(datetime):
    @classmethod
    def now(cls, tz=None):
        return NOW if tz is not None else NOW.replace(tzinfo=None)


def test_cli_distinguishes_policy_rejection_and_malformed_evidence(tmp_path, monkeypatch):
    monkeypatch.setattr("socket_capacity.datetime", _FixedDateTime)
    rejected = tmp_path / "rejected.json"
    malformed = tmp_path / "malformed.json"
    _write_snapshot(rejected, _snapshot(tcp_syncookies=0))
    malformed.write_text("{", encoding="utf-8")
    assert main(["audit", "--input", str(rejected), "--output", str(tmp_path / "r.json")]) == 3
    assert main(["audit", "--input", str(malformed), "--output", str(tmp_path / "m.json")]) == 2
