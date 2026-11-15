from __future__ import annotations

import json
import subprocess
import sys

import pytest

from resolver_audit import EvidenceError, ResolverConfig, ResolverPolicy, audit


def policy(**changes):
    values = {
        "allowed_nameserver_cidrs": ["10.42.0.0/16", "127.0.0.0/8", "::1/128"],
        "allowed_search_suffixes": ["svc.cluster.local", "cluster.local"],
        "allowed_option_flags": ["edns0", "rotate", "trust-ad"],
        "max_nameservers": 3,
        "max_ndots": 2,
        "max_timeout_seconds": 2,
        "max_attempts": 2,
    }
    values.update(changes)
    return ResolverPolicy.from_dict(values)


def config(text: str = "") -> ResolverConfig:
    return ResolverConfig.parse(
        text
        or """
        nameserver 10.42.0.2
        nameserver 127.0.0.53 # local systemd-resolved stub
        search api.svc.cluster.local cluster.local
        options ndots:2 timeout:2 attempts:2 edns0 rotate
        """
    )


def test_compliant_resolver_configuration_is_accepted():
    report = audit(config(), policy())
    assert report["status"] == "accepted"
    assert report["effective_options"] == {"ndots": 2, "timeout": 2, "attempts": 2}
    assert report["nameservers"] == ["10.42.0.2", "127.0.0.53"]


def test_nameserver_must_be_inside_an_allowed_cidr():
    report = audit(config("nameserver 8.8.8.8\noptions timeout:2"), policy())
    assert report["status"] == "rejected"
    assert [item["code"] for item in report["findings"]] == ["DNS003"]


def test_missing_or_ignored_nameservers_are_rejected():
    missing = audit(config("options timeout:2\n"), policy())
    assert [item["code"] for item in missing["findings"]] == ["DNS001"]

    too_many = audit(
        config(
            "nameserver 10.42.0.2\nnameserver 10.42.0.3\nnameserver 10.42.0.4\noptions timeout:2\n"
        ),
        policy(max_nameservers=2),
    )
    assert [item["code"] for item in too_many["findings"]] == ["DNS002"]


def test_search_suffix_matching_respects_label_boundary():
    report = audit(
        config("nameserver 10.42.0.2\nsearch evilcluster.local\noptions timeout:2\n"),
        policy(),
    )
    assert {item["code"] for item in report["findings"]} == {"DNS004"}


def test_retry_amplification_and_unapproved_flags_are_reported():
    report = audit(
        config(
            "nameserver 10.42.0.2\noptions ndots:5 timeout:4 attempts:3 single-request-reopen\n"
        ),
        policy(),
    )
    assert {item["code"] for item in report["findings"]} == {
        "DNS005",
        "DNS006",
        "DNS007",
        "DNS008",
    }


def test_glibc_defaults_are_evaluated_when_options_are_absent():
    report = audit(config("nameserver 10.42.0.2\n"), policy())
    assert report["effective_options"] == {"ndots": 1, "timeout": 5, "attempts": 2}
    assert [item["code"] for item in report["findings"]] == ["DNS006"]


@pytest.mark.parametrize(
    "text,message",
    [
        ("nameserver resolver.internal", "IP literal"),
        ("nameserver 10.42.0.2\nnameserver 10.42.0.2", "duplicate nameserver"),
        ("domain one.internal\nsearch two.internal", "ambiguous"),
        ("sortlist 10.0.0.0/8", "unsupported directive"),
        ("options ndots:2 ndots:3", "duplicate option"),
        ("options timeout:0", "timeout must be from 1 to 30"),
    ],
)
def test_ambiguous_or_unsupported_evidence_fails_closed(text, message):
    with pytest.raises(EvidenceError, match=message):
        config(text)


def test_policy_rejects_non_network_cidr():
    with pytest.raises(ValueError, match="invalid network"):
        policy(allowed_nameserver_cidrs=["10.42.1.1/16"])


def test_cli_returns_stable_policy_failure_code(tmp_path):
    resolv_conf = tmp_path / "resolv.conf"
    resolv_conf.write_text("nameserver 8.8.8.8\noptions timeout:2\n", encoding="utf-8")
    policy_path = tmp_path / "policy.json"
    policy_path.write_text(
        json.dumps(
            {
                "allowed_nameserver_cidrs": ["10.42.0.0/16"],
                "allowed_search_suffixes": [],
                "allowed_option_flags": [],
                "max_nameservers": 3,
                "max_ndots": 2,
                "max_timeout_seconds": 2,
                "max_attempts": 2,
            }
        ),
        encoding="utf-8",
    )
    result = subprocess.run(
        [
            sys.executable,
            "-m",
            "resolver_audit",
            "--resolv-conf",
            str(resolv_conf),
            "--policy",
            str(policy_path),
        ],
        check=False,
        capture_output=True,
        text=True,
    )
    assert result.returncode == 3
    assert json.loads(result.stdout)["status"] == "rejected"
