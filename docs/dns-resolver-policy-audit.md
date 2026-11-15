# DNS resolver policy audit

`resolver-audit` turns a Linux `resolv.conf` and an owned JSON policy into deterministic admission
evidence. It catches operationally risky configurations before they reach a host or container:

- nameservers outside approved address ranges;
- nameserver entries beyond the configured resolver limit;
- search suffixes that can leak single-label queries outside approved DNS zones;
- excessive `ndots`, timeout and attempt settings that multiply DNS traffic during failure;
- option flags that were not explicitly admitted.

```bash
resolver-audit \
  --resolv-conf /etc/resolv.conf \
  --policy examples/resolver-policy.json > resolver-report.json
```

Exit code `0` means the configuration is accepted, `2` means the evidence or policy is malformed,
and `3` means one or more policy controls rejected it. The parser fails closed on repeated
`domain`/`search` directives, duplicate options, hostnames in `nameserver` fields and directives it
cannot model. Defaults for `ndots`, `timeout` and `attempts` are evaluated even when `options` is
absent so an omitted value cannot silently bypass a limit.

## Trust boundary

This is an offline configuration audit. It does not prove which resolver library a process uses,
that systemd-resolved or a DNS proxy is healthy, that the configured address is authoritative for
an approved zone, or that responses are authenticated. Production rollout should pair this control
with runtime DNS latency/failure metrics and a probe from the same network namespace as the service.
