# Listener exposure audit

`listener_audit.py` turns Linux TCP listener state into a deterministic deployment gate. It
reads bounded snapshots from `/proc/net/tcp` and `/proc/net/tcp6`, decodes the kernel's IPv4 and
IPv6 byte order, aggregates `SO_REUSEPORT` instances, and compares every listening endpoint with
an exact address, port, and UID policy.

An empty policy means that no TCP listeners are expected. Wildcard addresses such as `0.0.0.0`
and `::` must be explicitly reviewed; a loopback rule never authorizes a wildcard listener.

```json
{
  "schema_version": "listener-policy/v1",
  "rules": [
    {
      "family": "ipv4",
      "address": "127.0.0.1",
      "port": 8000,
      "uid": 1000,
      "min_instances": 1,
      "max_instances": 4
    }
  ]
}
```

Run the audit with:

```bash
python listener_audit.py --policy listener-policy.json
```

The command returns `0` when the observed listeners satisfy the policy, `2` for policy findings,
and `3` for malformed, missing, or oversized evidence. Its JSON evidence includes normalized
listener exposure classes, stable finding codes, exact-source SHA-256 digests, a normalized policy
digest, and a self-digest for the complete report.

## Operational use

Capture the policy in the same reviewed deployment change that introduces a listener. Run the
audit in the target network namespace and service identity after startup, then retain the JSON
alongside the release evidence. Treat UID changes, instance-count drift, missing endpoints, and
new loopback or externally reachable listeners as reviewable findings rather than silently
updating the allowlist.

## Trust boundary and limitations

- Procfs is local observation, not remote reachability proof. Network namespaces, firewall rules,
  NAT, service meshes, and cloud security controls can change actual reachability.
- UID ownership is coarser than process identity. A different process under the same UID can bind
  an allowed endpoint; joining socket inodes to a cgroup or service unit is a useful next step.
- IPv4 and IPv6 files are read sequentially, so extremely rapid socket churn can span two moments.
- An IPv6 wildcard can also accept IPv4-mapped traffic when `IPV6_V6ONLY` is disabled; procfs does
  not expose that socket option.
- A privileged actor able to hide or alter procfs can forge the input. Retain audit evidence outside
  the host when it is part of a higher-assurance release gate.
