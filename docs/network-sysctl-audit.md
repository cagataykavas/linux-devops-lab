# Linux network sysctl admission audit

Kernel networking defaults can drift through image changes, bootstrap scripts, or
an operator applying `sysctl` in the wrong network namespace. A host can still
pass DNS and TCP probes while forwarding packets, accepting redirects, or
disabling SYN-flood protection contrary to its reviewed role.

`network_sysctl_audit.py` separates collection from admission:

1. `collect` reads only the allowlisted `/proc/sys` paths named by a policy and
   writes a private, atomic snapshot.
2. `verify` requires an exact key set, checks snapshot freshness and clock skew,
   compares every value with its explicit allowed set, and emits SHA-256
   commitments to the normalized policy and snapshot.

It requires no root privileges when the selected procfs files are readable.

## Run it

Copy the example and replace `eth0` with the reviewed external interface. The
example describes a non-routing server; it is deliberately not a universal
baseline. Routers, Kubernetes nodes, asymmetric paths, IPv6 SLAAC, and service
meshes need role-specific expectations.

```bash
python network_sysctl_audit.py collect \
  --policy examples/server-network-sysctl-policy.json \
  --output /run/network-sysctl-snapshot.json

python network_sysctl_audit.py verify \
  --policy examples/server-network-sysctl-policy.json \
  --snapshot /run/network-sysctl-snapshot.json \
  --output /run/network-sysctl-report.json
```

Exit status `0` means admitted, `3` means a fresh and well-formed snapshot
violated policy, and `2` means the inputs or collection boundary could not be
trusted. The verifier rejects duplicate JSON fields, unknown schema fields,
non-finite numbers, missing or extra sysctls, oversized documents, symlinked
inputs, stale evidence, and timestamps too far in the future.

## Policy guidance

- Set forwarding explicitly for the host's role. Never copy the example's
  `ip_forward=0` rule onto a router or Kubernetes node without review.
- Strict reverse-path filtering (`1`) is useful on simple single-homed servers;
  loose mode (`2`) is often required for asymmetric or policy-routed traffic.
- Audit both `all` and `default` where inheritance matters, then add exact
  interface keys for exposure-sensitive settings.
- Review IPv6 independently. Disabling IPv4 forwarding says nothing about IPv6.
- Capture inside the target network namespace; procfs is namespace-scoped.

## Security and operational boundary

This is point-in-time evidence from the local kernel namespace. It does not
prove that settings stayed unchanged after capture, that a container sees the
host namespace, or that cloud security groups, network ACLs, firewalls, routes,
and upstream appliances are correct. SHA-256 commitments detect accidental or
unanchored evidence changes; they are not signatures. Retain accepted reports
in an authenticated external system if they are used for deployment approval.

The next increment should bind the snapshot to the network-namespace inode and
boot ID, then export low-cardinality rejection metrics without exposing host or
interface inventories.
