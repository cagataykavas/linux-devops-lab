# Route intent verifier

Linux routes can drift when a VPN, bootstrap script, DHCP lease, or emergency
change adds a more-specific path. A healthy interface and a present default
route do not prove that sensitive traffic will leave through the intended
boundary. `route_guard.py` evaluates a captured main routing table with the same
core precedence rules operators inspect first: longest prefix wins, then lowest
metric.

## Capture and verify

Capture one snapshot per network namespace. Restricting the command to the main
table matches the verifier's declared scope.

```bash
ip -j route show table main > routes-v4.json
python route_guard.py --routes routes-v4.json --policy route-policy.json
```

Example policy:

```json
{
  "destinations": [
    {
      "name": "artifact-store",
      "address": "203.0.113.10",
      "allowed_devices": ["eth0"],
      "allowed_gateways": ["192.0.2.1"]
    },
    {
      "name": "node-local-metrics",
      "address": "127.0.0.1",
      "allowed_devices": ["lo"]
    }
  ]
}
```

`allowed_gateways` is optional for an intent where any direct or routed gateway
is acceptable. Destination values must be literal IPv4 or IPv6 addresses so
DNS changes cannot alter what was checked. A passing result exits `0`; policy
violations and invalid inputs exit `2`. The JSON report records the exact route
used as evidence.

The verifier fails closed when equal-prefix, equal-metric routes both match. It
also rejects `blackhole`, `unreachable`, and `prohibit` selections even if their
device would otherwise be approved. Inputs are bounded to 1 MiB, duplicate JSON
keys and non-finite numbers are rejected, and symlink inputs are refused.

## Verify the kernel's live decision

Static main-table evaluation is useful for deterministic review, but it cannot
resolve source rules, custom routing tables or the complete live namespace state.
Run the companion adapter in the target namespace to ask the kernel for each
policy destination directly:

```bash
python live_route_guard.py \
  --policy route-policy.json \
  --ip-command /usr/bin/ip \
  --timeout-seconds 2
```

The adapter passes only literal, already-validated policy addresses to the fixed
argument vector `ip -j route get <address>`; it never invokes a shell. Each lookup
has an independent deadline. Output is capped at 64 KiB, must contain exactly one
route object, and must echo the requested destination. Duplicate JSON fields,
non-finite values, family mismatches, unsupported route types and malformed table
identifiers fail closed.

The report retains the selected interface, gateway, preferred source and numeric
routing table. It never includes command stderr, environment contents or unrelated
route-table entries. A custom table in the result is valid when its selected device
and optional gateway satisfy the reviewed destination policy; the table ID remains
evidence for operators investigating policy-routing behavior.

## Scope and limitations

The static utility intentionally models only a captured main table. The live
adapter observes the kernel's final route decision, including policy-routing
effects, but does not explain which `ip rule`, VRF, packet mark or ECMP/nexthop
choice produced it. Both checks are point-in-time and a route can change
immediately afterward. Run them inside the workload's actual network namespace,
retain the bounded report with deployment evidence, and use `ip -j rule` plus
`ip -j nexthop` when root-cause evidence is required.
