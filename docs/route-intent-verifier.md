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

## Scope and limitations

This utility intentionally models a static snapshot of the main table. It does
not interpret `ip rule`, source-address policy routing, ECMP/nexthop objects,
VRFs, packet marks, or live namespace changes after capture. For those cases,
use this report as a deterministic admission check and confirm the result with
`ip route get <address>` inside the production namespace. A useful next step is
an adapter that captures and correlates `ip -j rule` and `ip -j nexthop`
evidence before evaluation.
