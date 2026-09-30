# Linux socket-capacity audit

Successful DNS, TCP and TLS probes do not prove that a host has enough kernel capacity for the next
traffic step. `socket_capacity.py` adds an unprivileged procfs collector and a separate admission gate
for the most common host-level exhaustion signals:

- usable ephemeral ports after reserved-range subtraction;
- conservative in-use plus `TIME_WAIT` pressure;
- netfilter conntrack utilization;
- orphan TCP sockets;
- accept and SYN backlog floors;
- SYN-cookie posture.

```bash
python socket_capacity.py collect --output /tmp/socket-snapshot.json
python socket_capacity.py audit \
  --input /tmp/socket-snapshot.json \
  --output /tmp/socket-report.json
```

The collector reads only bounded, fixed procfs paths and rejects symlinks, malformed ranges and
inconsistent counters. The audit rejects stale/future evidence, duplicate or non-finite JSON and
resource-budget violations. Exit codes are `0` for acceptance, `2` for malformed/operational evidence
and `3` for a policy rejection. Reports contain normalized capacity metrics and SHA-256 evidence, not
process lists, addresses, routes or hostnames.

## Interpretation boundary

Ephemeral-port pressure is deliberately conservative: Linux connection uniqueness also includes
source/destination addresses and ports. A single snapshot can miss short spikes, and host conntrack
does not measure a managed NAT gateway or upstream firewall. Production rollouts should sample this
collector over a governed window and correlate rejections with connection-error and NAT telemetry.
