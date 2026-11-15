# TCP retransmission-window audit

Linux exposes cumulative TCP MIB counters in `/proc/net/snmp`. A single counter
value has little operational meaning, so `tcp_health_audit.py` captures two
bounded snapshots from the same host boot and evaluates their deltas over a
monotonic sampling window.

The audit reports:

- retransmitted segments divided by outbound segments;
- established-connection resets per second;
- whether enough outbound traffic existed to evaluate the ratio; and
- a SHA-256 commitment over both snapshots and the complete policy.

It rejects counter regression, host reboots between samples, implausible sample
timing, malformed procfs columns, oversized sources, symlinks and invalid policy
values. Reports are written atomically with mode `0600`.

## Usage

```bash
python tcp_health_audit.py \
  --sample-seconds 10 \
  --minimum-out-segments 500 \
  --maximum-retransmission-ratio 0.02 \
  --maximum-established-resets-per-second 1.0 \
  --output artifacts/tcp-health.json
```

Exit codes distinguish an admitted window (`0`), a policy rejection or
insufficient traffic (`2`), and malformed or unavailable evidence (`3`). An
insufficient sample is intentionally not reported as healthy.

## Operational boundary

Thresholds must be calibrated per workload and network path. `RetransSegs` is a
host-wide transport symptom: it does not identify the affected destination,
process, namespace, interface or root cause. Retransmission can reflect loss,
congestion, reordering or receiver behavior. `EstabResets` is likewise a coarse
host counter rather than an application error metric.

This point-in-time audit complements continuous time-series monitoring. Run it
inside the target network namespace, retain evidence outside the host, and
correlate failures with interface, eBPF/socket, load-balancer and application
telemetry before acting.
