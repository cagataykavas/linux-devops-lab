# Linux & DevOps Lab

Small, executable exercises for the Linux/DevOps knowledge expected around ML and backend systems.

## Topics

- processes, signals, exit codes and background jobs
- permissions, users/groups and `chmod`
- pipes, redirection, `grep`, `awk`, `sed`, `xargs`
- environment variables and configuration
- `curl`, DNS lookup and TCP connectivity debugging
- systemd concepts and service lifecycle
- logs and rotation
- SSH and key-based access
- containers, namespaces and cgroups concepts
- Docker image/layer basics
- health checks and graceful shutdown

## Useful debugging sequence

```bash
ps aux | grep myservice
ss -lntp
curl -v http://127.0.0.1:8000/health
getent hosts example.com
ip addr
ip route
free -h
df -h
tail -n 100 app.log
```

## Mini lab: graceful service shutdown

See `graceful_service.py` for a process that handles SIGTERM, stops accepting work and exits cleanly. This is the behavior container orchestrators expect during rolling deployments.

## Link health admission gate

`link_health_audit.py` samples the fixed Linux link counters for an explicit interface allowlist and rejects a deployment window when packet-drop ratios, error rates, or operational state exceed policy. It binds both samples to the same boot ID, network-namespace inode, interface index, and operational state so a restart or interface replacement cannot be mistaken for healthy counter deltas.

```bash
python link_health_audit.py \
  --policy examples/link_health_policy.json \
  --report /tmp/link-health.json \
  --interval 2
```

Exit `0` means admitted, `3` means valid evidence failed policy, and `2` means the evidence or policy was invalid. Counters come from the namespace-local `/proc/net/dev` table; interface identity and administrative/running state come from fixed network ioctls. Reports are atomically replaced with mode `0600` and contain only interface names, link state, counter deltas, rates, ratios, and stable reason codes. They do not contain addresses, routes, packet contents, or process data.

The example thresholds are illustrative: calibrate them per interface role and traffic volume. Ratio checks are intentionally omitted below each configured packet floor rather than claiming health from a tiny sample; error-rate and link-state checks still apply. This point-in-time, namespace-local audit does not identify the affected flow, prove remote reachability, or replace switch, NIC, eBPF, or continuous monitoring. A privileged actor that can rewrite procfs or network-interface state is outside its trust boundary.
