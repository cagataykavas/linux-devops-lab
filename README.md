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


## Layered network diagnostic probe

`network_probe.py` separates endpoint troubleshooting into DNS, TCP and optional TLS stages
instead of returning one ambiguous connectivity failure.

```bash
network-probe api.example.com --port 443 --tls --timeout 5
```

The probe:

- resolves IPv4 and IPv6 stream addresses and removes duplicate answers;
- attempts resolved addresses in order until one succeeds;
- applies one end-to-end monotonic deadline rather than a fresh full timeout per address;
- preserves TLS hostname verification through SNI;
- records DNS, TCP, TLS and total timing separately;
- attributes terminal failure to DNS, TCP/TLS or deadline exhaustion;
- emits deterministic JSON and a non-zero failure exit code.

It is a diagnostic utility, not an application HTTP health check or an SSRF security boundary.
Production monitoring should also validate the application response contract, run from relevant
network locations and avoid exposing arbitrary probe targets to untrusted users.
