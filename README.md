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
