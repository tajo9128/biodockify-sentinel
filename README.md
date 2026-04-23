# BioDockify Sentinel + OpenClaw

Autonomous self-healing system for BioDockify.

## Architecture

```
Sentinel (monitor) → OpenClaw (decide + execute)
```

- **Sentinel**: Observer - collects diagnostics, emits structured reports
- **OpenClaw**: Decision engine + executor - handles incidents

## Quick Start

```bash
# Build and run
docker compose up -d --build

# Check status
docker ps | grep sentinel
docker ps | grep openclaw

# View logs
docker logs -f biodockify-sentinel
docker logs -f biodockify-openclaw
```

## API

### OpenClaw Endpoints

```
POST /incident  - Handle incident from Sentinel
GET  /health    - Health check + stats
GET  /audit     - Audit log
```

## Event Types

| Event | Severity | Auto-Fix |
|-------|----------|----------|
| OOM_CRASH | critical | Restart with memory limit |
| RESTART_LOOP | high | Inspect + restart |
| API_DOWN | high | Restart |
| CADDY_502 | high | Restart dependency |
| DISK_FULL | critical | Cleanup logs |
| QUEUE_BACKLOG | medium | Alert |

## Environment Variables

### Sentinel
| Variable | Default | Description |
|----------|---------|-------------|
| CHECK_INTERVAL | 120 | Check interval (seconds) |
| COOLDOWN_SECONDS | 300 | Cooldown between same events |
| OPENCLAW_URL | http://biodockify-openclaw:8001 | OpenClaw endpoint |
| MONITORED_SERVICES | biodockify-api,... | Comma-separated list |
| AUTO_HEAL | true | Enable auto-healing |

### OpenClaw
| Variable | Default | Description |
|----------|---------|-------------|
| DRY_RUN | false | Dry run mode (no execution) |
| SERVICE_POLICIES | | service:auto_heal pairs |

## License

MIT