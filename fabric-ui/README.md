# Fabric UI Console (Phase 1)

Cybersecurity-themed observability dashboard for the existing Fabric `socnet` network. Phase 1 scope is read-only status + guarded admin controls (logs/restart).

## What it does

- Auto-starts Fabric + CCaaS through `/opt/fabric-dev/socnet/start_socnet.sh up`.
- Displays **Network Overview & Trust Foundation**:
  - top status bar (network/channels/health/last refresh)
  - summary cards (peers, orderer, channels, chaincode, CCaaS reachability, block heights)
  - org table (Org1/Org2)
  - services table (status/uptime/network/ports/IP)
  - chaincode card (`lognotary` metadata)
  - latest events feed (status transitions, CCaaS reachability changes, block height changes)
- Admin endpoints are password-protected with `x-admin-password`.

## Required structure

```
fabric-ui/
  backend/
  frontend/
  docker-compose.ui.yml
  run.sh
```

## One-command start options

### Option A (recommended in WSL/local):

```bash
cd /workspace/fabric/fabric-ui
./run.sh
```

### Option B (compose from root):

```bash
cd /workspace/fabric
ADMIN_PASSWORD=yourStrongPass docker compose -f fabric-ui/docker-compose.ui.yml up --build
```

## Environment variables

Backend (`fabric-ui/backend`):

- `PORT` (default `4000`)
- `FRONTEND_ORIGIN` (default `http://localhost:5173`)
- `ADMIN_PASSWORD` (default `changeme`)
- `ALLOW_CORE_RESTART` (`true|false`, default `false`)
- `SOCNET_DIR` (default `/opt/fabric-dev/socnet`)
- `START_SCRIPT` (default `/opt/fabric-dev/socnet/start_socnet.sh`)
- `CHANNEL_NAME` (default `soclogs`)

## API endpoints

- `GET /api/status/overview`
- `GET /api/status/containers`
- `GET /api/status/chaincode`
- `GET /api/status/channels`
- `POST /api/admin/restart` body: `{ "service": "lognotary-ccaas" }`
- `GET /api/admin/logs?service=lognotary-ccaas&tail=200`

Admin calls must include header:

```
x-admin-password: <ADMIN_PASSWORD>
```

## Verify after startup

```bash
curl -s http://localhost:4000/health
curl -s http://localhost:4000/api/status/overview | jq
curl -s -H "x-admin-password: changeme" "http://localhost:4000/api/admin/logs?service=lognotary-ccaas&tail=20"
```

## Troubleshooting

### 1) DNS resolution fails for `lognotary-ccaas`

- Check peer DNS from host:
  ```bash
  docker exec peer0.org1.example.com getent hosts lognotary-ccaas
  ```
- Ensure container is on `socnet` network:
  ```bash
  docker inspect lognotary-ccaas --format '{{json .NetworkSettings.Networks}}'
  ```

### 2) CCaaS down/unreachable

- Restart from UI admin panel (recommended), or CLI:
  ```bash
  docker restart lognotary-ccaas
  docker logs lognotary-ccaas --tail 100
  ```

### 3) peer commands fail (`env_org1.sh` not loaded)

- Validate scripts exist:
  ```bash
  ls /opt/fabric-dev/socnet/compose/env_org1.sh /opt/fabric-dev/socnet/compose/env_org2.sh
  ```
- Re-run bootstrap:
  ```bash
  /opt/fabric-dev/socnet/start_socnet.sh up
  ```

### 4) docker network missing

- Confirm `socnet` exists:
  ```bash
  docker network ls | grep socnet
  ```
- If missing, bootstrap again:
  ```bash
  /opt/fabric-dev/socnet/start_socnet.sh up
  ```
