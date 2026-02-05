# Fabric UI Console (Phase 1 + Phase 2)

Cybersecurity-themed observability and explorer dashboard for the existing Fabric `socnet` network.

- **Phase 1 remains intact**: network overview + guarded admin controls (logs/restart).
- **Phase 2 adds read-only Fabric Explorer**: blocks, transactions, search, chaincode views, and sanitized audit exports.

## Run

```bash
cd /workspace/fabric/fabric-ui
./run.sh
```

This keeps the same startup flow as before: it boots socnet + CCaaS and starts backend/frontend.

## Phase 1 features (unchanged)

- Auto-starts Fabric + CCaaS through `/opt/fabric-dev/socnet/start_socnet.sh up`.
- Overview cards (peers/orderer/channels/chaincodes/CCaaS/block heights).
- Organization and services tables.
- Chaincode panel for `lognotary`.
- Latest events feed.
- Guarded admin actions (logs + restart) via `x-admin-password`.

## Phase 2 features

### UI sections

Left navigation with:

- **Overview**
- **Explorer**
  - Blocks
  - Transactions
  - Search
- **Chaincode**
  - Definition
  - Invocations
- **Audit**
  - Exports

### Explorer capabilities

- Blocks Explorer with filter + loading/empty/error states.
- Transaction detail viewer (forensic layout):
  - Summary (txid, block number, timestamp, validation)
  - Endorsements/creator org (best-effort)
  - Chaincode/function (best-effort)
  - RW set summary (best-effort)
  - Collapsible raw JSON panel
- Search by block number or txid.
- Copy helpers (txid, block hash, export bundle).

### Chaincode + audit

- Chaincode committed definition for `lognotary` on `soclogs`.
- Recent invocation history (best-effort scan window).
- Verification bundle export endpoints for blocks and tx.

## API endpoints

Existing endpoints are unchanged:

- `GET /api/status/overview`
- `GET /api/status/containers`
- `GET /api/status/chaincode`
- `GET /api/status/channels`
- `POST /api/admin/restart`
- `GET /api/admin/logs?service=...&tail=...`

New Phase 2 read-only endpoints under `/api/v1`:

- `GET /api/v1/explorer/blocks?channel=soclogs&limit=20&from=<optional>`
- `GET /api/v1/explorer/blocks/:number?channel=soclogs`
- `GET /api/v1/explorer/tx/:txid?channel=soclogs`
- `GET /api/v1/chaincode/definition?channel=soclogs&name=lognotary`
- `GET /api/v1/chaincode/invocations?channel=soclogs&name=lognotary&limit=50`
- `GET /api/v1/audit/export/block/:number?channel=soclogs`
- `GET /api/v1/audit/export/tx/:txid?channel=soclogs`

## Environment variables

Backend (`fabric-ui/backend`):

- `PORT` (default `4000`)
- `FRONTEND_ORIGIN` (default `http://localhost:5173`)
- `ADMIN_PASSWORD` (default `changeme`)
- `ALLOW_CORE_RESTART` (`true|false`, default `false`)
- `SOCNET_DIR` (default `/opt/fabric-dev/socnet`)
- `START_SCRIPT` (default `/opt/fabric-dev/socnet/start_socnet.sh`)
- `CHANNEL_NAME` (default `soclogs`)

## Troubleshooting / data availability notes

- Some transaction-level fields are **best-effort** via CLI decode.
- If chaincode function, creator MSP, endorsements, or RW set are unavailable, API returns `null` with a reason.
- RWSet decode is intentionally not faked when unavailable.
- Exports are sanitized (no certificate PEM dumps, no payload argument dumps).

## Manual test steps

1. Start UI with `./run.sh`.
2. Verify overview still refreshes and admin log/restart endpoints work.
3. Open Explorer → Blocks and load recent blocks.
4. Open a block, then open transaction forensic view.
5. Search by txid and by block number.
6. Open Chaincode → Definition + Invocations.
7. Export block bundle and tx bundle from Audit section.

## Quick checks

```bash
curl -s http://localhost:4000/health
curl -s http://localhost:4000/api/status/overview | jq
curl -s 'http://localhost:4000/api/v1/explorer/blocks?channel=soclogs&limit=5' | jq
curl -s 'http://localhost:4000/api/v1/chaincode/definition?channel=soclogs&name=lognotary' | jq
curl -s -H "x-admin-password: changeme" "http://localhost:4000/api/admin/logs?service=lognotary-ccaas&tail=20"
```
