# Analysis Tool

This project converts multiple evidence sources into OCSF NDJSON using plugins (detect/parse/map/pipeline).

## Install dependencies

```bash
pip install -r requirements.txt
```

## Webapp connector startup

When you start the FastAPI webapp, it automatically launches the Sysmon and Windows Security
connectors (and reuses any already-running instances on their default ports). The Elastic
connector is also launched when the webapp starts (and reuses any existing instance on port 8789),
as long as you provide Elasticsearch credentials via environment variables. No manual
`python -m app.connectors.*` invocation is required. On Windows, Sysmon and Security event
collection may require running the webapp as Administrator, especially for the Windows
Security connector. If the Security connector fails to start, check
`/api/connectors/logs?name=security` for a clear error message.

## Sysmon Direct Endpoint Connector

This repository includes a Windows Sysmon connector that continuously exports raw Sysmon events (no OCSF normalization) to NDJSON and maintains a checkpoint to avoid duplicates.

### Prerequisites

- Sysmon installed and logging to `Microsoft-Windows-Sysmon/Operational`.
- Administrative PowerShell access to read the Sysmon channel.
- Python 3.11+.

### Install

```bash
pip install pywin32
```

If `pywin32` is unavailable, the connector falls back to PowerShell `Get-WinEvent`.

### Run

```bash
python -m app.connectors.sysmon --poll-seconds 5 --max-events 500
```

Enable the optional local verification server (binds to 127.0.0.1 only):

```bash
python -m app.connectors.sysmon --poll-seconds 5 --max-events 500 --http-port 8787
```

### Output

Events are appended to daily NDJSON files:

```
out/raw/endpoint/windows_sysmon/<hostname>/<YYYY>/<MM>/<DD>/events.ndjson
```

Each line is a RawEvent envelope (v1.0). Example:

```json
{"envelope_version":"1.0","source":{"type":"sysmon","vendor":"microsoft","product":"sysmon","channel":"Microsoft-Windows-Sysmon/Operational","collector":{"name":"sysmon-connector","instance_id":"HOSTNAME:sysmon","host":"HOSTNAME"}},"event":{"time":{"observed_utc":"2024-01-02T03:04:06.000Z","created_utc":"2024-01-02T03:04:05.678Z"}},"ids":{"record_id":123,"event_id":1,"activity_id":null,"correlation_id":null,"dedupe_hash":"sha256:ee29a3127270e1471e2bae6a6d7a4d321cbffc4af988544c64aac088ce1b0acf"},"host":{"hostname":"HOSTNAME","os":"windows","timezone":"UTC+0000"},"severity":"information","tags":["live","sysmon"],"raw":{"format":"xml","data":"<Event>...</Event>","rendered_message":null,"xml":"<Event>...</Event>"}}
```

Checkpoint state is stored at:

```
state/sysmon_checkpoint.json
```

### Reset checkpoint

Stop the connector, then delete the checkpoint file:

```bash
rm state/sysmon_checkpoint.json
```

The next run will re-export from the current log start (no duplicates beyond the reset).

### Webapp verification polling

```bash
GET http://127.0.0.1:<port>/status
GET http://127.0.0.1:<port>/tail?limit=20
```

## Sysmon → OCSF (Phase 2)

Phase 2 produces schema-valid OCSF NDJSON for Sysmon Event IDs 1, 3, and 11 using the
vendored OCSF schema files in `app/ocsf_schema/`.

### Convert RawEvent NDJSON to OCSF NDJSON

```bash
python -m app.normalizers.sysmon_to_ocsf.cli \
  --in out/raw/endpoint/windows_sysmon/<hostname>/<YYYY>/<MM>/<DD>/events.ndjson \
  --out out/ocsf/endpoint/windows_sysmon/<hostname>/<YYYY>/<MM>/<DD>/events.ndjson \
  --strict
```

The converter requires the `jsonschema` package:

```bash
pip install jsonschema
```

The converter writes:

- OCSF NDJSON output:
  `out/ocsf/endpoint/windows_sysmon/<hostname>/<YYYY>/<MM>/<DD>/events.ndjson`
- Mapping/validation report NDJSON (default):
  `out/ocsf/endpoint/windows_sysmon/<hostname>/<YYYY>/<MM>/<DD>/events.report.ndjson`

### Schema validation behavior

- Every mapped event is validated against the vendored OCSF JSON schemas (offline).
- In `--strict` mode, invalid OCSF events are not written, but a report line is still produced.
- Unsupported Sysmon Event IDs emit a report entry with `status="unsupported"` and no OCSF output.

### Sysmon OCSF UI

Open the local UI page:

```
http://127.0.0.1:8000/ui/ocsf/sysmon
```

Use `record_id` or `dedupe_hash` query params to select a specific event, for example:

```
http://127.0.0.1:8000/ui/ocsf/sysmon?record_id=123
```

### Unified pipeline UI

Open the end-to-end pipeline UI for the latest raw events across Sysmon, Windows Security,
and Elastic:

```
http://127.0.0.1:8000/ui/pipeline
```

Use the source dropdown, pick a recent event, and review the original payload, RawEvent
envelope, OCSF (when supported), and the validation/mapping report.

### Phase 1 verification checklist

**Completeness check with `wevtutil`**

1) Capture the latest Sysmon RecordId from the event log:
   ```bash
   wevtutil qe Microsoft-Windows-Sysmon/Operational /f:xml /c:1 /rd:true
   ```
2) Compare the `EventRecordID` in the XML output to the latest `ids.record_id` value in the
   most recent NDJSON line. Confirm `raw.xml` contains the same XML payload.

**Restart safety test**

1) Start the connector and let it ingest for a few cycles.
2) Kill the process mid-run (e.g., Ctrl+C or Task Manager).
3) Restart the connector and confirm:
   - `ids.record_id` continues to increase monotonically.
   - No gaps appear in the NDJSON file for the inspected window.
   - Duplicate records are only skipped when `ids.dedupe_hash` matches exactly.

**Hash determinism test**

1) Pick a single NDJSON line and extract `raw.xml`, `ids.record_id`, and `ids.event_id`.
2) Recompute the dedupe hash with:
   ```text
   sha256(hostname|Microsoft-Windows-Sysmon/Operational|record_id|event_id|created_utc)
   ```
3) Confirm it matches `ids.dedupe_hash`.

### Identity Fields: evidence_id vs dedupe_hash vs metadata.uid

- `ids.dedupe_hash`: ingestion deduplication and restart safety for raw collection.
- `evidence_id`: primary evidence identity used for custody tracking and blockchain anchoring.
- `metadata.original_event_uid`: the source system's record identifier (for example, a Sysmon Record ID).
- `metadata.uid`: the SHA-256 of the canonicalized OCSF JSON, formatted as `sha256:<ocsf_hash>`.

## Windows Security Direct Endpoint Connector

This repository includes a Windows Security connector that continuously exports raw Security events (no OCSF normalization) to NDJSON and maintains a checkpoint to avoid duplicates.

### Prerequisites

- Administrative PowerShell access to read the `Security` channel.
- Python 3.11+.

### Install

```bash
pip install pywin32
```

If `pywin32` is unavailable, the connector falls back to PowerShell `Get-WinEvent`.

### Run

```bash
python -m app.connectors.security --poll-seconds 5 --max-events 500
```

Enable the optional local verification server (binds to 127.0.0.1 only):

```bash
python -m app.connectors.security --poll-seconds 5 --max-events 500 --http-port 8787
```

### Output

Each NDJSON line is a RawEvent v1 envelope (no UI-proxy wrapping required): 

```json
{"envelope_version":"1.0","source":{"type":"security","vendor":"microsoft","product":"windows-security-auditing","channel":"Security","collector":{"name":"security-connector","instance_id":"HOST:security","host":"HOST"}},"event":{"time":{"observed_utc":"2024-03-04T10:11:12.000Z","created_utc":"2024-03-04T10:11:12.000Z"}},"ids":{"record_id":4096,"event_id":4673,"activity_id":null,"correlation_id":null,"dedupe_hash":"sha256:..."},"host":{"hostname":"HOST","os":"windows","timezone":"UTC+0200"},"severity":"high","tags":["live","security"],"raw":{"format":"json","data":{"record_id":4096,"event_id":4673,"provider":"Microsoft-Windows-Security-Auditing", "...":"..."},"rendered_message":null,"xml":"<Event>...</Event>"}} 
```

Events are appended to daily NDJSON files:

```
out/raw/endpoint/windows_security/<hostname>/<YYYY>/<MM>/<DD>/events.ndjson
```

Checkpoint state is stored at:

```
state/security_checkpoint.json
```

### Reset checkpoint

Stop the connector, then delete the checkpoint file:

```bash
rm state/security_checkpoint.json
```

The next run will re-export from the current log start (no duplicates beyond the reset).

### Webapp verification polling

```bash
GET http://127.0.0.1:<port>/status
GET http://127.0.0.1:<port>/tail?limit=20
```

### Manual validation in the web UI

1) Start the connector with the HTTP status server:
   ```bash
   python -m app.connectors.security --poll-seconds 5 --max-events 200 --http-port 8787
   ```
2) Start the web UI and switch **Live source** = Windows Security.
3) Confirm both panels show matching counts and the RAW ENVELOPE validator stays green.
4) Confirm `collector.name` is `security-connector` (not `ui-proxy`).

## Elastic SIEM Connector (Local Elasticsearch)

This repository includes a read-only Elastic connector that continuously exports raw Elasticsearch
documents (no OCSF normalization) to NDJSON and maintains a checkpoint to avoid duplicates.

### Prerequisites

- Local Elasticsearch reachable at `http://127.0.0.1:9200`.
- Credentials (Basic auth) via `ELASTIC_PASSWORD` (username defaults to `elastic`).
- Python 3.11+.

### Run

```bash
export ELASTIC_PASSWORD="your_password"
python -m app.connectors.elastic --poll-seconds 10 --max-events 500 --http-port 8789
```

Override indices and starting window if needed:

```bash
python -m app.connectors.elastic --indices "logs-*-default*" --start-ago-seconds 3600 --http-port 8789
```

You can also override the default index pattern with the `ELASTIC_INDEX` environment variable.

### Output

Events are appended to daily NDJSON files:

```
out/raw/siem/elastic/local/<index>/<YYYY>/<MM>/<DD>/events.ndjson
```

Elastic connector output is RawEvent v1 envelopes (one JSON object per line). Example:

```json
{"envelope_version":"1.0","source":{"type":"elastic","vendor":"elastic","product":"elastic-stack"},"event":{"time":{"observed_utc":"2024-04-01T12:34:56.789Z","created_utc":"2024-04-01T12:35:00Z"}},"raw":{"format":"json","data":{"_index":"logs-test-default","_id":"abc123","_source":{"@timestamp":"2024-04-01T12:34:56.789Z","message":"Example"}}}}
```

Checkpoint state is stored at:

```
state/elastic_checkpoint.json
```

### Reset checkpoint

Stop the connector, then delete the checkpoint file:

```bash
rm state/elastic_checkpoint.json
```

The next run will re-export from the configured `--start-ago-seconds` window.

### Webapp verification polling

```bash
GET http://127.0.0.1:8789/status
GET http://127.0.0.1:8789/tail?limit=20
```

### How to generate test SIEM logs (Kibana Dev Tools)

Use Kibana Dev Tools (Console) to insert documents into a data stream such as
`logs-test-default`. Replace `<id>` with a unique id and adjust fields as needed:

```json
POST logs-test-default/_create/<id>
{
  "@timestamp": "2024-06-07T12:34:56Z",
  "event": {
    "dataset": "test",
    "kind": "event",
    "action": "sample"
  },
  "message": "Test SIEM log entry from Kibana Dev Tools."
}
```

## Documentation
- [Digital Evidence Coverage Framework](docs/evidence_coverage_framework.md)
