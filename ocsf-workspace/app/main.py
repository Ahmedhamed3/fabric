import asyncio
import json
import urllib.parse
import urllib.request
from pathlib import Path
from html import escape
from string import Template
from typing import Any, Dict, List, Optional

from fastapi import FastAPI, UploadFile, File, HTTPException, Form
from fastapi.responses import HTMLResponse, JSONResponse, StreamingResponse

from app.correlation.process_chain import build_process_chains
from app.conversion import (
    SOURCE_PIPELINES,
    convert_events_to_ocsf_jsonl,
    convert_events_with_source_to_ocsf_jsonl,
)
from app.connectors.manager import ConnectorManager
from app.connectors.elastic import tail_elastic_ndjson
from app.detect import auto_detect_source, summarize_event_detection
from app.formats.reader import iter_events_from_upload
from app.plugins.azure_ad_signin.detect import score_events as score_azure_ad_signin
from app.plugins.file_artifact.detect import score_events as score_file_artifact
from app.plugins.suricata.detect import score_events as score_suricata
from app.plugins.sysmon.detect import score_events as score_sysmon
from app.plugins.windows_security.detect import score_events as score_windows_security
from app.plugins.zeek.detect import score_events as score_zeek
from app.plugins.zeek_http.detect import score_events as score_zeek_http
from app.plugins.proxy_http.detect import score_events as score_proxy_http
from app.ui.highlight import (
    collect_unmapped_original_events,
    extract_values,
    highlight_json_text,
)
from app.normalizers.elastic_to_ocsf.io_ndjson import (
    class_path_for_event as elastic_class_path_for_event,
)
from app.normalizers.elastic_to_ocsf.mapper import (
    MappingContext as ElasticMappingContext,
    map_raw_event as map_elastic_raw_event,
    mapping_attempted as elastic_mapping_attempted,
    missing_required_fields as elastic_missing_required_fields,
)
from app.normalizers.sysmon_to_ocsf.io_ndjson import class_path_for_event
from app.normalizers.sysmon_to_ocsf.mapper import (
    MappingContext,
    map_raw_event,
    mapping_attempted,
    missing_required_fields,
)
from app.normalizers.sysmon_to_ocsf.report import build_report
from app.normalizers.sysmon_to_ocsf.validator import OcsfSchemaLoader
from app.normalizers.windows_security_to_ocsf.io_ndjson import (
    class_path_for_event as security_class_path_for_event,
)
from app.normalizers.windows_security_to_ocsf.mapper import (
    MappingContext as SecurityMappingContext,
    map_raw_event as map_security_raw_event,
    mapping_attempted as security_mapping_attempted,
    missing_required_fields as security_missing_required_fields,
)
from app.utils.http_status import tail_ndjson
from app.utils.evidence_hashing import apply_evidence_hashing
from app.utils.timeutil import utc_now_iso

app = FastAPI(
    title="Log → OCSF Converter (MVP)",
    docs_url=None,
    redoc_url=None,
    openapi_url=None,
)

connector_manager = ConnectorManager()


@app.on_event("startup")
async def startup_connectors() -> None:
    await asyncio.to_thread(connector_manager.startup)


@app.on_event("shutdown")
async def shutdown_connectors() -> None:
    await asyncio.to_thread(connector_manager.shutdown)

MAX_UPLOAD_BYTES = 50 * 1024 * 1024
DETECTION_SAMPLE_SIZE = 10
DETECTION_THRESHOLD = 0.6

SOURCE_SCORERS = {
    "azure_ad_signin": score_azure_ad_signin,
    "sysmon": score_sysmon,
    "zeek": score_zeek,
    "zeek_http": score_zeek_http,
    "suricata": score_suricata,
    "windows-security": score_windows_security,
    "file-artifact": score_file_artifact,
    "proxy_http": score_proxy_http,
}

SOURCE_OPTIONS = [
    ("auto", "Auto Detect"),
    ("sysmon", "Sysmon"),
    ("azure_ad_signin", "Azure AD Sign-In"),
    ("zeek", "Zeek DNS"),
    ("zeek_http", "Zeek HTTP"),
    ("suricata", "Suricata Alerts"),
    ("windows-security", "Windows Security"),
    ("file-artifact", "File Artifact"),
    ("proxy_http", "Proxy HTTP"),
]

HTML_PAGE_TEMPLATE = Template(
    """<!doctype html>
<html lang="en">
  <head>
    <meta charset="utf-8" />
    <meta name="viewport" content="width=device-width, initial-scale=1" />
    <title>Log → OCSF Converter</title>
    <style>
      body {
        font-family: Arial, sans-serif;
        margin: 24px;
        color: #1f2933;
        background: #f8f9fb;
      }
      .controls {
        display: flex;
        flex-wrap: wrap;
        gap: 12px;
        align-items: center;
        margin-bottom: 16px;
      }
      select {
        padding: 6px 10px;
        border-radius: 6px;
        border: 1px solid #cbd2d9;
        background: #fff;
      }
      button {
        padding: 8px 12px;
        border-radius: 6px;
        border: 1px solid #cbd2d9;
        background: #fff;
        cursor: pointer;
      }
      button.primary {
        background: #2563eb;
        border-color: #2563eb;
        color: #fff;
      }
      button.toggle-on {
        background: #16a34a;
        border-color: #16a34a;
        color: #fff;
      }
      .live-controls {
        display: flex;
        align-items: center;
        gap: 8px;
      }
      .hl {
        padding: 0 2px;
        border-radius: 4px;
      }
      .status-note {
        font-size: 12px;
        color: #52606d;
      }
      .pane-grid {
        display: grid;
        grid-template-columns: repeat(auto-fit, minmax(280px, 1fr));
        gap: 16px;
      }
      .detect-panel {
        background: #fff;
        border: 1px solid #e4e7eb;
        border-radius: 8px;
        padding: 12px 16px;
        margin-bottom: 16px;
        display: flex;
        flex-direction: column;
        gap: 6px;
      }
      .detect-panel h3 {
        margin: 0;
        font-size: 13px;
        text-transform: uppercase;
        color: #52606d;
        letter-spacing: 0.04em;
      }
      .detect-row {
        font-size: 13px;
        color: #1f2933;
      }
      .pane {
        background: #fff;
        border: 1px solid #e4e7eb;
        border-radius: 8px;
        padding: 12px;
        display: flex;
        flex-direction: column;
        min-height: 360px;
      }
      .pane h2 {
        font-size: 14px;
        margin: 0 0 8px 0;
        color: #52606d;
        text-transform: uppercase;
        letter-spacing: 0.04em;
      }
      .envelope-indicator {
        font-size: 12px;
        color: #334155;
        margin-bottom: 8px;
      }
      pre {
        flex: 1;
        margin: 0;
        padding: 12px;
        background: #0f172a;
        color: #e2e8f0;
        border-radius: 6px;
        overflow: auto;
        font-family: "SFMono-Regular", Consolas, "Liberation Mono", Menlo, monospace;
        font-size: 12px;
        white-space: pre-wrap;
        word-break: break-word;
      }
    </style>
  </head>
  <body>
    <form class="controls" method="post" action="/" enctype="multipart/form-data">
      <input type="file" id="fileInput" name="file" required />
      <select id="sourceSelect" name="source">
        $source_options
      </select>
      <label>
        <input type="checkbox" name="highlight" value="1" $highlight_checked />
        Highlight mappings/values
      </label>
      <button class="primary" id="previewBtn" type="submit">Convert</button>
      <div class="live-controls">
        <label for="liveSource">
          Live source
          <select id="liveSource">
            <option value="sysmon" selected>Windows Sysmon</option>
            <option value="security">Windows Security</option>
            <option value="elastic">Elastic</option>
          </select>
        </label>
        <button type="button" id="liveToggle">Live: OFF (Windows Sysmon)</button>
        <label for="liveLimit">
          Show last
          <select id="liveLimit">
            <option value="5">5</option>
            <option value="10">10</option>
            <option value="20" selected>20</option>
            <option value="50">50</option>
            <option value="100">100</option>
          </select>
        </label>
      </div>
    </form>
    <div class="detect-panel" id="detectPanel">
      <h3>Detection</h3>
      <div class="detect-row" id="detectSource">Source: $detect_source</div>
      <div class="detect-row" id="detectConfidence">Confidence: $detect_confidence</div>
      <div class="detect-row" id="detectReason">Reason: $detect_reason</div>
      <div class="detect-row" id="detectBreakdown">Breakdown: $detect_breakdown</div>
    </div>
    <div class="detect-panel" id="connectorStatusPanel">
      <h3>Connector Status</h3>
      <div class="detect-row" id="cursorPrimary">Last cursor: —</div>
      <div class="detect-row" id="sysmonEventsWritten">Events written total: —</div>
      <div class="detect-row" id="sysmonLastBatch">Last batch count: —</div>
      <div class="detect-row" id="cursorSecondary">Last cursor detail: —</div>
      <div class="detect-row" id="sysmonLastError">Last error: —</div>
      <div class="status-note" id="sysmonStatusMessage"></div>
    </div>
    <div class="pane-grid">
      <div class="pane">
        <h2>Original Logs</h2>
        <pre id="originalPane">$original_text</pre>
      </div>
      <div class="pane">
        <h2>RAW ENVELOPE</h2>
        <div class="envelope-indicator" id="envelopeIndicator">Envelope validation: —</div>
        <pre id="rawEnvelopePane">$unified_text</pre>
      </div>
    </div>
    <script>
      const liveState = {
        enabled: false,
        timerId: null,
      };
      const requiredEnvelopeKeys = ["envelope_version", "source", "event", "raw"];
      const sourceConfig = {
        sysmon: { label: "Windows Sysmon", port: 8787 },
        security: { label: "Windows Security", port: 8788 },
        elastic: { label: "Elastic", port: 8789 },
      };
      const liveToggle = document.getElementById("liveToggle");
      const liveLimit = document.getElementById("liveLimit");
      const liveSource = document.getElementById("liveSource");
      const originalPane = document.getElementById("originalPane");
      const rawEnvelopePane = document.getElementById("rawEnvelopePane");
      const envelopeIndicator = document.getElementById("envelopeIndicator");
      const statusMessage = document.getElementById("sysmonStatusMessage");
      const statusFields = {
        cursor_primary: document.getElementById("cursorPrimary"),
        events_written_total: document.getElementById("sysmonEventsWritten"),
        last_batch_count: document.getElementById("sysmonLastBatch"),
        cursor_secondary: document.getElementById("cursorSecondary"),
        last_error: document.getElementById("sysmonLastError"),
      };

      function setStatusMessage(message) {
        statusMessage.textContent = message || "";
      }

      function updateStatusFields(data) {
        const sourceKey = getCurrentSource();
        if (sourceKey === "elastic") {
          statusFields.cursor_primary.textContent = `Last timestamp: ${data?.last_ts ?? "—"}`;
          statusFields.cursor_secondary.textContent = `Last ids at timestamp: ${
            data?.last_ids_at_ts_count ?? "—"
          }`;
        } else {
          statusFields.cursor_primary.textContent = `Last record id: ${data?.last_record_id ?? "—"}`;
          statusFields.cursor_secondary.textContent = `Last event time (UTC): ${
            data?.last_event_time_utc ?? "—"
          }`;
        }
        statusFields.events_written_total.textContent = `Events written total: ${
          data?.events_written_total ?? "—"
        }`;
        statusFields.last_batch_count.textContent = `Last batch count: ${data?.last_batch_count ?? "—"}`;
        statusFields.last_error.textContent = `Last error: ${data?.last_error ?? "—"}`;
      }

      function extractTailItems(payload) {
        if (Array.isArray(payload)) {
          return payload;
        }
        if (payload && Array.isArray(payload.items)) {
          return payload.items;
        }
        return [];
      }

      function parseTailItem(item) {
        if (typeof item === "string") {
          try {
            return { parsed: JSON.parse(item), raw: item, parsedOk: true };
          } catch (error) {
            return { parsed: item, raw: item, parsedOk: false };
          }
        }
        return { parsed: item, raw: item, parsedOk: true };
      }

      function renderTailEvents(payload) {
        const events = extractTailItems(payload);
        if (!Array.isArray(events) || events.length === 0) {
          return "No events returned yet.";
        }
        return events.map((ev) => JSON.stringify(ev)).join("\\n");
      }

      function renderRawEnvelope(payload) {
        const events = extractTailItems(payload);
        if (!Array.isArray(events) || events.length === 0) {
          return "No envelope data returned yet.";
        }
        return events
          .map((item) => {
            const parsed = parseTailItem(item).parsed;
            if (parsed && typeof parsed === "object") {
              return JSON.stringify(parsed, null, 2);
            }
            return String(parsed ?? "");
          })
          .join("\\n\\n");
      }

      function updateEnvelopeIndicator(payload) {
        const events = extractTailItems(payload);
        if (!Array.isArray(events) || events.length === 0) {
          envelopeIndicator.textContent = "Envelope validation: —";
          return;
        }
        const latest = parseTailItem(events[events.length - 1]).parsed;
        if (!latest || typeof latest !== "object" || Array.isArray(latest)) {
          envelopeIndicator.textContent = `Envelope validation: ❌ Missing: ${requiredEnvelopeKeys.join(
            ", "
          )}`;
          return;
        }
        const missing = requiredEnvelopeKeys.filter((key) => !(key in latest));
        envelopeIndicator.textContent =
          missing.length === 0
            ? "Envelope validation: ✅ Valid Envelope"
            : `Envelope validation: ❌ Missing: ${missing.join(", ")}`;
      }

      async function fetchJson(url) {
        const response = await fetch(url, { method: "GET" });
        if (!response.ok) {
          throw new Error(`HTTP ${response.status}`);
        }
        return response.json();
      }

      function getCurrentSource() {
        return liveSource.value || "sysmon";
      }

      function updateLiveToggleLabel() {
        const sourceKey = getCurrentSource();
        const label = sourceConfig[sourceKey]?.label ?? sourceKey;
        liveToggle.textContent = liveState.enabled ? `Live: ON (${label})` : `Live: OFF (${label})`;
      }

      async function pollLiveSource() {
        const limit = liveLimit.value || "20";
        const sourceKey = getCurrentSource();
        const config = sourceConfig[sourceKey] || { label: sourceKey, port: "??" };
        try {
          const [statusData, tailData] = await Promise.all([
            fetchJson(`/api/${sourceKey}/status`),
            fetchJson(`/api/${sourceKey}/tail?limit=${encodeURIComponent(limit)}`),
          ]);
          updateStatusFields(statusData);
          setStatusMessage("");
          originalPane.textContent = renderTailEvents(tailData);
          rawEnvelopePane.textContent = renderRawEnvelope(tailData);
          updateEnvelopeIndicator(tailData);
        } catch (error) {
          const message = `${config.label} connector not running. Start it with --http-port ${config.port}.`;
          setStatusMessage(message);
          originalPane.textContent = message;
          rawEnvelopePane.textContent = message;
          envelopeIndicator.textContent = "Envelope validation: —";
        }
      }

      function setLiveState(enabled) {
        liveState.enabled = enabled;
        updateLiveToggleLabel();
        if (enabled) {
          liveToggle.classList.add("toggle-on");
          pollLiveSource();
          if (liveState.timerId) {
            clearInterval(liveState.timerId);
          }
          liveState.timerId = setInterval(pollLiveSource, 2000);
        } else {
          liveToggle.classList.remove("toggle-on");
          if (liveState.timerId) {
            clearInterval(liveState.timerId);
            liveState.timerId = null;
          }
        }
      }

      liveToggle.addEventListener("click", () => {
        setLiveState(!liveState.enabled);
      });

      liveSource.addEventListener("change", () => {
        updateLiveToggleLabel();
        if (liveState.enabled) {
          pollLiveSource();
        }
      });

      liveLimit.addEventListener("change", () => {
        if (liveState.enabled) {
          pollLiveSource();
        }
      });

      updateLiveToggleLabel();
    </script>
  </body>
</html>
"""
)

SYS_MON_OCSF_TEMPLATE = Template(
    """<!doctype html>
<html lang="en">
  <head>
    <meta charset="utf-8" />
    <meta name="viewport" content="width=device-width, initial-scale=1" />
    <title>Sysmon → OCSF (Phase 2)</title>
    <style>
      body {
        font-family: Arial, sans-serif;
        margin: 24px;
        color: #1f2933;
        background: #f8f9fb;
      }
      .header {
        display: flex;
        justify-content: space-between;
        align-items: center;
        margin-bottom: 16px;
      }
      .controls {
        display: flex;
        gap: 12px;
        align-items: center;
        flex-wrap: wrap;
      }
      .event-list {
        display: flex;
        gap: 8px;
        flex-wrap: wrap;
        margin-bottom: 16px;
      }
      .empty-state {
        padding: 12px;
        background: #fff;
        border: 1px dashed #cbd2d9;
        border-radius: 8px;
        color: #52606d;
        font-size: 13px;
      }
      .event-list button {
        border: 1px solid #cbd2d9;
        border-radius: 6px;
        background: #fff;
        padding: 6px 10px;
        cursor: pointer;
      }
      .event-list button.active {
        background: #2563eb;
        color: #fff;
        border-color: #2563eb;
      }
      .panel-grid {
        display: grid;
        grid-template-columns: repeat(auto-fit, minmax(280px, 1fr));
        gap: 16px;
      }
      .panel {
        background: #fff;
        border: 1px solid #e4e7eb;
        border-radius: 8px;
        padding: 12px;
        display: flex;
        flex-direction: column;
        min-height: 360px;
      }
      .panel h2 {
        font-size: 14px;
        margin: 0 0 8px 0;
        color: #52606d;
        text-transform: uppercase;
        letter-spacing: 0.04em;
      }
      pre {
        flex: 1;
        margin: 0;
        padding: 12px;
        background: #0f172a;
        color: #e2e8f0;
        border-radius: 6px;
        overflow: auto;
        font-family: "SFMono-Regular", Consolas, "Liberation Mono", Menlo, monospace;
        font-size: 12px;
        white-space: pre-wrap;
        word-break: break-word;
      }
      .status {
        font-size: 12px;
        color: #52606d;
      }
    </style>
  </head>
  <body>
    <div class="header">
      <h1>Sysmon → OCSF (Phase 2)</h1>
      <div class="controls">
        <label>
          Latest events:
          <input id="limitInput" type="number" min="1" max="200" value="$limit" />
        </label>
        <button id="refreshButton">Refresh</button>
        <span class="status" id="statusLabel"></span>
      </div>
    </div>
    <div class="event-list" id="eventList"></div>
    <div class="panel-grid">
      <div class="panel">
        <h2>RawEvent JSON</h2>
        <pre id="rawPanel">Select an event...</pre>
      </div>
      <div class="panel">
        <h2>OCSF JSON</h2>
        <pre id="ocsfPanel">Select an event...</pre>
      </div>
      <div class="panel">
        <h2>Validation + Mapping Report</h2>
        <pre id="reportPanel">Select an event...</pre>
      </div>
    </div>
    <script>
      const eventList = document.getElementById("eventList");
      const rawPanel = document.getElementById("rawPanel");
      const ocsfPanel = document.getElementById("ocsfPanel");
      const reportPanel = document.getElementById("reportPanel");
      const statusLabel = document.getElementById("statusLabel");
      const limitInput = document.getElementById("limitInput");
      const refreshButton = document.getElementById("refreshButton");

      function formatJson(value) {
        if (!value) {
          return "—";
        }
        return JSON.stringify(value, null, 2);
      }

      async function loadEvents() {
        statusLabel.textContent = "Loading…";
        const limit = limitInput.value || $limit;
        const response = await fetch("/api/ocsf/sysmon/events?limit=" + limit);
        const data = await response.json();
        eventList.innerHTML = "";
        if (!data.events.length) {
          statusLabel.textContent = data.message || "No raw events found.";
          return;
        }
        statusLabel.textContent = data.message || "";
        data.events.forEach((item) => {
          const button = document.createElement("button");
          button.textContent = "Record " + item.record_id + " (EID " + item.event_id + ")";
          button.dataset.recordId = item.record_id;
          button.dataset.dedupeHash = item.dedupe_hash;
          button.addEventListener("click", () => selectEvent(button.dataset.recordId, button.dataset.dedupeHash));
          eventList.appendChild(button);
        });
        const params = new URLSearchParams(window.location.search);
        const recordId = params.get("record_id");
        const dedupeHash = params.get("dedupe_hash");
        if (recordId || dedupeHash) {
          await selectEvent(recordId, dedupeHash);
        }
      }

      async function selectEvent(recordId, dedupeHash) {
        if (!recordId && !dedupeHash) return;
        Array.from(eventList.children).forEach((button) => {
          button.classList.toggle("active", button.dataset.recordId === recordId);
        });
        const query = new URLSearchParams();
        if (recordId) query.set("record_id", recordId);
        if (dedupeHash) query.set("dedupe_hash", dedupeHash);
        const response = await fetch("/api/ocsf/sysmon/event?" + query.toString());
        const payload = await response.json();
        rawPanel.textContent = formatJson(payload.raw_event);
        ocsfPanel.textContent = formatJson(payload.ocsf_event);
        reportPanel.textContent = formatJson(payload.report);
      }

      refreshButton.addEventListener("click", () => loadEvents());
      loadEvents();
    </script>
  </body>
</html>
"""
)

PIPELINE_UI_TEMPLATE = Template(
    """<!doctype html>
<html lang="en">
  <head>
    <meta charset="utf-8" />
    <meta name="viewport" content="width=device-width, initial-scale=1" />
    <title>Pipeline Viewer</title>
    <style>
      body {
        font-family: Arial, sans-serif;
        margin: 24px;
        color: #1f2933;
        background: #f8f9fb;
      }
      .header {
        display: flex;
        justify-content: space-between;
        align-items: center;
        margin-bottom: 16px;
        flex-wrap: wrap;
        gap: 12px;
      }
      .controls {
        display: flex;
        gap: 12px;
        align-items: center;
        flex-wrap: wrap;
      }
      select,
      input[type="number"] {
        padding: 6px 10px;
        border-radius: 6px;
        border: 1px solid #cbd2d9;
        background: #fff;
      }
      button {
        border: 1px solid #cbd2d9;
        border-radius: 6px;
        background: #fff;
        padding: 6px 10px;
        cursor: pointer;
      }
      .event-list {
        display: flex;
        gap: 8px;
        flex-wrap: wrap;
        margin-bottom: 16px;
      }
      .event-list button.active {
        background: #2563eb;
        color: #fff;
        border-color: #2563eb;
      }
      .panel-grid {
        display: grid;
        grid-template-columns: repeat(2, minmax(280px, 1fr));
        gap: 16px;
      }
      .panel {
        background: #fff;
        border: 1px solid #e4e7eb;
        border-radius: 8px;
        padding: 12px;
        display: flex;
        flex-direction: column;
        min-height: 320px;
      }
      .panel h2 {
        font-size: 14px;
        margin: 0 0 8px 0;
        color: #52606d;
        text-transform: uppercase;
        letter-spacing: 0.04em;
      }
      pre {
        flex: 1;
        margin: 0;
        padding: 12px;
        background: #0f172a;
        color: #e2e8f0;
        border-radius: 6px;
        overflow: auto;
        font-family: "SFMono-Regular", Consolas, "Liberation Mono", Menlo, monospace;
        font-size: 12px;
        white-space: pre-wrap;
        word-break: break-word;
      }
      .status {
        font-size: 12px;
        color: #52606d;
      }
      @media (max-width: 768px) {
        .panel-grid {
          grid-template-columns: 1fr;
        }
      }
    </style>
  </head>
  <body>
    <div class="header">
      <h1>Pipeline Viewer</h1>
      <div class="controls">
        <label>
          Source:
          <select id="sourceSelect">
            <option value="sysmon" selected>Sysmon</option>
            <option value="security">Windows Security</option>
            <option value="elastic">Elastic</option>
          </select>
        </label>
        <label>
          Latest N:
          <input id="limitInput" type="number" min="1" max="200" value="$limit" />
        </label>
        <button id="refreshButton">Refresh</button>
        <span class="status" id="statusLabel"></span>
      </div>
    </div>
    <div class="event-list" id="eventList"></div>
    <div class="panel-grid">
      <div class="panel">
        <h2>Original</h2>
        <pre id="originalPanel">Select an event...</pre>
      </div>
      <div class="panel">
        <h2>Raw Event Envelope</h2>
        <pre id="rawPanel">Select an event...</pre>
      </div>
      <div class="panel">
        <h2>OCSF JSON</h2>
        <pre id="ocsfPanel">Select an event...</pre>
      </div>
      <div class="panel">
        <h2>Validation + Mapping Report</h2>
        <pre id="reportPanel">Select an event...</pre>
      </div>
    </div>
    <script>
      const sourceSelect = document.getElementById("sourceSelect");
      const eventList = document.getElementById("eventList");
      const originalPanel = document.getElementById("originalPanel");
      const rawPanel = document.getElementById("rawPanel");
      const ocsfPanel = document.getElementById("ocsfPanel");
      const reportPanel = document.getElementById("reportPanel");
      const statusLabel = document.getElementById("statusLabel");
      const limitInput = document.getElementById("limitInput");
      const refreshButton = document.getElementById("refreshButton");

      function formatJson(value, fallback = "—") {
        if (value === null || value === undefined) {
          return fallback;
        }
        if (typeof value === "string") {
          return value;
        }
        return JSON.stringify(value, null, 2);
      }

      function clearPanels(message) {
        originalPanel.textContent = message;
        rawPanel.textContent = message;
        ocsfPanel.textContent = message;
        reportPanel.textContent = message;
      }

      async function loadEvents() {
        statusLabel.textContent = "Loading…";
        const source = sourceSelect.value;
        const limit = limitInput.value || $limit;
        const response = await fetch(`/api/${source}/tail?limit=${limit}`);
        if (!response.ok) {
          statusLabel.textContent = "Failed to load events.";
          clearPanels("No data.");
          return;
        }
        const data = await response.json();
        const items = data.items || [];
        eventList.innerHTML = "";
        if (!items.length) {
          statusLabel.textContent = "No events found.";
          eventList.innerHTML = "<div class=\\"empty-state\\">No events yet. Try refreshing or adjusting the source.</div>";
          clearPanels("No data.");
          return;
        }
        statusLabel.textContent = "";
        items.forEach((item) => {
          const ids = item.ids || {};
          const recordId = ids.record_id ?? "—";
          const eventId = ids.event_id ?? "—";
          const key = ids.dedupe_hash || recordId;
          const button = document.createElement("button");
          button.textContent = `Record ${recordId} (EID ${eventId})`;
          button.dataset.key = key;
          button.addEventListener("click", () => selectEvent(key));
          eventList.appendChild(button);
        });
        const firstKey = eventList.firstChild?.dataset?.key;
        if (firstKey) {
          selectEvent(firstKey);
        }
      }

      async function selectEvent(key) {
        if (!key) {
          return;
        }
        Array.from(eventList.children).forEach((button) => {
          button.classList.toggle("active", button.dataset.key === key);
        });
        const source = sourceSelect.value;
        const response = await fetch(`/api/pipeline/event?source=${source}&key=${encodeURIComponent(key)}`);
        if (!response.ok) {
          const error = await response.json().catch(() => ({}));
          const message = error.detail || "Failed to load event.";
          statusLabel.textContent = message;
          clearPanels(message);
          return;
        }
        const payload = await response.json();
        originalPanel.textContent = formatJson(payload.original, "Not available.");
        rawPanel.textContent = formatJson(payload.raw_envelope, "Not available.");
        if (payload.ocsf) {
          ocsfPanel.textContent = formatJson(payload.ocsf, "Not available.");
        } else if (payload.report?.status === "unsupported") {
          ocsfPanel.textContent = "Not supported yet.";
        } else if (payload.report?.message) {
          ocsfPanel.textContent = payload.report.message;
        } else {
          ocsfPanel.textContent = "No OCSF output.";
        }
        reportPanel.textContent = formatJson(payload.report, "Not available.");
      }

      refreshButton.addEventListener("click", loadEvents);
      sourceSelect.addEventListener("change", loadEvents);
      limitInput.addEventListener("change", loadEvents);
      loadEvents();
    </script>
  </body>
</html>
"""
)

_OCSF_SCHEMA_LOADER: Optional[OcsfSchemaLoader] = None


def _get_ocsf_schema_loader() -> OcsfSchemaLoader:
    global _OCSF_SCHEMA_LOADER
    if _OCSF_SCHEMA_LOADER is None:
        _OCSF_SCHEMA_LOADER = OcsfSchemaLoader(Path("app/ocsf_schema"))
    return _OCSF_SCHEMA_LOADER


def _latest_raw_path(base_dir: Path) -> Optional[Path]:
    if not base_dir.exists():
        return None
    candidates = list(base_dir.rglob("events.ndjson"))
    if not candidates:
        return None
    return max(candidates, key=lambda path: path.stat().st_mtime)


def _latest_sysmon_raw_path() -> Optional[Path]:
    return _latest_raw_path(Path("out/raw/endpoint/windows_sysmon"))


def _load_sysmon_raw_events(limit: int) -> List[Dict[str, Any]]:
    path = _latest_sysmon_raw_path()
    if path is None:
        return []
    lines = path.read_text(encoding="utf-8").splitlines()
    selected = lines[-limit:] if limit else lines
    events = []
    for line in selected:
        line = line.strip()
        if not line:
            continue
        events.append(json.loads(line))
    return events


def _latest_security_raw_path() -> Optional[Path]:
    return _latest_raw_path(Path("out/raw/endpoint/windows_security"))


def _load_security_raw_events(limit: int) -> List[Dict[str, Any]]:
    path = _latest_security_raw_path()
    if path is None:
        return []
    return tail_ndjson(path, limit)


def _load_elastic_raw_events(limit: int) -> List[Dict[str, Any]]:
    return tail_elastic_ndjson("out/raw/siem/elastic", limit)


def _build_sysmon_ocsf_payload(raw_event: Dict[str, Any]) -> Dict[str, Any]:
    schema_loader = _get_ocsf_schema_loader()
    context = MappingContext(ocsf_version=schema_loader.version)
    ocsf_event = map_raw_event(raw_event, context)
    attempted = mapping_attempted(raw_event)
    supported = attempted
    missing_fields = missing_required_fields(raw_event)
    validation_errors: List[str] = []
    evidence_commit = None
    raw_event_output = raw_event
    if supported and ocsf_event is not None:
        class_path = class_path_for_event(ocsf_event)
        if class_path:
            validation = schema_loader.validate_event(ocsf_event, class_path)
            validation_errors = validation.errors
            if not validation.errors:
                hash_result = apply_evidence_hashing(
                    raw_event,
                    ocsf_event,
                    ocsf_schema=class_path,
                    ocsf_version=context.ocsf_version,
                )
                raw_event_output = hash_result.raw_envelope
                ocsf_event = hash_result.ocsf_event
                evidence_commit = hash_result.evidence_commit
        else:
            supported = False
            ocsf_event = None
    elif not attempted:
        supported = False
    report = build_report(
        raw_event=raw_event,
        ocsf_event=ocsf_event,
        supported=supported,
        validation_errors=validation_errors,
        mapping_attempted=attempted,
        missing_fields=missing_fields,
    )
    if evidence_commit is not None:
        report["evidence_commit"] = evidence_commit
    return {
        "raw_event": raw_event_output,
        "ocsf_event": ocsf_event,
        "report": report,
        "evidence_commit": evidence_commit,
    }


def _build_security_ocsf_payload(raw_event: Dict[str, Any]) -> Dict[str, Any]:
    schema_loader = _get_ocsf_schema_loader()
    context = SecurityMappingContext(ocsf_version=schema_loader.version)
    ocsf_event = map_security_raw_event(raw_event, context)
    attempted = security_mapping_attempted(raw_event)
    supported = attempted
    missing_fields = security_missing_required_fields(raw_event)
    validation_errors: List[str] = []
    evidence_commit = None
    raw_event_output = raw_event
    if supported and ocsf_event is not None:
        class_path = security_class_path_for_event(ocsf_event)
        if class_path:
            validation = schema_loader.validate_event(ocsf_event, class_path)
            validation_errors = validation.errors
            if not validation.errors:
                hash_result = apply_evidence_hashing(
                    raw_event,
                    ocsf_event,
                    ocsf_schema=class_path,
                    ocsf_version=context.ocsf_version,
                )
                raw_event_output = hash_result.raw_envelope
                ocsf_event = hash_result.ocsf_event
                evidence_commit = hash_result.evidence_commit
        else:
            supported = False
            ocsf_event = None
    report = build_report(
        raw_event=raw_event,
        ocsf_event=ocsf_event,
        supported=supported,
        validation_errors=validation_errors,
        mapping_attempted=attempted,
        missing_fields=missing_fields,
    )
    if evidence_commit is not None:
        report["evidence_commit"] = evidence_commit
    return {
        "raw_event": raw_event_output,
        "ocsf_event": ocsf_event,
        "report": report,
        "evidence_commit": evidence_commit,
    }


def _build_elastic_ocsf_payload(raw_event: Dict[str, Any]) -> Dict[str, Any]:
    schema_loader = _get_ocsf_schema_loader()
    context = ElasticMappingContext(ocsf_version=schema_loader.version)
    ocsf_event = map_elastic_raw_event(raw_event, context)
    attempted = elastic_mapping_attempted(raw_event)
    supported = attempted
    missing_fields = elastic_missing_required_fields(raw_event)
    validation_errors: List[str] = []
    evidence_commit = None
    raw_event_output = raw_event
    if supported and ocsf_event is not None:
        class_path = elastic_class_path_for_event(ocsf_event)
        if class_path:
            validation = schema_loader.validate_event(ocsf_event, class_path)
            validation_errors = validation.errors
            if not validation.errors:
                hash_result = apply_evidence_hashing(
                    raw_event,
                    ocsf_event,
                    ocsf_schema=class_path,
                    ocsf_version=context.ocsf_version,
                )
                raw_event_output = hash_result.raw_envelope
                ocsf_event = hash_result.ocsf_event
                evidence_commit = hash_result.evidence_commit
        else:
            supported = False
            ocsf_event = None
    report = build_report(
        raw_event=raw_event,
        ocsf_event=ocsf_event,
        supported=supported,
        validation_errors=validation_errors,
        mapping_attempted=attempted,
        missing_fields=missing_fields,
    )
    if evidence_commit is not None:
        report["evidence_commit"] = evidence_commit
    return {
        "raw_event": raw_event_output,
        "ocsf_event": ocsf_event,
        "report": report,
        "evidence_commit": evidence_commit,
    }


def _build_not_implemented_report(raw_event: Dict[str, Any], source: str) -> Dict[str, Any]:
    ids = raw_event.get("ids") or {}
    return {
        "record_id": ids.get("record_id"),
        "dedupe_hash": ids.get("dedupe_hash"),
        "event_id": ids.get("event_id"),
        "supported": False,
        "schema_valid": False,
        "validation_errors": [],
        "mapped": False,
        "status": "not_implemented",
        "message": f"OCSF mapping not implemented for source '{source}'.",
    }


def _extract_original_payload(raw_event: Dict[str, Any], source: str) -> Any:
    raw = raw_event.get("raw") or {}
    if source == "sysmon":
        return raw.get("xml") or raw.get("data")
    if source == "security":
        return raw.get("xml") or raw.get("data")
    return raw.get("data")


def _matches_event_key(raw_event: Dict[str, Any], key: str) -> bool:
    ids = raw_event.get("ids") or {}
    if ids.get("dedupe_hash") == key:
        return True
    record_id = ids.get("record_id")
    if record_id is None:
        return False
    return str(record_id) == key


def _build_source_options(selected_source: str) -> str:
    options = []
    for value, label in SOURCE_OPTIONS:
        selected = " selected" if value == selected_source else ""
        options.append(f'<option value="{value}"{selected}>{label}</option>')
    return "\n        ".join(options)


def _format_confidence(confidence: Optional[float]) -> str:
    if confidence is None:
        return "—"
    return f"{confidence:.2f}"


def _render_index(
    *,
    detection: Optional[Dict[str, Any]] = None,
    original_html: str = "",
    unified_html: str = "",
    error_message: Optional[str] = None,
    selected_source: str = "auto",
    highlight_enabled: bool = False,
) -> str:
    if not unified_html:
        unified_html = escape("Live envelopes appear here when Live is ON.")
    if not detection:
        detect_source = "—"
        detect_confidence = "—"
        detect_reason = "—"
        detect_breakdown = "—"
    else:
        detect_source = detection.get("source_type") or "unknown"
        confidence = detection.get("confidence")
        detect_confidence = _format_confidence(confidence if isinstance(confidence, (int, float)) else None)
        reason_text = detection.get("reason") or "—"
        if error_message:
            reason_text = f"{reason_text} ({error_message})"
        detect_reason = reason_text
        breakdown = detection.get("breakdown")
        if isinstance(breakdown, list) and breakdown:
            breakdown_lines = []
            for item in breakdown:
                source = item.get("source", "unknown")
                count = item.get("count", 0)
                total = item.get("total", 0)
                ratio = item.get("ratio", 0)
                ratio_text = f"{ratio:.2f}" if isinstance(ratio, (int, float)) else "0.00"
                breakdown_lines.append(f"{source}: {count}/{total} ({ratio_text})")
            detect_breakdown = ", ".join(breakdown_lines)
        else:
            detect_breakdown = "—"
    return HTML_PAGE_TEMPLATE.safe_substitute(
        source_options=_build_source_options(selected_source),
        detect_source=escape(str(detect_source)),
        detect_confidence=escape(str(detect_confidence)),
        detect_reason=escape(str(detect_reason)),
        detect_breakdown=escape(str(detect_breakdown)),
        original_text=original_html,
        unified_text=unified_html,
        highlight_checked="checked" if highlight_enabled else "",
    )


def _pretty_json(obj: Any) -> str:
    if isinstance(obj, list) and len(obj) == 1:
        obj = obj[0]
    return json.dumps(obj, indent=2, ensure_ascii=False)


def _parse_ocsf_json_lines(lines: List[str]) -> Optional[Any]:
    objects: List[Any] = []
    for line in lines:
        try:
            objects.append(json.loads(line))
        except json.JSONDecodeError:
            continue
    if not objects:
        return None
    if len(objects) == 1:
        return objects[0]
    return objects


REQUIRED_ENVELOPE_KEYS = ("envelope_version", "source", "event", "raw")


def _has_required_envelope_keys(payload: Any) -> bool:
    if not isinstance(payload, dict):
        return False
    return all(key in payload for key in REQUIRED_ENVELOPE_KEYS)


def _build_envelope(source_key: str, raw_payload: Any) -> Dict[str, Any]:
    return {
        "envelope_version": "1.0",
        "source": {
            "type": source_key,
            "collector": {
                "name": "ui-proxy",
            },
        },
        "event": {
            "time": {
                "observed_utc": utc_now_iso(),
            },
        },
        "raw": raw_payload,
    }


def _coerce_envelope_item(source_key: str, item: Any) -> Dict[str, Any]:
    if isinstance(item, str):
        try:
            parsed = json.loads(item)
        except json.JSONDecodeError:
            parsed = None
        if parsed is not None and _has_required_envelope_keys(parsed):
            return parsed
        raw_payload = parsed if parsed is not None else item
        return _build_envelope(source_key, raw_payload)
    if _has_required_envelope_keys(item):
        return item
    return _build_envelope(source_key, item)


def _extract_tail_items(payload: Any) -> List[Any]:
    if isinstance(payload, list):
        return payload
    if isinstance(payload, dict):
        items = payload.get("items")
        if isinstance(items, list):
            return items
    return []


def _wrap_tail_payload(
    source_key: str,
    payload: Any,
    limit: int | None = None,
    *,
    wrap_items: bool = True,
) -> Dict[str, Any]:
    items = _extract_tail_items(payload)
    if limit is not None:
        items = items[-limit:]
    if not wrap_items:
        return {"items": items}
    return {"items": [_coerce_envelope_item(source_key, item) for item in items]}


@app.get("/", response_class=HTMLResponse)
async def index():
    return _render_index()


@app.post("/", response_class=HTMLResponse)
async def index_post(
    file: UploadFile = File(...),
    source: str = Form("auto"),
    highlight: Optional[str] = Form(None),
):
    upload = await _read_upload(file)
    error_message = None
    if source == "auto":
        detection = summarize_event_detection(
            upload["events"],
            threshold=DETECTION_THRESHOLD,
        )
        detection["auto"] = True
        unified_lines = list(
            convert_events_to_ocsf_jsonl(upload["events"], threshold=DETECTION_THRESHOLD)
        )
        if detection.get("source_type") == "unknown":
            error_message = "Unable to confidently auto-detect source."
    else:
        _validate_selected_source(source, upload["events"])
        unified_lines = list(
            convert_events_with_source_to_ocsf_jsonl(
                upload["events"],
                source_type=source,
            )
        )
        detection = _build_detection_payload(
            source,
            auto=False,
            reason="Selected manually.",
        )
    highlight_enabled = highlight is not None
    original_json = _pretty_json(upload["events"])
    ocsf_objects = _parse_ocsf_json_lines(unified_lines)
    if ocsf_objects is None:
        unified_json = "\n".join(unified_lines)
    else:
        unified_json = _pretty_json(ocsf_objects)
    if highlight_enabled and ocsf_objects is not None:
        original_values = extract_values(upload["events"])
        ocsf_values = extract_values(ocsf_objects)
        shared_values = original_values & ocsf_values
        preserve_values = collect_unmapped_original_events(ocsf_objects)
        original_panel_html = highlight_json_text(original_json, shared_values)
        unified_panel_html = highlight_json_text(
            unified_json,
            shared_values,
            preserve_values=preserve_values,
        )
    else:
        original_panel_html = escape(original_json)
        unified_panel_html = escape(unified_json)
    return _render_index(
        detection=detection,
        original_html=original_panel_html,
        unified_html="",
        error_message=error_message,
        selected_source=source,
        highlight_enabled=highlight_enabled,
    )


async def _read_upload(file: UploadFile) -> Dict[str, Any]:
    content = await file.read()
    if len(content) > MAX_UPLOAD_BYTES:
        raise HTTPException(status_code=413, detail="File too large (max 50MB for MVP).")
    events = list(iter_events_from_upload(content))
    if not events:
        raise HTTPException(status_code=400, detail="No events found in upload.")
    original_text = content.decode("utf-8-sig", errors="replace")
    return {"content": content, "events": events, "original_text": original_text}


def _validate_selected_source(source_type: str, events: List[dict]) -> Dict[str, Any]:
    scorer = SOURCE_SCORERS.get(source_type)
    if not scorer:
        raise HTTPException(status_code=400, detail=f"Unknown source type: {source_type}.")
    confidence, reason = scorer(events[:DETECTION_SAMPLE_SIZE])
    if confidence < DETECTION_THRESHOLD:
        raise HTTPException(
            status_code=400,
            detail={
                "error": f"Unsupported file or not detected as {source_type}.",
                "confidence": confidence,
                "reason": reason,
            },
        )
    return {"confidence": confidence, "reason": reason}


def _get_converter(source_type: str):
    converter = SOURCE_PIPELINES.get(source_type)
    if not converter:
        raise HTTPException(status_code=400, detail=f"Unknown source type: {source_type}.")
    return converter


def _build_detection_payload(
    source_type: str,
    *,
    auto: bool,
    confidence: Optional[float] = None,
    reason: Optional[str] = None,
) -> Dict[str, Any]:
    return {
        "source_type": source_type,
        "confidence": confidence,
        "reason": reason or "—",
        "auto": auto,
    }


def _extract_actor_process(event: Dict[str, Any]) -> Dict[str, Any]:
    actor = event.get("actor", {})
    if isinstance(actor, dict):
        process = actor.get("process", {})
        if isinstance(process, dict):
            return process
    return {}


def _extract_target_process(event: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    target = event.get("process", {})
    if not isinstance(target, dict):
        return None
    if not any(target.get(key) for key in ("uid", "executable", "command_line")):
        return None
    return {
        "uid": target.get("uid"),
        "executable": target.get("executable"),
        "command_line": target.get("command_line"),
    }


def _format_chain_event(event: Dict[str, Any]) -> Dict[str, Any]:
    actor_process = _extract_actor_process(event)
    formatted = {
        "time": event.get("time"),
        "activity_id": event.get("activity_id"),
        "type_uid": event.get("type_uid"),
        "executable": actor_process.get("executable"),
        "command_line": actor_process.get("command_line"),
    }
    target_process = _extract_target_process(event)
    if target_process:
        formatted["target_process"] = target_process
    return formatted


def _format_chain(chain) -> Dict[str, Any]:
    return {
        "process_uid": chain.process_uid,
        "parent_process_uid": chain.parent_process_uid,
        "event_count": len(chain.events),
        "events": [_format_chain_event(event) for event in chain.events],
    }


@app.post("/correlate/process-chains")
async def correlate_process_chains(events: List[Dict[str, Any]]):
    chains = build_process_chains(events)
    return JSONResponse([_format_chain(chain) for chain in chains])

def _stream_ndjson(events: List[dict], source_type: str, filename: str) -> StreamingResponse:
    return StreamingResponse(
        (
            line + "\n"
            for line in convert_events_with_source_to_ocsf_jsonl(
                events,
                source_type=source_type,
            )
        ),
        media_type="application/x-ndjson",
        headers={"Content-Disposition": f"attachment; filename={filename}"},
    )


def _stream_auto_ndjson(events: List[dict], filename: str) -> StreamingResponse:
    return StreamingResponse(
        (line + "\n" for line in convert_events_to_ocsf_jsonl(events, threshold=DETECTION_THRESHOLD)),
        media_type="application/x-ndjson",
        headers={"Content-Disposition": f"attachment; filename={filename}"},
    )


def _build_preview_response(
    *,
    original_text: str,
    unified_lines: List[str],
    detection: Dict[str, Any],
    error: Optional[str] = None,
) -> JSONResponse:
    payload: Dict[str, Any] = {
        "original": original_text,
        "unified_ndjson": "\n".join(unified_lines),
        "detection": detection,
    }
    if error:
        payload["error"] = error
    return JSONResponse(payload)


SYS_MON_PROXY_BASE = "http://127.0.0.1:8787"
SECURITY_PROXY_BASE = "http://127.0.0.1:8788"
ELASTIC_PROXY_BASE = "http://127.0.0.1:8789"


async def _fetch_sysmon_json(path: str, params: Optional[Dict[str, Any]] = None) -> Any:
    query = f"?{urllib.parse.urlencode(params)}" if params else ""
    url = f"{SYS_MON_PROXY_BASE}{path}{query}"

    def _load() -> bytes:
        with urllib.request.urlopen(url, timeout=2) as response:
            return response.read()

    try:
        payload = await asyncio.to_thread(_load)
    except Exception as exc:
        raise HTTPException(
            status_code=502,
            detail="Sysmon connector not reachable.",
        ) from exc

    try:
        return json.loads(payload)
    except json.JSONDecodeError as exc:
        raise HTTPException(
            status_code=502,
            detail="Sysmon connector returned invalid JSON.",
        ) from exc


async def _fetch_security_json(path: str, params: Optional[Dict[str, Any]] = None) -> Any:
    query = f"?{urllib.parse.urlencode(params)}" if params else ""
    url = f"{SECURITY_PROXY_BASE}{path}{query}"

    def _load() -> bytes:
        with urllib.request.urlopen(url, timeout=2) as response:
            return response.read()

    try:
        payload = await asyncio.to_thread(_load)
    except Exception as exc:
        raise HTTPException(
            status_code=502,
            detail="Security connector not reachable.",
        ) from exc

    try:
        return json.loads(payload)
    except json.JSONDecodeError as exc:
        raise HTTPException(
            status_code=502,
            detail="Security connector returned invalid JSON.",
        ) from exc


async def _fetch_elastic_json(path: str, params: Optional[Dict[str, Any]] = None) -> Any:
    query = f"?{urllib.parse.urlencode(params)}" if params else ""
    url = f"{ELASTIC_PROXY_BASE}{path}{query}"

    def _load() -> bytes:
        with urllib.request.urlopen(url, timeout=2) as response:
            return response.read()

    try:
        payload = await asyncio.to_thread(_load)
    except Exception as exc:
        raise HTTPException(
            status_code=502,
            detail="Elastic connector not reachable.",
        ) from exc

    try:
        return json.loads(payload)
    except json.JSONDecodeError as exc:
        raise HTTPException(
            status_code=502,
            detail="Elastic connector returned invalid JSON.",
        ) from exc


@app.get("/api/connectors")
async def connectors_status():
    return JSONResponse(connector_manager.status())


@app.get("/api/connectors/logs")
async def connectors_logs(name: str, limit: int = 100):
    if name not in connector_manager.connector_names():
        raise HTTPException(status_code=404, detail="Unknown connector name.")
    return JSONResponse(
        {
            "name": name,
            "lines": connector_manager.logs(name, limit=limit),
        }
    )


@app.get("/api/sysmon/status")
async def sysmon_status_proxy():
    return JSONResponse(await _fetch_sysmon_json("/status"))


@app.get("/api/sysmon/tail")
async def sysmon_tail_proxy(limit: int = 20):
    safe_limit = max(1, min(limit, 1000))
    payload = await _fetch_sysmon_json("/tail", {"limit": safe_limit})
    return JSONResponse(_wrap_tail_payload("sysmon", payload, safe_limit))


@app.get("/api/security/status")
async def security_status_proxy():
    return JSONResponse(await _fetch_security_json("/status"))


@app.get("/api/security/tail")
async def security_tail_proxy(limit: int = 20):
    safe_limit = max(1, min(limit, 1000))
    payload = await _fetch_security_json("/tail", {"limit": safe_limit})
    return JSONResponse(_wrap_tail_payload("security", payload, safe_limit))


@app.get("/api/elastic/status")
async def elastic_status_proxy():
    return JSONResponse(await _fetch_elastic_json("/status"))


@app.get("/api/elastic/tail")
async def elastic_tail_proxy(limit: int = 20):
    safe_limit = max(1, min(limit, 1000))
    payload = await _fetch_elastic_json("/tail", {"limit": safe_limit})
    return JSONResponse(_wrap_tail_payload("elastic", payload, safe_limit, wrap_items=False))


@app.post("/convert/sysmon")
async def convert_sysmon(file: UploadFile = File(...)):
    upload = await _read_upload(file)
    _validate_selected_source("sysmon", upload["events"])
    return _stream_ndjson(upload["events"], "sysmon", "output.ocsf.jsonl")


@app.post("/convert/sysmon/preview")
async def convert_sysmon_preview(file: UploadFile = File(...)):
    upload = await _read_upload(file)
    _validate_selected_source("sysmon", upload["events"])
    unified_lines = list(
        convert_events_with_source_to_ocsf_jsonl(
            upload["events"],
            source_type="sysmon",
        )
    )
    detection = _build_detection_payload(
        "sysmon",
        auto=False,
        reason="Selected manually.",
    )
    return _build_preview_response(
        original_text=upload["original_text"],
        unified_lines=unified_lines,
        detection=detection,
    )


@app.get("/ui/ocsf/sysmon")
async def sysmon_ocsf_ui(limit: int = 20):
    safe_limit = max(1, min(limit, 200))
    return HTMLResponse(SYS_MON_OCSF_TEMPLATE.substitute(limit=safe_limit))


@app.get("/ui/pipeline")
async def pipeline_ui(limit: int = 20):
    safe_limit = max(1, min(limit, 200))
    return HTMLResponse(PIPELINE_UI_TEMPLATE.safe_substitute(limit=safe_limit))


@app.get("/api/ocsf/sysmon/events")
async def sysmon_ocsf_events(limit: int = 20):
    safe_limit = max(1, min(limit, 200))
    events = _load_sysmon_raw_events(safe_limit)
    payload = []
    for event in events:
        ids = event.get("ids") or {}
        time_info = (event.get("event") or {}).get("time") or {}
        payload.append(
            {
                "record_id": ids.get("record_id"),
                "dedupe_hash": ids.get("dedupe_hash"),
                "event_id": ids.get("event_id"),
                "time": time_info.get("created_utc") or time_info.get("observed_utc"),
            }
        )
    message = None
    if not payload:
        message = "No raw events found."
    return JSONResponse({"events": payload, "message": message})


@app.get("/api/ocsf/sysmon/event")
async def sysmon_ocsf_event(record_id: Optional[int] = None, dedupe_hash: Optional[str] = None):
    if record_id is None and not dedupe_hash:
        raise HTTPException(status_code=400, detail="record_id or dedupe_hash is required.")
    events = _load_sysmon_raw_events(200)
    matched = None
    for event in events:
        ids = event.get("ids") or {}
        if record_id is not None and ids.get("record_id") == record_id:
            matched = event
            break
        if dedupe_hash and ids.get("dedupe_hash") == dedupe_hash:
            matched = event
            break
    if matched is None:
        raise HTTPException(status_code=404, detail="Raw event not found.")
    return JSONResponse(_build_sysmon_ocsf_payload(matched))


@app.get("/api/pipeline/event")
async def pipeline_event(source: str, key: str):
    source_key = source.strip().lower()
    if source_key not in {"sysmon", "security", "elastic"}:
        raise HTTPException(status_code=400, detail="source must be sysmon, security, or elastic.")
    if not key:
        raise HTTPException(status_code=400, detail="key is required.")
    clean_key = key.strip()
    if source_key == "sysmon":
        events = _load_sysmon_raw_events(200)
    elif source_key == "security":
        events = _load_security_raw_events(200)
    else:
        events = _load_elastic_raw_events(200)
    matched = None
    for event in events:
        if _matches_event_key(event, clean_key):
            matched = event
            break
    if matched is None:
        raise HTTPException(status_code=404, detail="Raw event not found.")
    original = _extract_original_payload(matched, source_key)
    if source_key == "sysmon":
        payload = _build_sysmon_ocsf_payload(matched)
        return JSONResponse(
            {
                "source": source_key,
                "original": original,
                "raw_envelope": matched,
                "ocsf": payload["ocsf_event"],
                "report": payload["report"],
            }
        )
    if source_key == "security":
        payload = _build_security_ocsf_payload(matched)
        return JSONResponse(
            {
                "source": source_key,
                "original": original,
                "raw_envelope": matched,
                "ocsf": payload["ocsf_event"],
                "report": payload["report"],
            }
        )
    payload = _build_elastic_ocsf_payload(matched)
    return JSONResponse(
        {
            "source": source_key,
            "original": original,
            "raw_envelope": matched,
            "ocsf": payload["ocsf_event"],
            "report": payload["report"],
        }
    )


@app.post("/convert/zeek")
async def convert_zeek(file: UploadFile = File(...)):
    upload = await _read_upload(file)
    _validate_selected_source("zeek", upload["events"])
    return _stream_ndjson(upload["events"], "zeek", "output.zeek.ocsf.jsonl")


@app.post("/convert/zeek/preview")
async def convert_zeek_preview(file: UploadFile = File(...)):
    upload = await _read_upload(file)
    _validate_selected_source("zeek", upload["events"])
    unified_lines = list(
        convert_events_with_source_to_ocsf_jsonl(
            upload["events"],
            source_type="zeek",
        )
    )
    detection = _build_detection_payload(
        "zeek",
        auto=False,
        reason="Selected manually.",
    )
    return _build_preview_response(
        original_text=upload["original_text"],
        unified_lines=unified_lines,
        detection=detection,
    )


@app.post("/convert/zeek_http")
async def convert_zeek_http(file: UploadFile = File(...)):
    upload = await _read_upload(file)
    _validate_selected_source("zeek_http", upload["events"])
    return _stream_ndjson(upload["events"], "zeek_http", "output.zeek_http.ocsf.jsonl")


@app.post("/convert/zeek_http/preview")
async def convert_zeek_http_preview(file: UploadFile = File(...)):
    upload = await _read_upload(file)
    _validate_selected_source("zeek_http", upload["events"])
    unified_lines = list(
        convert_events_with_source_to_ocsf_jsonl(
            upload["events"],
            source_type="zeek_http",
        )
    )
    detection = _build_detection_payload(
        "zeek_http",
        auto=False,
        reason="Selected manually.",
    )
    return _build_preview_response(
        original_text=upload["original_text"],
        unified_lines=unified_lines,
        detection=detection,
    )


@app.post("/convert/suricata")
async def convert_suricata(file: UploadFile = File(...)):
    upload = await _read_upload(file)
    _validate_selected_source("suricata", upload["events"])
    return _stream_ndjson(upload["events"], "suricata", "output.suricata.ocsf.jsonl")


@app.post("/convert/suricata/preview")
async def convert_suricata_preview(file: UploadFile = File(...)):
    upload = await _read_upload(file)
    _validate_selected_source("suricata", upload["events"])
    unified_lines = list(
        convert_events_with_source_to_ocsf_jsonl(
            upload["events"],
            source_type="suricata",
        )
    )
    detection = _build_detection_payload(
        "suricata",
        auto=False,
        reason="Selected manually.",
    )
    return _build_preview_response(
        original_text=upload["original_text"],
        unified_lines=unified_lines,
        detection=detection,
    )


@app.post("/convert/windows-security")
async def convert_windows_security(file: UploadFile = File(...)):
    upload = await _read_upload(file)
    _validate_selected_source("windows-security", upload["events"])
    return _stream_ndjson(
        upload["events"],
        "windows-security",
        "output.windows-security.ocsf.jsonl",
    )


@app.post("/convert/windows-security/preview")
async def convert_windows_security_preview(file: UploadFile = File(...)):
    upload = await _read_upload(file)
    _validate_selected_source("windows-security", upload["events"])
    unified_lines = list(
        convert_events_with_source_to_ocsf_jsonl(
            upload["events"],
            source_type="windows-security",
        )
    )
    detection = _build_detection_payload(
        "windows-security",
        auto=False,
        reason="Selected manually.",
    )
    return _build_preview_response(
        original_text=upload["original_text"],
        unified_lines=unified_lines,
        detection=detection,
    )


@app.post("/convert/file-artifact")
async def convert_file_artifact(file: UploadFile = File(...)):
    upload = await _read_upload(file)
    _validate_selected_source("file-artifact", upload["events"])
    return _stream_ndjson(
        upload["events"],
        "file-artifact",
        "output.file-artifact.ocsf.jsonl",
    )


@app.post("/convert/file-artifact/preview")
async def convert_file_artifact_preview(file: UploadFile = File(...)):
    upload = await _read_upload(file)
    _validate_selected_source("file-artifact", upload["events"])
    unified_lines = list(
        convert_events_with_source_to_ocsf_jsonl(
            upload["events"],
            source_type="file-artifact",
        )
    )
    detection = _build_detection_payload(
        "file-artifact",
        auto=False,
        reason="Selected manually.",
    )
    return _build_preview_response(
        original_text=upload["original_text"],
        unified_lines=unified_lines,
        detection=detection,
    )


@app.post("/convert/proxy_http")
async def convert_proxy_http(file: UploadFile = File(...)):
    upload = await _read_upload(file)
    _validate_selected_source("proxy_http", upload["events"])
    return _stream_ndjson(upload["events"], "proxy_http", "output.proxy_http.ocsf.jsonl")


@app.post("/convert/proxy_http/preview")
async def convert_proxy_http_preview(file: UploadFile = File(...)):
    upload = await _read_upload(file)
    _validate_selected_source("proxy_http", upload["events"])
    unified_lines = list(
        convert_events_with_source_to_ocsf_jsonl(
            upload["events"],
            source_type="proxy_http",
        )
    )
    detection = _build_detection_payload(
        "proxy_http",
        auto=False,
        reason="Selected manually.",
    )
    return _build_preview_response(
        original_text=upload["original_text"],
        unified_lines=unified_lines,
        detection=detection,
    )


@app.post("/convert/auto")
async def convert_auto(file: UploadFile = File(...)):
    upload = await _read_upload(file)
    detection = auto_detect_source(
        upload["events"][:DETECTION_SAMPLE_SIZE],
        threshold=DETECTION_THRESHOLD,
    )
    detection["auto"] = True
    return _stream_auto_ndjson(upload["events"], "output.auto.ocsf.jsonl")


@app.post("/convert/auto/preview")
async def convert_auto_preview(file: UploadFile = File(...)):
    upload = await _read_upload(file)
    detection = summarize_event_detection(
        upload["events"],
        threshold=DETECTION_THRESHOLD,
    )
    detection["auto"] = True
    unified_lines = list(
        convert_events_to_ocsf_jsonl(upload["events"], threshold=DETECTION_THRESHOLD)
    )
    error = None
    if detection["source_type"] == "unknown":
        error = "Unable to confidently auto-detect source."
    return _build_preview_response(
        original_text=upload["original_text"],
        unified_lines=unified_lines,
        detection=detection,
        error=error,
    )
