const express = require("express");
const cors = require("cors");
const crypto = require("crypto");

const app = express();
app.use(express.json({ limit: "25mb" }));
app.use(cors({ origin: [/^http:\/\/127\.0\.0\.1:\d+$/, /^http:\/\/localhost:\d+$/] }));

const PORT = Number(process.env.PORT || 4100);
const EVENT_BUFFER_SIZE = Math.max(1, Number(process.env.EVIDENCE_EVENT_BUFFER_SIZE || 200));
const eventBuffer = [];
const stats = {
  totalEvents: 0,
  eventsBySource: new Map(),
  lastEventBySource: new Map(),
};

function sha256Hex(value) {
  return crypto.createHash("sha256").update(value).digest("hex");
}

function toUtcIso(value) {
  if (!value) {
    return null;
  }
  const parsed = new Date(value);
  if (Number.isNaN(parsed.getTime())) {
    return null;
  }
  return parsed.toISOString();
}

function firstNdjsonRecord(ndjson) {
  if (typeof ndjson !== "string") {
    return null;
  }
  const lines = ndjson.split("\n");
  for (const line of lines) {
    const trimmed = line.trim();
    if (!trimmed) {
      continue;
    }
    try {
      return JSON.parse(trimmed);
    } catch (error) {
      return null;
    }
  }
  return null;
}

function normalizeSourceKey(source) {
  const sourceType = source?.type || "unknown";
  const product = source?.product || "unknown";
  return `${sourceType}:${product}`;
}

function addToBuffer(eventMeta) {
  eventBuffer.push(eventMeta);
  if (eventBuffer.length > EVENT_BUFFER_SIZE) {
    eventBuffer.shift();
  }
}

app.post("/api/v1/evidence/commit-bundle", async (req, res) => {
  const payload = req.body;
  if (!payload || typeof payload !== "object" || Array.isArray(payload)) {
    return res.status(400).json({ error: "body must be a JSON object" });
  }

  const manifest = payload?.bundle_manifest || {};
  const source = manifest?.source || {};
  const evidenceId = manifest?.bundle_id || payload?.bundle_id || null;
  const observedUtc = toUtcIso(manifest?.time_window?.end_utc) || toUtcIso(manifest?.time_window?.start_utc);
  const firstOcsfEvent = firstNdjsonRecord(payload?.ocsf_bundle_ndjson);
  const classUid = firstOcsfEvent?.class_uid || null;
  const typeUid = firstOcsfEvent?.type_uid || null;
  const rawEnvelopeHash = manifest?.hashes?.raw_bundle?.sha256
    || (typeof payload?.raw_bundle_ndjson === "string" ? sha256Hex(payload.raw_bundle_ndjson) : null);
  const ocsfHash = manifest?.hashes?.ocsf_bundle?.sha256
    || (typeof payload?.ocsf_bundle_ndjson === "string" ? sha256Hex(payload.ocsf_bundle_ndjson) : null);

  const isValid = Boolean(
    evidenceId
    && source?.type
    && source?.product
    && observedUtc
    && classUid
    && typeUid
    && rawEnvelopeHash
    && ocsfHash
  );

  const eventMeta = {
    evidence_id: evidenceId,
    source: {
      type: source?.type || null,
      product: source?.product || null,
    },
    timestamps: {
      observed_utc: observedUtc,
    },
    ocsf: {
      class_uid: classUid,
      type_uid: typeUid,
    },
    hashes: {
      raw_envelope_hash: rawEnvelopeHash,
      ocsf_hash: ocsfHash,
    },
    validation: {
      status: isValid ? "valid" : "invalid",
    },
  };

  addToBuffer(eventMeta);
  stats.totalEvents += 1;
  const sourceKey = normalizeSourceKey(eventMeta.source);
  stats.eventsBySource.set(sourceKey, (stats.eventsBySource.get(sourceKey) || 0) + 1);
  if (eventMeta.timestamps.observed_utc) {
    stats.lastEventBySource.set(sourceKey, eventMeta.timestamps.observed_utc);
  }

  console.log(`[EVIDENCE-API] commit-bundle received evidence_id=${evidenceId || "unknown"} source=${sourceKey}`);

  return res.status(200).json({ status: "ok" });
});

app.get("/api/v1/evidence/events", (req, res) => {
  const limit = Math.max(1, Number(req.query.limit || EVENT_BUFFER_SIZE));
  const startIndex = Math.max(0, eventBuffer.length - Math.min(limit, EVENT_BUFFER_SIZE));
  const items = eventBuffer.slice(startIndex);
  return res.json({ items, total: eventBuffer.length, limit });
});

app.get("/api/v1/evidence/stats", (_req, res) => {
  return res.json({
    total_events: stats.totalEvents,
    events_by_source: Object.fromEntries(stats.eventsBySource.entries()),
    last_event_by_source: Object.fromEntries(stats.lastEventBySource.entries()),
  });
});

app.get("/healthz", (_req, res) => {
  res.json({ ok: true });
});

app.listen(PORT, () => {
  console.log(`[evidence-api] listening on http://127.0.0.1:${PORT}`);
});
