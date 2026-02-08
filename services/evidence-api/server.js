const express = require("express");
const cors = require("cors");
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

app.post("/api/v1/evidence/events", async (req, res) => {
  const payload = req.body;
  if (!payload || typeof payload !== "object" || Array.isArray(payload)) {
    return res.status(400).json({ error: "body must be a JSON object" });
  }

  const eventMeta = {
    evidence_id: payload?.evidence_id || null,
    source: {
      type: payload?.source?.type || null,
      vendor: payload?.source?.vendor || null,
      product: payload?.source?.product || null,
      channel: payload?.source?.channel || null,
    },
    timestamps: {
      observed_utc: toUtcIso(payload?.timestamps?.observed_utc),
    },
    ocsf: {
      class_uid: payload?.ocsf?.class_uid || null,
      type_uid: payload?.ocsf?.type_uid || null,
    },
    host: {
      hostname: payload?.host?.hostname || null,
    },
    hashes: {
      raw_envelope_sha256: payload?.hashes?.raw_envelope_sha256 || null,
      raw_payload_sha256: payload?.hashes?.raw_payload_sha256 || null,
      ocsf_sha256: payload?.hashes?.ocsf_sha256 || null,
    },
  };

  addToBuffer(eventMeta);
  stats.totalEvents += 1;
  const sourceKey = normalizeSourceKey(eventMeta.source);
  stats.eventsBySource.set(sourceKey, (stats.eventsBySource.get(sourceKey) || 0) + 1);
  if (eventMeta.timestamps.observed_utc) {
    stats.lastEventBySource.set(sourceKey, eventMeta.timestamps.observed_utc);
  }

  console.log(`[EVIDENCE-API] event received evidence_id=${eventMeta.evidence_id || "unknown"} source=${sourceKey}`);
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
