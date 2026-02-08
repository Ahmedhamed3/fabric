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

function addToBuffer(eventEntry) {
  eventBuffer.push(eventEntry);
  if (eventBuffer.length > EVENT_BUFFER_SIZE) {
    eventBuffer.shift();
  }
}

function formatMetadataResponse(eventEntry) {
  return {
    evidence_id: eventEntry.evidence_id,
    source: eventEntry.metadata.source,
    timestamps: eventEntry.metadata.timestamps,
    ocsf: eventEntry.metadata.ocsf,
    host: eventEntry.metadata.host,
    hashes: eventEntry.hashes,
  };
}

app.post("/api/v1/evidence/events", async (req, res) => {
  const payload = req.body;
  if (!payload || typeof payload !== "object" || Array.isArray(payload)) {
    return res.status(400).json({ error: "body must be a JSON object" });
  }

  // BACKWARD COMPATIBLE
  const metadataSource = payload?.metadata && typeof payload.metadata === "object" && !Array.isArray(payload.metadata)
    ? payload.metadata
    : payload;

  const eventEntry = {
    evidence_id: metadataSource?.evidence_id || null,
    metadata: {
      source: {
        type: metadataSource?.source?.type || null,
        vendor: metadataSource?.source?.vendor || null,
        product: metadataSource?.source?.product || null,
        channel: metadataSource?.source?.channel || null,
      },
      timestamps: {
        observed_utc: toUtcIso(metadataSource?.timestamps?.observed_utc),
      },
      ocsf: {
        class_uid: metadataSource?.ocsf?.class_uid || null,
        type_uid: metadataSource?.ocsf?.type_uid || null,
      },
      host: {
        hostname: metadataSource?.host?.hostname || null,
      },
    },
    hashes: {
      raw_envelope_sha256: metadataSource?.hashes?.raw_envelope_sha256 || null,
      raw_payload_sha256: metadataSource?.hashes?.raw_payload_sha256 || null,
      ocsf_sha256: metadataSource?.hashes?.ocsf_sha256 || null,
    },
  };

  // OPTIONAL ARTIFACT SUPPORT
  if (Object.prototype.hasOwnProperty.call(payload, "artifacts")) {
    eventEntry.artifacts = payload.artifacts;
  }

  addToBuffer(eventEntry);
  stats.totalEvents += 1;
  const sourceKey = normalizeSourceKey(eventEntry.metadata.source);
  stats.eventsBySource.set(sourceKey, (stats.eventsBySource.get(sourceKey) || 0) + 1);
  if (eventEntry.metadata.timestamps.observed_utc) {
    stats.lastEventBySource.set(sourceKey, eventEntry.metadata.timestamps.observed_utc);
  }

  console.log(`[EVIDENCE-API] event received evidence_id=${eventEntry.evidence_id || "unknown"} source=${sourceKey}`);
  return res.status(200).json({ status: "ok" });
});

app.get("/api/v1/evidence/events", (req, res) => {
  const limit = Math.max(1, Number(req.query.limit || EVENT_BUFFER_SIZE));
  const startIndex = Math.max(0, eventBuffer.length - Math.min(limit, EVENT_BUFFER_SIZE));
  const includeArtifacts = String(req.query.include_artifacts || "false").toLowerCase() === "true";
  const items = eventBuffer.slice(startIndex);

  // BACKWARD COMPATIBLE
  if (!includeArtifacts) {
    return res.json({ items: items.map((entry) => formatMetadataResponse(entry)), total: eventBuffer.length, limit });
  }

  // OPTIONAL ARTIFACT SUPPORT
  const itemsWithArtifacts = items.map((entry) => {
    if (Object.prototype.hasOwnProperty.call(entry, "artifacts")) {
      return entry;
    }
    return { ...entry, artifacts: null };
  });
  return res.json({ items: itemsWithArtifacts, total: eventBuffer.length, limit });
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
