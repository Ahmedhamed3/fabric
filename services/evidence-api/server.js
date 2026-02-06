const express = require("express");
const cors = require("cors");
const crypto = require("crypto");
const fs = require("fs/promises");
const path = require("path");
const Database = require("better-sqlite3");
const { spawn } = require("child_process");

const app = express();
app.use(express.json({ limit: "25mb" }));
app.use(cors({ origin: [/^http:\/\/127\.0\.0\.1:\d+$/, /^http:\/\/localhost:\d+$/] }));

const PORT = Number(process.env.PORT || 4100);
const MAX_FILE_BYTES = Number(process.env.EVIDENCE_MAX_FILE_BYTES || 2 * 1024 * 1024);
const serviceRoot = __dirname;
const repoRoot = path.resolve(serviceRoot, "../..");
const storageRoot = path.join(serviceRoot, "storage");
const dbPath = path.join(storageRoot, "index.db");
const invokeScript = process.env.FABRIC_INVOKE_SCRIPT || path.join(repoRoot, "socnet", "scripts", "invoke_putlog.sh");

const inMemoryIndex = new Map();
let db;

function initDb() {
  db = new Database(dbPath);
  db.exec(`
    CREATE TABLE IF NOT EXISTS evidence_bundles (
      bundle_id TEXT PRIMARY KEY,
      time_start_utc TEXT,
      time_end_utc TEXT,
      event_count INTEGER,
      host TEXT,
      source_type TEXT,
      vendor TEXT,
      product TEXT,
      channel TEXT,
      collector_instance_id TEXT,
      ocsf_version TEXT,
      class_uid_counts_json TEXT,
      raw_hash_sha256 TEXT,
      ocsf_hash_sha256 TEXT,
      raw_size_bytes INTEGER,
      ocsf_size_bytes INTEGER,
      created_utc TEXT,
      fabric_tx_id TEXT NULL,
      manifest_path TEXT,
      raw_path TEXT,
      ocsf_path TEXT
    );
  `);
}

const upsertBundleStmt = () => db.prepare(`
  INSERT INTO evidence_bundles (
    bundle_id, time_start_utc, time_end_utc, event_count, host, source_type, vendor,
    product, channel, collector_instance_id, ocsf_version, class_uid_counts_json,
    raw_hash_sha256, ocsf_hash_sha256, raw_size_bytes, ocsf_size_bytes, created_utc,
    fabric_tx_id, manifest_path, raw_path, ocsf_path
  ) VALUES (
    @bundle_id, @time_start_utc, @time_end_utc, @event_count, @host, @source_type, @vendor,
    @product, @channel, @collector_instance_id, @ocsf_version, @class_uid_counts_json,
    @raw_hash_sha256, @ocsf_hash_sha256, @raw_size_bytes, @ocsf_size_bytes, @created_utc,
    @fabric_tx_id, @manifest_path, @raw_path, @ocsf_path
  )
  ON CONFLICT(bundle_id) DO UPDATE SET
    time_start_utc = excluded.time_start_utc,
    time_end_utc = excluded.time_end_utc,
    event_count = excluded.event_count,
    host = excluded.host,
    source_type = excluded.source_type,
    vendor = excluded.vendor,
    product = excluded.product,
    channel = excluded.channel,
    collector_instance_id = excluded.collector_instance_id,
    ocsf_version = excluded.ocsf_version,
    class_uid_counts_json = excluded.class_uid_counts_json,
    raw_hash_sha256 = excluded.raw_hash_sha256,
    ocsf_hash_sha256 = excluded.ocsf_hash_sha256,
    raw_size_bytes = excluded.raw_size_bytes,
    ocsf_size_bytes = excluded.ocsf_size_bytes,
    created_utc = excluded.created_utc,
    fabric_tx_id = excluded.fabric_tx_id,
    manifest_path = excluded.manifest_path,
    raw_path = excluded.raw_path,
    ocsf_path = excluded.ocsf_path
`);

function parseBundleRecord(bundleManifest, paths, fabricTxId) {
  return {
    bundle_id: bundleManifest.bundle_id,
    time_start_utc: bundleManifest?.time_window?.start_utc || null,
    time_end_utc: bundleManifest?.time_window?.end_utc || null,
    event_count: Number(bundleManifest?.event_count || 0),
    host: bundleManifest?.source?.host || null,
    source_type: bundleManifest?.source?.type || null,
    vendor: bundleManifest?.source?.vendor || null,
    product: bundleManifest?.source?.product || null,
    channel: bundleManifest?.source?.channel || null,
    collector_instance_id: bundleManifest?.source?.collector?.instance_id || null,
    ocsf_version: bundleManifest?.ocsf?.version || null,
    class_uid_counts_json: JSON.stringify(bundleManifest?.ocsf?.class_uid_counts || {}),
    raw_hash_sha256: bundleManifest?.hashes?.raw_bundle?.sha256 || null,
    ocsf_hash_sha256: bundleManifest?.hashes?.ocsf_bundle?.sha256 || null,
    raw_size_bytes: Number(bundleManifest?.hashes?.raw_bundle?.size_bytes || 0),
    ocsf_size_bytes: Number(bundleManifest?.hashes?.ocsf_bundle?.size_bytes || 0),
    created_utc: bundleManifest?.integrity?.created_utc || new Date().toISOString(),
    fabric_tx_id: fabricTxId || null,
    manifest_path: paths.manifest_json,
    raw_path: paths.raw_ndjson,
    ocsf_path: paths.ocsf_ndjson,
  };
}

function sha256Hex(value) {
  return crypto.createHash("sha256").update(value).digest("hex");
}

function prettyJson(value) {
  return JSON.stringify(value, null, 2);
}

function canonicalJson(value) {
  if (value === null || typeof value !== "object") {
    return JSON.stringify(value);
  }
  if (Array.isArray(value)) {
    return `[${value.map((item) => canonicalJson(item)).join(",")}]`;
  }
  const keys = Object.keys(value).sort();
  const parts = keys.map((key) => `${JSON.stringify(key)}:${canonicalJson(value[key])}`);
  return `{${parts.join(",")}}`;
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

function buildManifest({ evidenceId, evidenceCommit, originalXml, rawEnvelope, ocsfEvent }) {
  const source = evidenceCommit?.source || rawEnvelope?.source || {};
  const collector = source?.collector || {};
  const envelopeTime = rawEnvelope?.event?.time || {};
  const ids = rawEnvelope?.ids || {};

  const observedUtc =
    toUtcIso(evidenceCommit?.timestamps?.observed_utc) ||
    toUtcIso(envelopeTime?.observed_utc) ||
    toUtcIso(ocsfEvent?.time);
  const createdUtc =
    toUtcIso(evidenceCommit?.timestamps?.created_utc) ||
    toUtcIso(envelopeTime?.created_utc);
  const hashedUtc = toUtcIso(evidenceCommit?.timestamps?.hashed_utc) || new Date().toISOString();

  const xmlHash = evidenceCommit?.raw_hashes?.payload?.hash_sha256 || `sha256:${sha256Hex(originalXml)}`;
  const envelopeString = prettyJson(rawEnvelope);
  const envelopeHash = evidenceCommit?.raw_hashes?.envelope?.hash_sha256 || `sha256:${sha256Hex(envelopeString)}`;
  const ocsfString = prettyJson(ocsfEvent);
  const ocsfHash = evidenceCommit?.ocsf?.hash_sha256 || `sha256:${sha256Hex(ocsfString)}`;

  return {
    evidence_id: evidenceId,
    source: {
      type: source?.type || null,
      vendor: source?.vendor || null,
      product: source?.product || null,
      channel: source?.channel || null,
      collector: {
        host: collector?.host || null,
        instance_id: collector?.instance_id || null,
      },
    },
    timestamps: {
      observed_utc: observedUtc,
      created_utc: createdUtc,
      hashed_utc: hashedUtc,
    },
    raw_hashes: {
      payload: {
        hash_sha256: xmlHash,
        size: Buffer.byteLength(originalXml, "utf8"),
        format: "xml",
      },
      envelope: {
        hash_sha256: envelopeHash,
        size: Buffer.byteLength(envelopeString, "utf8"),
        format: "json",
      },
    },
    ocsf: {
      hash_sha256: ocsfHash,
      schema: evidenceCommit?.ocsf?.schema || ocsfEvent?.metadata?.schema_name || "ocsf",
      version: evidenceCommit?.ocsf?.version || ocsfEvent?.metadata?.version || null,
      class_uid: evidenceCommit?.ocsf?.class_uid || ocsfEvent?.class_uid || null,
      type_uid: evidenceCommit?.ocsf?.type_uid || ocsfEvent?.type_uid || null,
    },
    linkage: {
      record_id: evidenceCommit?.linkage?.record_id || ids?.record_id || null,
      dedupe_hash: evidenceCommit?.linkage?.dedupe_hash || ids?.dedupe_hash || null,
      correlation_id: evidenceCommit?.linkage?.correlation_id || ids?.correlation_id || null,
    },
    integrity: {
      canonicalization: "rfc8785",
      hash_alg: "SHA-256",
    },
    storage_refs: {
      raw_payload_ref: `local://evidence/${evidenceId}/raw.xml`,
      ocsf_ref: `local://evidence/${evidenceId}/ocsf.json`,
      envelope_ref: `local://evidence/${evidenceId}/envelope.json`,
    },
  };
}

function runInvokeScript(evidenceId, manifestString) {
  return new Promise((resolve, reject) => {
    const child = spawn("bash", [invokeScript, evidenceId, manifestString], {
      cwd: repoRoot,
      env: process.env,
      stdio: ["ignore", "pipe", "pipe"],
    });

    let stdout = "";
    let stderr = "";

    child.stdout.on("data", (chunk) => {
      stdout += chunk.toString();
    });

    child.stderr.on("data", (chunk) => {
      stderr += chunk.toString();
    });

    child.on("error", (error) => reject(error));
    child.on("close", (code) => {
      if (code !== 0) {
        return reject(new Error(`Invoke failed (exit ${code}): ${stderr || stdout}`));
      }
      const txMatch = stdout.match(/txid\s*[:=]\s*([A-Za-z0-9]+)/i) || stdout.match(/TxID\s*[:=]\s*([A-Za-z0-9]+)/i);
      const fabricTxId = txMatch ? txMatch[1] : "submitted";
      return resolve({ fabricTxId, stdout, stderr });
    });
  });
}

app.post("/api/v1/evidence/commit", async (req, res) => {
  const { original_xml: originalXml, raw_envelope: rawEnvelope, ocsf_event: ocsfEvent, evidence_commit: evidenceCommit } = req.body || {};

  if (typeof originalXml !== "string" || !originalXml.trim()) {
    return res.status(400).json({ error: "original_xml must be a non-empty string" });
  }
  if (!rawEnvelope || typeof rawEnvelope !== "object" || Array.isArray(rawEnvelope)) {
    return res.status(400).json({ error: "raw_envelope must be an object" });
  }
  if (!ocsfEvent || typeof ocsfEvent !== "object" || Array.isArray(ocsfEvent)) {
    return res.status(400).json({ error: "ocsf_event must be an object" });
  }
  if (!evidenceCommit || typeof evidenceCommit !== "object" || Array.isArray(evidenceCommit)) {
    return res.status(400).json({ error: "evidence_commit must be an object" });
  }

  const evidenceId = evidenceCommit?.evidence_id;
  if (typeof evidenceId !== "string" || !evidenceId.trim()) {
    return res.status(400).json({ error: "evidence_commit.evidence_id must be a non-empty string" });
  }

  const manifest = buildManifest({
    evidenceId,
    evidenceCommit,
    originalXml,
    rawEnvelope,
    ocsfEvent,
  });

  const evidenceDir = path.join(storageRoot, evidenceId);

  try {
    await fs.mkdir(evidenceDir, { recursive: true });
    await fs.writeFile(path.join(evidenceDir, "raw.xml"), originalXml, "utf8");
    await fs.writeFile(path.join(evidenceDir, "ocsf.json"), prettyJson(ocsfEvent), "utf8");
    await fs.writeFile(path.join(evidenceDir, "envelope.json"), prettyJson(rawEnvelope), "utf8");
    await fs.writeFile(path.join(evidenceDir, "manifest.json"), prettyJson(manifest), "utf8");

    const manifestString = JSON.stringify(manifest);
    const invokeResult = await runInvokeScript(evidenceId, manifestString);

    const stored = {
      evidence_id: evidenceId,
      manifest,
      refs: {
        raw_xml: path.join(evidenceDir, "raw.xml"),
        ocsf_json: path.join(evidenceDir, "ocsf.json"),
        envelope_json: path.join(evidenceDir, "envelope.json"),
        manifest_json: path.join(evidenceDir, "manifest.json"),
      },
      fabric_tx_id: invokeResult.fabricTxId,
    };

    inMemoryIndex.set(evidenceId, stored);

    return res.json({
      evidence_id: evidenceId,
      fabric_tx_id: invokeResult.fabricTxId,
      status: "NOTARIZED",
    });
  } catch (error) {
    return res.status(500).json({
      error: "Failed to commit evidence",
      detail: error.message,
    });
  }
});

app.post("/api/v1/evidence/commit-bundle", async (req, res) => {
  const { bundle_id: bundleId, raw_bundle_ndjson: rawBundleNdjson, ocsf_bundle_ndjson: ocsfBundleNdjson, bundle_manifest: bundleManifest } = req.body || {};

  if (typeof bundleId !== "string" || !bundleId.trim()) {
    return res.status(400).json({ error: "bundle_id must be a non-empty string" });
  }
  if (typeof rawBundleNdjson !== "string" || !rawBundleNdjson.trim()) {
    return res.status(400).json({ error: "raw_bundle_ndjson must be a non-empty string" });
  }
  if (typeof ocsfBundleNdjson !== "string" || !ocsfBundleNdjson.trim()) {
    return res.status(400).json({ error: "ocsf_bundle_ndjson must be a non-empty string" });
  }
  if (!bundleManifest || typeof bundleManifest !== "object" || Array.isArray(bundleManifest)) {
    return res.status(400).json({ error: "bundle_manifest must be an object" });
  }
  if (bundleManifest.bundle_id !== bundleId) {
    return res.status(400).json({ error: "bundle_manifest.bundle_id must match bundle_id" });
  }

  const bundleDir = path.join(storageRoot, "bundles", bundleId);

  try {
    await fs.mkdir(bundleDir, { recursive: true });
    const refs = {
      raw_ndjson: path.join(bundleDir, "raw.ndjson"),
      ocsf_ndjson: path.join(bundleDir, "ocsf.ndjson"),
      manifest_json: path.join(bundleDir, "manifest.json"),
    };

    await fs.writeFile(refs.raw_ndjson, rawBundleNdjson, "utf8");
    await fs.writeFile(refs.ocsf_ndjson, ocsfBundleNdjson, "utf8");
    await fs.writeFile(refs.manifest_json, prettyJson(bundleManifest), "utf8");

    const invokeResult = await runInvokeScript(bundleId, canonicalJson(bundleManifest));

    const stored = {
      bundle_id: bundleId,
      manifest: bundleManifest,
      refs,
      fabric_tx_id: invokeResult.fabricTxId,
    };
    inMemoryIndex.set(bundleId, stored);
    upsertBundleStmt().run(parseBundleRecord(bundleManifest, refs, invokeResult.fabricTxId));

    return res.json({
      bundle_id: bundleId,
      fabric_tx_id: invokeResult.fabricTxId,
      status: "BUNDLE_NOTARIZED",
    });
  } catch (error) {
    return res.status(500).json({
      error: "Failed to commit bundle",
      detail: error.message,
    });
  }
});

app.get("/api/v1/evidence/bundles", (req, res) => {
  const host = req.query.host ? String(req.query.host) : null;
  const sourceType = req.query.source_type ? String(req.query.source_type) : null;
  const fromUtc = req.query.from_utc ? String(req.query.from_utc) : null;
  const toUtc = req.query.to_utc ? String(req.query.to_utc) : null;
  const classUid = req.query.class_uid ? String(req.query.class_uid) : null;
  const limit = Math.max(1, Math.min(500, Number(req.query.limit || 100)));
  const offset = Math.max(0, Number(req.query.offset || 0));

  const where = [];
  const params = {};

  if (host) {
    where.push("host = @host");
    params.host = host;
  }
  if (sourceType) {
    where.push("source_type = @sourceType");
    params.sourceType = sourceType;
  }
  if (fromUtc) {
    where.push("time_start_utc >= @fromUtc");
    params.fromUtc = fromUtc;
  }
  if (toUtc) {
    where.push("time_end_utc <= @toUtc");
    params.toUtc = toUtc;
  }
  if (classUid) {
    where.push("instr(class_uid_counts_json, @classKey) > 0");
    params.classKey = `\"${classUid}\"`;
  }

  const whereSql = where.length ? `WHERE ${where.join(" AND ")}` : "";
  const countRow = db.prepare(`SELECT COUNT(*) as total FROM evidence_bundles ${whereSql}`).get(params);
  const rows = db.prepare(`
    SELECT *
    FROM evidence_bundles
    ${whereSql}
    ORDER BY time_end_utc DESC
    LIMIT @limit OFFSET @offset
  `).all({ ...params, limit, offset });

  const items = rows.map((row) => ({
    bundle_id: row.bundle_id,
    time_start_utc: row.time_start_utc,
    time_end_utc: row.time_end_utc,
    event_count: row.event_count,
    host: row.host,
    source_type: row.source_type,
    product: row.product,
    channel: row.channel,
    class_uid_counts: JSON.parse(row.class_uid_counts_json || "{}"),
    raw_hash_sha256: row.raw_hash_sha256,
    ocsf_hash_sha256: row.ocsf_hash_sha256,
    fabric_tx_id: row.fabric_tx_id || null,
  }));

  return res.json({
    items,
    total: Number(countRow?.total || 0),
    limit,
    offset,
  });
});

app.get("/api/v1/evidence/bundles/:bundle_id", async (req, res) => {
  const bundleId = req.params.bundle_id;
  const row = db.prepare("SELECT * FROM evidence_bundles WHERE bundle_id = ?").get(bundleId);
  if (!row) {
    return res.status(404).json({ error: "Bundle not found" });
  }

  try {
    const manifestRaw = await fs.readFile(row.manifest_path, "utf8");
    const manifest = JSON.parse(manifestRaw);
    const startMs = Date.parse(row.time_start_utc || "");
    const endMs = Date.parse(row.time_end_utc || "");
    const windowDurationSeconds = Number.isNaN(startMs) || Number.isNaN(endMs) ? null : Math.max(0, Math.round((endMs - startMs) / 1000));

    return res.json({
      bundle_id: row.bundle_id,
      time_start_utc: row.time_start_utc,
      time_end_utc: row.time_end_utc,
      event_count: row.event_count,
      source: {
        host: row.host,
        source_type: row.source_type,
        vendor: row.vendor,
        product: row.product,
        channel: row.channel,
        collector_instance_id: row.collector_instance_id,
      },
      hashes: {
        raw_hash_sha256: row.raw_hash_sha256,
        ocsf_hash_sha256: row.ocsf_hash_sha256,
      },
      sizes: {
        raw_size_bytes: row.raw_size_bytes,
        ocsf_size_bytes: row.ocsf_size_bytes,
      },
      class_uid_counts: JSON.parse(row.class_uid_counts_json || "{}"),
      created_utc: row.created_utc,
      fabric_tx_id: row.fabric_tx_id,
      refs: {
        manifest_path: row.manifest_path,
        raw_path: row.raw_path,
        ocsf_path: row.ocsf_path,
      },
      computed: {
        window_duration_seconds: windowDurationSeconds,
      },
      manifest,
    });
  } catch (error) {
    return res.status(500).json({ error: "Failed to load bundle detail", detail: error.message });
  }
});

app.get("/api/v1/evidence/bundles/:bundle_id/files", async (req, res) => {
  const bundleId = req.params.bundle_id;
  const type = String(req.query.type || "manifest");
  const row = db.prepare("SELECT * FROM evidence_bundles WHERE bundle_id = ?").get(bundleId);
  if (!row) {
    return res.status(404).json({ error: "Bundle not found" });
  }

  const pathByType = {
    raw: row.raw_path,
    ocsf: row.ocsf_path,
    manifest: row.manifest_path,
  };
  const targetPath = pathByType[type];
  if (!targetPath) {
    return res.status(400).json({ error: "type must be raw, ocsf, or manifest" });
  }

  try {
    const stat = await fs.stat(targetPath);
    if (stat.size > MAX_FILE_BYTES) {
      return res.status(413).json({ error: `file exceeds max size (${MAX_FILE_BYTES} bytes)` });
    }
    const file = await fs.readFile(targetPath, "utf8");
    if (type === "manifest") {
      res.type("application/json");
    } else {
      res.type("text/plain");
    }
    return res.send(file);
  } catch (error) {
    return res.status(500).json({ error: "Failed to read file", detail: error.message });
  }
});

app.get("/api/v1/evidence/:id", async (req, res) => {
  const evidenceId = req.params.id;
  const memoryHit = inMemoryIndex.get(evidenceId);
  if (memoryHit) {
    return res.json(memoryHit);
  }

  const evidenceDir = path.join(storageRoot, evidenceId);
  try {
    const manifestText = await fs.readFile(path.join(evidenceDir, "manifest.json"), "utf8");
    const manifest = JSON.parse(manifestText);
    return res.json({
      evidence_id: evidenceId,
      manifest,
      refs: {
        raw_xml: path.join(evidenceDir, "raw.xml"),
        ocsf_json: path.join(evidenceDir, "ocsf.json"),
        envelope_json: path.join(evidenceDir, "envelope.json"),
        manifest_json: path.join(evidenceDir, "manifest.json"),
      },
    });
  } catch (error) {
    return res.status(404).json({ error: "Evidence not found" });
  }
});

app.get("/healthz", (_req, res) => {
  res.json({ ok: true });
});

app.listen(PORT, async () => {
  await fs.mkdir(storageRoot, { recursive: true });
  initDb();
  console.log(`[evidence-api] listening on http://127.0.0.1:${PORT}`);
});
