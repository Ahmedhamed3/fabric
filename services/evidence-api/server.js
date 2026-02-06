const express = require("express");
const crypto = require("crypto");
const fs = require("fs/promises");
const path = require("path");
const { spawn } = require("child_process");

const app = express();
app.use(express.json({ limit: "25mb" }));

const PORT = Number(process.env.PORT || 4100);
const serviceRoot = __dirname;
const repoRoot = path.resolve(serviceRoot, "../..");
const storageRoot = path.join(serviceRoot, "storage");
const invokeScript = process.env.FABRIC_INVOKE_SCRIPT || path.join(repoRoot, "socnet", "scripts", "invoke_putlog.sh");

const inMemoryIndex = new Map();

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
    await fs.writeFile(path.join(bundleDir, "raw.ndjson"), rawBundleNdjson, "utf8");
    await fs.writeFile(path.join(bundleDir, "ocsf.ndjson"), ocsfBundleNdjson, "utf8");
    await fs.writeFile(path.join(bundleDir, "manifest.json"), prettyJson(bundleManifest), "utf8");

    const invokeResult = await runInvokeScript(bundleId, canonicalJson(bundleManifest));

    const stored = {
      bundle_id: bundleId,
      manifest: bundleManifest,
      refs: {
        raw_ndjson: path.join(bundleDir, "raw.ndjson"),
        ocsf_ndjson: path.join(bundleDir, "ocsf.ndjson"),
        manifest_json: path.join(bundleDir, "manifest.json"),
      },
      fabric_tx_id: invokeResult.fabricTxId,
    };
    inMemoryIndex.set(bundleId, stored);

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
  console.log(`[evidence-api] listening on http://127.0.0.1:${PORT}`);
});
