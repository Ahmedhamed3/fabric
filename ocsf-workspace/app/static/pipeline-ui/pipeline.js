const limitInput = document.getElementById("limitInput");
const loadButton = document.getElementById("loadButton");
const prevButton = document.getElementById("prevButton");
const nextButton = document.getElementById("nextButton");
const statusLabel = document.getElementById("statusLabel");
const eventTableBody = document.getElementById("eventTableBody");

const rawEventPanel = document.getElementById("rawEventPanel");
const rawEnvelopePanel = document.getElementById("rawEnvelopePanel");
const ocsfPanel = document.getElementById("ocsfPanel");
const validationPanel = document.getElementById("validationPanel");

let evidenceEvents = [];
let selectedIndex = -1;
let selectedEvidenceId = null;

function formatValue(value, fallback) {
  if (value === null || value === undefined) {
    return fallback;
  }
  if (typeof value === "string") {
    return value;
  }
  return JSON.stringify(value, null, 2);
}

function formatSource(event) {
  const source = event.source || {};
  const parts = [];
  if (source.type) {
    parts.push(source.type);
  }
  if (source.product) {
    parts.push(source.product);
  }
  if (source.vendor) {
    parts.push(source.vendor);
  }
  return parts.length ? parts.join(" · ") : "—";
}

function formatObserved(event) {
  return (event.timestamps || {}).observed_utc || event.observed_utc || "—";
}

function formatHost(event) {
  return (event.host || {}).hostname || "—";
}

function formatClassType(event) {
  const ocsf = event.ocsf || {};
  const classUid = ocsf.class_uid ?? "—";
  const typeUid = ocsf.type_uid ?? "—";
  return `${classUid} / ${typeUid}`;
}

function renderTable() {
  eventTableBody.innerHTML = "";
  if (!evidenceEvents.length) {
    const row = document.createElement("tr");
    const cell = document.createElement("td");
    cell.colSpan = 5;
    cell.textContent = "No evidence metadata loaded.";
    row.appendChild(cell);
    eventTableBody.appendChild(row);
    return;
  }

  evidenceEvents.forEach((event, index) => {
    const row = document.createElement("tr");
    row.dataset.index = String(index);
    if (index === selectedIndex) {
      row.classList.add("active");
    }

    const timeCell = document.createElement("td");
    timeCell.textContent = formatObserved(event);

    const sourceCell = document.createElement("td");
    sourceCell.textContent = formatSource(event);

    const evidenceCell = document.createElement("td");
    evidenceCell.textContent = event.evidence_id || "—";

    const hostCell = document.createElement("td");
    hostCell.textContent = formatHost(event);

    const classCell = document.createElement("td");
    classCell.textContent = formatClassType(event);

    row.appendChild(timeCell);
    row.appendChild(sourceCell);
    row.appendChild(evidenceCell);
    row.appendChild(hostCell);
    row.appendChild(classCell);

    row.addEventListener("click", () => selectEvent(index));
    eventTableBody.appendChild(row);
  });
}

function updatePanels(payload) {
  rawEventPanel.textContent = formatValue(payload.raw, "No raw payload found.");
  rawEnvelopePanel.textContent = formatValue(payload.envelope, "No envelope found.");
  ocsfPanel.textContent = formatValue(payload.ocsf, "No OCSF output found.");
  validationPanel.textContent = formatValue(payload.validation, "No validation report found.");
}

function setEmptyPanels(message) {
  rawEventPanel.textContent = message;
  rawEnvelopePanel.textContent = message;
  ocsfPanel.textContent = message;
  validationPanel.textContent = message;
}

async function selectEvent(index) {
  if (index < 0 || index >= evidenceEvents.length) {
    return;
  }
  selectedIndex = index;
  selectedEvidenceId = evidenceEvents[index].evidence_id || null;
  renderTable();
  updateNavButtons();
  if (!selectedEvidenceId) {
    setEmptyPanels("No evidence_id available for this record.");
    return;
  }
  setEmptyPanels("Loading artifacts…");
  await loadLookup(selectedEvidenceId);
}

function updateNavButtons() {
  prevButton.disabled = selectedIndex <= 0;
  nextButton.disabled = selectedIndex === -1 || selectedIndex >= evidenceEvents.length - 1;
}

async function loadLookup(evidenceId) {
  try {
    const response = await fetch(
      `/api/pipeline/viewer/lookup?evidence_id=${encodeURIComponent(evidenceId)}`
    );
    const data = await response.json();
    updatePanels(data || {});
  } catch (error) {
    setEmptyPanels("Unable to load pipeline artifacts.");
  }
}

async function loadEvidenceEvents() {
  statusLabel.textContent = "Loading evidence metadata…";
  const limit = Math.min(Math.max(Number(limitInput.value) || 50, 1), 200);
  try {
    const response = await fetch(`/api/pipeline/viewer/metadata?limit=${limit}`);
    const data = await response.json();
    evidenceEvents = data.events || [];
    statusLabel.textContent = data.message || `${evidenceEvents.length} evidence records loaded.`;
    selectedIndex = evidenceEvents.length ? 0 : -1;
    selectedEvidenceId = evidenceEvents.length ? evidenceEvents[0].evidence_id : null;
    renderTable();
    if (selectedEvidenceId) {
      await loadLookup(selectedEvidenceId);
    } else {
      setEmptyPanels("No evidence metadata available.");
    }
    updateNavButtons();
  } catch (error) {
    evidenceEvents = [];
    statusLabel.textContent = "Unable to load evidence metadata.";
    renderTable();
    setEmptyPanels("Unable to load evidence metadata.");
    updateNavButtons();
  }
}

prevButton.addEventListener("click", () => selectEvent(selectedIndex - 1));
nextButton.addEventListener("click", () => selectEvent(selectedIndex + 1));
loadButton.addEventListener("click", loadEvidenceEvents);

loadEvidenceEvents();
