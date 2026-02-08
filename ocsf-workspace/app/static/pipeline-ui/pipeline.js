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

let events = [];
let selectedIndex = -1;

function formatValue(value) {
  if (value === null || value === undefined) {
    return "null";
  }
  if (typeof value === "string") {
    return value;
  }
  return JSON.stringify(value, null, 2);
}

function renderTable() {
  eventTableBody.innerHTML = "";
  events.forEach((event, index) => {
    const row = document.createElement("tr");
    row.dataset.index = String(index);
    if (index === selectedIndex) {
      row.classList.add("active");
    }

    const timeCell = document.createElement("td");
    timeCell.textContent = event.time || "—";

    const sourceCell = document.createElement("td");
    sourceCell.textContent = event.source || "—";

    const recordCell = document.createElement("td");
    recordCell.textContent = event.record_id ?? "—";

    const classCell = document.createElement("td");
    const classUid = event.class_uid ?? "—";
    const typeUid = event.type_uid ?? "—";
    classCell.textContent = `${classUid} / ${typeUid}`;

    const statusCell = document.createElement("td");
    const status = event.validation_status || "—";
    const pill = document.createElement("span");
    pill.classList.add("status-pill");
    if (status === "valid") {
      pill.classList.add("status-valid");
    } else if (status === "invalid") {
      pill.classList.add("status-invalid");
    } else if (status === "unmapped" || status === "unsupported") {
      pill.classList.add("status-unmapped");
    }
    pill.textContent = status;
    statusCell.appendChild(pill);

    row.appendChild(timeCell);
    row.appendChild(sourceCell);
    row.appendChild(recordCell);
    row.appendChild(classCell);
    row.appendChild(statusCell);

    row.addEventListener("click", () => selectEvent(index));
    eventTableBody.appendChild(row);
  });
}

function updatePanels(event) {
  rawEventPanel.textContent = formatValue(event.raw_event);
  rawEnvelopePanel.textContent = formatValue(event.raw_envelope);
  ocsfPanel.textContent = formatValue(event.ocsf_event);
  validationPanel.textContent = formatValue(event.validation_report);
}

function selectEvent(index) {
  if (index < 0 || index >= events.length) {
    return;
  }
  selectedIndex = index;
  renderTable();
  updatePanels(events[index]);
  updateNavButtons();
}

function updateNavButtons() {
  prevButton.disabled = selectedIndex <= 0;
  nextButton.disabled = selectedIndex === -1 || selectedIndex >= events.length - 1;
}

async function loadEvents() {
  statusLabel.textContent = "Loading pipeline events…";
  const limit = Math.min(Math.max(Number(limitInput.value) || 50, 1), 200);
  const response = await fetch(`/api/debug/pipeline/events?limit=${limit}`);
  const data = await response.json();
  events = data.events || [];
  statusLabel.textContent = data.message || `${events.length} events loaded.`;
  selectedIndex = events.length ? 0 : -1;
  renderTable();
  if (selectedIndex >= 0) {
    updatePanels(events[selectedIndex]);
  } else {
    rawEventPanel.textContent = "No events available.";
    rawEnvelopePanel.textContent = "No events available.";
    ocsfPanel.textContent = "No events available.";
    validationPanel.textContent = "No events available.";
  }
  updateNavButtons();
}

prevButton.addEventListener("click", () => selectEvent(selectedIndex - 1));
nextButton.addEventListener("click", () => selectEvent(selectedIndex + 1));
loadButton.addEventListener("click", loadEvents);

loadEvents();
