const limitInput = document.getElementById("limitInput");
const loadButton = document.getElementById("loadButton");
const showOcsfOnly = document.getElementById("showOcsfOnly");
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
let selectedEventKey = null;
let visibleEvents = [];

function formatValue(value) {
  if (value === null || value === undefined) {
    return "Not produced (unsupported / skipped)";
  }
  if (typeof value === "string") {
    return value;
  }
  return JSON.stringify(value, null, 2);
}

function renderTable() {
  eventTableBody.innerHTML = "";
  visibleEvents.forEach((event, index) => {
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
  rawEventPanel.textContent = formatValue(event.raw);
  rawEnvelopePanel.textContent = formatValue(event.envelope);
  ocsfPanel.textContent = formatValue(event.ocsf);
  validationPanel.textContent = formatValue(event.validation);
}

function selectEvent(index) {
  if (index < 0 || index >= visibleEvents.length) {
    return;
  }
  selectedIndex = index;
  selectedEventKey = visibleEvents[index].event_key;
  renderTable();
  updatePanels(visibleEvents[index]);
  updateNavButtons();
}

function updateNavButtons() {
  prevButton.disabled = selectedIndex <= 0;
  nextButton.disabled = selectedIndex === -1 || selectedIndex >= visibleEvents.length - 1;
}

function updateVisibleEvents() {
  visibleEvents = showOcsfOnly.checked
    ? events.filter((event) => event.ocsf)
    : events;
  if (selectedEventKey) {
    const nextIndex = visibleEvents.findIndex(
      (event) => event.event_key === selectedEventKey
    );
    selectedIndex = nextIndex;
  }
  if (selectedIndex < 0 && visibleEvents.length) {
    selectedIndex = 0;
    selectedEventKey = visibleEvents[0].event_key;
  }
  if (!visibleEvents.length) {
    selectedIndex = -1;
    selectedEventKey = null;
  }
}

async function loadEvents() {
  statusLabel.textContent = "Loading pipeline events…";
  const limit = Math.min(Math.max(Number(limitInput.value) || 50, 1), 200);
  const response = await fetch(`/api/debug/pipeline/events?limit=${limit}`);
  const data = await response.json();
  events = data.events || [];
  statusLabel.textContent = data.message || `${events.length} events loaded.`;
  selectedEventKey = events.length ? events[0].event_key : null;
  updateVisibleEvents();
  renderTable();
  if (selectedIndex >= 0) {
    updatePanels(visibleEvents[selectedIndex]);
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
showOcsfOnly.addEventListener("change", () => {
  updateVisibleEvents();
  renderTable();
  if (selectedIndex >= 0) {
    updatePanels(visibleEvents[selectedIndex]);
  } else {
    rawEventPanel.textContent = "No events available.";
    rawEnvelopePanel.textContent = "No events available.";
    ocsfPanel.textContent = "No events available.";
    validationPanel.textContent = "No events available.";
  }
  updateNavButtons();
});

loadEvents();
