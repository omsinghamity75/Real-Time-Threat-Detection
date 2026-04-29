const state = {
  report: null,
  refreshTimer: null,
};

async function requestJson(url, options = {}) {
  const response = await fetch(url, {
    headers: { "Content-Type": "application/json" },
    ...options,
  });

  if (!response.ok) {
    throw new Error(`Request failed: ${response.status}`);
  }

  return response.json();
}

function setStatus(text) {
  document.getElementById("statusBadge").textContent = text;
}

function renderReport(report) {
  state.report = report;
  document.getElementById("totalEvents").textContent = report.total_events;
  document.getElementById("attackCount").textContent = report.labels.attack ?? 0;
  document.getElementById("suspiciousCount").textContent = report.labels.suspicious ?? 0;
  document.getElementById("normalCount").textContent = report.labels.normal ?? 0;
  document.getElementById("averageConfidence").textContent = report.average_confidence.toFixed(3);
  document.getElementById("feedbackCount").textContent = report.feedback_items;

  const blockedSources = document.getElementById("blockedSources");
  blockedSources.innerHTML = "";
  if (report.blocked_sources.length === 0) {
    blockedSources.innerHTML = `<span class="chip">none</span>`;
  } else {
    report.blocked_sources.forEach((source) => {
      blockedSources.insertAdjacentHTML("beforeend", `<span class="chip">${source}</span>`);
    });
  }

  renderActionBars(report.actions ?? {});
  renderProtocolBars(report.protocols ?? {});
  renderTrendChart(report.label_trend ?? []);
  renderEvents(report.recent_events ?? []);
  setStatus("Synced");
}

function renderActionBars(actions) {
  const total = Object.values(actions).reduce((sum, value) => sum + value, 0) || 1;
  const target = document.getElementById("actionBars");
  target.innerHTML = "";

  const labels = [
    ["allow", "Allowed"],
    ["allow_with_alert", "Alerted"],
    ["block", "Blocked"],
  ];

  labels.forEach(([key, label]) => {
    const count = actions[key] ?? 0;
    const width = Math.max((count / total) * 100, count > 0 ? 8 : 0);
    target.insertAdjacentHTML(
      "beforeend",
      `
        <div class="bar-row">
          <span>${label}</span>
          <div class="bar-track"><div class="bar-fill" style="width:${width}%"></div></div>
          <strong>${count}</strong>
        </div>
      `,
    );
  });
}

function renderProtocolBars(protocols) {
  const total = Object.values(protocols).reduce((sum, value) => sum + value, 0) || 1;
  const target = document.getElementById("protocolBars");
  target.innerHTML = "";

  Object.entries(protocols).forEach(([protocol, count]) => {
    const width = Math.max((count / total) * 100, count > 0 ? 8 : 0);
    target.insertAdjacentHTML(
      "beforeend",
      `
        <div class="bar-row">
          <span>${protocol}</span>
          <div class="bar-track"><div class="bar-fill protocol" style="width:${width}%"></div></div>
          <strong>${count}</strong>
        </div>
      `,
    );
  });

  if (target.innerHTML === "") {
    target.innerHTML = "<p>No protocol activity yet.</p>";
  }
}

function renderTrendChart(trendRows) {
  const target = document.getElementById("trendChart");
  target.innerHTML = "";

  if (!trendRows.length) {
    target.innerHTML = "<p>No trend data yet.</p>";
    return;
  }

  const grouped = new Map();
  trendRows
    .slice()
    .reverse()
    .forEach((row) => {
      const bucket = row.hour_bucket;
      if (!grouped.has(bucket)) {
        grouped.set(bucket, { attack: 0, suspicious: 0, normal: 0 });
      }
      grouped.get(bucket)[row.label] = row.total;
    });

  grouped.forEach((counts, bucket) => {
    const total = counts.attack + counts.suspicious + counts.normal || 1;
    const attackWidth = (counts.attack / total) * 100;
    const suspiciousWidth = (counts.suspicious / total) * 100;
    const normalWidth = (counts.normal / total) * 100;

    target.insertAdjacentHTML(
      "beforeend",
      `
        <div class="trend-row">
          <span class="trend-time">${bucket.replace("T", " ")}</span>
          <div class="trend-stack" title="A:${counts.attack} S:${counts.suspicious} N:${counts.normal}">
            <div class="trend-segment attack" style="width:${attackWidth}%"></div>
            <div class="trend-segment suspicious" style="width:${suspiciousWidth}%"></div>
            <div class="trend-segment normal" style="width:${normalWidth}%"></div>
          </div>
        </div>
      `,
    );
  });
}

function renderEvents(events) {
  const target = document.getElementById("eventList");
  target.innerHTML = "";

  if (events.length === 0) {
    target.innerHTML = `<p>No events stored yet. Run a simulation to populate the dashboard.</p>`;
    return;
  }

  events.forEach((event) => {
    const reasons = event.reasons
      .map((reason) => `<span class="reason-chip">${reason}</span>`)
      .join("");

    target.insertAdjacentHTML(
      "beforeend",
      `
        <article class="event-card">
          <div>
            <div class="label-pill ${event.label}">${event.label}</div>
            <p class="event-meta">${event.event_id}</p>
          </div>
          <div>
            <h3>${event.source_ip} -> ${event.destination_ip}</h3>
            <p>${event.protocol} on port ${event.destination_port} with action <strong>${event.action}</strong></p>
            <div class="event-reasons">${reasons}</div>
          </div>
          <div>
            <p><strong>${event.confidence.toFixed(2)}</strong> confidence</p>
            <p class="event-meta">${new Date(event.created_at).toLocaleString()}</p>
          </div>
        </article>
      `,
    );
  });
}

async function refreshReport() {
  setStatus("Refreshing");
  const report = await requestJson("/api/report");
  renderReport(report);
}

async function processSimulation() {
  setStatus("Processing");
  await requestJson("/api/simulate", { method: "POST", body: "{}" });
  await refreshReport();
}

async function processDemo() {
  setStatus("Processing");
  await requestJson("/api/demo", { method: "POST", body: "{}" });
  await refreshReport();
}

async function submitUpload(event) {
  event.preventDefault();
  const file = document.getElementById("fileInput").files[0];
  if (!file) {
    document.getElementById("uploadMessage").textContent = "Choose a CSV or JSONL file first.";
    return;
  }

  setStatus("Ingesting");
  const content = await file.text();
  await requestJson("/api/upload", {
    method: "POST",
    body: JSON.stringify({
      filename: file.name,
      content,
    }),
  });

  document.getElementById("uploadMessage").textContent = `Processed ${file.name}.`;
  document.getElementById("uploadForm").reset();
  await refreshReport();
}

async function submitFeedback(event) {
  event.preventDefault();
  const payload = {
    event_id: document.getElementById("eventIdInput").value.trim(),
    actual_label: document.getElementById("actualLabelInput").value,
    notes: document.getElementById("notesInput").value.trim(),
  };

  if (!payload.event_id) {
    document.getElementById("feedbackMessage").textContent = "Event ID is required.";
    return;
  }

  await requestJson("/api/feedback", {
    method: "POST",
    body: JSON.stringify(payload),
  });

  document.getElementById("feedbackMessage").textContent = `Feedback stored for ${payload.event_id}.`;
  document.getElementById("feedbackForm").reset();
  await refreshReport();
}

function startAutoRefresh() {
  if (state.refreshTimer) {
    clearInterval(state.refreshTimer);
  }

  state.refreshTimer = setInterval(async () => {
    try {
      await refreshReport();
    } catch (error) {
      setStatus("Retrying");
    }
  }, 10000);
}

async function init() {
  document.getElementById("simulateButton").addEventListener("click", processSimulation);
  document.getElementById("demoButton").addEventListener("click", processDemo);
  document.getElementById("uploadForm").addEventListener("submit", submitUpload);
  document.getElementById("feedbackForm").addEventListener("submit", submitFeedback);

  try {
    await refreshReport();
    startAutoRefresh();
  } catch (error) {
    setStatus("Error");
    document.getElementById("eventList").innerHTML = `<p>Could not load dashboard data.</p>`;
  }
}

init();
