/**
 * static/js/app.js
 * Cybex Recon Engine – Module 1, 2 & 3
 *
 * Module 1: Expanded DNS Footprinting + RDAP   → POST /resolve
 * Module 2: Live/Simulated Service Assessment   → POST /assessment, GET /scenarios
 * Module 3: OSV-enriched Analysis & Reporting   → POST /analyse, POST /report/download
 */

"use strict";

/* ============================================================
   SHARED UTILITY HELPERS
   ============================================================ */

function escapeHtml(str) {
  return String(str)
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;");
}

function showAlertIn(container, message, type = "danger") {
  const iconMap = {
    danger:  "bi-exclamation-triangle-fill",
    warning: "bi-exclamation-circle-fill",
    success: "bi-check-circle-fill",
  };
  container.innerHTML = `
    <div class="alert alert-${type} d-flex align-items-center gap-2 mb-0" role="alert">
      <i class="bi ${iconMap[type] || "bi-info-circle-fill"}"></i>
      <span>${escapeHtml(message)}</span>
    </div>`;
}

function clearAlertIn(container) { container.innerHTML = ""; }

function animateCards(selector) {
  document.querySelectorAll(selector).forEach((card, i) => {
    card.classList.remove("cre-animate-in");
    void card.offsetWidth;
    card.style.animationDelay = `${i * 80}ms`;
    card.classList.add("cre-animate-in");
  });
}

function switchToModule2() {
  const tab = document.getElementById("module2-tab");
  if (tab) tab.click();
}
function switchToModule3() {
  const tab = document.getElementById("module3-tab");
  if (tab) tab.click();
}


/* ============================================================
   ====  MODULE 1 – EXPANDED DNS FOOTPRINTING + RDAP  ====
   ============================================================ */

const targetInput    = document.getElementById("targetInput");
const resolveBtn     = document.getElementById("resolveBtn");
const btnText        = document.getElementById("btnText");
const btnSpinner     = document.getElementById("btnSpinner");
const alertArea      = document.getElementById("alertArea");
const resultsPanel   = document.getElementById("resultsPanel");

const cardTarget     = document.getElementById("cardTarget");
const cardIP         = document.getElementById("cardIP");
const cardDNS        = document.getElementById("cardDNS");
const cardStatus     = document.getElementById("cardStatus");
const statusIcon     = document.getElementById("statusIcon");
const statusIconBg   = document.getElementById("statusIconBg");

const aRecordsList   = document.getElementById("aRecordsList");
const mxRecordsList  = document.getElementById("mxRecordsList");
const aRecordsBadge  = document.getElementById("aRecordsBadge");
const mxRecordsBadge = document.getElementById("mxRecordsBadge");

// New record panels
const aaaaRecordsList  = document.getElementById("aaaaRecordsList");
const nsRecordsList    = document.getElementById("nsRecordsList");
const txtRecordsList   = document.getElementById("txtRecordsList");
const cnameRecord      = document.getElementById("cnameRecord");
const soaRecord        = document.getElementById("soaRecord");
const rdapInfo         = document.getElementById("rdapInfo");
const aaaaRecordsBadge = document.getElementById("aaaaRecordsBadge");
const nsRecordsBadge   = document.getElementById("nsRecordsBadge");
const txtRecordsBadge  = document.getElementById("txtRecordsBadge");

/* ---- M1 helpers ---- */
function setM1Loading(on) {
  resolveBtn.disabled  = on;
  targetInput.disabled = on;
  btnText.classList.toggle("d-none", on);
  btnSpinner.classList.toggle("d-none", !on);
}

function renderARecord(ip) {
  return `
    <div class="cre-record-item">
      <i class="bi bi-hdd-fill cre-record-icon cre-icon-blue"></i>
      <span>${escapeHtml(ip)}</span>
      <span class="cre-record-tag cre-tag-a">A</span>
    </div>`;
}

function renderAaaaRecord(ip) {
  return `
    <div class="cre-record-item">
      <i class="bi bi-hdd-stack cre-record-icon cre-icon-purple"></i>
      <span class="cre-mono" style="font-size:.8rem">${escapeHtml(ip)}</span>
      <span class="cre-record-tag" style="background:rgba(168,85,247,.15);color:#a855f7">AAAA</span>
    </div>`;
}

function renderMxRecord(r) {
  return `
    <div class="cre-record-item">
      <i class="bi bi-envelope-fill cre-record-icon cre-icon-green"></i>
      <span>${escapeHtml(r.exchange)}</span>
      <span class="cre-mx-pref">[${escapeHtml(String(r.preference))}]</span>
      <span class="cre-record-tag cre-tag-mx">MX</span>
    </div>`;
}

function renderNsRecord(ns) {
  return `
    <div class="cre-record-item">
      <i class="bi bi-diagram-2 cre-record-icon cre-icon-blue"></i>
      <span>${escapeHtml(ns)}</span>
      <span class="cre-record-tag cre-tag-a">NS</span>
    </div>`;
}

function renderTxtRecord(txt) {
  return `
    <div class="cre-record-item cre-txt-item">
      <i class="bi bi-file-text cre-record-icon cre-icon-yellow"></i>
      <span class="cre-txt-value">${escapeHtml(txt)}</span>
    </div>`;
}

function renderSoa(soa) {
  if (!soa) return `<span class="cre-empty-state">No SOA record found.</span>`;
  return `
    <div class="cre-soa-grid">
      <div class="cre-soa-row"><span class="cre-soa-label">Primary NS</span><span class="cre-mono">${escapeHtml(soa.mname)}</span></div>
      <div class="cre-soa-row"><span class="cre-soa-label">Resp. Mailbox</span><span class="cre-mono">${escapeHtml(soa.rname)}</span></div>
      <div class="cre-soa-row"><span class="cre-soa-label">Serial</span><span class="cre-mono">${escapeHtml(String(soa.serial))}</span></div>
      <div class="cre-soa-row"><span class="cre-soa-label">Refresh</span><span class="cre-mono">${escapeHtml(String(soa.refresh))}s</span></div>
      <div class="cre-soa-row"><span class="cre-soa-label">Retry</span><span class="cre-mono">${escapeHtml(String(soa.retry))}s</span></div>
      <div class="cre-soa-row"><span class="cre-soa-label">Expire</span><span class="cre-mono">${escapeHtml(String(soa.expire))}s</span></div>
      <div class="cre-soa-row"><span class="cre-soa-label">Min TTL</span><span class="cre-mono">${escapeHtml(String(soa.minimum))}s</span></div>
    </div>`;
}

function renderRdap(rdap) {
  if (!rdap) return `<span class="cre-empty-state">No RDAP data available.</span>`;
  if (rdap.note) return `<div class="cre-record-item"><i class="bi bi-info-circle cre-record-icon cre-icon-blue"></i><span>${escapeHtml(rdap.note)}</span></div>`;
  return `
    <div class="cre-soa-grid">
      <div class="cre-soa-row"><span class="cre-soa-label">ASN</span><span class="cre-mono">${escapeHtml(rdap.asn || "N/A")}</span></div>
      <div class="cre-soa-row"><span class="cre-soa-label">Organization</span><span>${escapeHtml(rdap.asn_description || "N/A")}</span></div>
      <div class="cre-soa-row"><span class="cre-soa-label">Network CIDR</span><span class="cre-mono">${escapeHtml(rdap.network_cidr || "N/A")}</span></div>
      <div class="cre-soa-row"><span class="cre-soa-label">Network Name</span><span>${escapeHtml(rdap.network_name || "N/A")}</span></div>
      <div class="cre-soa-row"><span class="cre-soa-label">Country</span><span>${escapeHtml(rdap.country || "N/A")}</span></div>
      <div class="cre-soa-row"><span class="cre-soa-label">Registry</span><span>${escapeHtml(rdap.registrar || "N/A")}</span></div>
    </div>`;
}

function applyStatusStyle(status) {
  const map = {
    success: { label: "SUCCESS", iconCls: "bi-check-circle-fill",       bgCls: "cre-icon-bg-green",  textCls: "text-success" },
    partial: { label: "PARTIAL", iconCls: "bi-exclamation-circle-fill", bgCls: "cre-icon-bg-yellow", textCls: "text-warning" },
    failed:  { label: "FAILED",  iconCls: "bi-x-circle-fill",           bgCls: "cre-icon-bg-red",    textCls: "text-danger"  },
  };
  const cfg = map[status] || map.failed;
  statusIcon.className   = `bi ${cfg.iconCls}`;
  statusIconBg.className = `cre-summary-icon ${cfg.bgCls}`;
  cardStatus.textContent = cfg.label;
  cardStatus.className   = `cre-summary-value ${cfg.textCls}`;
}

function renderM1Results(data) {
  cardTarget.textContent = data.target || "—";
  cardIP.textContent     = data.resolved_ip || "N/A";

  // Count total record types for the summary card
  const total = (data.a_records?.length ?? 0)
              + (data.aaaa_records?.length ?? 0)
              + (data.mx_records?.length ?? 0)
              + (data.ns_records?.length ?? 0)
              + (data.txt_records?.length ?? 0)
              + (data.cname ? 1 : 0)
              + (data.soa  ? 1 : 0);
  cardDNS.textContent = `${total} record${total !== 1 ? "s" : ""}`;
  applyStatusStyle(data.status || "failed");

  // A records
  const aC = data.a_records?.length ?? 0;
  aRecordsBadge.textContent = aC;
  aRecordsList.innerHTML = aC > 0
    ? data.a_records.map(renderARecord).join("")
    : `<span class="cre-empty-state">No A records found.</span>`;

  // AAAA records
  const aaC = data.aaaa_records?.length ?? 0;
  aaaaRecordsBadge.textContent = aaC;
  aaaaRecordsList.innerHTML = aaC > 0
    ? data.aaaa_records.map(renderAaaaRecord).join("")
    : `<span class="cre-empty-state">No AAAA records found.</span>`;

  // MX records
  const mC = data.mx_records?.length ?? 0;
  mxRecordsBadge.textContent = mC;
  mxRecordsList.innerHTML = mC > 0
    ? data.mx_records.map(renderMxRecord).join("")
    : `<span class="cre-empty-state">No MX records found.</span>`;

  // NS records
  const nsC = data.ns_records?.length ?? 0;
  nsRecordsBadge.textContent = nsC;
  nsRecordsList.innerHTML = nsC > 0
    ? data.ns_records.map(renderNsRecord).join("")
    : `<span class="cre-empty-state">No NS records found.</span>`;

  // TXT records
  const txC = data.txt_records?.length ?? 0;
  txtRecordsBadge.textContent = txC;
  txtRecordsList.innerHTML = txC > 0
    ? data.txt_records.map(renderTxtRecord).join("")
    : `<span class="cre-empty-state">No TXT records found.</span>`;

  // CNAME
  cnameRecord.innerHTML = data.cname
    ? `<div class="cre-record-item"><i class="bi bi-arrow-right-circle cre-record-icon cre-icon-green"></i><span>${escapeHtml(data.cname)}</span><span class="cre-record-tag cre-tag-mx">CNAME</span></div>`
    : `<span class="cre-empty-state">No CNAME record found.</span>`;

  // SOA
  soaRecord.innerHTML = renderSoa(data.soa);

  // RDAP
  rdapInfo.innerHTML = renderRdap(data.rdap);

  resultsPanel.classList.remove("d-none");
  animateCards("#summaryCards .cre-summary-card");
}

async function resolve() {
  const target = targetInput.value.trim();
  if (!target) {
    showAlertIn(alertArea, "Please enter a domain name or IPv4 address.", "warning");
    targetInput.focus();
    return;
  }
  clearAlertIn(alertArea);
  setM1Loading(true);
  try {
    const res  = await fetch("/resolve", {
      method:  "POST",
      headers: { "Content-Type": "application/json" },
      body:    JSON.stringify({ target }),
    });
    const json = await res.json();
    if (!res.ok || !json.ok) {
      showAlertIn(alertArea, json.error || `Server error (HTTP ${res.status}).`, "danger");
      resultsPanel.classList.add("d-none");
      return;
    }
    if (json.data?.status === "partial") {
      showAlertIn(alertArea, json.data.error || "Partial resolution.", "warning");
    }
    renderM1Results(json.data);
  } catch (err) {
    showAlertIn(alertArea, "Network error – is the server running?", "danger");
    console.error("[CRE M1]", err);
  } finally {
    setM1Loading(false);
  }
}

resolveBtn.addEventListener("click", resolve);
targetInput.addEventListener("keydown", (e) => { if (e.key === "Enter") resolve(); });
targetInput.addEventListener("input",   () => { if (alertArea.innerHTML) clearAlertIn(alertArea); });


/* ===============================================/* ============================================================
   ====  MODULE 2 – REAL LOCAL MACHINE SERVICE ASSESSMENT ====
   ============================================================ */

const scenarioSelect    = document.getElementById("scenarioSelect");
const refreshTargetsBtn = document.getElementById("refreshTargetsBtn");
const assessTarget      = document.getElementById("assessTarget");
const assessBtn         = document.getElementById("assessBtn");
const assessBtnText     = document.getElementById("assessBtnText");
const assessBtnSpinner  = document.getElementById("assessBtnSpinner");
const assessAlertArea   = document.getElementById("assessAlertArea");
const assessPanel       = document.getElementById("assessPanel");
const analyseBtn        = document.getElementById("analyseBtn");

const reportTarget      = document.getElementById("reportTarget");
const reportScenario    = document.getElementById("reportScenario");
const reportTimestamp   = document.getElementById("reportTimestamp");
const reportScanType    = document.getElementById("reportScanType");

const sumTotal          = document.getElementById("sumTotal");
const sumOpen           = document.getElementById("sumOpen");
const sumClosed         = document.getElementById("sumClosed");
const sumHighRisk       = document.getElementById("sumHighRisk");

const servicesTableBody = document.getElementById("servicesTableBody");
const tableRowCount     = document.getElementById("tableRowCount");
const serviceSearch     = document.getElementById("serviceSearch");
const riskFilterGroup   = document.getElementById("riskFilterGroup");

/** In-memory store of the last successful assessment result. Module 3 reads this. */
let _lastAssessmentData = null;

/** Active status filter for Module 2 table ("all", "open", "closed"). */
let _activeRisk = "all";

/** Track active operations across modules */
let _isScanning = false;
let _isAnalysing = false;

/* ---- M2 helpers ---- */
function setM2Loading(on) {
  _isScanning = on;
  assessBtn.disabled         = on;
  scenarioSelect.disabled    = on;
  if (refreshTargetsBtn) refreshTargetsBtn.disabled = on;
  assessBtnText.classList.toggle("d-none", on);
  assessBtnSpinner.classList.toggle("d-none", !on);
}

function statusBadge(status) {
  const st = (status || "").toLowerCase();
  return st === "open"
    ? `<span class="cre-status-pill cre-status-pill--open"><i class="bi bi-circle-fill me-1" style="font-size:.45rem;vertical-align:middle"></i>Open</span>`
    : `<span class="cre-status-pill cre-status-pill--closed"><i class="bi bi-circle me-1" style="font-size:.45rem;vertical-align:middle"></i>Closed</span>`;
}

/** Maps raw backend service_source values to user-friendly display labels. */
function getSourceLabel(src) {
  const labels = {
    port_mapping:    "Port-based",
    observed_banner: "Banner detected",
    inferred:        "Inferred",
    unknown:         "Unknown",
  };
  return labels[src] || src || "Unknown";
}

function sourceBadge(source) {
  const src = source || "unknown";
  const label = getSourceLabel(src);
  let cls = "cre-src-badge--default";
  switch (src) {
    case "observed_banner": cls = "cre-src-badge--banner"; break;
    case "port_mapping":    cls = "cre-src-badge--port";   break;
    case "inferred":        cls = "cre-src-badge--infer";  break;
    default:                cls = "cre-src-badge--default";
  }
  return `<span class="cre-src-badge ${cls}">${escapeHtml(label)}</span>`;
}

function renderServicesTable(services) {
  if (!services?.length) {
    servicesTableBody.innerHTML = `<tr><td colspan="7" class="text-center cre-empty-state py-4">No local assessment has been run yet. Select a local address and start an assessment.</td></tr>`;
    tableRowCount.textContent = "0 services";
    return;
  }

  servicesTableBody.innerHTML = services.map((s, i) => {
    const port        = s.port ?? "—";
    const protocol    = s.protocol || "TCP";
    const service     = s.service || s.service_name || "Unknown";
    const source      = s.service_source || "unknown";
    const status      = (s.status || "closed").toLowerCase();
    const evidenceRaw = s.evidence || "";
    // Shorten verbose evidence phrases for display
    const evidenceText = evidenceRaw
      .replace("TCP connection refused or timed out", "Connection refused")
      .replace("TCP connection accepted", "Connection accepted")
      || "—";

    let bannerHtml = "";
    if (s.banner && s.banner !== "Not observed" && s.banner !== "Not applicable") {
      bannerHtml = `<span class="cre-banner-tag" title="${escapeHtml(s.banner)}"><i class="bi bi-terminal me-1"></i>${escapeHtml(s.banner)}</span>`;
    } else {
      const defaultBanner = s.banner || (status === "open" ? "Not observed" : "—");
      bannerHtml = `<span class="cre-cell-dim">${escapeHtml(defaultBanner)}</span>`;
    }

    return `
    <tr data-status="${escapeHtml(status)}" data-service="${escapeHtml(service.toLowerCase())}" data-port="${escapeHtml(String(port))}" data-idx="${i}">
      <td><span class="cre-port">${escapeHtml(String(port))}</span></td>
      <td><span class="cre-proto">${escapeHtml(protocol)}</span></td>
      <td><span class="cre-svc-name">${escapeHtml(service)}</span></td>
      <td>${sourceBadge(source)}</td>
      <td>${statusBadge(status)}</td>
      <td class="cre-cell-banner">${bannerHtml}</td>
      <td class="cre-cell-evidence"><span class="cre-evidence-text">${escapeHtml(evidenceText)}</span></td>
    </tr>`;
  }).join("");

  applyTableFilters();
}

function applyTableFilters() {
  const q    = (serviceSearch.value || "").trim().toLowerCase();
  const rows = servicesTableBody.querySelectorAll("tr[data-status]");
  let vis    = 0;
  rows.forEach((row) => {
    const statusMatch = (_activeRisk === "all" || row.dataset.status === _activeRisk);
    const searchMatch = (!q || row.dataset.service.includes(q) || row.dataset.port.includes(q));
    const ok = statusMatch && searchMatch;
    row.classList.toggle("cre-row-hidden", !ok);
    if (ok) vis++;
  });
  tableRowCount.textContent = `${vis} service${vis !== 1 ? "s" : ""}`;
}

function renderAssessmentResults(data) {
  _lastAssessmentData = data;
  _lastAnalysis = null; // Invalidate previous report with new scan data

  reportTarget.textContent    = data.target || "127.0.0.1";
  reportScenario.textContent  = data.assessment_type || data.scenario || "Local Machine TCP Assessment";
  reportTimestamp.textContent = data.timestamp || "—";
  reportScanType.innerHTML    = `<span class="cre-live-badge"><i class="bi bi-shield-check me-1"></i>REAL LOCAL SCAN</span>`;

  const s = data.summary || {};
  sumTotal.textContent    = s.total_ports ?? s.total ?? "—";
  sumOpen.textContent     = s.open_ports  ?? s.open  ?? "0";
  sumClosed.textContent   = s.closed_ports ?? s.closed ?? "0";
  sumHighRisk.textContent = data.duration_seconds ? `${data.duration_seconds}s` : "0.00s";

  renderServicesTable(data.services || data.results || []);
  assessPanel.classList.remove("d-none");
  analyseBtn.disabled = false;
  animateCards("#assessSummaryCards .cre-summary-card");

  // If user is currently on Module 3 tab, automatically generate analysis
  const m3Tab = document.getElementById("module3-tab");
  if (m3Tab && m3Tab.classList.contains("active")) {
    runAnalysis(_lastAssessmentData);
  }
}

async function loadLocalTargets() {
  try {
    const res  = await fetch("/local-targets");
    const json = await res.json();
    let targets = [];
    if (res.ok && json.ok && json.data?.targets) {
      targets = json.data.targets;
    } else {
      // Fallback local addresses if endpoint errors
      targets = [
        { label: "Localhost (Loopback)", ip: "127.0.0.1", type: "loopback" }
      ];
    }

    scenarioSelect.innerHTML = targets.map(
      t => `<option value="${escapeHtml(t.ip)}">${escapeHtml(t.label)}</option>`
    ).join("");

    if (targets.length) {
      assessTarget.value = targets[0].ip;
    }
  } catch (err) {
    scenarioSelect.innerHTML = '<option value="127.0.0.1">Localhost (127.0.0.1)</option>';
    assessTarget.value = "127.0.0.1";
    console.error("[CRE M2] Local targets discovery error:", err);
  }
}

async function runAssessment() {
  const target = (scenarioSelect.value || assessTarget.value || "127.0.0.1").trim();
  if (!target) {
    showAlertIn(assessAlertArea, "Please select a valid local machine target address.", "warning");
    return;
  }

  clearAlertIn(assessAlertArea);
  setM2Loading(true);
  updateM3ViewState();

  try {
    const res  = await fetch("/assessment", {
      method:  "POST",
      headers: { "Content-Type": "application/json" },
      body:    JSON.stringify({ target: target, authorized: true }),
    });
    const json = await res.json();
    if (!res.ok || !json.ok) {
      showAlertIn(assessAlertArea, json.error || `Server error (HTTP ${res.status}).`, "danger");
      return;
    }
    renderAssessmentResults(json.data);
  } catch (err) {
    showAlertIn(assessAlertArea, "Network error – is the server running?", "danger");
    console.error("[CRE M2]", err);
  } finally {
    setM2Loading(false);
    updateM3ViewState();
  }
}

/* ---- M2 event listeners ---- */
if (riskFilterGroup) {
  riskFilterGroup.addEventListener("click", (e) => {
    const btn = e.target.closest(".cre-filter-btn");
    if (!btn) return;
    riskFilterGroup.querySelectorAll(".cre-filter-btn").forEach(b => b.classList.remove("active"));
    btn.classList.add("active");
    _activeRisk = btn.dataset.risk || "all";
    applyTableFilters();
  });
}

if (serviceSearch) serviceSearch.addEventListener("input", applyTableFilters);
if (scenarioSelect) {
  scenarioSelect.addEventListener("change", () => {
    assessTarget.value = scenarioSelect.value;
    if (assessAlertArea.innerHTML) clearAlertIn(assessAlertArea);
  });
}
if (refreshTargetsBtn) {
  refreshTargetsBtn.addEventListener("click", () => {
    loadLocalTargets();
    showAlertIn(assessAlertArea, "Local interface addresses refreshed.", "info");
  });
}

assessBtn.addEventListener("click", runAssessment);

analyseBtn.addEventListener("click", () => {
  if (!_lastAssessmentData) {
    showAlertIn(assessAlertArea, "Please run a local machine assessment first.", "warning");
    return;
  }
  switchToModule3();
  runAnalysis(_lastAssessmentData);
});

analyseBtn.disabled = true;

/* Discover and load local targets on page ready */
loadLocalTargets();


/* ============================================================
   ====  MODULE 3 – ANALYSIS & REPORTING (OSV-enriched)  ====
   ============================================================ */

const m3AlertArea        = document.getElementById("m3AlertArea");
const m3Loading          = document.getElementById("m3Loading");
const m3LoadingIcon      = document.getElementById("m3LoadingIcon");
const m3LoadingTitle     = document.getElementById("m3LoadingTitle");
const m3LoadingDesc      = document.getElementById("m3LoadingDesc");
const m3LoadingAction    = document.getElementById("m3LoadingAction");
const m3Placeholder      = document.getElementById("m3Placeholder");
const m3Panel            = document.getElementById("m3Panel");

const m3Target           = document.getElementById("m3Target");
const m3Scenario         = document.getElementById("m3Scenario");
const m3Date             = document.getElementById("m3Date");

const m3RiskScore        = document.getElementById("m3RiskScore");
const m3RiskLabel        = document.getElementById("m3RiskLabel");
const m3GaugeBar         = document.getElementById("m3GaugeBar");
const m3Distribution     = document.getElementById("m3Distribution");

const m3StatTotal        = document.getElementById("m3StatTotal");
const m3StatOpen         = document.getElementById("m3StatOpen");
const m3StatFindings     = document.getElementById("m3StatFindings");

const m3ExecSummary      = document.getElementById("m3ExecSummary");

const findingsTableBody  = document.getElementById("findingsTableBody");
const findingsRowCount   = document.getElementById("findingsRowCount");
const m3FindingsBadge    = document.getElementById("m3FindingsBadge");
const findingFilterGroup = document.getElementById("findingFilterGroup");

const downloadTxtBtn     = document.getElementById("downloadTxtBtn");
const downloadJsonBtn    = document.getElementById("downloadJsonBtn");

let _activeSev   = "all";
let _lastAnalysis = null;

function updateM3ViewState() {
  if (!m3Loading || !m3Placeholder || !m3Panel) return;

  if (_isScanning) {
    // Scan is actively running in Module 2
    m3Placeholder.classList.add("d-none");
    m3Panel.classList.add("d-none");
    m3Loading.classList.remove("d-none");

    if (m3LoadingIcon) {
      m3LoadingIcon.innerHTML = `<i class="bi bi-radar cre-radar-pulse"></i>`;
    }
    if (m3LoadingTitle) {
      m3LoadingTitle.textContent = "Port Assessment in Progress...";
    }
    if (m3LoadingDesc) {
      m3LoadingDesc.textContent = "Module 2 is currently probing local TCP ports. Security analysis will automatically generate when port scanning completes.";
    }
    if (m3LoadingAction) {
      m3LoadingAction.classList.remove("d-none");
    }
  } else if (_isAnalysing) {
    // Analysis request is in-flight
    m3Placeholder.classList.add("d-none");
    m3Panel.classList.add("d-none");
    m3Loading.classList.remove("d-none");

    if (m3LoadingIcon) {
      m3LoadingIcon.innerHTML = `<span class="spinner-border text-teal" style="width: 3rem; height: 3rem;" role="status"></span>`;
    }
    if (m3LoadingTitle) {
      m3LoadingTitle.textContent = "Generating Security Analysis Report...";
    }
    if (m3LoadingDesc) {
      m3LoadingDesc.textContent = "Correlating exposure findings, scoring risk level, and querying vulnerability intelligence...";
    }
    if (m3LoadingAction) {
      m3LoadingAction.classList.add("d-none");
    }
  } else if (_lastAnalysis) {
    // Analysis is ready and rendered
    m3Loading.classList.add("d-none");
    m3Placeholder.classList.add("d-none");
    m3Panel.classList.remove("d-none");
  } else if (_lastAssessmentData) {
    // Have assessment data but no analysis yet -> trigger analysis
    runAnalysis(_lastAssessmentData);
  } else {
    // No assessment has been run
    m3Loading.classList.add("d-none");
    m3Panel.classList.add("d-none");
    m3Placeholder.classList.remove("d-none");
  }
}

/* ---- M3: Risk gauge ---- */
function scoreClass(score) {
  if (score >= 70) return "critical";
  if (score >= 45) return "high";
  if (score >= 20) return "medium";
  return "low";
}

function renderGauge(score, label) {
  const cls = scoreClass(score);
  m3RiskScore.textContent = score;
  m3GaugeBar.style.width  = `${score}%`;
  m3GaugeBar.setAttribute("aria-valuenow", score);
  m3GaugeBar.className    = `progress-bar score-${cls}`;
  m3RiskLabel.textContent = label.toUpperCase();
  m3RiskLabel.className   = `cre-risk-label cre-risk-label--${cls} mt-2`;
  const colourMap = { critical: "#f87171", high: "#fca5a5", medium: "#fcd34d", low: "#86efac" };
  m3RiskScore.style.color = colourMap[cls] || "#e2e8f0";
}

function renderDistribution(breakdown) {
  const rows = [
    { key: "critical", label: "Critical" },
    { key: "high",     label: "High"     },
    { key: "medium",   label: "Medium"   },
    { key: "low",      label: "Low"      },
  ];
  const max = Math.max(...Object.values(breakdown), 1);
  m3Distribution.innerHTML = rows.map(({ key, label }) => {
    const n   = breakdown[key] ?? 0;
    const pct = Math.round((n / max) * 100);
    return `
      <div class="cre-dist-row">
        <span class="cre-dist-label" style="color: var(--cre-${key === "critical" || key === "high" ? "red" : key === "medium" ? "yellow" : "green"})">${label}</span>
        <div class="cre-dist-bar-wrap">
          <div class="cre-dist-bar cre-dist-bar--${key}" style="width:${pct}%"></div>
        </div>
        <span class="cre-dist-count">${n}</span>
      </div>`;
  }).join("");
}

function severityBadge(sev) {
  const cls = { critical: "cre-risk-critical", high: "cre-risk-high", medium: "cre-risk-medium", low: "cre-risk-low" };
  return `<span class="cre-risk-badge ${cls[sev] || "cre-risk-low"}">${escapeHtml((sev || "—").toUpperCase())}</span>`;
}

function dataSourceBadge(src) {
  return src === "osv.dev"
    ? `<span class="cre-osv-badge"><i class="bi bi-cloud-fill me-1"></i>OSV.dev</span>`
    : `<span class="cre-local-badge"><i class="bi bi-database-fill me-1"></i>Local</span>`;
}

function renderFindingsTable(findings) {
  m3FindingsBadge.textContent = findings.length;
  if (!findings.length) {
    findingsTableBody.innerHTML = `<tr><td colspan="9" class="text-center cre-empty-state py-4">No open port findings generated.</td></tr>`;
    findingsRowCount.textContent = "0 findings";
    return;
  }

  findingsTableBody.innerHTML = findings.map((f, i) => {
    const bannerCell = f.banner && f.banner !== "Not observed" && f.banner !== "Not applicable"
      ? `<span class="cre-banner-tag" title="${escapeHtml(f.banner)}">${escapeHtml(f.banner.slice(0, 35))}${f.banner.length > 35 ? "…" : ""}</span>`
      : `<span class="cre-empty-state" style="font-size:.75rem">—</span>`;
    return `
    <tr data-sev="${escapeHtml(f.severity || "")}" data-idx="${i}">
      <td><span class="cre-finding-num">${i + 1}</span></td>
      <td><span class="cre-svc-name">${escapeHtml(f.service || "—")}</span></td>
      <td><span class="cre-port">${escapeHtml(String(f.port || "—"))}</span></td>
      <td>${severityBadge(f.severity)}</td>
      <td>
        <a href="${escapeHtml(f.reference || "#")}" target="_blank" rel="noopener noreferrer" class="cre-finding-ref">
          ${escapeHtml(f.cve || "N/A")}
        </a>
      </td>
      <td>${dataSourceBadge(f.data_source)}</td>
      <td>${bannerCell}</td>
      <td><span class="cre-finding-desc">${escapeHtml(f.description || "—")}</span></td>
      <td><span class="cre-finding-rec">${escapeHtml(f.recommendation || "—")}</span></td>
    </tr>`;
  }).join("");

  applyFindingsFilter();
}

function applyFindingsFilter() {
  const rows = findingsTableBody.querySelectorAll("tr[data-sev]");
  let vis    = 0;
  rows.forEach((row) => {
    const ok = _activeSev === "all" || row.dataset.sev === _activeSev;
    row.classList.toggle("cre-finding-hidden", !ok);
    if (ok) vis++;
  });
  findingsRowCount.textContent = `${vis} finding${vis !== 1 ? "s" : ""}`;
}

function renderAnalysis(data) {
  _lastAnalysis = data;

  m3Target.textContent   = data.target   || "—";
  m3Scenario.textContent = data.scenario || "—";
  m3Date.textContent     = data.analysis_date || "—";

  renderGauge(data.risk_score ?? 0, data.risk_label || "Low");
  renderDistribution(data.score_breakdown || {});

  m3StatTotal.textContent    = data.services_total ?? "—";
  m3StatOpen.textContent     = data.open_services  ?? "—";
  m3StatFindings.textContent = (data.findings || []).length;

  m3ExecSummary.textContent = data.executive_summary || "—";

  renderFindingsTable(data.findings || []);

  if (m3AlertArea) clearAlertIn(m3AlertArea);
  updateM3ViewState();
  animateCards("#m3Panel .cre-summary-card");
}

async function runAnalysis(assessmentData) {
  if (!assessmentData || _isAnalysing) return;

  _isAnalysing = true;
  if (m3AlertArea) clearAlertIn(m3AlertArea);
  updateM3ViewState();

  try {
    const res  = await fetch("/analyse", {
      method:  "POST",
      headers: { "Content-Type": "application/json" },
      body:    JSON.stringify({ assessment: assessmentData }),
    });
    const json = await res.json();
    if (!res.ok || !json.ok) {
      console.error("[CRE M3] Analysis error:", json.error);
      if (m3AlertArea) {
        m3AlertArea.innerHTML = `
          <div class="alert alert-danger d-flex flex-column gap-2" role="alert">
            <div class="d-flex align-items-center gap-2">
              <i class="bi bi-exclamation-triangle-fill"></i>
              <span>${escapeHtml(json.error || `Server error during analysis (HTTP ${res.status}).`)}</span>
            </div>
            <div>
              <button class="btn btn-sm cre-btn-teal" onclick="runAnalysis(_lastAssessmentData)">
                <i class="bi bi-arrow-clockwise me-1"></i>Retry Analysis
              </button>
            </div>
          </div>`;
      }
      return;
    }
    renderAnalysis(json.data);
  } catch (err) {
    console.error("[CRE M3] Fetch error:", err);
    if (m3AlertArea) {
      m3AlertArea.innerHTML = `
        <div class="alert alert-danger d-flex flex-column gap-2" role="alert">
          <div class="d-flex align-items-center gap-2">
            <i class="bi bi-exclamation-triangle-fill"></i>
            <span>Network error while generating security analysis report.</span>
          </div>
          <div>
            <button class="btn btn-sm cre-btn-teal" onclick="runAnalysis(_lastAssessmentData)">
              <i class="bi bi-arrow-clockwise me-1"></i>Retry Analysis
            </button>
          </div>
        </div>`;
    }
  } finally {
    _isAnalysing = false;
    updateM3ViewState();
  }
}

async function downloadReport(format) {
  if (!_lastAssessmentData) {
    console.warn("[CRE M3] No assessment data to download.");
    return;
  }

  const btn = format === "json" ? downloadJsonBtn : downloadTxtBtn;
  const originalHtml = btn ? btn.innerHTML : "";
  if (btn) {
    btn.disabled = true;
    btn.innerHTML = `<span class="spinner-border spinner-border-sm me-1" role="status"></span>Generating...`;
  }

  try {
    const res = await fetch("/report/download", {
      method:  "POST",
      headers: { "Content-Type": "application/json" },
      body:    JSON.stringify({
        assessment: _lastAssessmentData,
        analysis:   _lastAnalysis,
        format:     format,
      }),
    });
    if (!res.ok) {
      const err = await res.json().catch(() => ({}));
      console.error("[CRE M3] Download error:", err.error || res.status);
      if (m3AlertArea) showAlertIn(m3AlertArea, err.error || "Failed to download report.", "danger");
      return;
    }
    const cd       = res.headers.get("Content-Disposition") || "";
    const match    = cd.match(/filename="?([^"]+)"?/);
    const filename = match ? match[1] : `cre_report.${format}`;
    const blob = await res.blob();
    const url  = URL.createObjectURL(blob);
    const a    = document.createElement("a");
    a.href     = url;
    a.download = filename;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(url);
  } catch (err) {
    console.error("[CRE M3] Download fetch error:", err);
    if (m3AlertArea) showAlertIn(m3AlertArea, "Network error downloading report.", "danger");
  } finally {
    if (btn) {
      btn.disabled = false;
      btn.innerHTML = originalHtml;
    }
  }
}

if (findingFilterGroup) {
  findingFilterGroup.addEventListener("click", (e) => {
    const btn = e.target.closest(".cre-filter-btn");
    if (!btn) return;
    findingFilterGroup.querySelectorAll(".cre-filter-btn").forEach(b => b.classList.remove("active"));
    btn.classList.add("active");
    _activeSev = btn.dataset.sev || "all";
    applyFindingsFilter();
  });
}

if (downloadTxtBtn) {
  downloadTxtBtn.addEventListener("click", () => downloadReport("txt"));
}
if (downloadJsonBtn) {
  downloadJsonBtn.addEventListener("click", () => downloadReport("json"));
}

const module3Tab = document.getElementById("module3-tab");
if (module3Tab) {
  module3Tab.addEventListener("shown.bs.tab", () => {
    updateM3ViewState();
  });
}
