const statusBar = document.getElementById("statusBar");
const progressEl = document.getElementById("progress");
const resultsEl = document.getElementById("results");
const headerResults = document.getElementById("headerResults");
const scoreEl = document.getElementById("score");
const scanBtn = document.getElementById("scanBtn");
const clearBtn = document.getElementById("clearBtn");
const exportBtn = document.getElementById("exportBtn");
const deleteHistoryBtn = document.getElementById("deleteHistoryBtn");
const historyList = document.getElementById("historyList");
const targetHost = document.getElementById("targetHost");
const targetFav = document.getElementById("targetFav");
const toggleHeadersBtn = document.getElementById("toggleHeaders");
const tabSelect = document.getElementById("tabSelect");
const refreshTabsBtn = document.getElementById("refreshTabsBtn");
const findingsCountEl = document.getElementById("findingsCount");
const reviewCountEl = document.getElementById("reviewCount");
const brandVersion = document.getElementById("brandVersion");
const aboutVersion = document.getElementById("aboutVersion");
const scanModeEl = document.getElementById("scanMode");
const scanModePicker = document.getElementById("scanModePicker");
const scanModeSummary = document.getElementById("scanModeSummary");
const fullScanToggle = document.getElementById("fullScanToggle");
const requestBudgetEl = document.getElementById("requestBudget");
const modeHelp = document.getElementById("modeHelp");
const stageProgressEl = document.getElementById("stageProgress");
const resultOverviewEl = document.getElementById("resultOverview");
const resultSearchEl = document.getElementById("resultSearch");
const categoryFilterEl = document.getElementById("categoryFilter");
const confidenceFilterEl = document.getElementById("confidenceFilter");
const sourceFilterEl = document.getElementById("sourceFilter");
const changeFilterEl = document.getElementById("changeFilter");
const triageFilterEl = document.getElementById("triageFilter");
const comparisonPanelEl = document.getElementById("comparisonPanel");
const checkPicker = document.getElementById("checkPicker");
const checkPickerSummary = document.getElementById("checkPickerSummary");
const selectAllChecksBtn = document.getElementById("selectAllChecks");
const clearChecksBtn = document.getElementById("clearChecks");
const cancelScanBtn = document.getElementById("cancelScanBtn");
const requestLogEl = document.getElementById("requestLog");
const requestSummaryEl = document.getElementById("requestSummary");
const toggleRequestLogBtn = document.getElementById("toggleRequestLog");
const exportMenu = document.getElementById("exportMenu");
const exportMarkdownBtn = document.getElementById("exportMarkdownBtn");
const exportJsonBtn = document.getElementById("exportJsonBtn");
const exportSecretsBtn = document.getElementById("exportSecretsBtn");
const authorizationModal = document.getElementById("authorizationModal");
const authorizationDetails = document.getElementById("authorizationDetails");
const authorizationCheck = document.getElementById("authorizationCheck");
const authorizationStart = document.getElementById("authorizationStart");
const authorizationCancel = document.getElementById("authorizationCancel");
const secretExportModal = document.getElementById("secretExportModal");
const secretExportCheck = document.getElementById("secretExportCheck");
const secretExportConfirm = document.getElementById("secretExportConfirm");
const secretExportCancel = document.getElementById("secretExportCancel");
const clearAllDataBtn = document.getElementById("clearAllDataBtn");
const findingDrawer = document.getElementById("findingDrawer");
const findingDrawerBackdrop = document.getElementById("findingDrawerBackdrop");
const findingDrawerClose = document.getElementById("findingDrawerClose");
const findingDrawerTitle = document.getElementById("findingDrawerTitle");
const findingDrawerBody = document.getElementById("findingDrawerBody");
const findingTriageState = document.getElementById("findingTriageState");
const copyFindingBriefBtn = document.getElementById("copyFindingBrief");
const showAffectedBtn = document.getElementById("showAffectedBtn");
const scanMapDialog = document.getElementById("scanMapDialog");
const scanMapBackdrop = document.getElementById("scanMapBackdrop");
const scanMapClose = document.getElementById("scanMapClose");
const scanMapSubtitle = document.getElementById("scanMapSubtitle");
const scanMapSearch = document.getElementById("scanMapSearch");
const scanMapKind = document.getElementById("scanMapKind");
const scanMapBucket = document.getElementById("scanMapBucket");
const scanMapSeverity = document.getElementById("scanMapSeverity");
const scanMapSvg = document.getElementById("scanMapSvg");
const scanMapViewport = document.getElementById("scanMapViewport");
const scanMapDetails = document.getElementById("scanMapDetails");
const scanMapStatus = document.getElementById("scanMapStatus");
const scanMapZoomOut = document.getElementById("scanMapZoomOut");
const scanMapZoomIn = document.getElementById("scanMapZoomIn");
const scanMapFit = document.getElementById("scanMapFit");
const scanMapReset = document.getElementById("scanMapReset");

let selectedTabId = null;
let currentFindings = [];
let currentFilter = "all";
let currentBucket = "finding";
let currentSearch = "";
let currentCategory = "all";
let currentConfidence = "all";
let currentSource = "all";
let currentChange = "all";
let currentTriage = "all";
let currentComparisonStatuses = new Map();
let triageStates = {};
let activeFindingFingerprint = null;
let lastScanData = null;
let scanning = false;
let activeScanId = null;
let knownTabs = [];
let currentRequestController = null;
let authorizationResolve = null;
let scanCancelled = false;
let drawerReturnFocus = null;
let mapScanData = null;
let mapView = "surface";
let mapScale = 1;
let mapPanX = 0;
let mapPanY = 0;
let mapDragging = false;
let mapPointer = null;
let mapReturnFocus = null;

if (brandVersion) {
  brandVersion.textContent = "v" + chrome.runtime.getManifest().version;
}
if (aboutVersion) aboutVersion.textContent = "v" + chrome.runtime.getManifest().version;

function escapeHtml(value) {
  return String(value === undefined || value === null ? "" : value)
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;");
}

function setProgress(message) {
  if (!message) {
    progressEl.style.display = "none";
    progressEl.textContent = "";
    return;
  }
  progressEl.style.display = "block";
  progressEl.textContent = message;
}

function setStatus(message) {
  statusBar.textContent = String(message || "").replace(/^\/\/\s*/, "");
}

function showTarget(url, favIconUrl) {
  try {
    const parsed = new URL(url);
    targetHost.textContent = parsed.hostname + (parsed.pathname !== "/" ? parsed.pathname.slice(0, 60) : "");
    if (favIconUrl) {
      targetFav.src = favIconUrl;
      targetFav.style.display = "block";
    } else {
      targetFav.removeAttribute("src");
      targetFav.style.display = "none";
    }
  } catch (e) {
    targetHost.textContent = url || "No tab selected";
  }
}

function comparableUrl(value) {
  return VulnscanUrls.comparable(value);
}

function targetUrl(value) {
  return VulnscanUrls.target(value);
}

function redactUrl(value) {
  const redacted = VulnscanUrls.redact(value);
  return redacted === "[invalid URL]" ? "" : redacted;
}

function urlFingerprint(value) {
  return VulnscanFindings.key(targetUrl(value));
}

function exactUrlFingerprint(value) {
  return VulnscanFindings.key(comparableUrl(value));
}

function storageGet(key) {
  return new Promise(function (resolve) {
    chrome.storage.local.get(key, function (data) {
      resolve(data[key] || null);
    });
  });
}

function requestSitePermission(origins) {
  return new Promise(function (resolve, reject) {
    let finished = false;
    const complete = function (value) {
      if (finished) return;
      finished = true;
      if (chrome.runtime.lastError) reject(new Error(chrome.runtime.lastError.message));
      else resolve(!!value);
    };
    try {
      const pending = chrome.permissions.request({ origins: origins }, complete);
      if (pending && typeof pending.then === "function") pending.then(complete, reject);
    } catch (error) {
      reject(error);
    }
  });
}

function executeScript(options) {
  return new Promise(function (resolve, reject) {
    let finished = false;
    const complete = function (result) {
      if (finished) return;
      finished = true;
      if (chrome.runtime.lastError) reject(new Error(chrome.runtime.lastError.message));
      else resolve(result || []);
    };
    try {
      const pending = chrome.scripting.executeScript(options, complete);
      if (pending && typeof pending.then === "function") pending.then(complete, reject);
    } catch (error) {
      reject(error);
    }
  });
}

const triageOptions = ["open", "investigating", "accepted", "false-positive", "resolved"];

function triageKey(finding) {
  if (!finding || !lastScanData) return "";
  return lastScanData.urlFingerprint + ":" + finding.identityFingerprint;
}

function triageStateFor(finding) {
  const key = triageKey(finding);
  let saved = triageStates[key];
  if (!saved && lastScanData) {
    const legacyKey = (lastScanData.legacyUrlFingerprint || lastScanData.urlFingerprint) + ":" + finding.fingerprint;
    saved = triageStates[legacyKey];
    if (saved) triageStates[key] = saved;
  }
  return saved && triageOptions.includes(saved.status) ? saved.status : "open";
}

function triageLabel(value) {
  const labels = {
    open: "Open",
    investigating: "Investigating",
    accepted: "Accepted risk",
    "false-positive": "False positive",
    resolved: "Resolved"
  };
  return labels[value] || labels.open;
}

function saveTriageState(finding, status) {
  const key = triageKey(finding);
  if (!key || !triageOptions.includes(status)) return;
  triageStates[key] = { status: status, updatedAt: Date.now() };
  const recent = Object.keys(triageStates).sort(function (left, right) {
    return triageStates[right].updatedAt - triageStates[left].updatedAt;
  }).slice(0, 500);
  const stored = {};
  recent.forEach(function (item) { stored[item] = triageStates[item]; });
  triageStates = stored;
  chrome.storage.local.set({ findingTriage: triageStates });
}

function findingByFingerprint(fingerprint) {
  return currentFindings.find(function (finding) {
    return finding.fingerprint === fingerprint;
  }) || null;
}

function investigationBrief(finding) {
  const guidance = VulnscanGuidance.get(finding);
  const priority = VulnscanGuidance.priority(finding);
  const education = guidance.exploitability;
  let text = finding.type + "\n";
  text += "Target: " + (lastScanData ? lastScanData.url : "") + "\n";
  text += "Severity: " + finding.severity + " | Confidence: " + finding.confidence + " | Priority: " + priority.label + " (" + priority.score + ")\n";
  text += "Workflow: " + triageLabel(triageStateFor(finding)) + "\n";
  text += "Stage: " + sourceLabel(finding.source) + " | Category: " + categoryLabel(finding.category) + "\n\n";
  text += "Observation\n" + finding.detail + "\n\n";
  text += "Evidence\n" + (finding.evidence || "No additional evidence recorded.") + "\n\n";
  text += "Why it matters\n" + guidance.impact + "\n\n";
  text += "Exploitability\n" + guidance.exploitability.plainLanguage + "\n";
  text += "What was observed: " + guidance.exploitability.observed + "\n";
  text += "Required conditions: " + guidance.exploitability.prerequisites.join("; ") + "\n";
  text += "Evidence that would weaken it: " + guidance.exploitability.weakens.join("; ") + "\n\n";
  text += "Recommended action\n" + guidance.remediation + "\n\n";
  text += "Verification\n" + (finding.verification || guidance.steps[0]) + "\n\n";
  if (finding.location) text += "Affected location: " + finding.location + "\n";
  text += "Check ID: " + finding.checkId + "\nFingerprint: " + finding.fingerprint + "\nIdentity: " + finding.identityFingerprint + "\n";
  return text;
}

function closeFindingDrawer() {
  if (!findingDrawer) return;
  findingDrawer.hidden = true;
  activeFindingFingerprint = null;
  if (drawerReturnFocus && typeof drawerReturnFocus.focus === "function") drawerReturnFocus.focus();
  drawerReturnFocus = null;
}

function openFindingDrawer(fingerprint) {
  const finding = findingByFingerprint(fingerprint);
  if (!finding || !findingDrawer || !findingDrawerBody) return;
  const guidance = VulnscanGuidance.get(finding);
  const priority = VulnscanGuidance.priority(finding);
  const education = guidance.exploitability;
  const change = currentComparisonStatuses.get(finding.fingerprint);
  const workflow = triageStateFor(finding);
  const steps = [finding.verification].concat(guidance.steps).filter(Boolean).filter(function (step, index, list) {
    return list.indexOf(step) === index;
  });
  const list = function (items) {
    return "<ol>" + items.map(function (item) { return "<li>" + escapeHtml(item) + "</li>"; }).join("") + "</ol>";
  };
  const lab = education.lab ? '<details class="learning-details"><summary>Safe lab walkthrough</summary><div class="learning-content"><h4>' +
    escapeHtml(education.lab.title) + '</h4><pre><code>' + escapeHtml(education.lab.template) + '</code></pre><button class="btn-mini copy-lab-template" type="button">Copy template</button>' +
    '<div class="learning-outcomes"><p><strong>Secure result</strong>' + escapeHtml(education.lab.safeResult) + '</p><p><strong>Needs review</strong>' + escapeHtml(education.lab.riskyResult) +
    '</p></div><p class="learning-safety">' + escapeHtml(education.lab.safety) + "</p></div></details>" : "";
  const terms = education.terms.length ? '<details class="learning-details"><summary>Terms used</summary><div class="learning-content glossary-list">' + education.terms.map(function (term) {
    return "<p><strong>" + escapeHtml(term.term) + "</strong>" + escapeHtml(term.definition) + "</p>";
  }).join("") + "</div></details>" : "";
  activeFindingFingerprint = finding.fingerprint;
  drawerReturnFocus = document.activeElement || null;
  findingDrawerTitle.textContent = finding.type;
  findingTriageState.value = workflow;
  findingDrawerBody.innerHTML = '<div class="drawer-summary">' +
    '<span class="severity ' + escapeHtml(finding.severity) + '">' + escapeHtml(finding.severity) + "</span>" +
    '<span class="confidence ' + escapeHtml(finding.confidence) + '">' + escapeHtml(finding.confidence) + " confidence</span>" +
    '<span class="triage-badge ' + escapeHtml(workflow) + '">' + escapeHtml(triageLabel(workflow)) + "</span>" +
    (change ? '<span class="change-badge ' + escapeHtml(change) + '">' + escapeHtml(change) + "</span>" : "") +
    "</div>" +
    '<div class="priority-meter"><span>' + escapeHtml(priority.label) + '</span><div class="priority-track"><div class="priority-fill" style="width:' + priority.score + '%"></div></div><strong>' + priority.score + "</strong></div>" +
    '<section class="drawer-section"><h3>Observation</h3><p>' + escapeHtml(finding.detail || "No additional detail recorded.") + "</p></section>" +
    '<section class="drawer-section"><h3>Evidence</h3><p>' + escapeHtml(finding.evidence || "No additional evidence recorded.") + "</p></section>" +
    '<section class="drawer-section"><h3>Why it matters</h3><p>' + escapeHtml(guidance.impact) + "</p></section>" +
    '<section class="drawer-section exploitability-section"><div class="exploitability-head"><h3>Exploitability</h3><span class="exploitability-badge ' + escapeHtml(education.level) + '">' + escapeHtml(education.level) + '</span></div><p class="exploitability-lead">' + escapeHtml(education.plainLanguage) + '</p>' +
    '<div class="observed-box"><strong>What Vulnscan observed</strong><span>' + escapeHtml(education.observed) + '</span></div>' +
    '<details class="learning-details"><summary>How exploitation could happen</summary><div class="learning-content"><h4>Required conditions</h4>' + list(education.prerequisites) + '<h4>Likely path</h4>' + list(education.attackPath) + '<h4>Possible impact</h4>' + list(education.possibleImpact) + '</div></details>' +
    '<details class="learning-details"><summary>What would weaken or disprove it</summary><div class="learning-content">' + list(education.weakens) + '</div></details>' + lab + terms + '</section>' +
    '<section class="drawer-section"><h3>Recommended action</h3><p>' + escapeHtml(guidance.remediation) + "</p></section>" +
    '<section class="drawer-section"><h3>Investigation steps</h3><ol>' + steps.map(function (step) {
      return "<li>" + escapeHtml(step) + "</li>";
    }).join("") + "</ol></section>" +
    '<section class="drawer-section"><h3>Technical details</h3><dl class="technical-grid">' +
    "<dt>Target</dt><dd>" + escapeHtml(lastScanData ? lastScanData.url : "") + "</dd>" +
    "<dt>Check ID</dt><dd>" + escapeHtml(finding.checkId) + "</dd>" +
    "<dt>Fingerprint</dt><dd>" + escapeHtml(finding.fingerprint) + "</dd>" +
    "<dt>Stable identity</dt><dd>" + escapeHtml(finding.identityFingerprint) + "</dd>" +
    "<dt>Affected location</dt><dd>" + escapeHtml(finding.location || "Not recorded") + "</dd>" +
    "<dt>Category</dt><dd>" + escapeHtml(finding.category) + "</dd>" +
    "<dt>Stage</dt><dd>" + escapeHtml(sourceLabel(finding.source)) + "</dd>" +
    "<dt>Occurrences</dt><dd>" + finding.occurrences + "</dd></dl></section>";
  const copyLab = findingDrawerBody.querySelector(".copy-lab-template");
  if (copyLab && education.lab) {
    copyLab.addEventListener("click", function () {
      navigator.clipboard.writeText(education.lab.template).then(function () {
        copyLab.textContent = "Copied";
        setTimeout(function () { copyLab.textContent = "Copy template"; }, 1200);
      });
    });
  }
  if (showAffectedBtn) showAffectedBtn.hidden = !finding.selector;
  findingDrawer.hidden = false;
  if (findingDrawerClose && typeof findingDrawerClose.focus === "function") findingDrawerClose.focus();
}

async function showAffectedOnPage(finding) {
  if (!finding || !finding.selector || !lastScanData) return;
  const tab = await getSelectedTab();
  if (!tab || urlFingerprint(tab.url) !== lastScanData.urlFingerprint) {
    setStatus("// select the scanned page before locating this result");
    return;
  }
  const response = await executeScript({
    target: { tabId: tab.id },
    func: function (selector) {
      let element;
      try { element = document.querySelector(selector); } catch (e) { return false; }
      if (!element) return false;
      const previousOutline = element.style.outline;
      const previousOffset = element.style.outlineOffset;
      element.scrollIntoView({ behavior: "smooth", block: "center" });
      element.style.outline = "3px solid #ffb454";
      element.style.outlineOffset = "3px";
      setTimeout(function () {
        element.style.outline = previousOutline;
        element.style.outlineOffset = previousOffset;
      }, 4000);
      return true;
    },
    args: [finding.selector]
  });
  const located = response && response[0] && response[0].result === true;
  setStatus(located ? "// affected element highlighted in the target tab" : "// affected element is no longer present on the page");
}

function closeScanMap() {
  if (!scanMapDialog) return;
  scanMapDialog.hidden = true;
  mapScanData = null;
  mapDragging = false;
  mapPointer = null;
  if (mapReturnFocus && typeof mapReturnFocus.focus === "function") mapReturnFocus.focus();
  mapReturnFocus = null;
}

function applyMapTransform() {
  if (!scanMapSvg) return;
  const layer = scanMapSvg.querySelector(".scan-map-layer");
  if (layer) layer.setAttribute("transform", "translate(" + mapPanX + " " + mapPanY + ") scale(" + mapScale + ")");
}

function resetMapTransform() {
  mapScale = 1;
  mapPanX = 0;
  mapPanY = 0;
  applyMapTransform();
}

function mapCoverage(node) {
  if (!mapScanData || node.kind !== "check") return null;
  return (mapScanData.coverage || []).find(function (entry) { return entry.checkId === node.checkId; }) || null;
}

function renderMapDetails(node) {
  if (!scanMapDetails || !node) return;
  if (node.kind === "finding") {
    const finding = node.data;
    const guidance = VulnscanGuidance.get(finding);
    const current = lastScanData && mapScanData && lastScanData.scanId === mapScanData.scanId;
    scanMapDetails.innerHTML = '<div class="map-detail-eyebrow">' + escapeHtml(finding.bucket) + " · " + escapeHtml(finding.severity) + '</div><h3>' + escapeHtml(finding.type) + '</h3>' +
      '<p>' + escapeHtml(finding.detail) + '</p><dl><dt>Evidence</dt><dd>' + escapeHtml(finding.evidence || "No additional evidence recorded.") + '</dd><dt>Exploitability</dt><dd>' + escapeHtml(guidance.exploitability.plainLanguage) + '</dd><dt>Affected location</dt><dd>' + escapeHtml(finding.location || "Not recorded") + '</dd><dt>Stage</dt><dd>' + escapeHtml(sourceLabel(finding.source)) + '</dd></dl>' +
      (current ? '<button class="btn primary map-investigate" data-fingerprint="' + escapeHtml(finding.fingerprint) + '">Open investigation</button>' : '<p class="map-readonly">Historical map — investigation details are read-only.</p>');
    const investigate = scanMapDetails.querySelector(".map-investigate");
    if (investigate) investigate.addEventListener("click", function () {
      const fingerprint = investigate.getAttribute("data-fingerprint");
      closeScanMap();
      openFindingDrawer(fingerprint);
    });
    return;
  }
  const coverage = mapCoverage(node);
  const detail = node.detail || node.kind;
  scanMapDetails.innerHTML = '<div class="map-detail-eyebrow">' + escapeHtml(categoryLabel(node.kind)) + '</div><h3>' + escapeHtml(node.label) + '</h3><p>' + escapeHtml(detail) + '</p><dl>' +
    (node.location ? '<dt>Location</dt><dd>' + escapeHtml(node.location) + '</dd>' : "") +
    (node.occurrences ? '<dt>Occurrences</dt><dd>' + Number(node.occurrences) + '</dd>' : "") +
    (node.status ? '<dt>Status</dt><dd>' + escapeHtml(node.status) + '</dd>' : "") +
    (coverage ? '<dt>Coverage</dt><dd>' + escapeHtml(coverage.status) + ' · ' + coverage.inspected + ' inspected · ' + coverage.matched + ' matched</dd>' : "") +
    '</dl>';
}

function renderScanMap() {
  if (!mapScanData || !scanMapSvg) return;
  const graph = VulnscanMap.build(mapScanData, mapView, {
    query: scanMapSearch ? scanMapSearch.value : "",
    kind: scanMapKind ? scanMapKind.value : "all",
    bucket: scanMapBucket ? scanMapBucket.value : "all",
    severity: scanMapSeverity ? scanMapSeverity.value : "all"
  });
  VulnscanMap.render(scanMapSvg, graph, renderMapDetails);
  resetMapTransform();
  if (scanMapDetails) scanMapDetails.innerHTML = '<div class="empty-hint">Select a map node to inspect it.</div>';
  if (scanMapStatus) {
    const notice = mapView === "surface" && !graph.available ? " · no structured surface data" : graph.truncated ? " · collection limit reached" : graph.overflow ? " · " + graph.overflow + " nodes summarized" : "";
    scanMapStatus.textContent = graph.nodes.length + " nodes · " + graph.edges.length + " relationships" + notice;
  }
  if (scanMapKind) scanMapKind.disabled = mapView !== "surface";
}

function openScanMap(scan, returnFocus) {
  const normalized = normalizeScan(scan);
  if (!normalized || !scanMapDialog) return;
  mapScanData = normalized;
  mapReturnFocus = returnFocus || document.activeElement || null;
  mapView = normalized.surface.nodes.some(function (node) { return node.kind !== "target"; }) ? "surface" : "flow";
  document.querySelectorAll(".scan-map-view").forEach(function (button) {
    button.classList.toggle("active", button.getAttribute("data-map-view") === mapView);
  });
  if (scanMapSubtitle) scanMapSubtitle.textContent = normalized.url + " · " + sourceLabel(normalized.scanMode) + " · " + new Date(normalized.timestamp).toLocaleString();
  if (scanMapSearch) scanMapSearch.value = "";
  if (scanMapKind) scanMapKind.value = "all";
  if (scanMapBucket) scanMapBucket.value = "all";
  if (scanMapSeverity) scanMapSeverity.value = "all";
  scanMapDialog.hidden = false;
  renderScanMap();
  if (scanMapClose) scanMapClose.focus();
}

function requestMode() {
  return ["passive", "safe", "lab", "full"].includes(scanModeEl.value) ? scanModeEl.value : "passive";
}

function requestBudget() {
  const value = VulnscanRequests.clampBudget(requestBudgetEl.value);
  requestBudgetEl.value = String(value);
  return value;
}

function selectedChecks() {
  const toggles = Array.from(document.querySelectorAll(".check-toggle"));
  if (!toggles.length) return VulnscanChecks.all();
  return VulnscanChecks.normalize(toggles.filter(function (input) {
    return input.checked;
  }).map(function (input) { return input.value; }));
}

function checksForMode(mode) {
  return VulnscanChecks.effective(selectedChecks(), mode || requestMode());
}

function updateCheckPicker() {
  const mode = requestMode();
  const selected = selectedChecks();
  const effective = VulnscanChecks.effective(selected, mode);
  if (checkPickerSummary) {
    checkPickerSummary.textContent = effective.length + " check" + (effective.length === 1 ? "" : "s") + " selected";
  }
}

function applySavedChecks(saved) {
  const enabled = new Set(VulnscanChecks.normalize(saved));
  document.querySelectorAll(".check-toggle").forEach(function (input) {
    input.checked = enabled.has(input.value);
  });
  updateCheckPicker();
}

function estimateRequests(mode, checks) {
  return VulnscanChecks.requestEstimate(checks || selectedChecks(), mode);
}

function normalizeRequestSummary(summary, mode) {
  const source = summary && typeof summary === "object" ? summary : {};
  return {
    mode: ["passive", "safe", "lab", "full", "legacy"].includes(source.mode) ? source.mode : mode,
    budget: Math.max(0, Math.min(50, Number(source.budget) || 0)),
    attempted: Math.max(0, Number(source.attempted) || 0),
    completed: Math.max(0, Number(source.completed) || 0),
    stoppedReason: source.stoppedReason ? String(source.stoppedReason).slice(0, 100) : null
  };
}

function updateModeHelp() {
  const copy = {
    passive: "No scanner-generated requests.",
    safe: "Same-origin GET, HEAD, and OPTIONS checks.",
    lab: "Soft-404-aware common-path discovery only.",
    full: "Passive, Safe Active, and Lab run in order with one shared budget."
  };
  const labels = { passive: "Passive", safe: "Safe Active", lab: "Lab", full: "Full Scan" };
  const mode = requestMode();
  modeHelp.textContent = copy[mode];
  if (scanModeSummary) scanModeSummary.textContent = labels[mode];
  updateCheckPicker();
}

function blankStageSummary(mode, checks) {
  const selected = checks || VulnscanChecks.effective(selectedChecks(), mode);
  return {
    passive: VulnscanChecks.stageEnabled(selected, mode, "passive") ? "pending" : "skipped",
    headers: VulnscanChecks.stageEnabled(selected, mode, "headers") ? "pending" : "skipped",
    safe: VulnscanChecks.stageEnabled(selected, mode, "safe") ? "pending" : "skipped",
    lab: VulnscanChecks.stageEnabled(selected, mode, "lab") ? "pending" : "skipped"
  };
}

function normalizeStageSummary(summary, mode, checks) {
  const allowed = ["pending", "running", "complete", "skipped", "stopped", "unavailable"];
  const source = summary && typeof summary === "object" ? summary : blankStageSummary(mode, checks);
  const fallback = blankStageSummary(mode, checks);
  const output = {};
  ["passive", "headers", "safe", "lab"].forEach(function (stage) {
    output[stage] = allowed.includes(source[stage]) ? source[stage] : fallback[stage];
  });
  return output;
}

function renderStages(summary, visible) {
  if (!stageProgressEl) return;
  stageProgressEl.hidden = visible === false;
  const stages = summary || blankStageSummary(requestMode());
  stageProgressEl.querySelectorAll(".scan-stage").forEach(function (item) {
    const state = stages[item.getAttribute("data-stage")] || "pending";
    item.className = "scan-stage " + state;
  });
}

function renderRequestLog(entries, summary) {
  const rows = entries || [];
  if (!rows.length) {
    requestLogEl.innerHTML = '<div class="empty-hint">No scanner-generated requests</div>';
  } else {
    requestLogEl.innerHTML = rows.map(function (entry) {
      const duration = Number(entry.durationMs !== undefined ? entry.durationMs : entry.duration) || 0;
      const outcome = entry.outcome || (entry.status ? "complete" : "unknown");
      const status = entry.status ? String(entry.status) + " " + outcome : outcome;
      return '<div class="request-row"><span class="request-method">' + escapeHtml(entry.method) +
        '</span><span class="request-url">' + escapeHtml(entry.url) +
        '</span><span class="request-status ' + escapeHtml(outcome) + '">' + escapeHtml(status) +
        '</span><span class="request-duration">' + duration + " ms</span></div>";
    }).join("");
  }
  if (!summary || summary.mode === "passive") {
    requestSummaryEl.textContent = "Passive mode — no requests";
    return;
  }
  requestSummaryEl.textContent = summary.attempted + "/" + summary.budget + " requests" +
    (summary.stoppedReason ? " — stopped: " + summary.stoppedReason : "");
}

function confirmActiveScan(origin, mode, budget, checks) {
  const names = { safe: "Safe Active", lab: "Lab", full: "Full Scan" };
  const stageCopy = mode === "full" ? " Passive inspection runs once, followed by Safe Active and Lab stages." : "";
  authorizationDetails.textContent = names[mode] + " mode will send up to " +
    Math.min(budget, estimateRequests(mode, checks)) + " same-origin requests to " + origin + "." + stageCopy +
    " Allowed methods: GET, HEAD, and OPTIONS.";
  authorizationCheck.checked = false;
  authorizationStart.disabled = true;
  authorizationModal.hidden = false;
  return new Promise(function (resolve) { authorizationResolve = resolve; });
}

function finishAuthorization(approved) {
  authorizationModal.hidden = true;
  const resolve = authorizationResolve;
  authorizationResolve = null;
  if (resolve) resolve(approved);
}

function normalizeScan(scan) {
  if (!scan || ![2, 3, 4, 5, 6, 7, 8].includes(scan.schemaVersion) || !scan.url) return null;
  const findings = VulnscanFindings.dedupe(scan.findings || []);
  const mode = ["passive", "safe", "lab", "full"].includes(scan.scanMode) ? scan.scanMode : "legacy";
  const checks = VulnscanChecks.effective(scan.checksRun, mode);
  return {
    schemaVersion: 8,
    scanId: scan.scanId || null,
    scanMode: mode,
    url: scan.url,
    urlFingerprint: urlFingerprint(scan.url),
    legacyUrlFingerprint: scan.legacyUrlFingerprint || scan.urlFingerprint || null,
    vaultFingerprint: scan.schemaVersion >= 7 ? scan.vaultFingerprint || null : null,
    timestamp: scan.timestamp || Date.now(),
    findings: findings,
    summary: VulnscanFindings.summarize(findings),
    risk: VulnscanFindings.risk(findings),
    requestSummary: normalizeRequestSummary(scan.requestSummary, mode),
    stageSummary: normalizeStageSummary(scan.stageSummary, mode, checks),
    checksRun: checks,
    scanLimits: {
      sourceTruncated: !!(scan.scanLimits && scan.scanLimits.sourceTruncated),
      domTruncated: !!(scan.scanLimits && scan.scanLimits.domTruncated),
      findingsTruncated: !!(scan.scanLimits && scan.scanLimits.findingsTruncated),
      secretsTruncated: !!(scan.scanLimits && scan.scanLimits.secretsTruncated),
      surfaceTruncated: !!(scan.scanLimits && scan.scanLimits.surfaceTruncated)
    },
    surface: VulnscanFindings.normalizeSurface(scan.surface),
    coverage: VulnscanFindings.normalizeCoverage(scan.coverage)
  };
}

function clearResults() {
  closeScanMap();
  lastScanData = null;
  currentFindings = [];
  chrome.runtime.sendMessage({ type: "clear_export_secrets" }, function () {});
  chrome.runtime.sendMessage({ type: "clear_request_log" }, function () {});
  chrome.storage.local.remove("lastScan");
  resultsEl.innerHTML = '<div class="empty-hint">No findings yet</div>';
  headerResults.innerHTML = '<div class="empty-hint">Run a scan to analyze headers</div>';
  scoreEl.textContent = "—";
  scoreEl.className = "stat-value score";
  findingsCountEl.textContent = "0";
  reviewCountEl.textContent = "0";
  if (resultOverviewEl) {
    resultOverviewEl.hidden = true;
    resultOverviewEl.innerHTML = "";
  }
  if (comparisonPanelEl) {
    comparisonPanelEl.hidden = true;
    comparisonPanelEl.innerHTML = "";
  }
  currentComparisonStatuses = new Map();
  currentChange = "all";
  currentTriage = "all";
  if (changeFilterEl) changeFilterEl.value = "all";
  if (triageFilterEl) triageFilterEl.value = "all";
  closeFindingDrawer();
  renderStages(null, false);
  renderRequestLog([], null);
  ["sumHigh", "sumMed", "sumLow", "sumInfo"].forEach(function (id) {
    document.getElementById(id).textContent = "0";
  });
  setProgress(null);
  setStatus("// results cleared — open a site tab and hit Scan");
}

function headerFinding(checkId, severity, type, detail, confidence, evidence, verification, location, category) {
  return VulnscanFindings.normalize({
    checkId: checkId,
    severity: severity,
    confidence: confidence,
    bucket: "review",
    category: category || "headers",
    type: type,
    detail: detail,
    evidence: evidence,
    verification: verification,
    location: location || checkId,
    source: "headers"
  });
}

function parseCsp(value) {
  const directives = new Map();
  String(value || "").split(";").forEach(function (part) {
    const tokens = part.trim().split(/\s+/).filter(Boolean);
    if (!tokens.length) return;
    directives.set(tokens.shift().toLowerCase(), tokens.map(function (token) { return token.toLowerCase(); }));
  });
  return directives;
}

function cspAllows(policies, token, elementDirective) {
  if (!policies.length) return false;
  return policies.every(function (policy) {
    const sources = elementDirective && policy.get("script-src-elem") || policy.get("script-src") || policy.get("default-src");
    return !sources || sources.includes(token);
  });
}

function referrerPolicyStatus(value) {
  const supported = new Set([
    "no-referrer", "no-referrer-when-downgrade", "origin", "origin-when-cross-origin",
    "same-origin", "strict-origin", "strict-origin-when-cross-origin", "unsafe-url"
  ]);
  const tokens = String(value || "").split(",").map(function (token) { return token.trim().toLowerCase(); }).filter(Boolean);
  const selected = tokens.slice().reverse().find(function (token) { return supported.has(token); }) || "";
  if (!selected) return { state: "weak", note: "Invalid" };
  if (selected === "unsafe-url" || selected === "no-referrer-when-downgrade") return { state: "weak", note: selected };
  return { state: "ok", note: selected };
}

function parseSetCookie(value) {
  const parts = String(value || "").split(";");
  const pair = parts.shift() || "";
  let name = pair.slice(0, pair.indexOf("=") < 0 ? pair.length : pair.indexOf("=")).trim();
  if (!name || name.length > 80 || !/^[A-Za-z0-9!#$%&'*+.^_`|~-]+$/.test(name)) name = "[cookie name hidden]";
  if (/[A-Za-z0-9_-]{40,}/.test(name)) name = "[long cookie name hidden]";
  const attributes = new Map();
  parts.forEach(function (part) {
    const separator = part.indexOf("=");
    const key = (separator < 0 ? part : part.slice(0, separator)).trim().toLowerCase();
    const attributeValue = separator < 0 ? "" : part.slice(separator + 1).trim();
    if (key) attributes.set(key, attributeValue);
  });
  return { name: name, attributes: attributes };
}

function analyzeHeaders(headerList, pageUrl, enabledChecks) {
  const values = {};
  (headerList || []).slice(0, 200).forEach(function (header) {
    const name = String(header.name || "").toLowerCase().slice(0, 120);
    if (!values[name]) values[name] = [];
    values[name].push(String(header.value || "").slice(0, VulnscanFindings.limits.messageTextCharacters));
  });
  const first = function (name) {
    return values[name] && values[name][0] ? values[name][0] : "";
  };
  const review = [];
  const rows = [];
  const selected = VulnscanChecks.normalize(enabledChecks);
  const securityEnabled = VulnscanChecks.enabled(selected, "headers.security");
  const cookiesEnabled = VulnscanChecks.enabled(selected, "headers.cookies");
  const boundariesEnabled = VulnscanChecks.enabled(selected, "headers.boundaries");

  if (securityEnabled) {
    const cspValues = values["content-security-policy"] || [];
    const reportOnlyValues = values["content-security-policy-report-only"] || [];
    const policies = cspValues.map(parseCsp);
    if (!policies.length) {
      rows.push(["Content-Security-Policy", "missing", "Missing"]);
      review.push(headerFinding(
        "header.csp.missing", "low", "Content Security Policy missing", "No Content-Security-Policy response header was captured.", "low",
        reportOnlyValues.length ? "A report-only policy was captured, but it does not enforce restrictions." : "The final main-frame response did not include an enforced CSP header.",
        "Confirm whether CSP is delivered by another response path and decide which script, style, frame, and connection sources the application should allow.",
        "Content-Security-Policy"
      ));
    } else {
      const unsafe = [];
      if (cspAllows(policies, "'unsafe-inline'", true)) unsafe.push("unsafe-inline");
      if (cspAllows(policies, "'unsafe-eval'", false)) unsafe.push("unsafe-eval");
      rows.push(["Content-Security-Policy", unsafe.length ? "weak" : "ok", policies.length + " enforced" + (unsafe.length ? " · " + unsafe.join(", ") : "")]);
      if (unsafe.length) {
      review.push(headerFinding(
          "header.csp.unsafe", "medium", "Content Security Policy allows unsafe script behavior", "Every enforced CSP policy permits " + unsafe.join(" and ") + " for scripts.", "medium",
          policies.length + " enforced policy value" + (policies.length === 1 ? " was" : "s were") + " evaluated together.",
          "Confirm which directive permits the behavior and test whether nonces, hashes, or bundled scripts can replace it.",
          "Content-Security-Policy"
      ));
      }
    }
    if (reportOnlyValues.length) {
      rows.push(["CSP Report-Only", "ok", reportOnlyValues.length + " policy value" + (reportOnlyValues.length === 1 ? "" : "s")]);
    }

    const hsts = first("strict-transport-security");
    const isHttps = String(pageUrl || "").startsWith("https://");
    if (!isHttps) {
      rows.push(["Strict-Transport-Security", "ok", "Not applicable"]);
    } else if (!hsts) {
      rows.push(["Strict-Transport-Security", "missing", "Missing"]);
      review.push(headerFinding(
        "header.hsts.missing", "low", "HSTS missing", "The HTTPS response has no Strict-Transport-Security header.", "high",
        "No Strict-Transport-Security header was captured on the final HTTPS response.",
        "Check the first HTTPS response and confirm whether the domain should enforce HTTPS for future visits."
      ));
    } else if (!/\bmax-age\s*=\s*[1-9][0-9]*\b/i.test(hsts)) {
      rows.push(["Strict-Transport-Security", "weak", "Disabled or invalid max-age"]);
      review.push(headerFinding(
        "header.hsts.disabled", "low", "HSTS is not active", "Strict-Transport-Security does not contain a positive max-age.", "high",
        "The captured HSTS value is missing a positive max-age or explicitly sets max-age=0.",
        "Set an appropriate positive max-age after confirming that the whole host is ready for HTTPS-only access.",
        "Strict-Transport-Security"
      ));
    } else {
      rows.push(["Strict-Transport-Security", "ok", "Present"]);
    }

    const xfo = first("x-frame-options");
    const normalizedXfo = xfo.trim().toUpperCase();
    const validXfo = normalizedXfo === "DENY" || normalizedXfo === "SAMEORIGIN";
    const frameAncestors = policies.some(function (policy) {
      const sources = policy.get("frame-ancestors");
      return sources && sources.length && !sources.includes("*");
    });
    if (xfo && !validXfo) {
      review.push(headerFinding(
        "header.framing.invalid", "medium", "Framing header needs review", "X-Frame-Options is present but does not use DENY or SAMEORIGIN.", "medium",
        "The captured X-Frame-Options value is not a widely supported protection.",
        "Use CSP frame-ancestors or a valid X-Frame-Options value and confirm the page cannot be framed by an untrusted origin.",
        "X-Frame-Options"
      ));
    }
    if (validXfo || frameAncestors) {
      rows.push(["Framing protection", "ok", frameAncestors ? "CSP frame-ancestors" : normalizedXfo]);
    } else if (xfo) {
      rows.push(["Framing protection", "weak", "Invalid X-Frame-Options"]);
    } else {
      rows.push(["Framing protection", "missing", "Missing"]);
      review.push(headerFinding(
        "header.framing.missing", "medium", "Framing protection missing", "Neither X-Frame-Options nor CSP frame-ancestors was captured.", "low",
        "The final response lacks both recognized framing controls.",
        "Attempt to frame the page from a controlled origin and confirm whether sensitive actions can be clickjacked."
      ));
    }

    const contentTypeOptions = first("x-content-type-options");
    if (contentTypeOptions.toLowerCase() === "nosniff") {
      rows.push(["X-Content-Type-Options", "ok", "nosniff"]);
    } else {
      rows.push(["X-Content-Type-Options", contentTypeOptions ? "weak" : "missing", contentTypeOptions ? "Unexpected value" : "Missing"]);
      review.push(headerFinding(
        "header.content-type-options", "low", "MIME sniffing protection missing", "X-Content-Type-Options is not set to nosniff.", "medium",
        contentTypeOptions ? "A non-nosniff value was captured." : "No X-Content-Type-Options header was captured.",
        "Confirm the final response and static assets use correct Content-Type headers before enabling nosniff."
      ));
    }

    const referrer = first("referrer-policy");
    if (!referrer) {
      rows.push(["Referrer-Policy", "missing", "Missing"]);
      review.push(headerFinding(
        "header.referrer-policy", "info", "Referrer-Policy missing", "No Referrer-Policy header was captured.", "low",
        "The final main-frame response did not include this header.",
        "Review whether cross-origin requests should receive the full referring URL.",
        "Referrer-Policy"
      ));
    } else {
      const referrerStatus = referrerPolicyStatus(referrer);
      rows.push(["Referrer-Policy", referrerStatus.state, referrerStatus.note]);
      if (referrerStatus.state === "weak") {
        review.push(headerFinding(
          "header.referrer-policy.weak", "info", "Referrer policy needs review", "The effective Referrer-Policy is invalid or may disclose more URL data than intended.", "medium",
          "Effective policy: " + referrerStatus.note + ".",
          "Choose a supported policy that matches the application's cross-origin referrer requirements.",
          "Referrer-Policy"
        ));
      }
    }

    const permissionsPolicy = first("permissions-policy");
    rows.push(["Permissions-Policy", permissionsPolicy ? "ok" : "missing", permissionsPolicy ? "Present" : "Missing"]);
    if (!permissionsPolicy) {
      review.push(headerFinding(
        "header.permissions-policy", "info", "Permissions-Policy missing", "No Permissions-Policy header was captured.", "low",
        "The final main-frame response did not include this header.",
        "Review which browser features the page and its frames need to use.",
        "Permissions-Policy"
      ));
    }
  }

  if (boundariesEnabled) {
    const allowOrigins = values["access-control-allow-origin"] || [];
    const allowCredentials = first("access-control-allow-credentials").trim().toLowerCase();
    const originValue = allowOrigins.length === 1 ? allowOrigins[0].trim() : "";
    if (!allowOrigins.length) {
      rows.push(["CORS policy", "neutral", "Not advertised"]);
    } else if (allowOrigins.length > 1 || originValue.includes(",")) {
      rows.push(["CORS policy", "weak", "Multiple origins"]);
      review.push(headerFinding(
        "header.cors.multiple-origins", "low", "CORS origin policy is invalid", "The response contains multiple Access-Control-Allow-Origin values.", "high",
        "Browsers require a single wildcard or serialized origin value.",
        "Confirm which layer adds each header and return one policy value for the requesting origin.",
        "Access-Control-Allow-Origin", "cross-origin"
      ));
    } else if (originValue === "null") {
      rows.push(["CORS policy", "weak", "Allows null origin"]);
      review.push(headerFinding(
        "header.cors.null-origin", allowCredentials === "true" ? "medium" : "low", "CORS allows the null origin", "Access-Control-Allow-Origin is set to null" + (allowCredentials === "true" ? " with credentials enabled." : "."), "high",
        "Sandboxed and non-hierarchical documents can have a serialized null origin.",
        "Use an explicit allowlist of trusted HTTPS origins and verify the policy on sensitive response paths.",
        "Access-Control-Allow-Origin", "cross-origin"
      ));
    } else if (originValue === "*") {
      rows.push(["CORS policy", allowCredentials === "true" ? "weak" : "ok", allowCredentials === "true" ? "Wildcard + credentials" : "Public without credentials"]);
      if (allowCredentials === "true") {
        review.push(headerFinding(
          "header.cors.wildcard-credentials", "low", "CORS credentials policy is contradictory", "The response combines a wildcard origin with Access-Control-Allow-Credentials: true.", "high",
          "Browsers reject credentialed reads with a wildcard origin, so this is not a confirmed data-exposure path.",
          "Use a specific trusted origin for credentialed access or remove the credentials header for intentionally public responses.",
          "Access-Control-Allow-Origin", "cross-origin"
        ));
      }
    } else {
      let validOrigin = false;
      try { validOrigin = new URL(originValue).origin === originValue; } catch (e) {}
      rows.push(["CORS policy", validOrigin ? "ok" : "weak", validOrigin ? "Restricted origin" : "Invalid origin"]);
      if (!validOrigin) {
        review.push(headerFinding(
          "header.cors.invalid-origin", "low", "CORS origin value is invalid", "Access-Control-Allow-Origin is neither a wildcard nor a valid serialized origin.", "high",
          "The browser is expected to ignore this policy value.",
          "Return exactly one valid trusted origin or omit the header.",
          "Access-Control-Allow-Origin", "cross-origin"
        ));
      }
    }

    const policyRows = [
      ["Cross-Origin-Opener-Policy", "cross-origin-opener-policy", new Set(["unsafe-none", "same-origin-allow-popups", "same-origin", "noopener-allow-popups"]), "header.coop.invalid"],
      ["Cross-Origin-Embedder-Policy", "cross-origin-embedder-policy", new Set(["unsafe-none", "require-corp", "credentialless"]), "header.coep.invalid"],
      ["Cross-Origin-Resource-Policy", "cross-origin-resource-policy", new Set(["same-origin", "same-site", "cross-origin"]), "header.corp.invalid"]
    ];
    policyRows.forEach(function (policy) {
      const value = first(policy[1]).split(";")[0].trim().toLowerCase();
      if (!value) {
        rows.push([policy[0], "neutral", "Not set"]);
        return;
      }
      const valid = policy[2].has(value);
      rows.push([policy[0], valid ? "ok" : "weak", valid ? value : "Invalid value"]);
      if (!valid) {
        review.push(headerFinding(
          policy[3], "info", policy[0] + " needs review", "The captured policy value is not recognized and may be ignored by the browser.", "high",
          "An unrecognized policy token was captured; its raw value was not retained in the finding.",
          "Choose a supported value that matches the application's isolation and embedding requirements.",
          policy[0], "cross-origin"
        ));
      }
    });
  }

  let html = rows.map(function (row) {
    return '<div class="header-item"><span class="name">' + escapeHtml(row[0]) +
      '</span><span class="status ' + row[1] + '">' + escapeHtml(row[2]) + '</span></div>';
  }).join("");

  const setCookies = values["set-cookie"] || [];
  if (cookiesEnabled && setCookies.length) {
    html += '<div class="header-section">// COOKIES</div>';
    setCookies.forEach(function (cookie) {
      const parsed = parseSetCookie(cookie);
      const name = parsed.name;
      const attributes = parsed.attributes;
      const missing = [];
      const issues = [];
      if (!attributes.has("secure")) missing.push("Secure");
      if (!attributes.has("httponly")) missing.push("HttpOnly");
      if (!attributes.has("samesite")) missing.push("SameSite");
      const sameSite = String(attributes.get("samesite") || "").toLowerCase();
      if (sameSite === "none" && !attributes.has("secure")) issues.push("SameSite=None without Secure");
      if (name.startsWith("__Secure-") && !attributes.has("secure")) issues.push("__Secure- prefix requirements not met");
      if (name.startsWith("__Host-") && (!attributes.has("secure") || attributes.has("domain") || attributes.get("path") !== "/")) {
        issues.push("__Host- prefix requirements not met");
      }
      if (name.startsWith("__Http-") && (!attributes.has("secure") || !attributes.has("httponly"))) issues.push("__Http- prefix requirements not met");
      if (name.startsWith("__Host-Http-") && (!attributes.has("secure") || !attributes.has("httponly") || attributes.has("domain") || attributes.get("path") !== "/")) {
        issues.push("__Host-Http- prefix requirements not met");
      }
      if (attributes.has("domain")) issues.push("Domain scope set");
      if (/auth|session|token|login|sid/i.test(name) && attributes.get("path") === "/") issues.push("site-wide Path scope");
      const notes = [];
      if (missing.length) notes.push("missing " + missing.join(", "));
      notes.push.apply(notes, issues);
      const status = notes.length === 0 ? "ok" : (missing.length >= 2 || issues.some(function (issue) { return issue.includes("requirements not met"); }) ? "missing" : "weak");
      const note = notes.length ? notes.join("; ") : "Secure + HttpOnly + SameSite";
      html += '<div class="header-item"><span class="name">' + escapeHtml(name) +
        '</span><span class="status ' + status + '">' + escapeHtml(note) + '</span></div>';
      if (notes.length) {
        review.push(headerFinding(
          "header.cookie-flags", "low", "Cookie flags need review", name + ": " + note, "medium",
          "Only the cookie name and attributes were assessed; its value was not retained.",
          "Determine whether this cookie carries sensitive state and which flags and scope are appropriate for its cross-site behavior.",
          "Set-Cookie: " + name
        ));
      }
    });
  }

  headerResults.innerHTML = html || '<div class="empty-hint">No selected header evidence was found.</div>';
  return VulnscanFindings.dedupe(review);
}

function activeFinding(options) {
  return VulnscanFindings.normalize(Object.assign({ source: "active" }, options));
}

function targetSurfaceIdFor(value) {
  return VulnscanFindings.surfaceId("target", VulnscanUrls.target(value));
}

function responseHeader(response, name) {
  return response && response.headers && typeof response.headers.get === "function" ? String(response.headers.get(name) || "") : "";
}

function sourceMapDeclaration(response, scriptUrl) {
  const header = responseHeader(response, "SourceMap") || responseHeader(response, "X-SourceMap");
  if (header) return header.trim();
  const body = String(response && response.body || "");
  const expressions = [
    /\/\/[#@]\s*sourceMappingURL\s*=\s*([^\s'"<>]+)/g,
    /\/\*[#@]\s*sourceMappingURL\s*=\s*([^*]+?)\s*\*\//g
  ];
  let value = "";
  expressions.forEach(function (expression) {
    let match;
    while ((match = expression.exec(body))) value = match[1].trim();
  });
  if (!value || value.length > 2000 || value.startsWith("data:")) return "";
  try {
    const resolved = new URL(value, scriptUrl);
    return resolved.origin === new URL(scriptUrl).origin ? resolved.href : "";
  } catch (e) {
    return "";
  }
}

function getCorsProbe(scanId) {
  return new Promise(function (resolve) {
    chrome.runtime.sendMessage({ type: "get_cors_probe", scanId: scanId }, function (response) {
      resolve(response || { observed: false, originSent: false, originMatchesExtension: false, originWasNull: false });
    });
  });
}

function applyFindingLimits(findings, scanLimits) {
  const state = Object.assign({ sourceTruncated: false, domTruncated: false, findingsTruncated: false, secretsTruncated: false, surfaceTruncated: false }, scanLimits || {});
  let list = VulnscanFindings.dedupe(findings);
  if (list.length > VulnscanFindings.limits.findings) state.findingsTruncated = true;
  if (!state.sourceTruncated && !state.domTruncated && !state.findingsTruncated && !state.secretsTruncated && !state.surfaceTruncated) {
    return { findings: list, scanLimits: state };
  }
  const notes = [];
  if (state.sourceTruncated) notes.push("page source processing limit reached");
  if (state.domTruncated) notes.push("DOM element processing limit reached");
  if (state.findingsTruncated) notes.push("finding limit reached");
  if (state.secretsTruncated) notes.push("secret export limit reached");
  if (state.surfaceTruncated) notes.push("surface map collection limit reached");
  list = list.filter(function (finding) { return finding.checkId !== "scan.limits"; }).slice(0, VulnscanFindings.limits.findings - 1);
  list.push(VulnscanFindings.normalize({
    checkId: "scan.limits",
    severity: "info",
    confidence: "high",
    bucket: "review",
    category: "scan-health",
    type: "Scan limits reached",
    detail: notes.join("; ") + ".",
    evidence: "The scanner stopped collecting affected data at its configured safety limit.",
    verification: "Narrow the page or selected checks and scan again if complete coverage is required.",
    location: "current page",
    source: "passive"
  }));
  return { findings: list, scanLimits: state };
}

async function runActiveChecks(pageUrl, scanId, requestController, options) {
  const extra = [];
  const coverage = [];
  const canary = "vxscan" + Date.now().toString(36);
  let parsed;
  try { parsed = new URL(pageUrl); } catch (e) { return extra; }
  const origin = parsed.origin;
  const settings = options || {};
  const controller = requestController || VulnscanRequests.create({
    mode: settings.mode === "safe" ? "safe" : "lab",
    origin: origin,
    budget: settings.budget || 50,
    fetchFn: fetch
  });
  const mode = settings.mode || (requestController ? controller.mode : "full");
  const enabledChecks = VulnscanChecks.normalize(settings.enabledChecks);
  const safeSelected = VulnscanChecks.stageEnabled(enabledChecks, mode, "safe");
  const labSelected = VulnscanChecks.stageEnabled(enabledChecks, mode, "lab");
  const includeSafe = safeSelected && (settings.includeSafe === true || (settings.includeSafe === undefined && (mode === "safe" || mode === "full")));
  const includeLab = labSelected && (settings.includeLab === true || (settings.includeLab === undefined && (mode === "lab" || mode === "full")));
  const onStage = typeof settings.onStage === "function" ? settings.onStage : function () {};

  function result() {
    const findings = VulnscanFindings.dedupe(extra);
    findings.coverage = VulnscanFindings.normalizeCoverage(coverage);
    return findings;
  }

  if (includeSafe) {
    onStage("safe", "running");
    if (VulnscanChecks.enabled(enabledChecks, "safe.reflection")) {
      const reflectParams = ["q", "search", "s", "query", "keyword", "term"];
      for (let i = 0; i < reflectParams.length && controller.canRequest(); i++) {
        const param = reflectParams[i];
        const testUrl = new URL(pageUrl);
        testUrl.searchParams.set(param, canary);
        const response = await controller.request(testUrl.href, { method: "GET" });
        if (response.body && response.body.indexOf(canary) !== -1) {
          extra.push(activeFinding({
            source: "safe-active",
            checkId: "active.reflection",
            severity: "low",
            confidence: "medium",
            bucket: "review",
            category: "xss",
            type: "Reflected input",
            detail: 'Parameter "' + param + '" was reflected in the response.',
            evidence: "A unique harmless marker was returned verbatim in the response body.",
            verification: "Locate the reflection context and confirm whether output encoding prevents HTML or script interpretation.",
            location: "query parameter: " + param,
            surfaceRefs: [VulnscanFindings.surfaceId("parameter", "query|" + param)]
          }));
          break;
        }
      }
    }

    if (VulnscanChecks.enabled(enabledChecks, "safe.redirects")) {
      const redirectParams = ["url", "redirect", "next", "return", "redirect_uri", "continue"];
      const destination = "https://vxscan-redirect.example/r/" + (scanId || canary);
      const redirectProbes = [];
      for (let i = 0; i < redirectParams.length && controller.canRequest(); i++) {
        const param = redirectParams[i];
        const testUrl = new URL(pageUrl);
        testUrl.searchParams.set(param, destination);
        redirectProbes.push({ param: param, url: comparableUrl(testUrl.href) });
        await controller.request(testUrl.href, { method: "GET" });
      }
      const redirects = await new Promise(function (resolve) {
        chrome.runtime.sendMessage({ type: "get_redirects", scanId: scanId }, function (response) {
          resolve((response && response.redirects) || []);
        });
      });
      const expected = new URL(destination);
      const match = redirects.find(function (entry) {
        const probe = redirectProbes.find(function (item) { return comparableUrl(entry.from) === item.url; });
        if (!probe || !entry.to) return false;
        try {
          const actual = new URL(entry.to);
          if (actual.origin !== expected.origin || actual.pathname !== expected.pathname) return false;
          entry.param = probe.param;
          return true;
        } catch (e) {
          return false;
        }
      });
      if (match) {
        extra.push(activeFinding({
          source: "safe-active",
          checkId: "active.open-redirect",
          severity: "high",
          confidence: "high",
          bucket: "finding",
          category: "redirects",
          type: "Open redirect confirmed",
          detail: 'Parameter "' + match.param + '" redirected to the injected external destination.',
          evidence: redactUrl(match.from) + " → " + redactUrl(match.to),
          verification: "Repeat with another controlled HTTPS destination and confirm that no allowlist or interstitial blocks the redirect.",
          location: "query parameter: " + match.param,
          surfaceRefs: [VulnscanFindings.surfaceId("parameter", "query|" + match.param)]
        }));
      }
    }

    if (VulnscanChecks.enabled(enabledChecks, "safe.robots") && controller.canRequest()) {
      const robots = await controller.request(origin + "/robots.txt", { method: "GET" });
      const sitemap = robots.ok && robots.body ? robots.body.match(/Sitemap:\s*(\S+)/i) : null;
      if (sitemap) {
        extra.push(activeFinding({
          source: "safe-active",
          checkId: "active.sitemap",
          severity: "info",
          confidence: "high",
          bucket: "review",
          category: "recon",
          type: "Sitemap declared",
          detail: redactUrl(sitemap[1]),
          evidence: "robots.txt contains a Sitemap directive.",
          verification: "Open the sitemap and review whether it exposes unexpected application routes.",
          location: "/robots.txt",
          surfaceRefs: [targetSurfaceIdFor(pageUrl)]
        }));
      }
    }

    if (VulnscanChecks.enabled(enabledChecks, "safe.cors") && controller.canRequest()) {
      const probeUrl = new URL(pageUrl);
      probeUrl.searchParams.set("__vulnscan_cors", scanId || canary);
      const response = await controller.request(probeUrl.href, { method: "GET", responseMode: "discard" });
      const observed = await getCorsProbe(scanId);
      let status = "complete";
      let note = "";
      if (!response || response.skipped || response.outcome !== "complete") {
        status = "stopped";
        note = controller.getSummary().stoppedReason === "budget-exhausted" ? "request-budget" : "request-stopped";
      } else if (!observed.observed || !observed.originSent) {
        status = "unavailable";
        note = "origin-not-observed";
      }
      const allowedOrigin = responseHeader(response, "Access-Control-Allow-Origin").trim();
      const credentials = responseHeader(response, "Access-Control-Allow-Credentials").trim().toLowerCase() === "true";
      const extensionOrigin = VulnscanUrls.origin(chrome.runtime.getURL(""));
      let accepted = false;
      if (status === "complete" && observed.originMatchesExtension && allowedOrigin === extensionOrigin) {
        accepted = true;
        const vary = responseHeader(response, "Vary").toLowerCase().split(",").map(function (value) { return value.trim(); });
        extra.push(activeFinding({
          source: "safe-active",
          checkId: "active.cors.origin-accepted",
          severity: credentials ? "medium" : "low",
          confidence: "high",
          bucket: "review",
          category: "cross-origin",
          type: "CORS probe origin accepted",
          detail: "The current response allowed the extension-origin probe" + (credentials ? " and advertised credential support." : "."),
          evidence: "The browser sent its extension origin and the response returned that exact origin. Credentials were omitted." + (vary.includes("origin") ? " Vary: Origin was present." : " Vary: Origin was not observed."),
          verification: "Repeat from a controlled HTTPS web origin against the intended API response and confirm whether arbitrary origins are accepted.",
          location: redactUrl(pageUrl),
          surfaceRefs: [targetSurfaceIdFor(pageUrl)]
        }));
      }
      coverage.push({ checkId: "safe.cors", status: status, inspected: response && !response.skipped ? 1 : 0, matched: accepted ? 1 : 0, note: note });
    } else if (VulnscanChecks.enabled(enabledChecks, "safe.cors")) {
      coverage.push({ checkId: "safe.cors", status: "stopped", inspected: 0, matched: 0, note: controller.getSummary().stoppedReason === "budget-exhausted" ? "request-budget" : "request-stopped" });
    }

    if (VulnscanChecks.enabled(enabledChecks, "safe.source-maps")) {
      const sourceSettings = settings.sourceMapCandidates || { urls: [], total: 0, truncated: false };
      const scripts = (sourceSettings.urls || []).slice(0, 3);
      let inspected = 0;
      let confirmed = 0;
      let responseLimited = false;
      for (let i = 0; i < scripts.length && controller.canRequest(); i++) {
        let scriptUrl;
        try { scriptUrl = new URL(scripts[i]); } catch (e) { continue; }
        if (scriptUrl.origin !== origin) continue;
        const scriptResponse = await controller.request(scriptUrl.href, { method: "GET" });
        inspected++;
        if (scriptResponse && scriptResponse.outcome === "response-too-large") responseLimited = true;
        const declaration = sourceMapDeclaration(scriptResponse, scriptUrl.href);
        if (!declaration || !controller.canRequest()) continue;
        let mapUrl;
        try { mapUrl = new URL(declaration, scriptUrl.href); } catch (e) { continue; }
        if (mapUrl.origin !== origin) continue;
        const mapResponse = await controller.request(mapUrl.href, { method: "GET" });
        if (!mapResponse || !mapResponse.ok || !mapResponse.body) continue;
        let map;
        try { map = JSON.parse(mapResponse.body); } catch (e) { continue; }
        if (!map || Number(map.version) !== 3 || !Array.isArray(map.sources)) continue;
        confirmed++;
        const embedded = Array.isArray(map.sourcesContent) && map.sourcesContent.some(function (value) {
          return typeof value === "string" && value.length > 0;
        });
        extra.push(activeFinding({
          source: "safe-active",
          checkId: "active.source-map",
          severity: "info",
          confidence: "high",
          bucket: "review",
          category: "disclosure",
          type: "Declared source map reachable",
          detail: "A same-origin script declared a valid source map with " + Math.min(10000, map.sources.length) + " source reference(s).",
          evidence: "Map: " + redactUrl(mapUrl.href) + ". Embedded source content: " + (embedded ? "present" : "not observed") + ".",
          verification: "Review the map in an authorized environment and decide whether original source or internal paths should be publicly available.",
          location: redactUrl(mapUrl.href),
          surfaceRefs: [VulnscanFindings.surfaceId("resource", "script|" + redactUrl(scriptUrl.href))]
        }));
      }
      const stoppedReason = controller.getSummary().stoppedReason;
      const limited = sourceSettings.truncated || responseLimited;
      coverage.push({
        checkId: "safe.source-maps",
        status: stoppedReason ? "stopped" : limited ? "limited" : "complete",
        inspected: inspected,
        matched: confirmed,
        note: stoppedReason === "budget-exhausted" ? "request-budget" : stoppedReason ? "request-stopped" : responseLimited ? "response-limit" : sourceSettings.truncated ? "candidate-limit" : ""
      });
    }
    onStage("safe", controller.getSummary().stoppedReason ? "stopped" : "complete");
  }

  if (!includeLab || !VulnscanChecks.enabled(enabledChecks, "lab.paths")) return result();
  if (!controller.canRequest()) {
    onStage("lab", "stopped");
    return result();
  }
  onStage("lab", "running");

  const commonPaths = [
    "/admin", "/admin/", "/login", "/wp-admin", "/wp-login.php", "/dashboard", "/panel",
    "/.env", "/.git/HEAD", "/.git/config", "/phpinfo.php", "/api", "/api/v1", "/graphql",
    "/swagger", "/actuator", "/actuator/health", "/server-status", "/config", "/backup",
    "/debug", "/console", "/manager", "/sitemap.xml"
  ];

  function normalizeBody(html) {
    return String(html || "")
      .replace(/<script[\s\S]*?<\/script>/gi, "")
      .replace(/<!--[\s\S]*?-->/g, "")
      .replace(/\s+/g, " ")
      .trim()
      .slice(0, 4000);
  }

  function bodyShingles(body) {
    const tokens = String(body || "").toLowerCase()
      .replace(/https?:\/\/\S+/g, " url ")
      .replace(/\b[0-9a-f]{8,}\b/g, " id ")
      .replace(/\b\d+\b/g, " number ")
      .match(/[a-z0-9]+/g) || [];
    const shingles = new Set();
    if (tokens.length < 3) {
      if (tokens.length) shingles.add(tokens.join(" "));
      return shingles;
    }
    for (let i = 0; i <= tokens.length - 3; i++) {
      shingles.add(tokens.slice(i, i + 3).join(" "));
    }
    return shingles;
  }

  function bodySimilarity(left, right) {
    const leftSet = bodyShingles(left);
    const rightSet = bodyShingles(right);
    if (!leftSet.size || !rightSet.size) return 0;
    let shared = 0;
    leftSet.forEach(function (item) {
      if (rightSet.has(item)) shared++;
    });
    return shared / (leftSet.size + rightSet.size - shared);
  }

  let baselineStatus = null;
  let baselineBody = "";
  try {
    const missingPath = "/vxscan-not-a-real-path-" + Date.now();
    const baseline = await controller.request(origin + missingPath, { method: "GET" });
    baselineStatus = baseline.status;
    baselineBody = normalizeBody(baseline.body);
  } catch (e) {}

  const foundPaths = [];
  async function probe(path) {
    if (!controller.canRequest()) return;
    const response = await controller.request(origin + path, { method: "GET" });
    if (!response.status || response.status === 404 || response.status === 410) return;
    if (baselineStatus && response.status === baselineStatus) {
      const body = normalizeBody(response.body);
      if (baselineBody && body === baselineBody) return;
      if (baselineBody && body.length > 50 && bodySimilarity(body, baselineBody) >= 0.82) return;
      if (baselineStatus === 403 || baselineStatus === 404) return;
    }
    foundPaths.push(path + " (" + response.status + ")");
  }

  for (let i = 0; i < commonPaths.length && controller.canRequest(); i++) {
    await probe(commonPaths[i]);
    setProgress("path discovery " + (i + 1) + "/" + commonPaths.length);
  }
  if (foundPaths.length) {
    extra.push(activeFinding({
      source: "lab",
      checkId: "active.interesting-paths",
      severity: "info",
      confidence: "medium",
      bucket: "review",
      category: "recon",
      type: "Interesting paths found",
      detail: foundPaths.join(", "),
      evidence: "These paths returned a status or body distinct from the soft-404 baseline.",
      verification: "Open each path manually and confirm that it exposes a real application surface rather than a custom error page.",
      location: "path discovery",
      occurrences: foundPaths.length
    }));
  }

  onStage("lab", controller.getSummary().stoppedReason ? "stopped" : "complete");

  return result();
}

function renderFindings(data) {
  const scan = normalizeScan(data);
  if (!scan) return false;
  lastScanData = scan;
  currentFindings = scan.findings;
  currentComparisonStatuses = new Map();
  currentChange = "all";
  if (changeFilterEl) changeFilterEl.value = "all";
  showTarget(scan.url || "");

  const summary = scan.summary;
  document.getElementById("sumHigh").textContent = summary.high;
  document.getElementById("sumMed").textContent = summary.medium;
  document.getElementById("sumLow").textContent = summary.low;
  document.getElementById("sumInfo").textContent = summary.info;
  findingsCountEl.textContent = summary.findings;
  reviewCountEl.textContent = summary.review;

  const labels = { high: "HIGH", medium: "MED", low: "LOW", review: "REVIEW" };
  scoreEl.textContent = scan.risk === "info" ? (summary.findings ? "INFO" : "OK") : (labels[scan.risk] || "OK");
  scoreEl.className = "stat-value score " +
    (scan.risk === "high" ? "bad" : scan.risk === "medium" || scan.risk === "review" ? "mid" : "good");
  renderStages(scan.stageSummary, true);
  renderOverview(scan);
  renderComparison(scan);
  updateCategoryFilter();
  applyFilter();
  chrome.runtime.sendMessage({ type: "get_request_log", scanId: scan.scanId }, function (response) {
    renderRequestLog((response && response.entries) || [], scan.requestSummary || (response && response.summary));
  });
  return true;
}

function categoryLabel(value) {
  return String(value || "general").split("-").map(function (part) {
    return part ? part.charAt(0).toUpperCase() + part.slice(1) : "";
  }).join(" ");
}

function sourceLabel(value) {
  const labels = {
    passive: "Passive",
    headers: "Headers",
    "safe-active": "Safe Active",
    active: "Active",
    lab: "Lab"
  };
  return labels[value] || categoryLabel(value);
}

function renderOverview(scan) {
  if (!resultOverviewEl) return;
  const counts = {};
  scan.findings.forEach(function (finding) {
    counts[finding.category] = (counts[finding.category] || 0) + 1;
  });
  const categories = Object.keys(counts).sort(function (left, right) { return counts[right] - counts[left]; }).slice(0, 8);
  const requestText = scan.requestSummary && scan.requestSummary.mode !== "passive" ?
    scan.requestSummary.attempted + " request" + (scan.requestSummary.attempted === 1 ? "" : "s") : "no active requests";
  const limited = scan.scanLimits && (scan.scanLimits.sourceTruncated || scan.scanLimits.domTruncated || scan.scanLimits.findingsTruncated || scan.scanLimits.secretsTruncated || scan.scanLimits.surfaceTruncated);
  const coverage = (scan.coverage || []).filter(function (entry) { return entry.status !== "complete"; });
  resultOverviewEl.innerHTML = '<div class="overview-main"><strong>' + escapeHtml(sourceLabel(scan.scanMode)) +
    '</strong><span>' + scan.summary.findings + ' actionable · ' + scan.summary.review + ' review · ' +
    scan.checksRun.length + ' checks · ' + requestText + '</span><button class="btn ghost open-scan-map">Open scan map</button></div>' +
    '<div class="overview-categories">' + categories.map(function (category) {
      return '<span>' + escapeHtml(categoryLabel(category)) + ' <strong>' + counts[category] + '</strong></span>';
    }).join("") + "</div>" + (limited ? '<div class="scan-limit-note">Coverage was capped by a scanner safety limit. Review the Scan health result before relying on completeness.</div>' : "") +
    (coverage.length ? '<div class="scan-limit-note">Some active checks had limited coverage: ' + escapeHtml(coverage.map(function (entry) {
      return entry.checkId + " (" + entry.status + ")";
    }).join(", ")) + '.</div>' : "");
  const openMap = resultOverviewEl.querySelector(".open-scan-map");
  if (openMap) openMap.addEventListener("click", function () { openScanMap(scan, openMap); });
  resultOverviewEl.hidden = false;
}

function checkProfileMatches(left, right) {
  const first = VulnscanChecks.normalize(left).slice().sort();
  const second = VulnscanChecks.normalize(right).slice().sort();
  return first.length === second.length && first.every(function (value, index) {
    return value === second[index];
  });
}

function stageForSource(source) {
  if (source === "headers") return "headers";
  if (source === "safe-active" || source === "active") return "safe";
  if (source === "lab") return "lab";
  return "passive";
}

function renderComparison(scan) {
  if (!comparisonPanelEl) return;
  comparisonPanelEl.hidden = false;
  comparisonPanelEl.innerHTML = '<div class="comparison-baseline">Looking for a matching earlier scan...</div>';
  chrome.storage.local.get("scanHistory", function (data) {
    if (!lastScanData || lastScanData.scanId !== scan.scanId) return;
    const history = Array.isArray(data.scanHistory) ? data.scanHistory : [];
    const previousRaw = history.find(function (entry) {
      return entry.scanId !== scan.scanId && entry.urlFingerprint === scan.urlFingerprint && entry.comparisonReady === true &&
        Array.isArray(entry.findings) && checkProfileMatches(entry.checksRun, scan.checksRun);
    });
    if (!previousRaw) {
      currentComparisonStatuses = new Map();
      comparisonPanelEl.innerHTML = '<div class="comparison-baseline"><strong>Comparison baseline saved.</strong> Run the same checks on this target again to see what changed.</div>';
      return;
    }

    const previous = normalizeScan(previousRaw);
    if (!previous) {
      comparisonPanelEl.innerHTML = '<div class="comparison-baseline">The previous matching scan cannot be compared with this report.</div>';
      return;
    }
    const comparableStages = ["passive", "headers", "safe", "lab"].filter(function (stage) {
      return scan.stageSummary[stage] === "complete" && previous.stageSummary[stage] === "complete";
    });
    if (!comparableStages.length) {
      currentComparisonStatuses = new Map();
      comparisonPanelEl.innerHTML = '<div class="comparison-baseline">No stages completed in both scans, so there is nothing reliable to compare.</div>';
      return;
    }
    const currentComparable = scan.findings.filter(function (finding) {
      return comparableStages.includes(stageForSource(finding.source));
    });
    const previousComparable = previous.findings.filter(function (finding) {
      return comparableStages.includes(stageForSource(finding.source));
    });
    const comparison = VulnscanFindings.compare(currentComparable, previousComparable);
    currentComparisonStatuses = new Map();
    comparison.new.forEach(function (finding) { currentComparisonStatuses.set(finding.fingerprint, "new"); });
    comparison.changed.forEach(function (pair) { currentComparisonStatuses.set(pair.current.fingerprint, "changed"); });
    comparison.unchanged.forEach(function (finding) { currentComparisonStatuses.set(finding.fingerprint, "unchanged"); });
    scan.comparison = {
      previousScanId: previous.scanId,
      previousTimestamp: previous.timestamp,
      comparableStages: comparableStages,
      new: comparison.new.length,
      changed: comparison.changed.length,
      resolved: comparison.resolved.length,
      unchanged: comparison.unchanged.length
    };
    const resolved = comparison.resolved.length ? '<details class="resolved-results"><summary>Show resolved results</summary><ul>' +
      comparison.resolved.map(function (finding) {
        return "<li>" + escapeHtml(finding.type) + " — " + escapeHtml(finding.detail) + "</li>";
      }).join("") + "</ul></details>" : "";
    comparisonPanelEl.innerHTML = '<div class="comparison-head"><strong>Compared with previous matching scan</strong><span>' +
      escapeHtml(new Date(previous.timestamp).toLocaleString()) + "</span></div>" +
      '<div class="comparison-counts"><span class="new">' + comparison.new.length + " new</span>" +
      '<span class="changed">' + comparison.changed.length + " changed</span>" +
      '<span class="resolved">' + comparison.resolved.length + " resolved</span>" +
      '<span class="unchanged">' + comparison.unchanged.length + " unchanged</span></div>" + resolved;
    applyFilter();
  });
}

function updateCategoryFilter() {
  if (!categoryFilterEl) return;
  const categories = Array.from(new Set(currentFindings.map(function (finding) { return finding.category; }))).sort();
  if (currentCategory !== "all" && !categories.includes(currentCategory)) currentCategory = "all";
  categoryFilterEl.innerHTML = '<option value="all">All categories</option>' + categories.map(function (category) {
    return '<option value="' + escapeHtml(category) + '">' + escapeHtml(categoryLabel(category)) + "</option>";
  }).join("");
  categoryFilterEl.value = currentCategory;
}

function applyFilter() {
  let list = currentFindings.filter(function (finding) {
    return finding.bucket === currentBucket;
  });
  if (currentFilter !== "all") {
    list = list.filter(function (finding) { return finding.severity === currentFilter; });
  }
  if (currentCategory !== "all") {
    list = list.filter(function (finding) { return finding.category === currentCategory; });
  }
  if (currentConfidence !== "all") {
    list = list.filter(function (finding) { return finding.confidence === currentConfidence; });
  }
  if (currentSource !== "all") {
    list = list.filter(function (finding) { return finding.source === currentSource; });
  }
  if (currentChange !== "all") {
    list = list.filter(function (finding) {
      return currentComparisonStatuses.get(finding.fingerprint) === currentChange;
    });
  }
  if (currentTriage !== "all") {
    list = list.filter(function (finding) {
      return triageStateFor(finding) === currentTriage;
    });
  }
  if (currentSearch) {
    list = list.filter(function (finding) {
      return [finding.type, finding.detail, finding.evidence, finding.category, finding.source].join(" ").toLowerCase().includes(currentSearch);
    });
  }
  if (!list.length) {
    const label = currentBucket === "finding" ? "actionable findings" : "items to review";
    resultsEl.innerHTML = '<div class="empty-hint">No ' + label + " match these filters</div>";
    return;
  }

  const severityOrder = { high: 0, medium: 1, low: 2, info: 3 };
  const confidenceOrder = { high: 0, medium: 1, low: 2 };
  list = list.slice().sort(function (left, right) {
    const severity = (severityOrder[left.severity] ?? 9) - (severityOrder[right.severity] ?? 9);
    if (severity) return severity;
    return (confidenceOrder[left.confidence] ?? 9) - (confidenceOrder[right.confidence] ?? 9);
  });

  const groups = {};
  list.forEach(function (finding, index) {
    if (!groups[finding.category]) groups[finding.category] = [];
    groups[finding.category].push({ finding: finding, index: index });
  });
  resultsEl.innerHTML = Object.keys(groups).map(function (category) {
    const cards = groups[category].map(function (entry) {
      const finding = entry.finding;
      const index = entry.index;
    const occurrences = finding.occurrences > 1 ? '<span class="occurrences">×' + finding.occurrences + "</span>" : "";
    const change = currentComparisonStatuses.get(finding.fingerprint);
    const changeBadge = change ? '<span class="change-badge ' + change + '">' + change + "</span>" : "";
    const workflow = triageStateFor(finding);
    return '<div class="finding ' + finding.severity + '">' +
      '<div class="type"><span class="severity ' + finding.severity + '">' + finding.severity + "</span>" +
      '<span class="confidence ' + finding.confidence + '">' + escapeHtml(finding.confidence) + " confidence</span>" +
      '<span class="source-badge ' + escapeHtml(finding.source) + '">' + escapeHtml(sourceLabel(finding.source)) + "</span>" +
      '<span class="finding-title">' + escapeHtml(finding.type) + "</span>" + occurrences + changeBadge +
      '<span class="triage-badge ' + escapeHtml(workflow) + '">' + escapeHtml(triageLabel(workflow)) + "</span>" +
      '<button class="inspect-btn" data-fingerprint="' + escapeHtml(finding.fingerprint) + '">Investigate</button>' +
      '<button class="copy-btn" data-idx="' + index + '">Copy</button></div>' +
      '<div class="detail">' + escapeHtml(finding.detail) + "</div>" +
      '<details class="finding-context"><summary>Evidence &amp; verification</summary>' +
      (finding.location ? '<div><strong>Affected:</strong> ' + escapeHtml(finding.location) + "</div>" : "") +
      '<div><strong>Evidence:</strong> ' + escapeHtml(finding.evidence || "No additional evidence recorded.") + "</div>" +
      '<div><strong>Verify:</strong> ' + escapeHtml(finding.verification || "Review the affected behavior manually.") + "</div>" +
      '<div class="finding-source">' + escapeHtml(finding.category) + " · " + escapeHtml(finding.source) + "</div>" +
      "</details></div>";
    }).join("");
    return '<section class="finding-group"><div class="finding-group-title"><span>' + escapeHtml(categoryLabel(category)) +
      '</span><strong>' + groups[category].length + "</strong></div>" + cards + "</section>";
  }).join("");

  resultsEl.querySelectorAll(".copy-btn").forEach(function (button) {
    button.addEventListener("click", function () {
      const finding = list[Number.parseInt(button.getAttribute("data-idx"), 10)];
      const text = "[" + finding.severity.toUpperCase() + "] [" + finding.confidence.toUpperCase() + " confidence] " +
        finding.type + ": " + finding.detail + "\nEvidence: " + finding.evidence + "\nVerify: " + finding.verification;
      navigator.clipboard.writeText(text).then(function () {
        button.textContent = "copied";
        setTimeout(function () { button.textContent = "copy"; }, 1000);
      });
    });
  });
  resultsEl.querySelectorAll(".inspect-btn").forEach(function (button) {
    button.addEventListener("click", function () {
      openFindingDrawer(button.getAttribute("data-fingerprint"));
    });
  });
}

function saveToHistory(scan) {
  if (!scan || !scan.url) return;
  chrome.storage.local.get("scanHistory", function (data) {
    const history = data.scanHistory || [];
    history.unshift({
      schemaVersion: 8,
      scanId: scan.scanId,
      url: scan.url,
      urlFingerprint: scan.urlFingerprint,
      risk: scan.risk,
      timestamp: scan.timestamp,
      summary: scan.summary,
      findingsCount: scan.summary.findings,
      reviewCount: scan.summary.review,
      scanMode: scan.scanMode,
      requestSummary: scan.requestSummary,
      stageSummary: scan.stageSummary,
      checksRun: scan.checksRun,
      scanLimits: scan.scanLimits,
      surface: VulnscanFindings.normalizeSurface(scan.surface),
      coverage: VulnscanFindings.normalizeCoverage(scan.coverage),
      findings: scan.findings.map(exportFinding),
      comparisonReady: true
    });
    chrome.storage.local.set({ scanHistory: history.slice(0, 12) });
  });
}

function loadHistory() {
  chrome.storage.local.get("scanHistory", function (data) {
    const history = data.scanHistory || [];
    if (!history.length) {
      historyList.innerHTML = '<div class="empty-hint">No history yet</div>';
      return;
    }
    historyList.innerHTML = history.map(function (entry, index) {
      const findingCount = Number.isInteger(entry.findingsCount) ? entry.findingsCount : 0;
      const reviewCount = Number.isInteger(entry.reviewCount) ? entry.reviewCount : 0;
      const risk = entry.risk || "legacy";
      const checkCount = Array.isArray(entry.checksRun) ? entry.checksRun.length : 0;
      return '<div class="hist-item"><div class="hist-url">' + escapeHtml(entry.url) + "</div>" +
        '<div class="hist-meta">' + escapeHtml(entry.scanMode || "legacy") + " · " + escapeHtml(risk) + " · " + findingCount + " findings · " + reviewCount +
        " review · " + (checkCount ? checkCount + " checks · " : "") + new Date(entry.timestamp).toLocaleString() + '</div><button class="btn ghost history-map" data-history-index="' + index + '">Open map</button></div>';
    }).join("");
    historyList.querySelectorAll(".history-map").forEach(function (button) {
      button.addEventListener("click", function () {
        const scan = history[Number.parseInt(button.getAttribute("data-history-index"), 10)];
        if (scan) openScanMap(scan, button);
      });
    });
  });
}

function loadTabs() {
  return new Promise(function (resolve) {
    chrome.runtime.sendMessage({ type: "list_tabs" }, function (response) {
      const tabs = (response && response.tabs) || [];
      knownTabs = tabs;
      if (!tabs.length) {
        tabSelect.innerHTML = '<option value="">No scannable tabs open</option>';
        selectedTabId = null;
        resolve(tabs);
        return;
      }
      const previous = selectedTabId;
      tabSelect.innerHTML = tabs.map(function (tab) {
        let label = tab.title || tab.url;
        if (label.length > 70) label = label.slice(0, 67) + "...";
        try { label = new URL(tab.url).hostname + " — " + label; } catch (e) {}
        return '<option value="' + tab.id + '">' + escapeHtml(label) + "</option>";
      }).join("");
      let selected = tabs.find(function (tab) { return tab.id === previous; });
      if (!selected) selected = tabs.find(function (tab) { return tab.active; }) || tabs[0];
      selectedTabId = selected.id;
      tabSelect.value = String(selected.id);
      showTarget(selected.url, selected.favIconUrl || "");
      resolve(tabs);
    });
  });
}

function getCachedSelectedTab() {
  const id = selectedTabId !== null ? selectedTabId : Number.parseInt(tabSelect.value, 10);
  if (!Number.isInteger(id)) return null;
  return knownTabs.find(function (tab) { return tab.id === id; }) || null;
}

function getSelectedTab() {
  return new Promise(function (resolve) {
    const cached = getCachedSelectedTab();
    if (!cached) {
      resolve(null);
      return;
    }
    chrome.runtime.sendMessage({ type: "get_tab", tabId: cached.id }, function (response) {
      resolve((response && response.tab) || null);
    });
  });
}

function getCapturedHeaders(tabId) {
  return new Promise(function (resolve) {
    chrome.runtime.sendMessage({ type: "get_headers", tabId: tabId }, function (response) {
      resolve(response || { headers: [], url: "", statusCode: 0 });
    });
  });
}

async function collectSourceMapCandidates(tabId, pageUrl) {
  const results = await executeScript({
    target: { tabId: tabId },
    func: function () {
      const currentOrigin = location.origin;
      const urls = [];
      Array.from(document.scripts || []).forEach(function (script) {
        if (!script.src) return;
        try {
          const url = new URL(script.src, location.href);
          if (url.origin === currentOrigin && !urls.includes(url.href)) urls.push(url.href);
        } catch (e) {}
      });
      return { urls: urls.slice(-3), total: urls.length, truncated: urls.length > 3 };
    }
  });
  const value = results && results[0] && results[0].result;
  if (!value || !Array.isArray(value.urls)) return { urls: [], total: 0, truncated: false };
  const origin = new URL(pageUrl).origin;
  const urls = value.urls.filter(function (url) {
    try { return new URL(url).origin === origin; } catch (e) { return false; }
  }).slice(0, 3);
  return { urls: urls, total: Math.max(urls.length, Math.min(1000, Number(value.total) || 0)), truncated: value.truncated === true };
}

async function waitForScanResult(scanId, pageUrl) {
  const deadline = Date.now() + 5000;
  while (Date.now() < deadline) {
    const stored = await storageGet("lastScan");
    if (stored && stored.schemaVersion === 8 && stored.scanId === scanId && stored.urlFingerprint === urlFingerprint(pageUrl)) {
      return stored;
    }
    await new Promise(function (resolve) { setTimeout(resolve, 100); });
  }
  throw new Error("Passive scan did not return a current result");
}

async function runScan() {
  if (scanning) return;
  scanning = true;
  scanBtn.disabled = true;
  scanModeEl.disabled = true;
  if (scanModePicker) scanModePicker.classList.add("disabled");
  if (checkPicker) checkPicker.classList.add("disabled");
  if (fullScanToggle) fullScanToggle.disabled = true;
  requestBudgetEl.disabled = true;
  cancelScanBtn.hidden = false;
  activeScanId = null;
  currentRequestController = null;
  scanCancelled = false;
  let stageSummary = blankStageSummary(requestMode());
  renderStages(stageSummary, true);
  setStatus("// scanning...");
  setProgress("resolving selected tab...");

  try {
    let tab = getCachedSelectedTab();
    if (!tab || !Number.isInteger(tab.id) || !tab.url) {
      setStatus("// no scannable tab selected — open a website and refresh the list");
      setProgress(null);
      return;
    }
    if (/^(chrome|chrome-extension|edge|about|devtools):\/\//.test(tab.url)) {
      setStatus("// cannot scan browser internal pages");
      setProgress(null);
      return;
    }

    const mode = requestMode();
    const checksRun = checksForMode(mode);
    if (!checksRun.length) {
      setStatus("// select at least one check available in this mode");
      setProgress(null);
      return;
    }
    stageSummary = blankStageSummary(mode, checksRun);
    renderStages(stageSummary, true);
    const budget = requestBudget();
    chrome.storage.local.set({ requestBudget: budget, enabledChecks: selectedChecks() });
    const plannedRequests = estimateRequests(mode, checksRun);
    const selectedOrigin = new URL(tab.url).origin;
    const originPattern = selectedOrigin + "/*";
    setProgress("requesting access to " + new URL(tab.url).hostname + "...");
    let granted = false;
    try {
      granted = await requestSitePermission([originPattern]);
    } catch (e) {
      throw new Error("Could not request site permission: " + e.message);
    }
    if (!granted) {
      setStatus("// permission denied for this site");
      setProgress(null);
      return;
    }

    tab = await getSelectedTab();
    if (!tab || !Number.isInteger(tab.id) || !tab.url) throw new Error("The selected tab is no longer available");
    if (new URL(tab.url).origin !== selectedOrigin) {
      await loadTabs();
      setStatus("// selected tab changed sites — scan again to grant access");
      setProgress(null);
      return;
    }

    if (plannedRequests > 0) {
      const approved = await confirmActiveScan(selectedOrigin, mode, budget, checksRun);
      if (!approved) {
        setStatus("// active scan cancelled before any requests were sent");
        setProgress(null);
        return;
      }
      tab = await getSelectedTab();
      if (!tab || !tab.url || new URL(tab.url).origin !== selectedOrigin) {
        await loadTabs();
        setStatus("// selected tab changed sites during confirmation — scan again");
        setProgress(null);
        return;
      }
    }
    const capturedHeaders = await getCapturedHeaders(tab.id);
    const headersAreCurrent = capturedHeaders.statusCode > 0 && comparableUrl(capturedHeaders.url) === comparableUrl(tab.url);

    activeScanId = "s" + Date.now();
    const scanStart = await new Promise(function (resolve) {
      chrome.runtime.sendMessage({
        type: "scan_begin",
        scanId: activeScanId,
        tabId: tab.id,
        origin: new URL(tab.url).origin,
        scanMode: mode
      }, function (response) { resolve(response || {}); });
    });
    if (scanStart.error) throw new Error(scanStart.error);

    showTarget(tab.url, tab.favIconUrl || "");
    if (stageSummary.headers !== "skipped") stageSummary.headers = "running";
    if (stageSummary.passive !== "skipped") stageSummary.passive = "running";
    renderStages(stageSummary, true);
    setProgress("passive scan...");
    let headerFindings = [];
    if (stageSummary.headers === "skipped") {
      headerResults.innerHTML = '<div class="empty-hint">Header checks were not selected.</div>';
    } else if (headersAreCurrent) {
      headerFindings = analyzeHeaders(capturedHeaders.headers || [], tab.url, checksRun);
      stageSummary.headers = "complete";
    } else {
      headerResults.innerHTML = '<div class="empty-hint">Headers were not captured for this page load. Refresh the target tab, then scan again to include them.</div>';
      stageSummary.headers = "unavailable";
    }
    renderStages(stageSummary, true);
    let passive = { findings: [] };
    if (stageSummary.passive !== "skipped") {
      await executeScript({
        target: { tabId: tab.id },
        func: function (scanId, scanMode, enabledChecks) {
          globalThis.__vulnscanScanId = scanId;
          globalThis.__vulnscanScanMode = scanMode;
          globalThis.__vulnscanEnabledChecks = enabledChecks;
        },
        args: [activeScanId, mode, checksRun]
      });
      await executeScript({
        target: { tabId: tab.id },
        files: ["finding-model.js", "url-utils.js", "scan-checks.js", "content.js"]
      });
      passive = await waitForScanResult(activeScanId, tab.url);
      stageSummary.passive = "complete";
    }
    renderStages(stageSummary, true);
    let activeFindings = [];
    let activeCoverage = [];
    let sourceMapCandidates = { urls: [], total: 0, truncated: false };
    if (VulnscanChecks.enabled(checksRun, "safe.source-maps")) {
      sourceMapCandidates = await collectSourceMapCandidates(tab.id, tab.url);
    }
    let requestSummary = { mode: mode, budget: plannedRequests ? budget : 0, attempted: 0, completed: 0, stoppedReason: null };
    let requestEntries = [];
    if (scanCancelled) throw new Error("Scan cancelled");
    if (plannedRequests > 0) {
      setProgress("running selected active checks...");
      currentRequestController = VulnscanRequests.create({
        mode: mode === "safe" ? "safe" : "lab",
        origin: selectedOrigin,
        budget: budget,
        fetchFn: fetch,
        onLog: function (entry, entries, summary) { renderRequestLog(entries, summary); }
      });
      activeFindings = await runActiveChecks(tab.url, activeScanId, currentRequestController, {
        mode: mode,
        budget: budget,
        includeSafe: mode === "safe" || mode === "full",
        includeLab: mode === "lab" || mode === "full",
        enabledChecks: checksRun,
        sourceMapCandidates: sourceMapCandidates,
        onStage: function (stage, state) {
          stageSummary[stage] = state;
          renderStages(stageSummary, true);
          if (state === "running") setProgress(stage === "safe" ? "safe active checks..." : "soft-404-aware path discovery...");
        }
      });
      activeCoverage = activeFindings.coverage || [];
      requestEntries = currentRequestController.getLog();
      requestSummary = currentRequestController.getSummary();
      requestSummary.mode = mode;
    }
    await new Promise(function (resolve) {
      chrome.runtime.sendMessage({
        type: "save_request_log",
        scanId: activeScanId,
        entries: requestEntries,
        summary: requestSummary
      }, function () { resolve(); });
    });

    const limited = applyFindingLimits((passive.findings || []).concat(headerFindings, activeFindings), passive.scanLimits);
    const findings = limited.findings;
    const scan = {
      schemaVersion: 8,
      scanId: activeScanId,
      scanMode: mode,
      url: redactUrl(tab.url),
      urlFingerprint: urlFingerprint(tab.url),
      vaultFingerprint: passive.vaultFingerprint || exactUrlFingerprint(tab.url),
      findings: findings,
      summary: VulnscanFindings.summarize(findings),
      risk: VulnscanFindings.risk(findings),
      timestamp: Date.now(),
      requestSummary: requestSummary,
      stageSummary: stageSummary,
      checksRun: checksRun,
      scanLimits: limited.scanLimits,
      surface: VulnscanFindings.normalizeSurface(passive.surface),
      coverage: VulnscanFindings.normalizeCoverage(activeCoverage)
    };
    chrome.storage.local.set({ lastScan: scan });
    saveToHistory(scan);
    renderFindings(scan);
    setProgress(null);
    const stopped = requestSummary.stoppedReason ? " — requests stopped: " + requestSummary.stoppedReason : "";
    setStatus("// scan complete — " + scan.summary.findings + " finding(s), " + scan.summary.review + " to review" + stopped);
  } catch (error) {
    setProgress(null);
    setStatus(error.message === "Scan cancelled" ? "// scan cancelled" : "// error: " + error.message);
  } finally {
    if (activeScanId) {
      chrome.runtime.sendMessage({ type: "scan_end", scanId: activeScanId }, function () {});
      activeScanId = null;
    }
    scanning = false;
    scanBtn.disabled = false;
    scanModeEl.disabled = false;
    if (scanModePicker) scanModePicker.classList.remove("disabled");
    if (checkPicker) checkPicker.classList.remove("disabled");
    if (fullScanToggle) fullScanToggle.disabled = false;
    requestBudgetEl.disabled = false;
    cancelScanBtn.hidden = true;
    currentRequestController = null;
  }
}

function getExportSecrets(callback) {
  if (!lastScanData) {
    callback([], false);
    return;
  }
  chrome.runtime.sendMessage({
    type: "get_export_secrets",
    scanId: lastScanData.scanId,
    vaultFingerprint: lastScanData.vaultFingerprint
  }, function (response) {
    callback(Array.from(new Set((response && response.secrets) || [])), !!(response && response.available));
  });
}

function exportFinding(finding) {
  return {
    checkId: finding.checkId,
    fingerprint: finding.fingerprint,
    identityFingerprint: finding.identityFingerprint,
    severity: finding.severity,
    confidence: finding.confidence,
    bucket: finding.bucket,
    category: finding.category,
    type: finding.type,
    detail: finding.detail,
    evidence: finding.evidence,
    verification: finding.verification,
    location: finding.location,
    selector: finding.selector,
    source: finding.source,
    occurrences: finding.occurrences,
    surfaceRefs: finding.surfaceRefs || []
  };
}

function exportInvestigation(finding) {
  const guidance = VulnscanGuidance.get(finding);
  const priority = VulnscanGuidance.priority(finding);
  return Object.assign(exportFinding(finding), {
    workflowState: triageStateFor(finding),
    priority: priority,
    impact: guidance.impact,
    remediation: guidance.remediation,
    exploitability: {
      level: guidance.exploitability.level,
      summary: guidance.exploitability.plainLanguage,
      observed: guidance.exploitability.observed,
      prerequisites: guidance.exploitability.prerequisites,
      possibleImpact: guidance.exploitability.possibleImpact,
      weakeningEvidence: guidance.exploitability.weakens
    },
    investigationSteps: [finding.verification].concat(guidance.steps).filter(Boolean).filter(function (step, index, list) {
      return list.indexOf(step) === index;
    })
  });
}

function downloadBlob(content, type, filename) {
  const url = URL.createObjectURL(new Blob([content], { type: type }));
  const link = document.createElement("a");
  link.href = url;
  link.download = filename;
  link.click();
  URL.revokeObjectURL(url);
}

function buildMarkdownReport(scan) {
  const findings = scan.findings.filter(function (finding) { return finding.bucket === "finding"; });
  const review = scan.findings.filter(function (finding) { return finding.bucket === "review"; });
  let markdown = "# VulnScan Report\n\n";
  markdown += "**URL:** " + scan.url + "\n\n";
  markdown += "**Mode:** " + scan.scanMode + "\n\n";
  markdown += "**Risk:** " + scan.risk + "\n\n";
  markdown += "**Time:** " + new Date(scan.timestamp).toISOString() + "\n\n";
  markdown += "**Checks run:** " + VulnscanChecks.effective(scan.checksRun, scan.scanMode).join(", ") + "\n\n";
  markdown += "**Stages:** " + ["passive", "headers", "safe", "lab"].map(function (stage) {
    return categoryLabel(stage) + " " + ((scan.stageSummary && scan.stageSummary[stage]) || "unknown");
  }).join(" · ") + "\n\n";
  if (scan.coverage && scan.coverage.length) {
    markdown += "**Active coverage:** " + scan.coverage.map(function (entry) {
      return entry.checkId + " " + entry.status + " (" + entry.inspected + " inspected, " + entry.matched + " matched)";
    }).join(" · ") + "\n\n";
  }
  const surface = VulnscanFindings.normalizeSurface(scan.surface);
  markdown += "**Observed surface:** " + surface.nodes.length + " nodes · " + surface.edges.length + " relationships" + (surface.truncated ? " · collection limit reached" : "") + "\n\n";
  if (scan.comparison) {
    markdown += "**Comparison:** " + scan.comparison.new + " new · " + scan.comparison.changed + " changed · " +
      scan.comparison.resolved + " resolved · " + scan.comparison.unchanged + " unchanged\n\n";
  }
  markdown += "## Findings\n\n";
  if (!findings.length) markdown += "No actionable findings.\n";
  function appendGroups(items) {
    const categories = Array.from(new Set(items.map(function (finding) { return finding.category; }))).sort();
    categories.forEach(function (category) {
      markdown += "\n### " + categoryLabel(category) + "\n\n";
      items.filter(function (finding) { return finding.category === category; }).forEach(function (finding) {
        const guidance = VulnscanGuidance.get(finding);
        const priority = VulnscanGuidance.priority(finding);
        markdown += "- **[" + finding.severity.toUpperCase() + "]** " + finding.type + " — " + finding.detail + "\n";
        markdown += "  - Confidence: " + finding.confidence + "\n";
        markdown += "  - Workflow: " + triageLabel(triageStateFor(finding)) + "\n";
        markdown += "  - Priority: " + priority.label + " (" + priority.score + ")\n";
        markdown += "  - Stage: " + sourceLabel(finding.source) + "\n";
        if (finding.location) markdown += "  - Affected location: " + finding.location + "\n";
        markdown += "  - Evidence: " + finding.evidence + "\n";
        markdown += "  - Why it matters: " + guidance.impact + "\n";
        markdown += "  - Exploitability: " + guidance.exploitability.plainLanguage + "\n";
        markdown += "  - Required conditions: " + guidance.exploitability.prerequisites.join("; ") + "\n";
        markdown += "  - Recommended action: " + guidance.remediation + "\n";
        markdown += "  - Verify: " + finding.verification + "\n";
      });
    });
  }
  appendGroups(findings);
  markdown += "\n## Review\n\n";
  if (!review.length) markdown += "No additional review items.\n";
  appendGroups(review);
  markdown += "\n> Secret values are redacted. Use the separate full-secret export only when you need the raw values.\n";
  return markdown;
}

function buildJsonReport(scan) {
  return {
    reportVersion: "6.2",
    schemaVersion: 8,
    url: scan.url,
    scanId: scan.scanId,
    scanMode: scan.scanMode,
    timestamp: scan.timestamp,
    risk: scan.risk,
    summary: scan.summary,
    requestSummary: scan.requestSummary,
    stageSummary: scan.stageSummary,
    checksRun: VulnscanChecks.effective(scan.checksRun, scan.scanMode),
    scanLimits: scan.scanLimits,
    surface: VulnscanFindings.normalizeSurface(scan.surface),
    coverage: VulnscanFindings.normalizeCoverage(scan.coverage),
    comparison: scan.comparison || null,
    secretsRedacted: true,
    findings: scan.findings.map(exportInvestigation)
  };
}

function exportRedactedMarkdown() {
  if (!lastScanData) {
    setStatus("// nothing to export");
    return;
  }
  downloadBlob(buildMarkdownReport(lastScanData), "text/markdown", "vuln-scan-" + Date.now() + ".md");
  setStatus("// redacted Markdown report exported");
}

function exportRedactedJson() {
  if (!lastScanData) {
    setStatus("// nothing to export");
    return;
  }
  downloadBlob(JSON.stringify(buildJsonReport(lastScanData), null, 2), "application/json", "vuln-scan-" + Date.now() + ".json");
  setStatus("// redacted JSON report exported");
}

function exportRawSecrets() {
  getExportSecrets(function (vault, available) {
    if (!available || !vault.length) {
      setStatus("// raw values are unavailable — run a fresh scan with a matching target");
      return;
    }
    let text = "VulnScan raw secret export\n";
    text += "Target: " + lastScanData.url + "\n";
    text += "Scan: " + lastScanData.scanId + "\n";
    text += "Created: " + new Date().toISOString() + "\n\n";
    text += vault.join("\n") + "\n";
    downloadBlob(text, "text/plain", "vuln-scan-secrets-" + Date.now() + ".txt");
    setStatus("// full secret values exported — handle the file securely");
  });
}

exportBtn.addEventListener("click", function () {
  exportMenu.hidden = !exportMenu.hidden;
  exportBtn.setAttribute("aria-expanded", String(!exportMenu.hidden));
});
exportMarkdownBtn.addEventListener("click", function () { exportMenu.hidden = true; exportRedactedMarkdown(); });
exportJsonBtn.addEventListener("click", function () { exportMenu.hidden = true; exportRedactedJson(); });
exportSecretsBtn.addEventListener("click", function () {
  exportMenu.hidden = true;
  if (!lastScanData) { setStatus("// nothing to export"); return; }
  secretExportCheck.checked = false;
  secretExportConfirm.disabled = true;
  secretExportModal.hidden = false;
});

document.querySelectorAll(".nav-btn").forEach(function (button) {
  button.addEventListener("click", function () {
    document.querySelectorAll(".nav-btn").forEach(function (item) { item.classList.remove("active"); });
    document.querySelectorAll(".view").forEach(function (view) { view.classList.remove("active"); });
    button.classList.add("active");
    const name = button.getAttribute("data-view");
    const view = document.getElementById("view-" + name);
    if (view) view.classList.add("active");
    if (name === "history") loadHistory();
  });
});

document.querySelectorAll(".bucket-filter").forEach(function (button) {
  button.addEventListener("click", function () {
    document.querySelectorAll(".bucket-filter").forEach(function (item) { item.classList.remove("active"); });
    button.classList.add("active");
    currentBucket = button.getAttribute("data-bucket");
    applyFilter();
  });
});

document.querySelectorAll(".filter").forEach(function (button) {
  button.addEventListener("click", function () {
    document.querySelectorAll(".filter").forEach(function (item) { item.classList.remove("active"); });
    button.classList.add("active");
    currentFilter = button.getAttribute("data-sev");
    applyFilter();
  });
});

document.querySelectorAll("input[name='scanModeChoice']").forEach(function (input) {
  input.addEventListener("change", function () {
    if (!input.checked || scanning) return;
    if (fullScanToggle) fullScanToggle.checked = false;
    scanModeEl.value = input.value;
    updateModeHelp();
    if (scanModePicker) scanModePicker.open = false;
  });
});

if (fullScanToggle) {
  fullScanToggle.addEventListener("change", function () {
    if (scanning) return;
    if (fullScanToggle.checked) {
      scanModeEl.value = "full";
    } else {
      const selected = Array.from(document.querySelectorAll("input[name='scanModeChoice']")).find(function (input) {
        return input.checked;
      });
      scanModeEl.value = selected ? selected.value : "passive";
    }
    updateModeHelp();
    if (scanModePicker) scanModePicker.open = false;
  });
}

if (resultSearchEl) {
  resultSearchEl.addEventListener("input", function () {
    currentSearch = resultSearchEl.value.trim().toLowerCase();
    applyFilter();
  });
}
if (categoryFilterEl) {
  categoryFilterEl.addEventListener("change", function () {
    currentCategory = categoryFilterEl.value || "all";
    applyFilter();
  });
}
if (confidenceFilterEl) {
  confidenceFilterEl.addEventListener("change", function () {
    currentConfidence = confidenceFilterEl.value || "all";
    applyFilter();
  });
}
if (sourceFilterEl) {
  sourceFilterEl.addEventListener("change", function () {
    currentSource = sourceFilterEl.value || "all";
    applyFilter();
  });
}
if (changeFilterEl) {
  changeFilterEl.addEventListener("change", function () {
    currentChange = changeFilterEl.value || "all";
    applyFilter();
  });
}
if (triageFilterEl) {
  triageFilterEl.addEventListener("change", function () {
    currentTriage = triageFilterEl.value || "all";
    applyFilter();
  });
}

document.querySelectorAll(".check-toggle").forEach(function (input) {
  input.addEventListener("change", function () {
    updateCheckPicker();
    chrome.storage.local.set({ enabledChecks: selectedChecks() });
  });
});
if (selectAllChecksBtn) {
  selectAllChecksBtn.addEventListener("click", function () {
    applySavedChecks(VulnscanChecks.all());
    chrome.storage.local.set({ enabledChecks: selectedChecks() });
  });
}
if (clearChecksBtn) {
  clearChecksBtn.addEventListener("click", function () {
    applySavedChecks([]);
    chrome.storage.local.set({ enabledChecks: [] });
  });
}

scanBtn.addEventListener("click", runScan);
clearBtn.addEventListener("click", clearResults);
cancelScanBtn.addEventListener("click", function () {
  scanCancelled = true;
  if (currentRequestController) currentRequestController.cancel();
  setStatus("// cancelling scan...");
});

scanModeEl.addEventListener("change", updateModeHelp);
requestBudgetEl.addEventListener("change", function () {
  chrome.storage.local.set({ requestBudget: requestBudget() });
});

authorizationCheck.addEventListener("change", function () {
  authorizationStart.disabled = !authorizationCheck.checked;
});
authorizationStart.addEventListener("click", function () {
  if (authorizationCheck.checked) finishAuthorization(true);
});
authorizationCancel.addEventListener("click", function () { finishAuthorization(false); });

secretExportCheck.addEventListener("change", function () {
  secretExportConfirm.disabled = !secretExportCheck.checked;
});
secretExportConfirm.addEventListener("click", function () {
  if (!secretExportCheck.checked) return;
  secretExportModal.hidden = true;
  exportRawSecrets();
});
secretExportCancel.addEventListener("click", function () { secretExportModal.hidden = true; });

if (findingDrawerClose) findingDrawerClose.addEventListener("click", closeFindingDrawer);
if (findingDrawerBackdrop) findingDrawerBackdrop.addEventListener("click", closeFindingDrawer);
if (findingTriageState) {
  findingTriageState.addEventListener("change", function () {
    const finding = findingByFingerprint(activeFindingFingerprint);
    if (!finding) return;
    saveTriageState(finding, findingTriageState.value);
    applyFilter();
    openFindingDrawer(finding.fingerprint);
    setStatus("Finding workflow updated to " + triageLabel(findingTriageState.value));
  });
}
if (copyFindingBriefBtn) {
  copyFindingBriefBtn.addEventListener("click", function () {
    const finding = findingByFingerprint(activeFindingFingerprint);
    if (!finding) return;
    navigator.clipboard.writeText(investigationBrief(finding)).then(function () {
      copyFindingBriefBtn.textContent = "Copied";
      setTimeout(function () { copyFindingBriefBtn.textContent = "Copy investigation brief"; }, 1200);
    });
  });
}
if (showAffectedBtn) {
  showAffectedBtn.addEventListener("click", function () {
    const finding = findingByFingerprint(activeFindingFingerprint);
    showAffectedOnPage(finding).catch(function (error) {
      setStatus("// could not locate the affected element: " + error.message);
    });
  });
}

if (clearAllDataBtn) {
  clearAllDataBtn.addEventListener("click", function () {
    chrome.storage.local.remove(["lastScan", "scanHistory", "requestBudget", "enabledChecks", "findingTriage"], function () {
      chrome.runtime.sendMessage({ type: "clear_all_session" }, function () {
        triageStates = {};
        applySavedChecks(VulnscanChecks.all());
        clearResults();
        historyList.innerHTML = '<div class="empty-hint">No history yet</div>';
        setStatus("// all saved scan data cleared");
      });
    });
  });
}

if (deleteHistoryBtn) {
  deleteHistoryBtn.addEventListener("click", function () {
    chrome.storage.local.set({ scanHistory: [] }, function () {
      historyList.innerHTML = '<div class="empty-hint">History deleted</div>';
    });
  });
}

if (toggleHeadersBtn) {
  toggleHeadersBtn.addEventListener("click", function () {
    const hidden = headerResults.style.display === "none";
    headerResults.style.display = hidden ? "block" : "none";
    toggleHeadersBtn.textContent = hidden ? "hide" : "show";
  });
}

if (toggleRequestLogBtn) {
  toggleRequestLogBtn.addEventListener("click", function () {
    const hidden = requestLogEl.style.display === "none";
    requestLogEl.style.display = hidden ? "block" : "none";
    toggleRequestLogBtn.textContent = hidden ? "hide" : "show";
  });
}

document.querySelectorAll(".scan-map-view").forEach(function (button) {
  button.addEventListener("click", function () {
    mapView = button.getAttribute("data-map-view") === "flow" ? "flow" : "surface";
    document.querySelectorAll(".scan-map-view").forEach(function (item) {
      item.classList.toggle("active", item === button);
    });
    renderScanMap();
  });
});
[scanMapSearch, scanMapKind, scanMapBucket, scanMapSeverity].forEach(function (control) {
  if (!control) return;
  control.addEventListener(control === scanMapSearch ? "input" : "change", renderScanMap);
});
if (scanMapClose) scanMapClose.addEventListener("click", closeScanMap);
if (scanMapBackdrop) scanMapBackdrop.addEventListener("click", closeScanMap);
if (scanMapZoomIn) scanMapZoomIn.addEventListener("click", function () {
  mapScale = Math.min(2.5, mapScale + 0.15);
  applyMapTransform();
});
if (scanMapZoomOut) scanMapZoomOut.addEventListener("click", function () {
  mapScale = Math.max(0.45, mapScale - 0.15);
  applyMapTransform();
});
if (scanMapFit) scanMapFit.addEventListener("click", resetMapTransform);
if (scanMapReset) scanMapReset.addEventListener("click", function () {
  mapView = mapScanData && mapScanData.surface.nodes.some(function (node) { return node.kind !== "target"; }) ? "surface" : "flow";
  if (scanMapSearch) scanMapSearch.value = "";
  if (scanMapKind) scanMapKind.value = "all";
  if (scanMapBucket) scanMapBucket.value = "all";
  if (scanMapSeverity) scanMapSeverity.value = "all";
  document.querySelectorAll(".scan-map-view").forEach(function (button) {
    button.classList.toggle("active", button.getAttribute("data-map-view") === mapView);
  });
  renderScanMap();
});
if (scanMapViewport) {
  scanMapViewport.addEventListener("wheel", function (event) {
    event.preventDefault();
    mapScale = Math.max(0.45, Math.min(2.5, mapScale + (event.deltaY < 0 ? 0.12 : -0.12)));
    applyMapTransform();
  }, { passive: false });
  scanMapViewport.addEventListener("pointerdown", function (event) {
    if (event.button !== 0) return;
    mapDragging = true;
    mapPointer = { id: event.pointerId, x: event.clientX, y: event.clientY };
    scanMapViewport.classList.add("dragging");
    if (typeof scanMapViewport.setPointerCapture === "function") scanMapViewport.setPointerCapture(event.pointerId);
  });
  scanMapViewport.addEventListener("pointermove", function (event) {
    if (!mapDragging || !mapPointer || event.pointerId !== mapPointer.id) return;
    const bounds = typeof scanMapViewport.getBoundingClientRect === "function" ? scanMapViewport.getBoundingClientRect() : { width: 1, height: 1 };
    const viewBox = scanMapSvg && scanMapSvg.viewBox && scanMapSvg.viewBox.baseVal;
    const ratioX = viewBox && bounds.width ? viewBox.width / bounds.width : 1;
    const ratioY = viewBox && bounds.height ? viewBox.height / bounds.height : 1;
    mapPanX += (event.clientX - mapPointer.x) * ratioX;
    mapPanY += (event.clientY - mapPointer.y) * ratioY;
    mapPointer.x = event.clientX;
    mapPointer.y = event.clientY;
    applyMapTransform();
  });
  const stopMapDrag = function (event) {
    if (!mapDragging || (mapPointer && event.pointerId !== mapPointer.id)) return;
    mapDragging = false;
    mapPointer = null;
    scanMapViewport.classList.remove("dragging");
  };
  scanMapViewport.addEventListener("pointerup", stopMapDrag);
  scanMapViewport.addEventListener("pointercancel", stopMapDrag);
}

document.addEventListener("keydown", function (event) {
  if (event.key === "Escape" && scanMapDialog && !scanMapDialog.hidden) {
    closeScanMap();
    return;
  }
  if (event.key === "Escape" && findingDrawer && !findingDrawer.hidden) {
    closeFindingDrawer();
    return;
  }
  if (event.target.tagName === "INPUT" || event.target.tagName === "TEXTAREA") return;
  const key = event.key.toLowerCase();
  if (key === "s") { event.preventDefault(); runScan(); }
  if (key === "c") { event.preventDefault(); clearResults(); }
  if (key === "e") { event.preventDefault(); exportRedactedMarkdown(); }
});

chrome.storage.local.get("lastScan", function (data) {
  if (!data.lastScan) return;
  if (!renderFindings(data.lastScan)) {
    chrome.storage.local.remove("lastScan", function () {
      setStatus("This saved result needs a fresh v6.2 scan — the incompatible cache was cleared");
    });
  }
});

tabSelect.addEventListener("change", function () {
  const parsed = Number.parseInt(tabSelect.value, 10);
  selectedTabId = Number.isNaN(parsed) ? null : parsed;
  getSelectedTab().then(function (tab) {
    if (tab) showTarget(tab.url, tab.favIconUrl || "");
  });
});

refreshTabsBtn.addEventListener("click", function () {
  loadTabs().then(function () { setStatus("// tab list refreshed"); });
});

chrome.storage.local.get("requestBudget", function (data) {
  if (data.requestBudget) requestBudgetEl.value = String(VulnscanRequests.clampBudget(data.requestBudget));
});
chrome.storage.local.get("enabledChecks", function (data) {
  const saved = data.enabledChecks;
  const oldAll = Array.isArray(saved) && checkProfileMatches(saved, VulnscanChecks.v61All());
  applySavedChecks(saved === undefined || oldAll ? VulnscanChecks.all() : saved);
});
chrome.storage.local.get("findingTriage", function (data) {
  triageStates = data.findingTriage && typeof data.findingTriage === "object" ? data.findingTriage : {};
  if (lastScanData) applyFilter();
});
updateModeHelp();
loadTabs();
