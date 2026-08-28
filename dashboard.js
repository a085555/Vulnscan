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
const investigationQueueEl = document.getElementById("investigationQueue");
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
const exportJourneyLogBtn = document.getElementById("exportJourneyLogBtn");
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
const showFindingMapBtn = document.getElementById("showFindingMapBtn");
const toggleQueueBtn = document.getElementById("toggleQueueBtn");
const scanMapDialog = document.getElementById("scanMapDialog");
const scanMapBackdrop = document.getElementById("scanMapBackdrop");
const scanMapClose = document.getElementById("scanMapClose");
const scanMapSubtitle = document.getElementById("scanMapSubtitle");
const scanMapSearch = document.getElementById("scanMapSearch");
const scanMapKind = document.getElementById("scanMapKind");
const scanMapBucket = document.getElementById("scanMapBucket");
const scanMapSeverity = document.getElementById("scanMapSeverity");
const scanMapConfidence = document.getElementById("scanMapConfidence");
const scanMapChange = document.getElementById("scanMapChange");
const scanMapFocus = document.getElementById("scanMapFocus");
const scanMapChanges = document.getElementById("scanMapChanges");
const scanMapExport = document.getElementById("scanMapExport");
const scanMapSvg = document.getElementById("scanMapSvg");
const scanMapViewport = document.getElementById("scanMapViewport");
const scanMapMiniMap = document.getElementById("scanMapMiniMap");
const scanMapDetails = document.getElementById("scanMapDetails");
const scanMapStatus = document.getElementById("scanMapStatus");
const scanMapZoomOut = document.getElementById("scanMapZoomOut");
const scanMapZoomIn = document.getElementById("scanMapZoomIn");
const scanMapFit = document.getElementById("scanMapFit");
const scanMapReset = document.getElementById("scanMapReset");
const startJourneyBtn = document.getElementById("startJourneyBtn");
const finishJourneyBtn = document.getElementById("finishJourneyBtn");
const discardJourneyBtn = document.getElementById("discardJourneyBtn");
const openJourneyMapBtn = document.getElementById("openJourneyMapBtn");
const journeyRecordingBar = document.getElementById("journeyRecordingBar");
const journeyOriginEl = document.getElementById("journeyOrigin");
const journeyElapsedEl = document.getElementById("journeyElapsed");
const journeyCurrentRouteEl = document.getElementById("journeyCurrentRoute");
const journeyPagesEl = document.getElementById("journeyPages");
const journeyApisEl = document.getElementById("journeyApis");
const journeyFindingsEl = document.getElementById("journeyFindings");
const journeyReviewEl = document.getElementById("journeyReview");
const journeyEventsEl = document.getElementById("journeyEvents");
const journeyNoticeEl = document.getElementById("journeyNotice");
const journeyResultSummaryEl = document.getElementById("journeyResultSummary");
const journeyResultListEl = document.getElementById("journeyResultList");
const journeyHotspotsEl = document.getElementById("journeyHotspots");
const journeyHistoryListEl = document.getElementById("journeyHistoryList");
const deleteJourneyHistoryBtn = document.getElementById("deleteJourneyHistoryBtn");
const captureConsole = document.getElementById("captureConsole");
const captureConsoleResize = document.getElementById("captureConsoleResize");
const consoleEventCount = document.getElementById("consoleEventCount");
const consolePauseBtn = document.getElementById("consolePauseBtn");
const consoleWrapBtn = document.getElementById("consoleWrapBtn");
const consoleExpandBtn = document.getElementById("consoleExpandBtn");
const consoleCollapseBtn = document.getElementById("consoleCollapseBtn");
const consoleSearchEl = document.getElementById("consoleSearch");
const consoleClearFocus = document.getElementById("consoleClearFocus");
const consoleLogEl = document.getElementById("consoleLog");
const consoleNewEvents = document.getElementById("consoleNewEvents");
const scanControls = document.getElementById("scanControls");

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
let currentComparisonScan = null;
let currentComparisonResult = null;
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
let mapGraph = null;
let mapView = "surface";
let mapScale = 1;
let mapPanX = 0;
let mapPanY = 0;
let mapDragging = false;
let mapPointer = null;
let mapReturnFocus = null;
let mapSelectedNodeId = null;
let mapFocusMode = true;
let mapCollapsedNodes = new Set();
let mapBaseStatus = "No map loaded";
let mapJourneyMode = false;
let activeView = "scan";
let activeJourney = null;
let selectedJourney = null;
let journeyTimer = null;
let consoleFilter = "all";
let consoleSearch = "";
let consolePaused = false;
let consoleUnseen = 0;
let consoleFollowing = true;
let consoleFocus = null;
let findingContext = "scan";
let journeyFindingsContext = [];
const mapScaleMin = 0.45;
const mapScaleMax = 24;

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

function markdownText(value) {
  return String(value === undefined || value === null ? "" : value)
    .replace(/[\u0000-\u001f\u007f-\u009f\u2028\u2029]+/g, " ")
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/([\\`*_{}\[\]()#+\-.!|~])/g, "\\$1");
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

function removeSitePermission(origins) {
  return new Promise(function (resolve) {
    let finished = false;
    const complete = function (value) {
      if (finished) return;
      if (chrome.runtime.lastError) {
        finished = true;
        resolve(false);
        return;
      }
      if (value !== false) {
        finished = true;
        resolve(true);
        return;
      }
      if (!chrome.permissions.contains) {
        finished = true;
        resolve(false);
        return;
      }
      finished = true;
      chrome.permissions.contains({ origins: origins }, function (granted) {
        resolve(!chrome.runtime.lastError && !granted);
      });
    };
    try {
      const pending = chrome.permissions.remove({ origins: origins }, complete);
      if (pending && typeof pending.then === "function") pending.then(complete, function () { complete(false); });
    } catch (error) {
      complete(false);
    }
  });
}

function endScanContext(message) {
  return new Promise(function (resolve) {
    chrome.runtime.sendMessage(message, function (response) {
      resolve(response || { error: chrome.runtime.lastError ? chrome.runtime.lastError.message : "No response" });
    });
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
  if (!finding) return "";
  if (findingContext === "journey" && selectedJourney) return VulnscanFindings.key(selectedJourney.origin) + ":" + finding.identityFingerprint;
  if (!lastScanData) return "";
  return lastScanData.urlFingerprint + ":" + finding.identityFingerprint;
}

function workflowFor(finding) {
  const key = triageKey(finding);
  let saved = triageStates[key];
  if (!saved && lastScanData && findingContext !== "journey") {
    const legacyKey = (lastScanData.legacyUrlFingerprint || lastScanData.urlFingerprint) + ":" + finding.fingerprint;
    saved = triageStates[legacyKey];
    if (saved) triageStates[key] = saved;
  }
  return {
    status: saved && triageOptions.includes(saved.status) ? saved.status : "open",
    pinned: !!(saved && saved.pinned),
    note: saved && typeof saved.note === "string" ? saved.note.slice(0, 2000) : "",
    verification: saved && Array.isArray(saved.verification) ? saved.verification.slice(0, 12).map(function (value) {
      return ["pending", "complete", "failed", "inconclusive"].includes(value) ? value : "pending";
    }) : [],
    updatedAt: saved && Number.isFinite(saved.updatedAt) ? saved.updatedAt : 0
  };
}

function triageStateFor(finding) {
  return workflowFor(finding).status;
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

function saveWorkflowState(finding, patch) {
  const key = triageKey(finding);
  if (!key) return;
  const current = workflowFor(finding);
  const next = Object.assign({}, current, patch || {});
  if (!triageOptions.includes(next.status)) next.status = "open";
  next.pinned = !!next.pinned;
  next.note = String(next.note || "").replace(/[\u0000-\u0008\u000b\u000c\u000e-\u001f]/g, "").slice(0, 2000);
  next.verification = Array.isArray(next.verification) ? next.verification.slice(0, 12).map(function (value) {
    return ["pending", "complete", "failed", "inconclusive"].includes(value) ? value : "pending";
  }) : [];
  next.updatedAt = Date.now();
  triageStates[key] = next;
  const recent = Object.keys(triageStates).sort(function (left, right) {
    return triageStates[right].updatedAt - triageStates[left].updatedAt;
  }).slice(0, 500);
  const stored = {};
  recent.forEach(function (item) { stored[item] = triageStates[item]; });
  triageStates = stored;
  chrome.storage.local.set({ findingTriage: triageStates });
}

function saveTriageState(finding, status) {
  saveWorkflowState(finding, { status: status });
}

function findingByFingerprint(fingerprint) {
  const source = findingContext === "journey" ? journeyFindingsContext : currentFindings;
  return source.find(function (finding) {
    return finding.fingerprint === fingerprint;
  }) || null;
}

function renderInvestigationQueue() {
  if (!investigationQueueEl) return;
  const queued = currentFindings.filter(function (finding) { return workflowFor(finding).pinned; });
  investigationQueueEl.hidden = !queued.length;
  if (!queued.length) {
    investigationQueueEl.innerHTML = "";
    return;
  }
  investigationQueueEl.innerHTML = '<div class="queue-head"><strong>Investigation queue</strong><span>' + queued.length + ' pinned</span></div><div class="queue-items">' + queued.map(function (finding) {
    return '<button class="queue-item" data-fingerprint="' + escapeHtml(finding.fingerprint) + '">' + escapeHtml(finding.type) + "</button>";
  }).join("") + "</div>";
  investigationQueueEl.querySelectorAll(".queue-item").forEach(function (button) {
    button.addEventListener("click", function () { openFindingDrawer(button.getAttribute("data-fingerprint")); });
  });
}

function investigationBrief(finding) {
  const guidance = VulnscanGuidance.get(finding);
  const priority = VulnscanGuidance.priority(finding);
  const education = guidance.exploitability;
  const journey = findingContext === "journey" ? selectedJourney : null;
  const journeyPages = journey ? (finding.pageRefs || []).map(function (pageRef) {
    return (journey.pages || []).find(function (page) { return page.id === pageRef; });
  }).filter(Boolean) : [];
  let text = finding.type + "\n";
  text += "Target: " + (journey ? journey.origin : lastScanData ? lastScanData.url : "") + "\n";
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
  if (journeyPages.length) text += "Affected pages\n" + journeyPages.map(function (page) { return "- " + page.route; }).join("\n") + "\n\n";
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
  const journey = findingContext === "journey" ? selectedJourney : null;
  const journeyPages = journey ? (finding.pageRefs || []).map(function (pageRef) {
    return (journey.pages || []).find(function (page) { return page.id === pageRef; });
  }).filter(Boolean) : [];
  const affectedPages = journeyPages.length ? '<section class="drawer-section"><h3>Affected pages</h3><ol>' + journeyPages.map(function (page) {
    return "<li>" + escapeHtml(page.route) + "</li>";
  }).join("") + "</ol></section>" : "";
  const change = currentComparisonStatuses.get(finding.fingerprint);
  const workflow = triageStateFor(finding);
  const workflowState = workflowFor(finding);
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
  const verificationPanel = '<section class="drawer-section"><h3>Verification checklist</h3><div class="verification-workflow">' + steps.map(function (step, index) {
    const state = workflowState.verification[index] || "pending";
    return '<label class="verification-step"><span>' + escapeHtml(step) + '</span><select class="verification-state" data-step="' + index + '">' +
      ["pending", "complete", "failed", "inconclusive"].map(function (value) {
        return '<option value="' + value + '"' + (value === state ? " selected" : "") + ">" + categoryLabel(value) + "</option>";
      }).join("") + "</select></label>";
  }).join("") + '</div></section><section class="drawer-section"><h3>Local note</h3><textarea class="finding-note" maxlength="2000" placeholder="Add investigation context without sensitive values">' + escapeHtml(workflowState.note) + '</textarea><p class="note-hint">Stored locally. Notes are not included in exported reports.</p></section>';
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
    affectedPages +
    '<section class="drawer-section"><h3>Evidence</h3><p>' + escapeHtml(finding.evidence || "No additional evidence recorded.") + "</p></section>" +
    '<section class="drawer-section"><h3>Why it matters</h3><p>' + escapeHtml(guidance.impact) + "</p></section>" +
    '<section class="drawer-section exploitability-section"><div class="exploitability-head"><h3>Exploitability</h3><span class="exploitability-badge ' + escapeHtml(education.level) + '">' + escapeHtml(education.level) + '</span></div><p class="exploitability-lead">' + escapeHtml(education.plainLanguage) + '</p>' +
    '<div class="observed-box"><strong>What Vulnscan observed</strong><span>' + escapeHtml(education.observed) + '</span></div>' +
    '<details class="learning-details"><summary>How exploitation could happen</summary><div class="learning-content"><h4>Required conditions</h4>' + list(education.prerequisites) + '<h4>Likely path</h4>' + list(education.attackPath) + '<h4>Possible impact</h4>' + list(education.possibleImpact) + '</div></details>' +
    '<details class="learning-details"><summary>What would weaken or disprove it</summary><div class="learning-content">' + list(education.weakens) + '</div></details>' + lab + terms + '</section>' +
    '<section class="drawer-section"><h3>Recommended action</h3><p>' + escapeHtml(guidance.remediation) + "</p></section>" +
    '<section class="drawer-section"><h3>Investigation steps</h3><ol>' + steps.map(function (step) {
      return "<li>" + escapeHtml(step) + "</li>";
    }).join("") + "</ol></section>" + verificationPanel +
    '<section class="drawer-section"><h3>Technical details</h3><dl class="technical-grid">' +
    "<dt>Target</dt><dd>" + escapeHtml(journey ? journey.origin : lastScanData ? lastScanData.url : "") + "</dd>" +
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
  findingDrawerBody.querySelectorAll(".verification-state").forEach(function (control) {
    control.addEventListener("change", function () {
      const verification = workflowFor(finding).verification;
      verification[Number.parseInt(control.getAttribute("data-step"), 10)] = control.value;
      saveWorkflowState(finding, { verification: verification });
      setStatus("Verification checklist updated");
    });
  });
  const note = findingDrawerBody.querySelector(".finding-note");
  if (note) note.addEventListener("change", function () {
    saveWorkflowState(finding, { note: note.value });
    setStatus("Local investigation note saved");
  });
  if (showAffectedBtn) showAffectedBtn.hidden = findingContext === "journey" || !finding.selector;
  if (showFindingMapBtn) showFindingMapBtn.hidden = findingContext === "journey" ? !selectedJourney : !lastScanData;
  if (toggleQueueBtn) toggleQueueBtn.textContent = workflowState.pinned ? "Remove from queue" : "Add to queue";
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
  mapJourneyMode = false;
  mapGraph = null;
  mapDragging = false;
  mapPointer = null;
  mapSelectedNodeId = null;
  mapCollapsedNodes = new Set();
  if (scanMapViewport) scanMapViewport.classList.remove("dragging");
  if (mapReturnFocus && typeof mapReturnFocus.focus === "function") mapReturnFocus.focus();
  mapReturnFocus = null;
}

function applyMapTransform() {
  if (!scanMapSvg) return;
  const layer = scanMapSvg.querySelector(".scan-map-layer");
  if (layer) layer.setAttribute("transform", "translate(" + mapPanX + " " + mapPanY + ") scale(" + mapScale + ")");
  if (scanMapMiniMap && mapGraph && !scanMapMiniMap.hidden) {
    VulnscanMap.updateMiniMap(scanMapMiniMap, mapGraph, { x: mapPanX, y: mapPanY, scale: mapScale }, mapSelectedNodeId);
  }
}

function resetMapTransform() {
  mapScale = 1;
  mapPanX = 0;
  mapPanY = 0;
  applyMapTransform();
}

function mapPoint(clientX, clientY) {
  if (scanMapSvg && typeof scanMapSvg.createSVGPoint === "function" && typeof scanMapSvg.getScreenCTM === "function") {
    const matrix = scanMapSvg.getScreenCTM();
    if (matrix && typeof matrix.inverse === "function") {
      const point = scanMapSvg.createSVGPoint();
      point.x = clientX;
      point.y = clientY;
      return point.matrixTransform(matrix.inverse());
    }
  }
  const bounds = scanMapViewport && typeof scanMapViewport.getBoundingClientRect === "function" ? scanMapViewport.getBoundingClientRect() : { left: 0, top: 0, width: 1, height: 1 };
  const viewBox = scanMapSvg && scanMapSvg.viewBox && scanMapSvg.viewBox.baseVal;
  return {
    x: (clientX - (bounds.left || 0)) * (viewBox && bounds.width ? viewBox.width / bounds.width : 1),
    y: (clientY - (bounds.top || 0)) * (viewBox && bounds.height ? viewBox.height / bounds.height : 1)
  };
}

function setMapScale(value, anchor) {
  const next = Math.max(mapScaleMin, Math.min(mapScaleMax, value));
  if (next === mapScale) return;
  if (anchor) {
    const contentX = (anchor.x - mapPanX) / mapScale;
    const contentY = (anchor.y - mapPanY) / mapScale;
    mapPanX = anchor.x - contentX * next;
    mapPanY = anchor.y - contentY * next;
  }
  mapScale = next;
  applyMapTransform();
}

function centerMapNode(node) {
  if (!node || !scanMapSvg) return;
  const viewBox = scanMapSvg.viewBox && scanMapSvg.viewBox.baseVal;
  const bounds = scanMapViewport && typeof scanMapViewport.getBoundingClientRect === "function" ? scanMapViewport.getBoundingClientRect() : null;
  if (!viewBox) return;
  if (bounds && bounds.width && bounds.height) {
    const baseScale = Math.min(bounds.width / Math.max(1, viewBox.width), bounds.height / Math.max(1, viewBox.height));
    const readableScale = 235 / Math.max(1, node.width * baseScale);
    mapScale = Math.max(mapScale, Math.min(mapScaleMax, readableScale));
  }
  mapPanX = viewBox.width / 2 - (node.x + node.width / 2) * mapScale;
  mapPanY = viewBox.height / 2 - (node.y + node.height / 2) * mapScale;
  applyMapTransform();
}

function mapCoverage(node) {
  if (!mapScanData || mapJourneyMode || node.kind !== "check") return null;
  return (mapScanData.coverage || []).find(function (entry) { return entry.checkId === node.checkId; }) || null;
}

function mapBreadcrumb(node) {
  if (!mapGraph || !node) return "";
  const selected = VulnscanMap.trace(mapGraph, node.id);
  return '<div class="map-breadcrumb" aria-label="Evidence path">' + selected.breadcrumb.map(function (item) {
    return "<span>" + escapeHtml(item.label) + "</span>";
  }).join("") + "</div>";
}

function updateMapSelection(node, center) {
  if (!mapGraph || !scanMapSvg || !node) return;
  mapSelectedNodeId = node.id;
  const selected = VulnscanMap.highlight(scanMapSvg, mapGraph, node.id, mapFocusMode);
  if (scanMapMiniMap && !scanMapMiniMap.hidden) VulnscanMap.updateMiniMap(scanMapMiniMap, mapGraph, { x: mapPanX, y: mapPanY, scale: mapScale }, node.id);
  renderMapDetails(node);
  if (mapJourneyMode) {
    consoleFocus = node.pageRef ? { pageRef: node.pageRef } : node.endpointRef ? { endpointRef: node.endpointRef } : node.findingRef ? { findingRef: node.findingRef } : null;
    if (consoleClearFocus) consoleClearFocus.hidden = !consoleFocus;
    renderCaptureConsole(true);
  }
  if (scanMapStatus) scanMapStatus.textContent = mapBaseStatus + " · " + selected.nodeIds.length + " nodes in path";
  if (center) centerMapNode(node);
}

function renderMapDetails(node) {
  if (!scanMapDetails || !node) return;
  if (node.kind === "finding") {
    const finding = node.data;
    const guidance = VulnscanGuidance.get(finding);
    const current = mapJourneyMode ? !!(selectedJourney && findingByFingerprint(finding.fingerprint)) :
      !node.resolved && lastScanData && mapScanData && lastScanData.scanId === mapScanData.scanId && !!findingByFingerprint(finding.fingerprint);
    const changed = node.change === "changed" && node.previous ? '<dt>Changed fields</dt><dd>' + escapeHtml((node.changedFields || []).join(", ") || "Recorded evidence") + '</dd><dt>Previous observation</dt><dd>' + escapeHtml(node.previous.detail || "Not recorded") + "</dd>" : "";
    const actions = '<div class="map-detail-actions"><button class="btn ghost map-center-node">Centre node</button>' +
      (current ? '<button class="btn primary map-investigate" data-fingerprint="' + escapeHtml(finding.fingerprint) + '">Open investigation</button>' : "") + "</div>";
    scanMapDetails.innerHTML = '<div class="map-detail-eyebrow">' + (node.change ? escapeHtml(node.change) + " · " : "") + escapeHtml(finding.bucket) + " · " + escapeHtml(finding.severity) + " · " + escapeHtml(finding.confidence) + ' confidence</div><h3>' + escapeHtml(finding.type) + '</h3>' + mapBreadcrumb(node) +
      '<p>' + escapeHtml(finding.detail) + '</p><dl><dt>Evidence</dt><dd>' + escapeHtml(finding.evidence || "No additional evidence recorded.") + '</dd>' + changed + '<dt>Exploitability</dt><dd>' + escapeHtml(guidance.exploitability.plainLanguage) + '</dd><dt>Affected location</dt><dd>' + escapeHtml(finding.location || "Not recorded") + '</dd><dt>Stage</dt><dd>' + escapeHtml(sourceLabel(finding.source)) + '</dd></dl>' +
      actions + (current ? "" : '<p class="map-readonly">Historical map — investigation details are read-only.</p>');
    const center = scanMapDetails.querySelector(".map-center-node");
    if (center) center.addEventListener("click", function () { centerMapNode(node); });
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
  const collapsible = node.kind === "group" || node.kind === "stage";
  const journeyData = mapJourneyMode && node.data ? node.data : null;
  const endpointStatuses = node.kind === "api-endpoint" && journeyData ? Object.keys(journeyData.statuses || {}).map(function (status) {
    return status + " × " + journeyData.statuses[status];
  }).join(", ") : "";
  const averageDuration = node.kind === "api-endpoint" && journeyData && journeyData.occurrences ? Math.round(journeyData.durationTotalMs / journeyData.occurrences) : 0;
  scanMapDetails.innerHTML = '<div class="map-detail-eyebrow">' + (node.change ? escapeHtml(node.change) + " · " : "") + escapeHtml(categoryLabel(node.kind)) + '</div><h3>' + escapeHtml(node.label) + '</h3>' + mapBreadcrumb(node) + '<p>' + escapeHtml(detail) + '</p><dl>' +
    (node.location ? '<dt>Location</dt><dd>' + escapeHtml(node.location) + '</dd>' : "") +
    (node.occurrences ? '<dt>Occurrences</dt><dd>' + Number(node.occurrences) + '</dd>' : "") +
    (node.status ? '<dt>Status</dt><dd>' + escapeHtml(node.status) + '</dd>' : "") +
    (endpointStatuses ? '<dt>Responses</dt><dd>' + escapeHtml(endpointStatuses) + '</dd><dt>Average duration</dt><dd>' + averageDuration + ' ms</dd>' : "") +
    (node.kind === "page" && journeyData ? '<dt>First seen</dt><dd>' + escapeHtml(new Date(journeyData.firstSeenAt).toLocaleString()) + '</dd><dt>Last seen</dt><dd>' + escapeHtml(new Date(journeyData.lastSeenAt).toLocaleString()) + '</dd>' : "") +
    (coverage ? '<dt>Coverage</dt><dd>' + escapeHtml(coverage.status) + ' · ' + coverage.inspected + ' inspected · ' + coverage.matched + ' matched</dd>' : "") +
    (node.hiddenCount ? '<dt>Collapsed</dt><dd>' + Number(node.hiddenCount) + " hidden nodes</dd>" : "") +
    '</dl><div class="map-detail-actions"><button class="btn ghost map-center-node">Centre node</button>' +
    (collapsible ? '<button class="btn ghost map-toggle-branch">' + (node.collapsed ? "Expand branch" : "Collapse branch") + "</button>" : "") + "</div>";
  const center = scanMapDetails.querySelector(".map-center-node");
  if (center) center.addEventListener("click", function () { centerMapNode(node); });
  const toggle = scanMapDetails.querySelector(".map-toggle-branch");
  if (toggle) toggle.addEventListener("click", function () {
    if (mapCollapsedNodes.has(node.id)) mapCollapsedNodes.delete(node.id);
    else mapCollapsedNodes.add(node.id);
    mapSelectedNodeId = node.id;
    renderScanMap();
  });
}

function renderScanMap(options) {
  if (!mapScanData || !scanMapSvg) return;
  const filters = {
    query: scanMapSearch ? scanMapSearch.value : "",
    kind: scanMapKind ? scanMapKind.value : "all",
    bucket: scanMapBucket ? scanMapBucket.value : "all",
    severity: scanMapSeverity ? scanMapSeverity.value : "all",
    confidence: scanMapConfidence ? scanMapConfidence.value : "all",
    change: scanMapChange ? scanMapChange.value : "all",
    collapsed: Array.from(mapCollapsedNodes),
    comparableStages: currentComparisonResult ? currentComparisonResult.comparableStages : []
  };
  if (mapJourneyMode) mapGraph = VulnscanMap.buildJourney(mapScanData, mapView, filters);
  else if (mapView === "changes" && currentComparisonScan && currentComparisonResult) mapGraph = VulnscanMap.buildComparison(mapScanData, currentComparisonScan, filters);
  else mapGraph = VulnscanMap.build(mapScanData, mapView, filters);
  VulnscanMap.render(scanMapSvg, mapGraph, {
    select: function (node) { updateMapSelection(node, false); },
    center: function (node) { updateMapSelection(node, true); }
  });
  if (scanMapMiniMap) {
    scanMapMiniMap.hidden = mapGraph.nodes.length < 18;
    if (!scanMapMiniMap.hidden) VulnscanMap.renderMiniMap(scanMapMiniMap, mapGraph);
  }
  if (options && options.resetView) resetMapTransform();
  else applyMapTransform();
  const selected = mapGraph.nodes.find(function (node) { return node.id === mapSelectedNodeId; });
  if (selected) updateMapSelection(selected, false);
  else {
    mapSelectedNodeId = null;
    if (scanMapDetails) scanMapDetails.innerHTML = '<div class="empty-hint">Select a node to inspect its evidence path.</div>';
  }
  if (scanMapStatus) {
    const notice = mapView === "surface" && !mapGraph.available ? " · no structured surface data" : mapGraph.truncated ? " · collection limit reached" : mapGraph.overflow ? " · " + mapGraph.overflow + " nodes summarized" : "";
    mapBaseStatus = mapGraph.nodes.length + " nodes · " + mapGraph.edges.length + " relationships" + notice;
    scanMapStatus.textContent = mapBaseStatus;
    if (selected) {
      const path = VulnscanMap.trace(mapGraph, selected.id);
      scanMapStatus.textContent += " · " + path.nodeIds.length + " nodes in path";
    }
  }
  if (scanMapKind) scanMapKind.disabled = !mapJourneyMode && mapView === "flow";
  if (scanMapChange) scanMapChange.disabled = mapView !== "changes";
}

function openScanMap(scan, returnFocus, selectedNodeId, preferredView) {
  const normalized = normalizeScan(scan);
  if (!normalized || !scanMapDialog) return;
  mapScanData = normalized;
  mapJourneyMode = false;
  findingContext = "scan";
  mapSelectedNodeId = selectedNodeId || null;
  mapCollapsedNodes = new Set();
  mapReturnFocus = returnFocus || document.activeElement || null;
  const changesAvailable = !!(currentComparisonScan && currentComparisonResult && lastScanData && lastScanData.scanId === normalized.scanId);
  mapView = preferredView === "changes" && changesAvailable ? "changes" : normalized.surface.nodes.some(function (node) { return node.kind !== "target"; }) ? "surface" : "flow";
  if (scanMapChanges) scanMapChanges.hidden = !changesAvailable;
  document.querySelectorAll(".scan-map-view").forEach(function (button) {
    if (button.getAttribute("data-map-view") === "flow") button.textContent = "Scan flow";
    button.classList.toggle("active", button.getAttribute("data-map-view") === mapView);
  });
  if (scanMapSubtitle) scanMapSubtitle.textContent = normalized.url + " · " + sourceLabel(normalized.scanMode) + " · " + new Date(normalized.timestamp).toLocaleString();
  if (scanMapSearch) scanMapSearch.value = "";
  if (scanMapKind) scanMapKind.value = "all";
  if (scanMapBucket) scanMapBucket.value = "all";
  if (scanMapSeverity) scanMapSeverity.value = "all";
  if (scanMapConfidence) scanMapConfidence.value = "all";
  if (scanMapChange) scanMapChange.value = "all";
  scanMapDialog.hidden = false;
  renderScanMap({ resetView: true });
  if (mapSelectedNodeId && mapGraph) {
    const selected = mapGraph.nodes.find(function (node) { return node.id === mapSelectedNodeId; });
    if (selected) updateMapSelection(selected, true);
  }
  if (scanMapClose) scanMapClose.focus();
}

function openJourneyMap(journey, returnFocus, selectedNodeId, preferredView) {
  const normalized = VulnscanJourneys.normalize(journey);
  if (!normalized || !scanMapDialog) return;
  selectedJourney = normalized;
  journeyFindingsContext = normalized.findings;
  findingContext = "journey";
  mapScanData = normalized;
  mapJourneyMode = true;
  mapSelectedNodeId = selectedNodeId || null;
  mapCollapsedNodes = new Set();
  mapReturnFocus = returnFocus || document.activeElement || null;
  mapView = preferredView === "surface" ? "surface" : "flow";
  if (scanMapChanges) scanMapChanges.hidden = true;
  document.querySelectorAll(".scan-map-view").forEach(function (button) {
    const view = button.getAttribute("data-map-view");
    button.classList.toggle("active", view === mapView);
    if (view === "surface") button.textContent = "Surface";
    if (view === "flow") button.textContent = "Journey flow";
  });
  if (scanMapSubtitle) scanMapSubtitle.textContent = normalized.origin + " · " + normalized.pages.length + " pages · " + normalized.apiEndpoints.length + " API routes";
  if (scanMapSearch) scanMapSearch.value = "";
  if (scanMapKind) scanMapKind.value = "all";
  if (scanMapBucket) scanMapBucket.value = "all";
  if (scanMapSeverity) scanMapSeverity.value = "all";
  if (scanMapConfidence) scanMapConfidence.value = "all";
  if (scanMapChange) scanMapChange.value = "all";
  scanMapDialog.hidden = false;
  renderScanMap({ resetView: true });
  if (mapSelectedNodeId && mapGraph) {
    const selected = mapGraph.nodes.find(function (node) { return node.id === mapSelectedNodeId; });
    if (selected) updateMapSelection(selected, true);
  }
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
  if (investigationQueueEl) {
    investigationQueueEl.hidden = true;
    investigationQueueEl.innerHTML = "";
  }
  currentComparisonStatuses = new Map();
  currentComparisonScan = null;
  currentComparisonResult = null;
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
  findingContext = "scan";
  lastScanData = scan;
  currentFindings = scan.findings;
  currentComparisonStatuses = new Map();
  currentComparisonScan = null;
  currentComparisonResult = null;
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
  renderInvestigationQueue();
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
  currentComparisonScan = null;
  currentComparisonResult = null;
  if (scanMapChanges) scanMapChanges.hidden = true;
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
    currentComparisonScan = previous;
    currentComparisonResult = { comparison: comparison, comparableStages: comparableStages };
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
      '<span class="unchanged">' + comparison.unchanged.length + " unchanged</span></div>" + resolved +
      '<div class="comparison-actions"><button class="btn ghost export-comparison">Export comparison</button><button class="btn ghost open-change-map">Open change map</button></div>';
    if (scanMapChanges) scanMapChanges.hidden = false;
    const exportButton = comparisonPanelEl.querySelector(".export-comparison");
    if (exportButton) exportButton.addEventListener("click", function () {
      downloadBlob(buildComparisonMarkdown(scan, previous, currentComparisonResult), "text/markdown", exportFilename(scan, "comparison", "md"));
      setStatus("Sanitized comparison report exported");
    });
    const openChanges = comparisonPanelEl.querySelector(".open-change-map");
    if (openChanges) openChanges.addEventListener("click", function () { openScanMap(scan, openChanges, null, "changes"); });
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
      return currentTriage === "queued" ? workflowFor(finding).pinned : triageStateFor(finding) === currentTriage;
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
    const queued = workflowFor(finding).pinned ? '<span class="queue-badge">queued</span>' : "";
    return '<div class="finding ' + finding.severity + '">' +
      '<div class="type"><span class="severity ' + finding.severity + '">' + finding.severity + "</span>" +
      '<span class="confidence ' + finding.confidence + '">' + escapeHtml(finding.confidence) + " confidence</span>" +
      '<span class="source-badge ' + escapeHtml(finding.source) + '">' + escapeHtml(sourceLabel(finding.source)) + "</span>" +
      '<span class="finding-title">' + escapeHtml(finding.type) + "</span>" + occurrences + changeBadge + queued +
      '<span class="triage-badge ' + escapeHtml(workflow) + '">' + escapeHtml(triageLabel(workflow)) + "</span>" +
      '<button class="inspect-btn" data-fingerprint="' + escapeHtml(finding.fingerprint) + '">Investigate</button>' +
      '<button class="map-btn" data-fingerprint="' + escapeHtml(finding.fingerprint) + '">Map</button>' +
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
  resultsEl.querySelectorAll(".map-btn").forEach(function (button) {
    button.addEventListener("click", function () {
      if (!lastScanData) return;
      openScanMap(lastScanData, button, "map-finding-" + button.getAttribute("data-fingerprint"));
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

function runtimeMessage(message) {
  return new Promise(function (resolve) {
    chrome.runtime.sendMessage(message, function (response) {
      resolve(response || { error: chrome.runtime.lastError ? chrome.runtime.lastError.message : "No response" });
    });
  });
}

function journeyForView() {
  return activeJourney || selectedJourney;
}

function formatElapsed(milliseconds) {
  const seconds = Math.max(0, Math.floor(milliseconds / 1000));
  const hours = Math.floor(seconds / 3600);
  const minutes = Math.floor((seconds % 3600) / 60);
  const remaining = seconds % 60;
  return (hours ? String(hours).padStart(2, "0") + ":" : "") + String(minutes).padStart(2, "0") + ":" + String(remaining).padStart(2, "0");
}

function updateJourneyClock() {
  if (!journeyElapsedEl) return;
  const journey = journeyForView();
  if (!journey) {
    journeyElapsedEl.textContent = "00:00";
    return;
  }
  const end = journey.status === "recording" ? Date.now() : journey.endedAt || journey.startedAt;
  journeyElapsedEl.textContent = formatElapsed(end - journey.startedAt);
}

function setJourneyTimer(active) {
  if (journeyTimer) clearInterval(journeyTimer);
  journeyTimer = null;
  updateJourneyClock();
  if (active) journeyTimer = setInterval(updateJourneyClock, 1000);
}

function journeyPage(journey, pageRef) {
  return journey && (journey.pages || []).find(function (page) { return page.id === pageRef; });
}

function journeyEventLabel(item) {
  if (item.kind === "api") return item.phase === "start" ? "API →" : "API ←";
  return { session: "SESSION", navigation: "NAV", page: "PAGE", finding: "FINDING", coverage: "COVERAGE", error: "ERROR" }[item.kind] || String(item.kind || "EVENT").toUpperCase();
}

function journeyEventMessage(item) {
  const details = item.details || {};
  const parts = [];
  if (item.method) parts.push(item.method);
  if (item.status) parts.push(String(item.status));
  if (item.route) parts.push(item.route);
  if (item.durationMs) parts.push(item.durationMs + " ms");
  if (details.findingType) parts.push((details.severity ? details.severity.toUpperCase() + " " : "") + details.findingType);
  if (details.findings !== undefined || details.review !== undefined) parts.push((details.findings || 0) + " findings · " + (details.review || 0) + " review");
  if (details.reason) parts.push(details.reason.replace(/-/g, " "));
  if (item.outcome && !["complete", "started"].includes(item.outcome)) parts.push(item.outcome);
  return parts.join("  ·  ") || item.phase;
}

function journeyEventOutcome(item) {
  const details = item.details || {};
  if (details.findingType) return (details.severity ? details.severity.toUpperCase() + " " : "") + details.findingType;
  if (details.findings !== undefined || details.review !== undefined) return (details.findings || 0) + " findings · " + (details.review || 0) + " review";
  if (details.reason) return details.reason.replace(/-/g, " ");
  return item.outcome && item.outcome !== "complete" ? item.outcome : item.phase;
}

function consoleEventVisible(item) {
  const system = ["session", "coverage", "error"].includes(item.kind);
  if (consoleFilter !== "all" && !(consoleFilter === "system" ? system : item.kind === consoleFilter)) return false;
  if (consoleFocus) {
    if (consoleFocus.pageRef && item.pageRef !== consoleFocus.pageRef) return false;
    if (consoleFocus.endpointRef && item.endpointRef !== consoleFocus.endpointRef) return false;
    if (consoleFocus.findingRef && item.findingRef !== consoleFocus.findingRef) return false;
  }
  if (!consoleSearch) return true;
  return [journeyEventLabel(item), journeyEventMessage(item), item.route, item.method, item.status].join(" ").toLowerCase().includes(consoleSearch);
}

function focusJourneyEvent(item, returnFocus) {
  const journey = journeyForView();
  if (!journey || !item) return;
  let nodeId = "";
  let view = "flow";
  if (item.findingRef) {
    nodeId = "map-journey-finding-" + item.findingRef;
    view = "surface";
  } else if (item.endpointRef) nodeId = "map-journey-api-" + item.endpointRef;
  else if (item.pageRef) nodeId = "map-journey-page-" + item.pageRef;
  if (nodeId) openJourneyMap(journey, returnFocus, nodeId, view);
}

function renderCaptureConsole(force) {
  if (!consoleLogEl) return;
  if (!force && (consolePaused || (!consoleFollowing && activeJourney))) return;
  const journey = journeyForView();
  const events = journey ? (journey.events || []).filter(consoleEventVisible) : [];
  consoleLogEl.textContent = "";
  if (!events.length) {
    const empty = document.createElement("div");
    empty.className = "console-empty";
    empty.textContent = journey ? "No events match the current console filters." : "Waiting for Journey Capture to start.";
    consoleLogEl.appendChild(empty);
  } else {
    events.forEach(function (item) {
      const row = document.createElement("div");
      row.className = "console-row event-" + item.kind + " level-" + item.level;
      row.setAttribute("data-sequence", item.sequence);
      if (consoleFocus && ((consoleFocus.pageRef && item.pageRef === consoleFocus.pageRef) || (consoleFocus.endpointRef && item.endpointRef === consoleFocus.endpointRef) || (consoleFocus.findingRef && item.findingRef === consoleFocus.findingRef))) row.classList.add("selected");
      const time = document.createElement("span");
      time.className = "console-time";
      time.textContent = new Date(item.timestamp).toISOString().slice(11, 23);
      const sequence = document.createElement("span");
      sequence.className = "console-sequence";
      sequence.textContent = "#" + String(item.sequence).padStart(4, "0");
      const kind = document.createElement("span");
      kind.className = "console-kind";
      kind.textContent = journeyEventLabel(item);
      const method = document.createElement("span");
      method.className = "console-method";
      method.textContent = item.method || "—";
      const route = document.createElement("span");
      route.className = "console-route";
      route.textContent = item.route || "—";
      const status = document.createElement("span");
      status.className = "console-status";
      status.textContent = item.status || "—";
      const duration = document.createElement("span");
      duration.className = "console-duration";
      duration.textContent = item.durationMs ? item.durationMs + " ms" : "—";
      const outcome = document.createElement("span");
      outcome.className = "console-outcome";
      outcome.textContent = journeyEventOutcome(item);
      row.appendChild(time);
      row.appendChild(sequence);
      row.appendChild(kind);
      row.appendChild(method);
      row.appendChild(route);
      row.appendChild(status);
      row.appendChild(duration);
      row.appendChild(outcome);
      row.addEventListener("click", function () { focusJourneyEvent(item, row); });
      consoleLogEl.appendChild(row);
    });
  }
  if (consoleEventCount) consoleEventCount.textContent = (journey ? journey.events.length : 0) + " events";
  if (consoleFollowing && !consolePaused) consoleLogEl.scrollTop = consoleLogEl.scrollHeight;
}

function renderJourneyResults(journey) {
  if (!journeyResultListEl || !journeyResultSummaryEl) return;
  journeyFindingsContext = journey ? journey.findings || [] : [];
  if (!journey || !journey.findings.length) {
    journeyResultSummaryEl.textContent = journey ? "No findings or review clues" : "No journey loaded";
    journeyResultListEl.innerHTML = '<div class="empty-hint">Findings from visited pages will be grouped here.</div>';
    return;
  }
  journeyResultSummaryEl.textContent = journey.summary.findings + " findings · " + journey.summary.review + " review";
  journeyResultListEl.innerHTML = journey.findings.map(function (finding) {
    return '<button class="journey-result" data-fingerprint="' + escapeHtml(finding.fingerprint) + '"><span class="severity ' + escapeHtml(finding.severity) + '">' + escapeHtml(finding.severity) + '</span><span><strong>' + escapeHtml(finding.type) + '</strong><small>' + escapeHtml(finding.detail) + '</small></span><span class="journey-result-pages">' + Number(finding.pageCount || 0) + ' page' + (finding.pageCount === 1 ? "" : "s") + "</span></button>";
  }).join("");
  journeyResultListEl.querySelectorAll(".journey-result").forEach(function (button) {
    button.addEventListener("click", function () {
      findingContext = "journey";
      openFindingDrawer(button.getAttribute("data-fingerprint"));
    });
  });
}

function renderJourneyHotspots(journey) {
  if (!journeyHotspotsEl) return;
  if (!journey || !journey.pages.length) {
    journeyHotspotsEl.innerHTML = '<div class="empty-hint">No page hotspots yet.</div>';
    return;
  }
  const endpoints = journey.apiEndpoints || [];
  const hotspots = journey.pages.map(function (page) {
    const findings = (journey.findings || []).filter(function (finding) { return (finding.pageRefs || []).includes(page.id); });
    return {
      page: page,
      findings: findings.filter(function (finding) { return finding.bucket === "finding"; }).length,
      review: findings.filter(function (finding) { return finding.bucket === "review"; }).length,
      apis: endpoints.filter(function (endpoint) { return (endpoint.pageRefs || []).includes(page.id); }).length
    };
  }).sort(function (left, right) {
    if (left.findings !== right.findings) return right.findings - left.findings;
    if (left.review !== right.review) return right.review - left.review;
    if (left.apis !== right.apis) return right.apis - left.apis;
    return left.page.route.localeCompare(right.page.route);
  }).slice(0, 5);
  journeyHotspotsEl.innerHTML = hotspots.map(function (item) {
    return '<button class="journey-hotspot" data-page-ref="' + escapeHtml(item.page.id) + '"><strong>' + escapeHtml(item.page.title || item.page.route) + '</strong><span>' + item.findings + " findings · " + item.review + " review · " + item.apis + " APIs</span></button>";
  }).join("");
  journeyHotspotsEl.querySelectorAll(".journey-hotspot").forEach(function (button) {
    button.addEventListener("click", function () {
      openJourneyMap(journey, button, "map-journey-page-" + button.getAttribute("data-page-ref"), "surface");
    });
  });
}

function renderJourney(journey) {
  const normalized = VulnscanJourneys.normalize(journey);
  if (normalized) selectedJourney = normalized;
  const shown = normalized || selectedJourney;
  const recording = !!(activeJourney && activeJourney.status === "recording");
  if (journeyRecordingBar) journeyRecordingBar.hidden = !recording;
  if (startJourneyBtn) startJourneyBtn.hidden = recording;
  if (finishJourneyBtn) finishJourneyBtn.hidden = !recording;
  if (discardJourneyBtn) discardJourneyBtn.hidden = !recording;
  if (openJourneyMapBtn) openJourneyMapBtn.hidden = !shown || !shown.pages.length;
  if (scanBtn) scanBtn.disabled = scanning || recording;
  if (tabSelect) tabSelect.disabled = recording;
  if (refreshTabsBtn) refreshTabsBtn.disabled = recording;
  if (captureConsole) captureConsole.classList.toggle("recording", recording);
  if (exportJourneyLogBtn) exportJourneyLogBtn.hidden = activeView !== "journey" || !shown;
  if (journeyOriginEl) journeyOriginEl.textContent = shown ? shown.origin : "No origin selected";
  const currentPage = shown ? journeyPage(shown, shown.currentPageRef) : null;
  if (journeyCurrentRouteEl) journeyCurrentRouteEl.textContent = currentPage ? currentPage.route : "Waiting for a page";
  if (journeyPagesEl) journeyPagesEl.textContent = shown ? shown.pages.length : 0;
  if (journeyApisEl) journeyApisEl.textContent = shown ? shown.apiEndpoints.length : 0;
  if (journeyFindingsEl) journeyFindingsEl.textContent = shown ? shown.summary.findings : 0;
  if (journeyReviewEl) journeyReviewEl.textContent = shown ? shown.summary.review : 0;
  if (journeyEventsEl) journeyEventsEl.textContent = shown ? shown.events.length : 0;
  if (journeyNoticeEl) {
    const limited = shown && shown.limits && Object.keys(shown.limits).filter(function (key) { return shown.limits[key]; });
    journeyNoticeEl.classList.toggle("warning", !!(limited && limited.length));
    journeyNoticeEl.textContent = limited && limited.length ? "Capture limits reached: " + limited.join(", ") + ". Aggregated results remain available, but coverage is incomplete." :
      recording ? "Recording passive evidence from the selected tab. Cross-origin API traffic remains outside this exact-origin session." :
        shown ? "Saved redacted journey. Raw secret values are available only if this is the latest journey from the current browser session." :
          "Select a normal website tab and start a journey. Capture stays on that exact origin and creates no requests of its own.";
  }
  renderJourneyResults(shown);
  renderJourneyHotspots(shown);
  renderCaptureConsole(false);
  setJourneyTimer(recording);
}

function loadJourneyHistory(selectNewest) {
  chrome.storage.local.get("journeyHistory", function (data) {
    const history = (Array.isArray(data.journeyHistory) ? data.journeyHistory : []).map(VulnscanJourneys.normalize).filter(Boolean);
    if (selectNewest && !activeJourney && history.length) selectedJourney = history[0];
    if (!journeyHistoryListEl) return;
    if (!history.length) {
      journeyHistoryListEl.innerHTML = '<div class="empty-hint">No saved journeys yet.</div>';
      if (!activeJourney) renderJourney(null);
      return;
    }
    journeyHistoryListEl.innerHTML = history.map(function (journey, index) {
      return '<div class="journey-history-item"><div><strong>' + escapeHtml(journey.name) + '</strong><small>' + escapeHtml(journey.origin) + " · " + journey.pages.length + " pages · " + journey.apiEndpoints.length + " APIs · " + new Date(journey.startedAt).toLocaleString() + '</small></div><div class="journey-history-actions"><button class="btn-mini journey-open" data-index="' + index + '">Open</button><button class="btn-mini journey-rename" data-index="' + index + '">Rename</button><button class="btn-mini journey-delete" data-index="' + index + '">Delete</button></div></div>';
    }).join("");
    journeyHistoryListEl.querySelectorAll(".journey-open").forEach(function (button) {
      button.addEventListener("click", function () {
        selectedJourney = history[Number.parseInt(button.getAttribute("data-index"), 10)];
        findingContext = "journey";
        renderJourney(selectedJourney);
      });
    });
    journeyHistoryListEl.querySelectorAll(".journey-rename").forEach(function (button) {
      button.addEventListener("click", function () {
        const index = Number.parseInt(button.getAttribute("data-index"), 10);
        const name = prompt("Journey name", history[index].name);
        if (name === null || !name.trim()) return;
        history[index].name = name.trim().slice(0, 80);
        chrome.storage.local.set({ journeyHistory: history }, function () { loadJourneyHistory(false); });
      });
    });
    journeyHistoryListEl.querySelectorAll(".journey-delete").forEach(function (button) {
      button.addEventListener("click", function () {
        const index = Number.parseInt(button.getAttribute("data-index"), 10);
        const removed = history[index];
        history.splice(index, 1);
        if (selectedJourney && removed && selectedJourney.journeyId === removed.journeyId) selectedJourney = history[0] || null;
        chrome.storage.local.set({ journeyHistory: history }, function () { loadJourneyHistory(false); renderJourney(selectedJourney); });
      });
    });
    if (selectNewest && selectedJourney) renderJourney(selectedJourney);
  });
}

async function loadJourneyState() {
  const response = await runtimeMessage({ type: "journey_get_state" });
  activeJourney = response.active ? VulnscanJourneys.normalize(response.journey) : null;
  if (activeJourney) {
    selectedJourney = activeJourney;
    findingContext = "journey";
    renderJourney(activeJourney);
  } else loadJourneyHistory(true);
}

async function startJourney() {
  if (scanning || activeJourney) return;
  let tab = getCachedSelectedTab();
  if (!tab || !tab.url || !Number.isInteger(tab.id)) {
    setStatus("// select a normal website tab first");
    return;
  }
  let origin;
  try { origin = new URL(tab.url).origin; } catch (e) { setStatus("// selected tab URL is invalid"); return; }
  if (!/^https?:\/\//.test(tab.url)) {
    setStatus("// Journey Capture supports normal HTTP and HTTPS pages");
    return;
  }
  startJourneyBtn.disabled = true;
  setStatus("// requesting access to " + origin);
  try {
    const granted = await requestSitePermission([origin + "/*"]);
    if (!granted) {
      setStatus("// permission denied for this site");
      return;
    }
    tab = await getSelectedTab();
    if (!tab || !tab.url || new URL(tab.url).origin !== origin) {
      setStatus("// selected tab changed sites — start the journey again");
      await removeSitePermission([origin + "/*"]);
      return;
    }
    const response = await runtimeMessage({
      type: "journey_begin",
      journeyId: "j" + Date.now(),
      tabId: tab.id,
      origin: origin,
      url: tab.url,
      title: tab.title || ""
    });
    if (response.error) throw new Error(response.error);
    activeJourney = VulnscanJourneys.normalize(response.journey);
    selectedJourney = activeJourney;
    findingContext = "journey";
    renderJourney(activeJourney);
    setStatus("// Journey Capture started — browse the selected origin normally");
  } catch (error) {
    setStatus("// could not start journey: " + error.message);
    await removeSitePermission([origin + "/*"]);
  } finally {
    startJourneyBtn.disabled = false;
  }
}

async function stopJourney(discard) {
  if (!activeJourney) return;
  const response = await runtimeMessage({ type: discard ? "journey_discard" : "journey_finish" });
  if (response.error) {
    setStatus("// could not stop journey: " + response.error);
    return;
  }
  activeJourney = null;
  selectedJourney = response.journey ? VulnscanJourneys.normalize(response.journey) : null;
  renderJourney(selectedJourney);
  loadJourneyHistory(!discard);
  setStatus(discard ? "// journey discarded and site access released" : "// journey saved and site access released");
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
  if (activeJourney) {
    setStatus("// finish or discard the active journey before running an assessment");
    return;
  }
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
  let grantedOriginPattern = "";
  let scanContextStarted = false;
  let scanCompleted = false;
  let headerCaptureNeeded = false;
  let scanTargetTabId = null;
  let scanTargetUrl = "";
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
    grantedOriginPattern = originPattern;

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
    const headersAreCurrent = capturedHeaders.statusCode > 0 && (capturedHeaders.urlFingerprint
      ? capturedHeaders.urlFingerprint === exactUrlFingerprint(tab.url)
      : comparableUrl(capturedHeaders.url) === comparableUrl(tab.url));
    scanTargetTabId = tab.id;
    scanTargetUrl = tab.url;

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
    scanContextStarted = true;

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
      headerResults.innerHTML = '<div class="empty-hint">Headers were not captured for this page load. Refresh the target tab within 10 minutes, then scan again to include them.</div>';
      stageSummary.headers = "unavailable";
      headerCaptureNeeded = true;
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
    scanCompleted = true;
    const stopped = requestSummary.stoppedReason ? " — requests stopped: " + requestSummary.stoppedReason : "";
    const headerNote = headerCaptureNeeded ? " — refresh the target within 10 minutes, then scan again for headers" : "";
    setStatus("// scan complete — " + scan.summary.findings + " finding(s), " + scan.summary.review + " to review" + stopped + headerNote);
  } catch (error) {
    setProgress(null);
    setStatus(error.message === "Scan cancelled" ? "// scan cancelled" : "// error: " + error.message);
  } finally {
    let accessHandled = false;
    if (activeScanId && scanContextStarted) {
      const ended = await endScanContext({
        type: "scan_end",
        scanId: activeScanId,
        retainHeaderCapture: scanCompleted && headerCaptureNeeded,
        tabId: scanTargetTabId,
        url: scanTargetUrl
      });
      accessHandled = !ended.error && (ended.siteAccessRetained === true || ended.siteAccessReleased !== false);
      activeScanId = null;
    }
    if (grantedOriginPattern && !accessHandled) {
      const released = await removeSitePermission([grantedOriginPattern]);
      if (!released) setStatus(statusBar.textContent + " — site access could not be released; use Clear all data");
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
  const workflow = workflowFor(finding);
  return Object.assign(exportFinding(finding), {
    workflowState: workflow.status,
    queued: workflow.pinned,
    verificationProgress: workflow.verification,
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

function exportFilename(scan, label, extension) {
  let host = "report";
  try { host = new URL(scan && (scan.url || scan.origin) ? scan.url || scan.origin : "").hostname || host; } catch (e) {}
  host = host.toLowerCase().replace(/[^a-z0-9.-]+/g, "-").replace(/^-+|-+$/g, "") || "report";
  const stamp = new Date().toISOString().replace(/\.\d{3}Z$/, "Z").replace(/:/g, "-");
  return "vulnscan-" + host + "-" + label + "-" + stamp + "." + extension;
}

function buildComparisonMarkdown(current, previous, state) {
  const comparison = state && state.comparison;
  if (!comparison) return "# VulnScan Comparison\n\nNo compatible comparison is available.\n";
  const graph = VulnscanMap.buildComparison(current, previous, { comparableStages: state.comparableStages });
  let markdown = "# VulnScan Comparison\n\n";
  markdown += "**Target:** " + markdownText(current.url) + "\n\n";
  markdown += "**Current scan:** " + markdownText(new Date(current.timestamp).toISOString()) + "\n\n";
  markdown += "**Previous scan:** " + markdownText(new Date(previous.timestamp).toISOString()) + "\n\n";
  markdown += "**Comparable stages:** " + state.comparableStages.map(markdownText).join(", ") + "\n\n";
  markdown += "**Finding changes:** " + comparison.new.length + " new · " + comparison.changed.length + " changed · " + comparison.resolved.length + " resolved · " + comparison.unchanged.length + " unchanged\n\n";
  if (graph.comparison) {
    markdown += "**Surface changes:** " + graph.comparison.surface.new + " new · " + graph.comparison.surface.changed + " changed · " + graph.comparison.surface.resolved + " resolved · " + graph.comparison.surface.unchanged + " unchanged\n\n";
  }
  function list(title, items, value) {
    markdown += "## " + markdownText(title) + "\n\n";
    if (!items.length) {
      markdown += "None.\n\n";
      return;
    }
    items.forEach(function (item) {
      const finding = value(item);
      markdown += "- **[" + markdownText(finding.severity.toUpperCase()) + "]** " + markdownText(finding.type) + " — " + markdownText(finding.detail) + "\n";
      if (finding.location) markdown += "  - Affected location: " + markdownText(finding.location) + "\n";
    });
    markdown += "\n";
  }
  list("New", comparison.new, function (finding) { return finding; });
  markdown += "## Changed\n\n";
  if (!comparison.changed.length) markdown += "None.\n\n";
  comparison.changed.forEach(function (pair) {
    const fields = ["severity", "confidence", "bucket", "type", "detail", "evidence", "verification", "location", "occurrences"].filter(function (field) {
      return String(pair.current[field] || "") !== String(pair.previous[field] || "");
    });
    markdown += "- **" + markdownText(pair.current.type) + "** — changed " + fields.map(markdownText).join(", ") + "\n";
    markdown += "  - Current: [" + markdownText(pair.current.severity) + "] " + markdownText(pair.current.detail) + "\n";
    markdown += "  - Previous: [" + markdownText(pair.previous.severity) + "] " + markdownText(pair.previous.detail) + "\n";
  });
  markdown += "\n";
  list("Resolved", comparison.resolved, function (finding) { return finding; });
  markdown += "> Scanner evidence is redacted. A changed or resolved status should be verified against the recorded coverage.\n";
  return markdown;
}

function buildMarkdownReport(scan) {
  const findings = scan.findings.filter(function (finding) { return finding.bucket === "finding"; });
  const review = scan.findings.filter(function (finding) { return finding.bucket === "review"; });
  const checks = VulnscanChecks.effective(scan.checksRun, scan.scanMode);
  let markdown = "# VulnScan Assessment Report\n\n";
  markdown += "## Summary\n\n";
  markdown += "| Field | Value |\n| --- | --- |\n";
  markdown += "| Target | " + markdownText(scan.url) + " |\n";
  markdown += "| Scan time | " + markdownText(new Date(scan.timestamp).toISOString()) + " |\n";
  markdown += "| Mode | " + markdownText(sourceLabel(scan.scanMode)) + " |\n";
  markdown += "| Risk | " + markdownText(String(scan.risk || "unknown").toUpperCase()) + " |\n";
  markdown += "| Actionable findings | " + findings.length + " |\n";
  markdown += "| Review items | " + review.length + " |\n\n";
  markdown += "## Coverage\n\n";
  markdown += "**Checks run:** " + (checks.length ? checks.map(markdownText).join(", ") : "None") + "\n\n";
  markdown += "**Stages:**\n\n" + ["passive", "headers", "safe", "lab"].map(function (stage) {
    return "- " + markdownText(categoryLabel(stage)) + ": " + markdownText((scan.stageSummary && scan.stageSummary[stage]) || "unknown");
  }).join("\n") + "\n\n";
  if (scan.coverage && scan.coverage.length) {
    markdown += "**Active-check coverage:**\n\n" + scan.coverage.map(function (entry) {
      return "- " + markdownText(entry.checkId) + ": " + markdownText(entry.status) + " — " + Number(entry.inspected || 0) + " inspected, " + Number(entry.matched || 0) + " matched";
    }).join("\n") + "\n\n";
  }
  const surface = VulnscanFindings.normalizeSurface(scan.surface);
  markdown += "**Observed surface:** " + surface.nodes.length + " nodes, " + surface.edges.length + " relationships" + (surface.truncated ? " — collection limit reached" : "") + "\n\n";
  if (scan.comparison) {
    markdown += "**Comparison:** " + scan.comparison.new + " new · " + scan.comparison.changed + " changed · " +
      scan.comparison.resolved + " resolved · " + scan.comparison.unchanged + " unchanged\n\n";
  }
  let itemNumber = 0;
  function appendGroups(items, emptyMessage) {
    if (!items.length) {
      markdown += emptyMessage + "\n\n";
      return;
    }
    const categories = Array.from(new Set(items.map(function (finding) { return finding.category; }))).sort();
    categories.forEach(function (category) {
      markdown += "\n### " + markdownText(categoryLabel(category)) + "\n\n";
      items.filter(function (finding) { return finding.category === category; }).forEach(function (finding) {
        const guidance = VulnscanGuidance.get(finding);
        const priority = VulnscanGuidance.priority(finding);
        itemNumber++;
        markdown += "#### " + itemNumber + ". [" + markdownText(finding.severity.toUpperCase()) + "] " + markdownText(finding.type) + "\n\n";
        markdown += markdownText(finding.detail || "No additional detail recorded.") + "\n\n";
        markdown += "- **Confidence:** " + markdownText(finding.confidence) + "\n";
        markdown += "- **Workflow:** " + markdownText(triageLabel(triageStateFor(finding))) + "\n";
        markdown += "- **Priority:** " + markdownText(priority.label) + " (" + Number(priority.score || 0) + ")\n";
        markdown += "- **Stage:** " + markdownText(sourceLabel(finding.source)) + "\n";
        if (finding.location) markdown += "- **Affected location:** " + markdownText(finding.location) + "\n";
        markdown += "- **Evidence:** " + markdownText(finding.evidence || "No additional evidence recorded.") + "\n";
        markdown += "- **Why it matters:** " + markdownText(guidance.impact) + "\n";
        markdown += "- **Exploitability:** " + markdownText(guidance.exploitability.plainLanguage) + "\n";
        markdown += "- **Required conditions:** " + (guidance.exploitability.prerequisites.length ? guidance.exploitability.prerequisites.map(markdownText).join("; ") : "None recorded") + "\n";
        markdown += "- **Recommended action:** " + markdownText(guidance.remediation) + "\n";
        markdown += "- **How to verify:** " + markdownText(finding.verification || "Review the affected behavior manually.") + "\n\n";
      });
    });
  }
  markdown += "## Findings (" + findings.length + ")\n\n";
  appendGroups(findings, "No actionable findings.");
  itemNumber = 0;
  markdown += "## Review (" + review.length + ")\n\n";
  appendGroups(review, "No additional review items.");
  markdown += "> Secret values are redacted. Use the separate full-secret export only when you need the raw values.\n";
  return markdown;
}

function buildJsonReport(scan) {
  return {
    reportVersion: "6.5",
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

function journeyFindingExport(finding) {
  return Object.assign(exportInvestigation(finding), {
    pageRefs: (finding.pageRefs || []).slice(),
    pageCount: Number(finding.pageCount) || 0,
    pageOccurrences: (finding.pageOccurrences || []).map(function (item) {
      return {
        pageRef: item.pageRef,
        detail: item.detail,
        evidence: item.evidence,
        location: item.location,
        occurrences: item.occurrences,
        lastSeenAt: item.lastSeenAt
      };
    })
  });
}

function buildJourneyJson(journey) {
  const item = VulnscanJourneys.normalize(journey);
  if (!item) return null;
  return {
    reportVersion: "6.5",
    reportType: "journey",
    journeySchemaVersion: 1,
    journeyId: item.journeyId,
    name: item.name,
    origin: item.origin,
    startedAt: item.startedAt,
    endedAt: item.endedAt,
    status: item.status,
    stopReason: item.stopReason,
    risk: item.risk,
    summary: item.summary,
    limits: item.limits,
    pages: item.pages,
    apiEndpoints: item.apiEndpoints,
    findings: item.findings.map(journeyFindingExport),
    events: item.events,
    surface: item.surface,
    secretsRedacted: true
  };
}

function buildJourneyMarkdown(journey) {
  const item = VulnscanJourneys.normalize(journey);
  if (!item) return "# VulnScan Journey Report\n\nNo journey is available.\n";
  const findings = item.findings.filter(function (finding) { return finding.bucket === "finding"; });
  const review = item.findings.filter(function (finding) { return finding.bucket === "review"; });
  const pageById = new Map(item.pages.map(function (page) { return [page.id, page]; }));
  let markdown = "# VulnScan Journey Report\n\n";
  markdown += "## Summary\n\n| Field | Value |\n| --- | --- |\n";
  markdown += "| Name | " + markdownText(item.name || "Journey") + " |\n";
  markdown += "| Authorized origin | " + markdownText(item.origin) + " |\n";
  markdown += "| Started | " + markdownText(new Date(item.startedAt).toISOString()) + " |\n";
  markdown += "| Finished | " + markdownText(item.endedAt ? new Date(item.endedAt).toISOString() : "Still recording") + " |\n";
  markdown += "| Outcome | " + markdownText(item.stopReason || item.status) + " |\n";
  markdown += "| Risk | " + markdownText(String(item.risk || "info").toUpperCase()) + " |\n";
  markdown += "| Pages | " + item.pages.length + " |\n| API routes | " + item.apiEndpoints.length + " |\n";
  markdown += "| Actionable findings | " + findings.length + " |\n| Review items | " + review.length + " |\n\n";
  const limitsReached = Object.keys(item.limits).filter(function (key) { return item.limits[key]; });
  markdown += "## Coverage\n\n";
  markdown += "Passive capture covered one top-level tab on the exact authorized origin. Cross-origin API traffic and request or response bodies were not collected.\n\n";
  markdown += limitsReached.length ? "**Collection limits reached:** " + limitsReached.map(markdownText).join(", ") + ".\n\n" : "No journey collection limits were reached.\n\n";
  markdown += "## Navigation and lifecycle\n\n";
  const timeline = item.events.filter(function (event) { return event.kind === "session" || event.kind === "navigation"; });
  markdown += timeline.length ? timeline.map(function (event) { return "- `" + markdownText(new Date(event.timestamp).toISOString()) + "` **" + markdownText(journeyEventLabel(event)) + "** " + markdownText(journeyEventMessage(event)); }).join("\n") + "\n\n" : "No navigation events were retained.\n\n";
  markdown += "## Pages\n\n" + (item.pages.length ? item.pages.map(function (page) {
    return "- **" + markdownText(page.title || page.route) + "** — " + markdownText(page.route) + " (" + page.visits + " visit" + (page.visits === 1 ? "" : "s") + ")";
  }).join("\n") + "\n\n" : "No pages recorded.\n\n");
  markdown += "## Same-origin API routes\n\n" + (item.apiEndpoints.length ? item.apiEndpoints.map(function (endpoint) {
    const statuses = Object.keys(endpoint.statuses).map(function (status) { return status + " × " + endpoint.statuses[status]; }).join(", ") || "no response";
    const average = endpoint.occurrences ? Math.round(endpoint.durationTotalMs / endpoint.occurrences) : 0;
    return "- `" + markdownText(endpoint.method) + "` " + markdownText(endpoint.route) + " — " + endpoint.occurrences + " request" + (endpoint.occurrences === 1 ? "" : "s") + ", " + statuses + ", " + average + " ms average";
  }).join("\n") + "\n\n" : "No same-origin API routes recorded.\n\n");
  function appendJourneyFindings(title, entries, empty) {
    markdown += "## " + title + " (" + entries.length + ")\n\n";
    if (!entries.length) { markdown += empty + "\n\n"; return; }
    entries.forEach(function (finding, index) {
      const guidance = VulnscanGuidance.get(finding);
      const routes = (finding.pageRefs || []).map(function (pageRef) { return pageById.get(pageRef); }).filter(Boolean).map(function (page) { return page.route; });
      markdown += "### " + (index + 1) + ". [" + markdownText(finding.severity.toUpperCase()) + "] " + markdownText(finding.type) + "\n\n";
      markdown += markdownText(finding.detail) + "\n\n- **Confidence:** " + markdownText(finding.confidence) + "\n";
      markdown += "- **Affected pages:** " + (routes.length ? routes.map(markdownText).join("; ") : "Not recorded") + "\n";
      markdown += "- **Evidence:** " + markdownText(finding.evidence || "No additional evidence recorded.") + "\n";
      markdown += "- **Why it matters:** " + markdownText(guidance.impact) + "\n- **Recommended action:** " + markdownText(guidance.remediation) + "\n";
      markdown += "- **How to verify:** " + markdownText(finding.verification || guidance.steps[0] || "Review manually.") + "\n\n";
    });
  }
  appendJourneyFindings("Findings", findings, "No actionable findings.");
  appendJourneyFindings("Review", review, "No additional review items.");
  markdown += "> URLs and secret evidence are redacted. The separate full-secret export is session-only and should be handled securely.\n";
  return markdown;
}

function buildJourneyLog(journey) {
  const item = VulnscanJourneys.normalize(journey);
  if (!item) return "";
  return [
    "VulnScan Redacted Journey Capture",
    "Origin: " + item.origin,
    "Started: " + new Date(item.startedAt).toISOString(),
    "Events: " + item.events.length,
    "",
    item.events.map(VulnscanJourneys.logLine).join("\n"),
    "",
    "Sensitive values, query values, credentials, fragments, bodies, cookies, and headers are not included.",
    ""
  ].join("\n");
}

function exportRedactedMarkdown() {
  if (activeView === "journey") {
    const journey = journeyForView();
    if (!journey) { setStatus("// nothing to export"); return; }
    downloadBlob(buildJourneyMarkdown(journey), "text/markdown", exportFilename(journey, "journey", "md"));
    setStatus("// redacted journey report exported");
    return;
  }
  if (!lastScanData) {
    setStatus("// nothing to export");
    return;
  }
  downloadBlob(buildMarkdownReport(lastScanData), "text/markdown", exportFilename(lastScanData, "report", "md"));
  setStatus("// redacted Markdown report exported");
}

function exportRedactedJson() {
  if (activeView === "journey") {
    const journey = journeyForView();
    if (!journey) { setStatus("// nothing to export"); return; }
    downloadBlob(JSON.stringify(buildJourneyJson(journey), null, 2) + "\n", "application/json", exportFilename(journey, "journey", "json"));
    setStatus("// redacted journey JSON exported");
    return;
  }
  if (!lastScanData) {
    setStatus("// nothing to export");
    return;
  }
  downloadBlob(JSON.stringify(buildJsonReport(lastScanData), null, 2) + "\n", "application/json", exportFilename(lastScanData, "report", "json"));
  setStatus("// redacted JSON report exported");
}

function buildSecretExport(scan, vault, createdAt) {
  let text = "VulnScan Full Secret Values\n";
  text += "===========================\n\n";
  text += "Handle this file securely. It contains unredacted values.\n\n";
  text += "Target: " + scan.url + "\n";
  text += "Scan ID: " + scan.scanId + "\n";
  text += "Created: " + createdAt + "\n";
  text += "Values: " + vault.length + "\n\n";
  vault.forEach(function (value, index) {
    text += "--- Value " + (index + 1) + " of " + vault.length + " ---\n" + value + "\n\n";
  });
  return text;
}

function exportRawSecrets() {
  if (activeView === "journey") {
    const journey = journeyForView();
    if (!journey) { setStatus("// nothing to export"); return; }
    chrome.runtime.sendMessage({ type: "get_journey_secrets", journeyId: journey.journeyId, origin: journey.origin }, function (response) {
      const vault = Array.from(new Set((response && response.secrets) || []));
      if (!(response && response.available) || !vault.length) {
        setStatus("// raw values are unavailable — only the latest matching journey in this browser session can export them");
        return;
      }
      const scanShape = { url: journey.origin, scanId: journey.journeyId };
      downloadBlob(buildSecretExport(scanShape, vault, new Date().toISOString()), "text/plain", exportFilename(journey, "journey-full-secrets", "txt"));
      setStatus("// full journey secret values exported — handle the file securely");
    });
    return;
  }
  getExportSecrets(function (vault, available) {
    if (!available || !vault.length) {
      setStatus("// raw values are unavailable — run a fresh scan with a matching target");
      return;
    }
    const text = buildSecretExport(lastScanData, vault, new Date().toISOString());
    downloadBlob(text, "text/plain", exportFilename(lastScanData, "full-secrets", "txt"));
    setStatus("// full secret values exported — handle the file securely");
  });
}

exportBtn.addEventListener("click", function () {
  exportMenu.hidden = !exportMenu.hidden;
  exportBtn.setAttribute("aria-expanded", String(!exportMenu.hidden));
});
exportMarkdownBtn.addEventListener("click", function () { exportMenu.hidden = true; exportRedactedMarkdown(); });
exportJsonBtn.addEventListener("click", function () { exportMenu.hidden = true; exportRedactedJson(); });
if (exportJourneyLogBtn) exportJourneyLogBtn.addEventListener("click", function () {
  exportMenu.hidden = true;
  const journey = journeyForView();
  if (!journey) { setStatus("// nothing to export"); return; }
  downloadBlob(buildJourneyLog(journey), "text/plain", exportFilename(journey, "capture", "log"));
  setStatus("// redacted capture log exported");
});
exportSecretsBtn.addEventListener("click", function () {
  exportMenu.hidden = true;
  if (activeView === "journey" ? !journeyForView() : !lastScanData) { setStatus("// nothing to export"); return; }
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
    activeView = name;
    const view = document.getElementById("view-" + name);
    if (view) view.classList.add("active");
    if (name === "history") loadHistory();
    if (name === "journey") {
      findingContext = "journey";
      loadJourneyState();
      loadJourneyHistory(false);
    } else if (name === "scan") findingContext = "scan";
    if (scanControls) scanControls.hidden = name !== "scan";
    if (scanBtn) scanBtn.hidden = name !== "scan";
    if (clearBtn) clearBtn.hidden = name !== "scan";
    if (cancelScanBtn && name !== "scan") cancelScanBtn.hidden = true;
    if (exportJourneyLogBtn) exportJourneyLogBtn.hidden = name !== "journey" || !journeyForView();
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
if (startJourneyBtn) startJourneyBtn.addEventListener("click", function () {
  startJourney().catch(function (error) { setStatus("// could not start journey: " + error.message); });
});
if (finishJourneyBtn) finishJourneyBtn.addEventListener("click", function () { stopJourney(false); });
if (discardJourneyBtn) discardJourneyBtn.addEventListener("click", function () {
  if (confirm("Discard this journey and release site access?")) stopJourney(true);
});
if (openJourneyMapBtn) openJourneyMapBtn.addEventListener("click", function () {
  const journey = journeyForView();
  if (journey) openJourneyMap(journey, openJourneyMapBtn, null, "flow");
});
if (deleteJourneyHistoryBtn) deleteJourneyHistoryBtn.addEventListener("click", function () {
  if (!confirm("Delete all saved journeys?")) return;
  chrome.storage.local.set({ journeyHistory: [] }, function () {
    if (!activeJourney) selectedJourney = null;
    loadJourneyHistory(false);
    renderJourney(activeJourney);
    setStatus("// saved journeys deleted");
  });
});
document.querySelectorAll(".console-filter").forEach(function (button) {
  button.addEventListener("click", function () {
    document.querySelectorAll(".console-filter").forEach(function (item) { item.classList.toggle("active", item === button); });
    consoleFilter = button.getAttribute("data-console-kind") || "all";
    consoleFollowing = true;
    consoleUnseen = 0;
    renderCaptureConsole(true);
  });
});
if (consoleSearchEl) consoleSearchEl.addEventListener("input", function () {
  consoleSearch = consoleSearchEl.value.trim().toLowerCase();
  consoleFollowing = true;
  consoleUnseen = 0;
  renderCaptureConsole(true);
});
if (consolePauseBtn) consolePauseBtn.addEventListener("click", function () {
  consolePaused = !consolePaused;
  consolePauseBtn.textContent = consolePaused ? "Resume output" : "Pause output";
  consolePauseBtn.classList.toggle("active", consolePaused);
  if (!consolePaused) {
    consoleFollowing = true;
    consoleUnseen = 0;
    if (consoleNewEvents) consoleNewEvents.hidden = true;
    renderCaptureConsole(true);
  }
});
if (consoleWrapBtn) consoleWrapBtn.addEventListener("click", function () {
  captureConsole.classList.toggle("wrap");
  consoleWrapBtn.classList.toggle("active", captureConsole.classList.contains("wrap"));
});
if (consoleExpandBtn) consoleExpandBtn.addEventListener("click", function () {
  captureConsole.classList.remove("collapsed");
  captureConsole.classList.toggle("expanded");
  consoleExpandBtn.textContent = captureConsole.classList.contains("expanded") ? "Restore" : "Expand";
});
if (consoleCollapseBtn) consoleCollapseBtn.addEventListener("click", function () {
  captureConsole.classList.remove("expanded");
  captureConsole.classList.toggle("collapsed");
  consoleExpandBtn.textContent = "Expand";
  consoleCollapseBtn.textContent = captureConsole.classList.contains("collapsed") ? "Open" : "Collapse";
});
if (consoleClearFocus) consoleClearFocus.addEventListener("click", function () {
  consoleFocus = null;
  consoleClearFocus.hidden = true;
  consoleFollowing = true;
  consoleUnseen = 0;
  renderCaptureConsole(true);
});
if (consoleLogEl) consoleLogEl.addEventListener("scroll", function () {
  const distance = consoleLogEl.scrollHeight - consoleLogEl.scrollTop - consoleLogEl.clientHeight;
  consoleFollowing = distance <= 12;
});
if (consoleNewEvents) consoleNewEvents.addEventListener("click", function () {
  consoleFollowing = true;
  consoleUnseen = 0;
  consoleNewEvents.hidden = true;
  renderCaptureConsole(true);
});
if (captureConsoleResize) captureConsoleResize.addEventListener("pointerdown", function (event) {
  if (captureConsole.classList.contains("expanded") || captureConsole.classList.contains("collapsed")) return;
  const startY = event.clientY;
  const startHeight = captureConsole.getBoundingClientRect().height;
  const move = function (next) {
    const height = Math.max(190, Math.min(700, startHeight + startY - next.clientY));
    captureConsole.style.height = height + "px";
  };
  const finish = function () {
    document.removeEventListener("pointermove", move);
    document.removeEventListener("pointerup", finish);
    chrome.storage.local.set({ journeyConsoleHeight: captureConsole.style.height });
  };
  document.addEventListener("pointermove", move);
  document.addEventListener("pointerup", finish);
});
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
    if (findingContext === "journey") {
      renderJourneyResults(selectedJourney);
      renderJourneyHotspots(selectedJourney);
    } else {
      applyFilter();
      renderInvestigationQueue();
    }
    openFindingDrawer(finding.fingerprint);
    setStatus("Finding workflow updated to " + triageLabel(findingTriageState.value));
  });
}
if (toggleQueueBtn) {
  toggleQueueBtn.addEventListener("click", function () {
    const finding = findingByFingerprint(activeFindingFingerprint);
    if (!finding) return;
    const pinned = !workflowFor(finding).pinned;
    saveWorkflowState(finding, { pinned: pinned });
    toggleQueueBtn.textContent = pinned ? "Remove from queue" : "Add to queue";
    if (findingContext === "journey") renderJourneyResults(selectedJourney);
    else {
      renderInvestigationQueue();
      applyFilter();
    }
    setStatus(pinned ? "Finding added to the investigation queue" : "Finding removed from the investigation queue");
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
if (showFindingMapBtn) {
  showFindingMapBtn.addEventListener("click", function () {
    const finding = findingByFingerprint(activeFindingFingerprint);
    if (!finding || (findingContext === "journey" ? !selectedJourney : !lastScanData)) return;
    const returnFocus = drawerReturnFocus || showFindingMapBtn;
    closeFindingDrawer();
    if (findingContext === "journey") openJourneyMap(selectedJourney, returnFocus, "map-journey-finding-" + finding.identityFingerprint, "surface");
    else openScanMap(lastScanData, returnFocus, "map-finding-" + finding.fingerprint);
  });
}

if (clearAllDataBtn) {
  clearAllDataBtn.addEventListener("click", function () {
    chrome.storage.local.remove(["lastScan", "scanHistory", "journeyHistory", "requestBudget", "enabledChecks", "findingTriage", "journeyConsoleHeight"], function () {
      chrome.runtime.sendMessage({ type: "clear_all_session" }, function (response) {
        triageStates = {};
        applySavedChecks(VulnscanChecks.all());
        clearResults();
        activeJourney = null;
        selectedJourney = null;
        renderJourney(null);
        historyList.innerHTML = '<div class="empty-hint">No history yet</div>';
        if (journeyHistoryListEl) journeyHistoryListEl.innerHTML = '<div class="empty-hint">No saved journeys yet.</div>';
        setStatus(response && response.siteAccessCleared === false
          ? "// saved scan data cleared, but site access could not be removed"
          : "// all saved scan data and site access cleared");
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
    const requested = button.getAttribute("data-map-view");
    if (requested === "changes" && (!currentComparisonScan || !currentComparisonResult)) return;
    mapView = ["surface", "flow", "changes"].includes(requested) ? requested : "surface";
    mapCollapsedNodes = new Set();
    document.querySelectorAll(".scan-map-view").forEach(function (item) {
      item.classList.toggle("active", item === button);
    });
    renderScanMap({ resetView: true });
  });
});
[scanMapSearch, scanMapKind, scanMapBucket, scanMapSeverity, scanMapConfidence, scanMapChange].forEach(function (control) {
  if (!control) return;
  control.addEventListener(control === scanMapSearch ? "input" : "change", renderScanMap);
});
if (scanMapClose) scanMapClose.addEventListener("click", closeScanMap);
if (scanMapBackdrop) scanMapBackdrop.addEventListener("click", closeScanMap);
if (scanMapZoomIn) scanMapZoomIn.addEventListener("click", function () {
  const bounds = scanMapViewport.getBoundingClientRect();
  setMapScale(mapScale * 1.2, mapPoint(bounds.left + bounds.width / 2, bounds.top + bounds.height / 2));
});
if (scanMapZoomOut) scanMapZoomOut.addEventListener("click", function () {
  const bounds = scanMapViewport.getBoundingClientRect();
  setMapScale(mapScale / 1.2, mapPoint(bounds.left + bounds.width / 2, bounds.top + bounds.height / 2));
});
if (scanMapFit) scanMapFit.addEventListener("click", resetMapTransform);
if (scanMapExport) scanMapExport.addEventListener("click", function () {
  if (!mapGraph) return;
  downloadBlob(VulnscanMap.exportSvg(mapGraph), "image/svg+xml", exportFilename(mapScanData, "scan-map", "svg"));
  setStatus("Sanitized scan map exported");
});
if (scanMapFocus) scanMapFocus.addEventListener("click", function () {
  mapFocusMode = !mapFocusMode;
  scanMapFocus.classList.toggle("active", mapFocusMode);
  scanMapFocus.setAttribute("aria-pressed", mapFocusMode ? "true" : "false");
  if (mapGraph && scanMapSvg && mapSelectedNodeId) VulnscanMap.highlight(scanMapSvg, mapGraph, mapSelectedNodeId, mapFocusMode);
});
if (scanMapReset) scanMapReset.addEventListener("click", function () {
  mapView = mapScanData && mapScanData.surface.nodes.some(function (node) { return node.kind !== "target"; }) ? "surface" : "flow";
  if (scanMapSearch) scanMapSearch.value = "";
  if (scanMapKind) scanMapKind.value = "all";
  if (scanMapBucket) scanMapBucket.value = "all";
  if (scanMapSeverity) scanMapSeverity.value = "all";
  if (scanMapConfidence) scanMapConfidence.value = "all";
  if (scanMapChange) scanMapChange.value = "all";
  mapSelectedNodeId = null;
  mapCollapsedNodes = new Set();
  mapFocusMode = true;
  if (scanMapFocus) {
    scanMapFocus.classList.add("active");
    scanMapFocus.setAttribute("aria-pressed", "true");
  }
  document.querySelectorAll(".scan-map-view").forEach(function (button) {
    button.classList.toggle("active", button.getAttribute("data-map-view") === mapView);
  });
  renderScanMap({ resetView: true });
});
if (scanMapViewport) {
  scanMapViewport.addEventListener("wheel", function (event) {
    event.preventDefault();
    const anchor = mapPoint(event.clientX, event.clientY);
    setMapScale(mapScale * (event.deltaY < 0 ? 1.12 : 1 / 1.12), anchor);
  }, { passive: false });
  scanMapViewport.addEventListener("pointerdown", function (event) {
    if (event.button !== 0 || !VulnscanMap.canPanFrom(event.target)) return;
    const point = mapPoint(event.clientX, event.clientY);
    mapPointer = { id: event.pointerId, startX: event.clientX, startY: event.clientY, x: point.x, y: point.y };
    if (typeof scanMapViewport.setPointerCapture === "function") scanMapViewport.setPointerCapture(event.pointerId);
  });
  scanMapViewport.addEventListener("pointermove", function (event) {
    if (!mapPointer || event.pointerId !== mapPointer.id) return;
    if (!mapDragging && Math.hypot(event.clientX - mapPointer.startX, event.clientY - mapPointer.startY) < 5) return;
    if (!mapDragging) {
      mapDragging = true;
      scanMapViewport.classList.add("dragging");
    }
    const point = mapPoint(event.clientX, event.clientY);
    mapPanX += point.x - mapPointer.x;
    mapPanY += point.y - mapPointer.y;
    mapPointer.x = point.x;
    mapPointer.y = point.y;
    applyMapTransform();
  });
  const stopMapDrag = function (event) {
    if (!mapPointer || event.pointerId !== mapPointer.id) return;
    mapDragging = false;
    mapPointer = null;
    scanMapViewport.classList.remove("dragging");
    if (typeof scanMapViewport.releasePointerCapture === "function" && scanMapViewport.hasPointerCapture && scanMapViewport.hasPointerCapture(event.pointerId)) {
      scanMapViewport.releasePointerCapture(event.pointerId);
    }
  };
  scanMapViewport.addEventListener("pointerup", stopMapDrag);
  scanMapViewport.addEventListener("pointercancel", stopMapDrag);
}
if (scanMapMiniMap) {
  scanMapMiniMap.addEventListener("click", function (event) {
    if (!mapGraph) return;
    const bounds = scanMapMiniMap.getBoundingClientRect();
    const x = (event.clientX - bounds.left) / Math.max(1, bounds.width) * mapGraph.width;
    const y = (event.clientY - bounds.top) / Math.max(1, bounds.height) * mapGraph.height;
    mapPanX = mapGraph.width / 2 - x * mapScale;
    mapPanY = mapGraph.height / 2 - y * mapScale;
    applyMapTransform();
  });
}

if (chrome.runtime.onMessage) chrome.runtime.onMessage.addListener(function (message) {
  if (!message || !/^journey_/.test(message.type || "")) return;
  if (message.type === "journey_event") {
    if (!activeJourney || message.journeyId !== activeJourney.journeyId || !message.event) return;
    const item = VulnscanJourneys.event(message.event);
    if (activeJourney.events.some(function (event) { return event.sequence === item.sequence; })) return;
    activeJourney.events.push(item);
    activeJourney.events.sort(function (left, right) { return left.sequence - right.sequence; });
    activeJourney.nextSequence = Math.max(activeJourney.nextSequence, item.sequence + 1);
    if (item.pageRef) activeJourney.currentPageRef = item.pageRef;
    selectedJourney = activeJourney;
    if (consolePaused || !consoleFollowing) {
      consoleUnseen++;
      if (consoleNewEvents) {
        consoleNewEvents.textContent = consoleUnseen + " new event" + (consoleUnseen === 1 ? "" : "s");
        consoleNewEvents.hidden = false;
      }
      if (consoleEventCount) consoleEventCount.textContent = activeJourney.events.length + " events";
    } else renderCaptureConsole(false);
    return;
  }
  if (message.type !== "journey_state_changed") return;
  if (message.state === "recording" && message.journey) {
    const nextJourney = VulnscanJourneys.normalize(message.journey);
    const previousSequence = activeJourney && activeJourney.events.length ? activeJourney.events[activeJourney.events.length - 1].sequence : 0;
    const newCount = nextJourney ? nextJourney.events.filter(function (event) { return event.sequence > previousSequence; }).length : 0;
    activeJourney = nextJourney;
    selectedJourney = activeJourney;
    findingContext = "journey";
    if ((consolePaused || !consoleFollowing) && newCount) {
      consoleUnseen += newCount;
      if (consoleNewEvents) {
        consoleNewEvents.textContent = consoleUnseen + " new event" + (consoleUnseen === 1 ? "" : "s");
        consoleNewEvents.hidden = false;
      }
    }
    renderJourney(activeJourney);
    return;
  }
  if (message.state === "complete") {
    activeJourney = null;
    selectedJourney = VulnscanJourneys.normalize(message.journey);
    findingContext = "journey";
    renderJourney(selectedJourney);
    loadJourneyHistory(false);
    setStatus("// journey saved and site access released");
    return;
  }
  if (message.state === "discarded") {
    activeJourney = null;
    selectedJourney = null;
    renderJourney(null);
    loadJourneyHistory(true);
  }
});

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
  if (key === "s" && activeView === "scan") { event.preventDefault(); runScan(); }
  if (key === "c" && activeView === "scan") { event.preventDefault(); clearResults(); }
  if (key === "e") { event.preventDefault(); exportRedactedMarkdown(); }
});

chrome.storage.local.get("lastScan", function (data) {
  if (!data.lastScan) return;
  if (!renderFindings(data.lastScan)) {
    chrome.storage.local.remove("lastScan", function () {
      setStatus("This saved result needs a fresh v6.5 scan — the incompatible cache was cleared");
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
  if (lastScanData) {
    applyFilter();
    renderInvestigationQueue();
  }
});
chrome.storage.local.get("journeyConsoleHeight", function (data) {
  if (captureConsole && /^\d{3}px$/.test(data.journeyConsoleHeight || "")) captureConsole.style.height = data.journeyConsoleHeight;
});
updateModeHelp();
loadTabs();
loadJourneyState().catch(function () {});
