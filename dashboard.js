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

let selectedTabId = null;
let currentFindings = [];
let currentFilter = "all";
let currentBucket = "finding";
let currentSearch = "";
let currentCategory = "all";
let currentConfidence = "all";
let currentSource = "all";
let lastScanData = null;
let scanning = false;
let secretVault = [];
let secretVaultUrl = "";
let secretVaultScanId = null;
let activeScanId = null;
let knownTabs = [];
let currentRequestController = null;
let authorizationResolve = null;
let scanCancelled = false;

if (brandVersion) {
  brandVersion.textContent = "v" + chrome.runtime.getManifest().version;
}
if (aboutVersion) aboutVersion.textContent = "v" + chrome.runtime.getManifest().version;

chrome.runtime.onMessage.addListener(function (message) {
  if (message && message.type === "export_secrets" && message.secrets) {
    secretVault = Array.from(new Set(message.secrets.map(String)));
    secretVaultUrl = message.url || "";
    secretVaultScanId = message.scanId || null;
  }
});

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
  progressEl.textContent = "// " + message;
}

function setStatus(message) {
  statusBar.textContent = message;
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
  try {
    const url = new URL(value);
    url.hash = "";
    return url.href;
  } catch (e) {
    return "";
  }
}

function redactUrl(value) {
  try {
    const url = new URL(value);
    url.username = "";
    url.password = "";
    url.hash = "";
    url.pathname = url.pathname.split("/").map(function (part) {
      return part.length >= 20 && /^[A-Za-z0-9._~-]+$/.test(part) ? "[redacted]" : part;
    }).join("/");
    Array.from(url.searchParams.keys()).forEach(function (name) {
      url.searchParams.set(name, "[redacted]");
    });
    return url.href;
  } catch (e) {
    return "";
  }
}

function urlFingerprint(value) {
  return VulnscanFindings.key(comparableUrl(value));
}

function storageGet(key) {
  return new Promise(function (resolve) {
    chrome.storage.local.get(key, function (data) {
      resolve(data[key] || null);
    });
  });
}

function requestMode() {
  return ["passive", "safe", "lab", "full"].includes(scanModeEl.value) ? scanModeEl.value : "passive";
}

function requestBudget() {
  const value = VulnscanRequests.clampBudget(requestBudgetEl.value);
  requestBudgetEl.value = String(value);
  return value;
}

function estimateRequests(mode) {
  if (mode === "passive") return 0;
  if (mode === "safe") return 13;
  if (mode === "lab") return 25;
  return 38;
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
}

function blankStageSummary(mode) {
  return {
    passive: "pending",
    headers: "pending",
    safe: mode === "safe" || mode === "full" ? "pending" : "skipped",
    lab: mode === "lab" || mode === "full" ? "pending" : "skipped"
  };
}

function normalizeStageSummary(summary, mode) {
  const allowed = ["pending", "running", "complete", "skipped", "stopped", "unavailable"];
  const source = summary && typeof summary === "object" ? summary : blankStageSummary(mode);
  const fallback = blankStageSummary(mode);
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

function confirmActiveScan(origin, mode, budget) {
  const names = { safe: "Safe Active", lab: "Lab", full: "Full Scan" };
  const stageCopy = mode === "full" ? " Passive inspection runs once, followed by Safe Active and Lab stages." : "";
  authorizationDetails.textContent = names[mode] + " mode will send up to " +
    Math.min(budget, estimateRequests(mode)) + " same-origin requests to " + origin + "." + stageCopy +
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
  if (!scan || ![2, 3, 4].includes(scan.schemaVersion) || !scan.url || !scan.urlFingerprint) return null;
  const findings = VulnscanFindings.dedupe(scan.findings || []);
  const mode = ["passive", "safe", "lab", "full"].includes(scan.scanMode) ? scan.scanMode : "legacy";
  return {
    schemaVersion: 4,
    scanId: scan.scanId || null,
    scanMode: mode,
    url: scan.url,
    urlFingerprint: scan.urlFingerprint || null,
    timestamp: scan.timestamp || Date.now(),
    findings: findings,
    summary: VulnscanFindings.summarize(findings),
    risk: VulnscanFindings.risk(findings),
    requestSummary: normalizeRequestSummary(scan.requestSummary, mode),
    stageSummary: normalizeStageSummary(scan.stageSummary, mode)
  };
}

function clearResults() {
  lastScanData = null;
  currentFindings = [];
  secretVault = [];
  secretVaultUrl = "";
  secretVaultScanId = null;
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
  renderStages(null, false);
  renderRequestLog([], null);
  ["sumHigh", "sumMed", "sumLow", "sumInfo"].forEach(function (id) {
    document.getElementById(id).textContent = "0";
  });
  setProgress(null);
  setStatus("// results cleared — open a site tab and hit Scan");
}

function headerFinding(checkId, severity, type, detail, confidence, evidence, verification) {
  return VulnscanFindings.normalize({
    checkId: checkId,
    severity: severity,
    confidence: confidence,
    bucket: "review",
    category: "headers",
    type: type,
    detail: detail,
    evidence: evidence,
    verification: verification,
    source: "headers"
  });
}

function analyzeHeaders(headerList, pageUrl) {
  const values = {};
  (headerList || []).forEach(function (header) {
    const name = String(header.name || "").toLowerCase();
    if (!values[name]) values[name] = [];
    values[name].push(String(header.value || ""));
  });
  const first = function (name) {
    return values[name] && values[name][0] ? values[name][0] : "";
  };
  const review = [];
  const rows = [];

  const csp = first("content-security-policy");
  if (!csp) {
    rows.push(["Content-Security-Policy", "missing", "Missing"]);
    review.push(headerFinding(
      "header.csp.missing", "low", "Content Security Policy missing", "No Content-Security-Policy response header was captured.", "low",
      "The final main-frame response did not include a CSP header.",
      "Confirm whether CSP is delivered by another response path and decide which script, style, frame, and connection sources the application should allow."
    ));
  } else if (/['"]unsafe-inline['"]|['"]unsafe-eval['"]/i.test(csp)) {
    rows.push(["Content-Security-Policy", "weak", "unsafe-inline/eval"]);
    review.push(headerFinding(
      "header.csp.unsafe", "medium", "Content Security Policy allows unsafe script behavior", "The CSP contains unsafe-inline or unsafe-eval.", "medium",
      csp,
      "Confirm which directive contains the unsafe source and test whether nonces, hashes, or bundled scripts can replace it."
    ));
  } else {
    rows.push(["Content-Security-Policy", "ok", "Present"]);
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
  } else {
    rows.push(["Strict-Transport-Security", "ok", "Present"]);
  }

  const xfo = first("x-frame-options");
  const frameAncestors = /(?:^|;)\s*frame-ancestors\s+/i.test(csp);
  if (xfo || frameAncestors) {
    rows.push(["Framing protection", "ok", frameAncestors ? "CSP frame-ancestors" : xfo]);
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
    rows.push(["X-Content-Type-Options", contentTypeOptions ? "weak" : "missing", contentTypeOptions || "Missing"]);
    review.push(headerFinding(
      "header.content-type-options", "low", "MIME sniffing protection missing", "X-Content-Type-Options is not set to nosniff.", "medium",
      contentTypeOptions || "No X-Content-Type-Options header was captured.",
      "Confirm the final response and static assets use correct Content-Type headers before enabling nosniff."
    ));
  }

  [
    ["Referrer-Policy", "referrer-policy", "header.referrer-policy", "Review whether cross-origin requests should receive the full referring URL."],
    ["Permissions-Policy", "permissions-policy", "header.permissions-policy", "Review which browser features the page and its frames need to use."]
  ].forEach(function (check) {
    const value = first(check[1]);
    rows.push([check[0], value ? "ok" : "missing", value || "Missing"]);
    if (!value) {
      review.push(headerFinding(
        check[2], "info", check[0] + " missing", "No " + check[0] + " header was captured.", "low",
        "The final main-frame response did not include this header.", check[3]
      ));
    }
  });

  let html = rows.map(function (row) {
    return '<div class="header-item"><span class="name">' + escapeHtml(row[0]) +
      '</span><span class="status ' + row[1] + '">' + escapeHtml(row[2]) + '</span></div>';
  }).join("");

  const setCookies = values["set-cookie"] || [];
  if (setCookies.length) {
    html += '<div class="header-section">// COOKIES</div>';
    setCookies.forEach(function (cookie) {
      const name = cookie.split("=")[0] || "cookie";
      const missing = [];
      if (!/;\s*secure/i.test(cookie)) missing.push("Secure");
      if (!/;\s*httponly/i.test(cookie)) missing.push("HttpOnly");
      if (!/;\s*samesite=/i.test(cookie)) missing.push("SameSite");
      const status = missing.length === 0 ? "ok" : (missing.length >= 2 ? "missing" : "weak");
      const note = missing.length ? "missing " + missing.join(", ") : "Secure + HttpOnly + SameSite";
      html += '<div class="header-item"><span class="name">' + escapeHtml(name) +
        '</span><span class="status ' + status + '">' + escapeHtml(note) + '</span></div>';
      if (missing.length) {
        review.push(headerFinding(
          "header.cookie-flags", "low", "Cookie flags need review", name + ": " + note, "medium",
          "The Set-Cookie header for " + name + " does not include " + missing.join(", ") + ".",
          "Determine whether this cookie carries sensitive state and which flags are appropriate for its cross-site behavior."
        ));
      }
    });
  }

  headerResults.innerHTML = html || '<div class="empty-hint">No headers captured</div>';
  return VulnscanFindings.dedupe(review);
}

function activeFinding(options) {
  return VulnscanFindings.normalize(Object.assign({ source: "active" }, options));
}

async function runActiveChecks(pageUrl, scanId, requestController, options) {
  const extra = [];
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
  const includeSafe = settings.includeSafe === true || (settings.includeSafe === undefined && (mode === "safe" || mode === "full"));
  const includeLab = settings.includeLab === true || (settings.includeLab === undefined && (mode === "lab" || mode === "full"));
  const onStage = typeof settings.onStage === "function" ? settings.onStage : function () {};

  if (includeSafe) {
    onStage("safe", "running");
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
          verification: "Locate the reflection context and confirm whether output encoding prevents HTML or script interpretation."
        }));
        break;
      }
    }

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
        verification: "Repeat with another controlled HTTPS destination and confirm that no allowlist or interstitial blocks the redirect."
      }));
    }

    if (controller.canRequest()) {
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
          verification: "Open the sitemap and review whether it exposes unexpected application routes."
        }));
      }
    }
    onStage("safe", controller.getSummary().stoppedReason ? "stopped" : "complete");
  }

  if (!includeLab) return VulnscanFindings.dedupe(extra);
  if (!controller.canRequest()) {
    onStage("lab", "stopped");
    return VulnscanFindings.dedupe(extra);
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
      occurrences: foundPaths.length
    }));
  }

  onStage("lab", controller.getSummary().stoppedReason ? "stopped" : "complete");

  return VulnscanFindings.dedupe(extra);
}

function renderFindings(data) {
  const scan = normalizeScan(data);
  if (!scan) return false;
  lastScanData = scan;
  currentFindings = scan.findings;
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
  resultOverviewEl.innerHTML = '<div class="overview-main"><strong>' + escapeHtml(sourceLabel(scan.scanMode)) +
    '</strong><span>' + scan.summary.findings + ' actionable · ' + scan.summary.review + ' review · ' + requestText + '</span></div>' +
    '<div class="overview-categories">' + categories.map(function (category) {
      return '<span>' + escapeHtml(categoryLabel(category)) + ' <strong>' + counts[category] + '</strong></span>';
    }).join("") + "</div>";
  resultOverviewEl.hidden = false;
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
    return '<div class="finding ' + finding.severity + '">' +
      '<div class="type"><span class="severity ' + finding.severity + '">' + finding.severity + "</span>" +
      '<span class="confidence ' + finding.confidence + '">' + escapeHtml(finding.confidence) + " confidence</span>" +
      '<span class="source-badge ' + escapeHtml(finding.source) + '">' + escapeHtml(sourceLabel(finding.source)) + "</span>" +
      '<span class="finding-title">' + escapeHtml(finding.type) + "</span>" + occurrences +
      '<button class="copy-btn" data-idx="' + index + '">copy</button></div>' +
      '<div class="detail">' + escapeHtml(finding.detail) + "</div>" +
      '<details class="finding-context"><summary>Evidence &amp; verification</summary>' +
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
}

function saveToHistory(scan) {
  if (!scan || !scan.url) return;
  chrome.storage.local.get("scanHistory", function (data) {
    const history = data.scanHistory || [];
    history.unshift({
      schemaVersion: 4,
      url: scan.url,
      risk: scan.risk,
      timestamp: scan.timestamp,
      summary: scan.summary,
      findingsCount: scan.summary.findings,
      reviewCount: scan.summary.review,
      scanMode: scan.scanMode,
      requestSummary: scan.requestSummary,
      stageSummary: scan.stageSummary
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
    historyList.innerHTML = history.map(function (entry) {
      const findingCount = Number.isInteger(entry.findingsCount) ? entry.findingsCount : 0;
      const reviewCount = Number.isInteger(entry.reviewCount) ? entry.reviewCount : 0;
      const risk = entry.risk || "legacy";
      return '<div class="hist-item"><div class="hist-url">' + escapeHtml(entry.url) + "</div>" +
        '<div class="hist-meta">' + escapeHtml(entry.scanMode || "legacy") + " · " + escapeHtml(risk) + " · " + findingCount + " findings · " + reviewCount +
        " review · " + new Date(entry.timestamp).toLocaleString() + "</div></div>";
    }).join("");
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

async function waitForScanResult(scanId, pageUrl) {
  const deadline = Date.now() + 5000;
  while (Date.now() < deadline) {
    const stored = await storageGet("lastScan");
    if (stored && stored.schemaVersion === 4 && stored.scanId === scanId && stored.urlFingerprint === urlFingerprint(pageUrl)) {
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
  if (fullScanToggle) fullScanToggle.disabled = true;
  requestBudgetEl.disabled = true;
  cancelScanBtn.hidden = false;
  secretVault = [];
  secretVaultUrl = "";
  secretVaultScanId = null;
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
    stageSummary = blankStageSummary(mode);
    renderStages(stageSummary, true);
    const budget = requestBudget();
    chrome.storage.local.set({ requestBudget: budget });
    const selectedOrigin = new URL(tab.url).origin;
    const originPattern = selectedOrigin + "/*";
    setProgress("requesting access to " + new URL(tab.url).hostname + "...");
    let granted = false;
    try {
      granted = await chrome.permissions.request({ origins: [originPattern] });
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

    if (mode !== "passive") {
      const approved = await confirmActiveScan(selectedOrigin, mode, budget);
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
    await new Promise(function (resolve) {
      chrome.runtime.sendMessage({
        type: "scan_begin",
        scanId: activeScanId,
        tabId: tab.id,
        origin: new URL(tab.url).origin,
        scanMode: mode
      }, function () { resolve(); });
    });

    showTarget(tab.url, tab.favIconUrl || "");
    stageSummary.headers = "running";
    stageSummary.passive = "running";
    renderStages(stageSummary, true);
    setProgress("passive scan...");
    let headerFindings = [];
    if (headersAreCurrent) {
      headerFindings = analyzeHeaders(capturedHeaders.headers || [], tab.url);
      stageSummary.headers = "complete";
    } else {
      headerResults.innerHTML = '<div class="empty-hint">Headers were not captured for this page load. Refresh the target tab, then scan again to include them.</div>';
      stageSummary.headers = "unavailable";
    }
    renderStages(stageSummary, true);
    await chrome.scripting.executeScript({
      target: { tabId: tab.id },
      func: function (scanId, scanMode) {
        globalThis.__vulnscanScanId = scanId;
        globalThis.__vulnscanScanMode = scanMode;
      },
      args: [activeScanId, mode]
    });
    await chrome.scripting.executeScript({
      target: { tabId: tab.id },
      files: ["finding-model.js", "content.js"]
    });

    const passive = await waitForScanResult(activeScanId, tab.url);
    stageSummary.passive = "complete";
    renderStages(stageSummary, true);
    let activeFindings = [];
    let requestSummary = { mode: mode, budget: mode === "passive" ? 0 : budget, attempted: 0, completed: 0, stoppedReason: null };
    let requestEntries = [];
    if (scanCancelled) throw new Error("Scan cancelled");
    if (mode !== "passive") {
      setProgress(mode === "full" ? "running Safe Active, then Lab..." : mode === "lab" ? "controlled path discovery..." : "safe active probes...");
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
        onStage: function (stage, state) {
          stageSummary[stage] = state;
          renderStages(stageSummary, true);
          if (state === "running") setProgress(stage === "safe" ? "safe active checks..." : "soft-404-aware path discovery...");
        }
      });
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

    const findings = VulnscanFindings.dedupe((passive.findings || []).concat(headerFindings, activeFindings));
    const scan = {
      schemaVersion: 4,
      scanId: activeScanId,
      scanMode: mode,
      url: redactUrl(tab.url),
      urlFingerprint: urlFingerprint(tab.url),
      findings: findings,
      summary: VulnscanFindings.summarize(findings),
      risk: VulnscanFindings.risk(findings),
      timestamp: Date.now(),
      requestSummary: requestSummary,
      stageSummary: stageSummary
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
    urlFingerprint: lastScanData.urlFingerprint
  }, function (response) {
    const localMatches = secretVaultScanId === lastScanData.scanId &&
      urlFingerprint(secretVaultUrl) === lastScanData.urlFingerprint;
    const combined = (localMatches ? secretVault : []).concat((response && response.secrets) || []);
    callback(Array.from(new Set(combined)), !!(localMatches || (response && response.available)));
  });
}

function exportFinding(finding) {
  return {
    checkId: finding.checkId,
    fingerprint: finding.fingerprint,
    severity: finding.severity,
    confidence: finding.confidence,
    bucket: finding.bucket,
    category: finding.category,
    type: finding.type,
    detail: finding.detail,
    evidence: finding.evidence,
    verification: finding.verification,
    source: finding.source,
    occurrences: finding.occurrences
  };
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
  markdown += "**Stages:** " + ["passive", "headers", "safe", "lab"].map(function (stage) {
    return categoryLabel(stage) + " " + ((scan.stageSummary && scan.stageSummary[stage]) || "unknown");
  }).join(" · ") + "\n\n";
  markdown += "## Findings\n\n";
  if (!findings.length) markdown += "No actionable findings.\n";
  function appendGroups(items) {
    const categories = Array.from(new Set(items.map(function (finding) { return finding.category; }))).sort();
    categories.forEach(function (category) {
      markdown += "\n### " + categoryLabel(category) + "\n\n";
      items.filter(function (finding) { return finding.category === category; }).forEach(function (finding) {
        markdown += "- **[" + finding.severity.toUpperCase() + "]** " + finding.type + " — " + finding.detail + "\n";
        markdown += "  - Confidence: " + finding.confidence + "\n";
        markdown += "  - Stage: " + sourceLabel(finding.source) + "\n";
        markdown += "  - Evidence: " + finding.evidence + "\n";
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
    reportVersion: "4.0",
    schemaVersion: 4,
    url: scan.url,
    scanId: scan.scanId,
    scanMode: scan.scanMode,
    timestamp: scan.timestamp,
    risk: scan.risk,
    summary: scan.summary,
    requestSummary: scan.requestSummary,
    stageSummary: scan.stageSummary,
    secretsRedacted: true,
    findings: scan.findings.map(exportFinding)
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

if (clearAllDataBtn) {
  clearAllDataBtn.addEventListener("click", function () {
    chrome.storage.local.remove(["lastScan", "scanHistory", "requestBudget"], function () {
      chrome.runtime.sendMessage({ type: "clear_all_session" }, function () {
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

document.addEventListener("keydown", function (event) {
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
      setStatus("// v5.4 needs a fresh scan — incompatible cached results were cleared");
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
updateModeHelp();
loadTabs();
