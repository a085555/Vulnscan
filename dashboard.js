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

let selectedTabId = null;
let currentFindings = [];
let currentFilter = "all";
let currentBucket = "finding";
let lastScanData = null;
let scanning = false;
let secretVault = [];
let secretVaultUrl = "";
let secretVaultScanId = null;
let activeScanId = null;
let knownTabs = [];

if (brandVersion) {
  brandVersion.textContent = "v" + chrome.runtime.getManifest().version;
}

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

function normalizeScan(scan) {
  if (!scan || scan.schemaVersion !== 2 || !scan.url || !scan.urlFingerprint) return null;
  const findings = VulnscanFindings.dedupe(scan.findings || []);
  return {
    schemaVersion: 2,
    scanId: scan.scanId || null,
    url: scan.url,
    urlFingerprint: scan.urlFingerprint || null,
    timestamp: scan.timestamp || Date.now(),
    findings: findings,
    summary: VulnscanFindings.summarize(findings),
    risk: VulnscanFindings.risk(findings)
  };
}

function clearResults() {
  lastScanData = null;
  currentFindings = [];
  secretVault = [];
  secretVaultUrl = "";
  secretVaultScanId = null;
  chrome.runtime.sendMessage({ type: "clear_export_secrets" }, function () {});
  chrome.storage.local.remove("lastScan");
  resultsEl.innerHTML = '<div class="empty-hint">No findings yet</div>';
  headerResults.innerHTML = '<div class="empty-hint">Run a scan to analyze headers</div>';
  scoreEl.textContent = "—";
  scoreEl.className = "stat-value score";
  findingsCountEl.textContent = "0";
  reviewCountEl.textContent = "0";
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

async function runActiveChecks(pageUrl, scanId) {
  const extra = [];
  const canary = "vxscan" + Date.now().toString(36);
  let parsed;
  try { parsed = new URL(pageUrl); } catch (e) { return extra; }
  const origin = parsed.origin;

  const reflectParams = ["q", "search", "s", "id", "page", "name", "query", "keyword", "term"];
  for (let i = 0; i < reflectParams.length; i++) {
    const param = reflectParams[i];
    try {
      const testUrl = new URL(pageUrl);
      testUrl.searchParams.set(param, canary);
      const response = await fetch(testUrl.toString(), { credentials: "omit", redirect: "manual" });
      const body = await response.text();
      if (body.indexOf(canary) !== -1) {
        extra.push(activeFinding({
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
    } catch (e) {}
  }

  const redirectParams = ["url", "redirect", "next", "return", "returnTo", "goto", "dest", "redirect_uri", "continue"];
  const markerHost = "vxscan-redirect.example";
  const destination = "https://" + markerHost + "/r/" + (scanId || canary);
  const redirectProbes = [];
  for (let i = 0; i < redirectParams.length; i++) {
    const param = redirectParams[i];
    try {
      const testUrl = new URL(pageUrl);
      testUrl.searchParams.set(param, destination);
      redirectProbes.push({ param: param, url: comparableUrl(testUrl.toString()) });
      await fetch(testUrl.toString(), { credentials: "omit", redirect: "manual" });
    } catch (e) {}
  }
  try {
    const redirects = await new Promise(function (resolve) {
      chrome.runtime.sendMessage({ type: "get_redirects", scanId: scanId }, function (response) {
        resolve((response && response.redirects) || []);
      });
    });
    const expected = new URL(destination);
    const match = redirects.find(function (entry) {
      const probe = redirectProbes.find(function (item) {
        return comparableUrl(entry.from) === item.url;
      });
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
  } catch (e) {}

  const commonPaths = [
    "/admin", "/admin/", "/login", "/wp-admin", "/wp-login.php", "/dashboard", "/panel",
    "/.env", "/.git/HEAD", "/.git/config", "/robots.txt", "/sitemap.xml", "/phpinfo.php",
    "/api", "/api/v1", "/graphql", "/swagger", "/actuator", "/actuator/health",
    "/server-status", "/config", "/backup", "/debug", "/console", "/manager"
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
    const baseline = await fetch(origin + missingPath, { credentials: "omit", redirect: "manual" });
    baselineStatus = baseline.status;
    baselineBody = normalizeBody(await baseline.text());
  } catch (e) {}

  const foundPaths = [];
  async function probe(path) {
    const controller = new AbortController();
    const timer = setTimeout(function () { controller.abort(); }, 2200);
    try {
      const response = await fetch(origin + path, {
        method: "GET",
        credentials: "omit",
        redirect: "manual",
        signal: controller.signal
      });
      clearTimeout(timer);
      if (!response.status || response.status === 0 || response.status === 404 || response.status === 410) return;
      if (baselineStatus && response.status === baselineStatus) {
        try {
          const body = normalizeBody(await response.clone().text());
          if (baselineBody && body === baselineBody) return;
          if (baselineBody && body.length > 50 && bodySimilarity(body, baselineBody) >= 0.82) return;
        } catch (e) {}
        if (baselineStatus === 403 || baselineStatus === 404) return;
      }
      foundPaths.push(path + " (" + response.status + ")");
    } catch (e) {
      clearTimeout(timer);
    }
  }

  for (let i = 0; i < commonPaths.length; i += 5) {
    await Promise.all(commonPaths.slice(i, i + 5).map(probe));
    setProgress("path discovery " + Math.min(i + 5, commonPaths.length) + "/" + commonPaths.length);
  }
  if (foundPaths.length) {
    extra.push(activeFinding({
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

  try {
    const response = await fetch(origin + "/robots.txt", { credentials: "omit" });
    if (response.ok) {
      const text = await response.text();
      const sitemap = text.match(/Sitemap:\s*(\S+)/i);
      if (sitemap) {
        extra.push(activeFinding({
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
  } catch (e) {}

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

  const labels = { high: "HIGH", medium: "MED", low: "LOW", review: "REVIEW", info: "OK" };
  scoreEl.textContent = labels[scan.risk] || "OK";
  scoreEl.className = "stat-value score " +
    (scan.risk === "high" ? "bad" : scan.risk === "medium" || scan.risk === "review" ? "mid" : "good");
  applyFilter();
  return true;
}

function applyFilter() {
  let list = currentFindings.filter(function (finding) {
    return finding.bucket === currentBucket;
  });
  if (currentFilter !== "all") {
    list = list.filter(function (finding) { return finding.severity === currentFilter; });
  }
  if (!list.length) {
    const label = currentBucket === "finding" ? "actionable findings" : "items to review";
    resultsEl.innerHTML = '<div class="empty-hint">No ' + label + (currentFilter === "all" ? "" : " in this filter") + "</div>";
    return;
  }

  const severityOrder = { high: 0, medium: 1, low: 2, info: 3 };
  const confidenceOrder = { high: 0, medium: 1, low: 2 };
  list = list.slice().sort(function (left, right) {
    const severity = (severityOrder[left.severity] ?? 9) - (severityOrder[right.severity] ?? 9);
    if (severity) return severity;
    return (confidenceOrder[left.confidence] ?? 9) - (confidenceOrder[right.confidence] ?? 9);
  });

  resultsEl.innerHTML = list.map(function (finding, index) {
    const occurrences = finding.occurrences > 1 ? '<span class="occurrences">×' + finding.occurrences + "</span>" : "";
    return '<div class="finding ' + finding.severity + '">' +
      '<div class="type"><span class="severity ' + finding.severity + '">' + finding.severity + "</span>" +
      '<span class="confidence ' + finding.confidence + '">' + escapeHtml(finding.confidence) + " confidence</span>" +
      '<span class="finding-title">' + escapeHtml(finding.type) + "</span>" + occurrences +
      '<button class="copy-btn" data-idx="' + index + '">copy</button></div>' +
      '<div class="detail">' + escapeHtml(finding.detail) + "</div>" +
      '<details class="finding-context"><summary>Evidence &amp; verification</summary>' +
      '<div><strong>Evidence:</strong> ' + escapeHtml(finding.evidence || "No additional evidence recorded.") + "</div>" +
      '<div><strong>Verify:</strong> ' + escapeHtml(finding.verification || "Review the affected behavior manually.") + "</div>" +
      '<div class="finding-source">' + escapeHtml(finding.category) + " · " + escapeHtml(finding.source) + "</div>" +
      "</details></div>";
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
      schemaVersion: 2,
      url: scan.url,
      risk: scan.risk,
      timestamp: scan.timestamp,
      summary: scan.summary,
      findingsCount: scan.summary.findings,
      reviewCount: scan.summary.review
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
        '<div class="hist-meta">' + escapeHtml(risk) + " · " + findingCount + " findings · " + reviewCount +
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

function reloadTabAndWait(tabId) {
  return new Promise(function (resolve, reject) {
    let settled = false;
    const timer = setTimeout(function () {
      finish(new Error("Timed out waiting for the target page to reload"));
    }, 15000);
    function finish(error, tab) {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      chrome.tabs.onUpdated.removeListener(onUpdated);
      if (error) reject(error);
      else resolve(tab || null);
    }
    function onUpdated(updatedTabId, changeInfo, tab) {
      if (updatedTabId === tabId && changeInfo.status === "complete") finish(null, tab);
    }
    chrome.tabs.onUpdated.addListener(onUpdated);
    chrome.tabs.reload(tabId, {}, function () {
      if (chrome.runtime.lastError) finish(new Error(chrome.runtime.lastError.message));
    });
  });
}

async function waitForScanResult(scanId, pageUrl) {
  const deadline = Date.now() + 5000;
  while (Date.now() < deadline) {
    const stored = await storageGet("lastScan");
    if (stored && stored.schemaVersion === 2 && stored.scanId === scanId && stored.urlFingerprint === urlFingerprint(pageUrl)) {
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
  secretVault = [];
  secretVaultUrl = "";
  secretVaultScanId = null;
  activeScanId = null;
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

    let capturedHeaders = await getCapturedHeaders(tab.id);
    const headersAreCurrent = capturedHeaders.statusCode > 0 && comparableUrl(capturedHeaders.url) === comparableUrl(tab.url);
    if (!headersAreCurrent) {
      setProgress("reloading target once to capture response headers...");
      const reloaded = await reloadTabAndWait(tab.id);
      tab = reloaded || await getSelectedTab();
      if (!tab || !tab.url) throw new Error("The target tab closed while reloading");
      if (new URL(tab.url).origin !== selectedOrigin) {
        await loadTabs();
        setStatus("// target redirected to another site — scan again to grant access");
        setProgress(null);
        return;
      }
      capturedHeaders = await getCapturedHeaders(tab.id);
    }

    activeScanId = "s" + Date.now();
    await new Promise(function (resolve) {
      chrome.runtime.sendMessage({
        type: "scan_begin",
        scanId: activeScanId,
        tabId: tab.id,
        origin: new URL(tab.url).origin
      }, function () { resolve(); });
    });

    showTarget(tab.url, tab.favIconUrl || "");
    setProgress("passive scan...");
    const headerFindings = analyzeHeaders(capturedHeaders.headers || [], tab.url);
    await chrome.scripting.executeScript({
      target: { tabId: tab.id },
      func: function (scanId) { globalThis.__vulnscanScanId = scanId; },
      args: [activeScanId]
    });
    await chrome.scripting.executeScript({
      target: { tabId: tab.id },
      files: ["finding-model.js", "content.js"]
    });

    const passive = await waitForScanResult(activeScanId, tab.url);
    setProgress("active probes + paths...");
    let activeFindings = [];
    try {
      activeFindings = await runActiveChecks(tab.url, activeScanId);
    } catch (e) {}

    const findings = VulnscanFindings.dedupe((passive.findings || []).concat(headerFindings, activeFindings));
    const scan = {
      schemaVersion: 2,
      scanId: activeScanId,
      url: redactUrl(tab.url),
      urlFingerprint: urlFingerprint(tab.url),
      findings: findings,
      summary: VulnscanFindings.summarize(findings),
      risk: VulnscanFindings.risk(findings),
      timestamp: Date.now()
    };
    chrome.storage.local.set({ lastScan: scan });
    saveToHistory(scan);
    renderFindings(scan);
    setProgress(null);
    setStatus("// scan complete — " + scan.summary.findings + " finding(s), " + scan.summary.review + " to review");
  } catch (error) {
    setProgress(null);
    setStatus("// error: " + error.message);
  } finally {
    if (activeScanId) {
      chrome.runtime.sendMessage({ type: "scan_end", scanId: activeScanId }, function () {});
      activeScanId = null;
    }
    scanning = false;
    scanBtn.disabled = false;
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

function secretExportFinding(value) {
  return {
    checkId: "secret.export",
    fingerprint: VulnscanFindings.fingerprint({ checkId: "secret.export", bucket: "finding", type: "Secret value (export)", detail: value }),
    severity: "high",
    confidence: "high",
    bucket: "finding",
    category: "secrets",
    type: "Secret value (export)",
    detail: value,
    evidence: "Full value requested through the explicit export action.",
    verification: "Rotate or revoke the value if it is active and was not intended for client delivery.",
    source: "export",
    occurrences: 1
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

exportBtn.addEventListener("click", function () {
  if (!lastScanData) {
    setStatus("// nothing to export");
    return;
  }
  getExportSecrets(function (vault, available) {
    const findings = lastScanData.findings.filter(function (finding) { return finding.bucket === "finding"; });
    const review = lastScanData.findings.filter(function (finding) { return finding.bucket === "review"; });
    let markdown = "# VulnScan Report\n\n";
    markdown += "**URL:** " + lastScanData.url + "\n\n";
    markdown += "**Risk:** " + lastScanData.risk + "\n\n";
    markdown += "**Time:** " + new Date(lastScanData.timestamp).toISOString() + "\n\n";
    markdown += "## Findings\n\n";
    if (!findings.length) markdown += "No actionable findings.\n";
    findings.forEach(function (finding) {
      markdown += "- **[" + finding.severity.toUpperCase() + "]** " + finding.type + " — " + finding.detail + "\n";
      markdown += "  - Confidence: " + finding.confidence + "\n";
      markdown += "  - Evidence: " + finding.evidence + "\n";
      markdown += "  - Verify: " + finding.verification + "\n";
    });
    markdown += "\n## Review\n\n";
    if (!review.length) markdown += "No additional review items.\n";
    review.forEach(function (finding) {
      markdown += "- **[" + finding.severity.toUpperCase() + "]** " + finding.type + " — " + finding.detail + "\n";
      markdown += "  - Confidence: " + finding.confidence + "\n";
      markdown += "  - Evidence: " + finding.evidence + "\n";
      markdown += "  - Verify: " + finding.verification + "\n";
    });
    if (vault.length) {
      markdown += "\n## Exported Secret Values\n\n";
      vault.forEach(function (secret) { markdown += "- " + secret + "\n"; });
    } else if (!available && lastScanData.findings.some(function (finding) { return finding.category === "secrets"; })) {
      markdown += "\n> Secret values are no longer available in this browser session. Run a fresh scan before exporting them.\n";
      setStatus("// report exported — secret values were unavailable; scan again to include them");
    }
    downloadBlob(markdown, "text/markdown", "vuln-scan-" + Date.now() + ".md");
  });
});

exportBtn.addEventListener("contextmenu", function (event) {
  event.preventDefault();
  if (!lastScanData) return;
  getExportSecrets(function (vault, available) {
    const reportFindings = lastScanData.findings.map(exportFinding).concat(vault.map(function (secret) {
      return secretExportFinding(secret);
    }));
    const report = {
      reportVersion: "2.0",
      schemaVersion: 2,
      url: lastScanData.url,
      scanId: lastScanData.scanId,
      timestamp: lastScanData.timestamp,
      risk: lastScanData.risk,
      summary: lastScanData.summary,
      secretsAvailable: available,
      findings: reportFindings
    };
    downloadBlob(JSON.stringify(report, null, 2), "application/json", "vuln-scan-" + Date.now() + ".json");
  });
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

scanBtn.addEventListener("click", runScan);
clearBtn.addEventListener("click", clearResults);

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

document.addEventListener("keydown", function (event) {
  if (event.target.tagName === "INPUT" || event.target.tagName === "TEXTAREA") return;
  const key = event.key.toLowerCase();
  if (key === "s") { event.preventDefault(); runScan(); }
  if (key === "c") { event.preventDefault(); clearResults(); }
  if (key === "e") { event.preventDefault(); exportBtn.click(); }
});

chrome.storage.local.get("lastScan", function (data) {
  if (!data.lastScan) return;
  if (!renderFindings(data.lastScan)) {
    chrome.storage.local.remove("lastScan", function () {
      setStatus("// v5.2 needs a fresh scan — previous cached results were cleared");
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

loadTabs();

