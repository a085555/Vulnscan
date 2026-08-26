if (typeof importScripts === "function") {
  importScripts("finding-model.js", "url-utils.js", "scan-checks.js");
}

const headerCache = {};
let redirectCache = {};
let currentScan = null;
const vaultKey = "secretVault";
const requestLogKey = "requestLog";
const scanContextKey = "scanContext";
const redirectLogKey = "redirectLog";
const corsProbeKey = "corsProbe";

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

function isExtensionPage(sender) {
  const base = chrome.runtime.getURL("");
  return !!(sender && sender.url && sender.url.startsWith(base));
}

function validScanSender(message, sender) {
  if (!currentScan || !sender || !sender.tab || sender.tab.id !== currentScan.tabId) return false;
  if (!message.scanId || message.scanId !== currentScan.id) return false;
  try {
    const senderUrl = new URL(sender.url || "");
    return senderUrl.origin === currentScan.origin && comparableUrl(sender.url) === comparableUrl(message.url);
  } catch (e) {
    return false;
  }
}

function cleanFinding(finding) {
  const item = finding && typeof finding === "object" ? finding : {};
  const short = function (value, limit) {
    return String(value === undefined || value === null ? "" : value).slice(0, limit || VulnscanFindings.limits.messageTextCharacters);
  };
  return VulnscanFindings.normalize({
    checkId: short(item.checkId, 120),
    severity: item.severity,
    confidence: item.confidence,
    bucket: item.bucket,
    category: short(item.category, 80),
    type: short(item.type, 240),
    detail: short(item.detail),
    evidence: short(item.evidence),
    verification: short(item.verification),
    location: short(item.location, 1000),
    selector: short(item.selector, 240),
    surfaceRefs: Array.isArray(item.surfaceRefs) ? item.surfaceRefs.slice(0, VulnscanFindings.limits.surfaceRefsPerFinding) : [],
    source: "passive",
    occurrences: Math.min(10000, Math.max(1, Number.parseInt(item.occurrences, 10) || 1))
  });
}

function cleanScanLimits(value) {
  const source = value && typeof value === "object" ? value : {};
  return {
    sourceTruncated: source.sourceTruncated === true,
    domTruncated: source.domTruncated === true,
    findingsTruncated: source.findingsTruncated === true,
    secretsTruncated: source.secretsTruncated === true,
    surfaceTruncated: source.surfaceTruncated === true
  };
}

function cleanSecrets(values) {
  const limits = VulnscanFindings.limits;
  const secrets = [];
  let size = 0;
  const seen = new Set();
  (Array.isArray(values) ? values : []).some(function (value) {
    const secret = String(value);
    if (!secret || secret.length > limits.secretValueCharacters || seen.has(secret)) return false;
    if (secrets.length >= limits.secretValues || size + secret.length > limits.secretVaultCharacters) return true;
    seen.add(secret);
    secrets.push(secret);
    size += secret.length;
    return false;
  });
  return secrets;
}

function clearVault(callback) {
  chrome.storage.session.remove(vaultKey, function () {
    if (callback) callback();
  });
}

function clearSessionData(callback) {
  chrome.storage.session.remove([vaultKey, requestLogKey, scanContextKey, redirectLogKey, corsProbeKey], function () {
    if (callback) callback();
  });
}

function loadScanContext(callback) {
  if (currentScan) {
    callback(currentScan);
    return;
  }
  chrome.storage.session.get(scanContextKey, function (data) {
    const stored = data[scanContextKey];
    if (stored && stored.id && Number.isInteger(stored.tabId) && stored.origin) currentScan = stored;
    callback(currentScan);
  });
}

function cleanRequestSummary(summary, fallbackMode) {
  const source = summary && typeof summary === "object" ? summary : {};
  const mode = ["passive", "safe", "lab", "full", "legacy"].includes(source.mode) ? source.mode : fallbackMode;
  return {
    mode: mode,
    budget: Math.max(0, Math.min(50, Number(source.budget) || 0)),
    attempted: Math.max(0, Number(source.attempted) || 0),
    completed: Math.max(0, Number(source.completed) || 0),
    stoppedReason: source.stoppedReason ? String(source.stoppedReason).slice(0, 100) : null
  };
}

function cleanStageSummary(summary, mode) {
  const source = summary && typeof summary === "object" ? summary : {};
  const allowed = ["pending", "running", "complete", "skipped", "stopped", "unavailable"];
  const active = {
    passive: "complete",
    headers: "unavailable",
    safe: mode === "safe" || mode === "full" ? "pending" : "skipped",
    lab: mode === "lab" || mode === "full" ? "pending" : "skipped"
  };
  Object.keys(active).forEach(function (stage) {
    if (allowed.includes(source[stage])) active[stage] = source[stage];
  });
  return active;
}

function migrateScan(scan) {
  if (!scan || !scan.url || ![2, 3, 4, 5, 6, 7, 8].includes(scan.schemaVersion)) return null;
  const findings = VulnscanFindings.dedupe(scan.findings || []);
  const mode = ["passive", "safe", "lab", "full"].includes(scan.scanMode) ? scan.scanMode : "legacy";
  return {
    schemaVersion: 8,
    scanId: scan.scanId || null,
    scanMode: mode,
    url: redactUrl(scan.url),
    urlFingerprint: urlFingerprint(scan.url),
    legacyUrlFingerprint: scan.legacyUrlFingerprint || (scan.schemaVersion < 7 ? scan.urlFingerprint : null),
    vaultFingerprint: scan.schemaVersion >= 7 ? scan.vaultFingerprint || null : null,
    findings: findings,
    timestamp: scan.timestamp || Date.now(),
    summary: VulnscanFindings.summarize(findings),
    risk: VulnscanFindings.risk(findings),
    requestSummary: cleanRequestSummary(scan.requestSummary, mode),
    stageSummary: cleanStageSummary(scan.stageSummary, mode),
    checksRun: VulnscanChecks.effective(scan.checksRun, mode),
    scanLimits: cleanScanLimits(scan.scanLimits),
    surface: VulnscanFindings.normalizeSurface(scan.surface),
    coverage: VulnscanFindings.normalizeCoverage(scan.coverage)
  };
}

function cleanRequestEntries(entries) {
  return (entries || []).slice(0, 50).map(function (entry) {
    return {
      method: ["GET", "HEAD", "OPTIONS"].includes(entry.method) ? entry.method : "GET",
      url: redactUrl(entry.url),
      status: Number.isInteger(entry.status) ? entry.status : 0,
      durationMs: Number.isFinite(entry.durationMs) ? Math.max(0, Math.round(entry.durationMs)) : 0,
      outcome: String(entry.outcome || "unknown").slice(0, 40)
    };
  });
}

function cleanCapturedHeaders(headers) {
  const allowed = new Set([
    "content-security-policy", "content-security-policy-report-only", "strict-transport-security",
    "x-frame-options", "x-content-type-options", "referrer-policy", "permissions-policy", "set-cookie",
    "access-control-allow-origin", "access-control-allow-credentials", "access-control-allow-methods",
    "access-control-allow-headers", "access-control-expose-headers", "vary",
    "cross-origin-opener-policy", "cross-origin-embedder-policy", "cross-origin-resource-policy"
  ]);
  return (headers || []).slice(0, 200).reduce(function (result, header) {
    const name = String(header.name || "").toLowerCase().slice(0, 120);
    if (!allowed.has(name)) return result;
    let value = String(header.value || "").slice(0, VulnscanFindings.limits.messageTextCharacters);
    if (name === "set-cookie") {
      const separator = value.indexOf(";");
      const pair = separator < 0 ? value : value.slice(0, separator);
      const equals = pair.indexOf("=");
      value = (equals < 0 ? pair : pair.slice(0, equals) + "=[redacted]") + (separator < 0 ? "" : value.slice(separator));
    }
    result.push({ name: name, value: value });
    return result;
  }, []);
}

chrome.webRequest.onBeforeRequest.addListener(
  function (details) {
    if (details.tabId >= 0 && details.type === "main_frame") {
      delete headerCache[details.tabId];
    }
  },
  { urls: ["<all_urls>"], types: ["main_frame"] }
);

function captureResponseHeaders(details) {
  if (details.tabId >= 0 && details.type === "main_frame") {
    headerCache[details.tabId] = {
      headers: cleanCapturedHeaders(details.responseHeaders),
      url: details.url,
      statusCode: details.statusCode
    };
  }
}

try {
  chrome.webRequest.onHeadersReceived.addListener(
    captureResponseHeaders,
    { urls: ["<all_urls>"], types: ["main_frame"] },
    ["responseHeaders", "extraHeaders"]
  );
} catch (error) {
  chrome.webRequest.onHeadersReceived.addListener(
    captureResponseHeaders,
    { urls: ["<all_urls>"], types: ["main_frame"] },
    ["responseHeaders"]
  );
}

function captureCorsProbeHeaders(details) {
  if (!details || !details.url) return;
  loadScanContext(function (scan) {
    if (!scan) return;
    let url;
    try { url = new URL(details.url); } catch (e) { return; }
    if (url.origin !== scan.origin || url.searchParams.get("__vulnscan_cors") !== scan.id) return;
    const originHeader = (details.requestHeaders || []).find(function (header) {
      return String(header.name || "").toLowerCase() === "origin";
    });
    const sent = !!(originHeader && originHeader.value);
    const extensionOrigin = VulnscanUrls.origin(chrome.runtime.getURL(""));
    const evidence = {
      scanId: scan.id,
      observed: true,
      originSent: sent,
      originMatchesExtension: sent && originHeader.value === extensionOrigin,
      originWasNull: sent && originHeader.value === "null"
    };
    chrome.storage.session.set({ [corsProbeKey]: evidence });
  });
}

if (chrome.webRequest.onBeforeSendHeaders) {
  try {
    chrome.webRequest.onBeforeSendHeaders.addListener(
      captureCorsProbeHeaders,
      { urls: ["<all_urls>"], types: ["xmlhttprequest"] },
      ["requestHeaders", "extraHeaders"]
    );
  } catch (error) {
    chrome.webRequest.onBeforeSendHeaders.addListener(
      captureCorsProbeHeaders,
      { urls: ["<all_urls>"], types: ["xmlhttprequest"] },
      ["requestHeaders"]
    );
  }
}

chrome.webRequest.onBeforeRedirect.addListener(
  function (details) {
    if (!details.url || !details.redirectUrl) return;
    loadScanContext(function (scan) {
      if (!scan) return;
      try {
        const from = new URL(details.url);
        if (scan.origin && from.origin !== scan.origin) return;
        const entry = {
          from: details.url,
          to: details.redirectUrl,
          status: details.statusCode,
          tabId: details.tabId,
          scanId: scan.id,
          ts: Date.now()
        };
        redirectCache[details.url + "->" + details.redirectUrl] = entry;
        chrome.storage.session.set({ [redirectLogKey]: redirectCache });
      } catch (e) {}
    });
  },
  { urls: ["<all_urls>"] }
);

chrome.tabs.onRemoved.addListener(function (tabId) {
  delete headerCache[tabId];
});

if (chrome.tabs.onReplaced) {
  chrome.tabs.onReplaced.addListener(function (addedTabId, removedTabId) {
    delete headerCache[removedTabId];
    delete headerCache[addedTabId];
  });
}

chrome.action.onClicked.addListener(function () {
  const url = chrome.runtime.getURL("dashboard.html");
  chrome.tabs.query({ url: url }, function (tabs) {
    if (tabs && tabs.length > 0) {
      chrome.tabs.update(tabs[0].id, { active: true }, function () {});
      chrome.windows.update(tabs[0].windowId, { focused: true }, function () {});
      return;
    }
    chrome.tabs.create({ url: url }, function () {});
  });
});

chrome.runtime.onInstalled.addListener(function () {
  clearSessionData();
  chrome.storage.local.get(["lastScan", "scanHistory"], function (data) {
    const migrated = migrateScan(data.lastScan);
    if (migrated) chrome.storage.local.set({ lastScan: migrated });
    else if (data.lastScan) chrome.storage.local.remove("lastScan");

    if (Array.isArray(data.scanHistory)) {
      const history = data.scanHistory.map(function (entry) {
        const mode = ["passive", "safe", "lab", "full"].includes(entry.scanMode) ? entry.scanMode : "legacy";
        return {
          schemaVersion: 8,
          scanId: entry.scanId || null,
          url: redactUrl(entry.url),
          urlFingerprint: urlFingerprint(entry.url),
          legacyUrlFingerprint: entry.legacyUrlFingerprint || (entry.schemaVersion < 7 ? entry.urlFingerprint || null : null),
          risk: entry.risk || "legacy",
          timestamp: entry.timestamp || Date.now(),
          summary: entry.summary && typeof entry.summary === "object" ? {
            high: Math.max(0, Number(entry.summary.high) || 0),
            medium: Math.max(0, Number(entry.summary.medium) || 0),
            low: Math.max(0, Number(entry.summary.low) || 0),
            info: Math.max(0, Number(entry.summary.info) || 0),
            review: Math.max(0, Number(entry.summary.review) || 0),
            findings: Math.max(0, Number(entry.summary.findings) || 0)
          } : null,
          findingsCount: Number.isInteger(entry.findingsCount) ? entry.findingsCount : 0,
          reviewCount: Number.isInteger(entry.reviewCount) ? entry.reviewCount : 0,
          scanMode: mode,
          requestSummary: entry.requestSummary ? cleanRequestSummary(entry.requestSummary, mode) : null,
          stageSummary: cleanStageSummary(entry.stageSummary, mode),
          checksRun: VulnscanChecks.effective(entry.checksRun, mode),
          findings: VulnscanFindings.dedupe(entry.findings || []),
          scanLimits: cleanScanLimits(entry.scanLimits),
          surface: VulnscanFindings.normalizeSurface(entry.surface),
          coverage: VulnscanFindings.normalizeCoverage(entry.coverage),
          comparisonReady: entry.schemaVersion >= 5 && Array.isArray(entry.findings)
        };
      }).slice(0, 12);
      chrome.storage.local.set({ scanHistory: history });
    }
  });
});

chrome.runtime.onMessage.addListener(function (message, sender, sendResponse) {
  if (!message || typeof message !== "object" || typeof message.type !== "string" || message.type.length > 80) {
    sendResponse({ error: "Invalid message" });
    return true;
  }
  if (message.type !== "scan_results" && message.type !== "export_secrets" && !isExtensionPage(sender)) {
    sendResponse({ error: "Extension page required" });
    return true;
  }

  if (message.type === "scan_results") {
    loadScanContext(function () {
      if (!validScanSender(message, sender)) {
        sendResponse({ error: "Scan context mismatch" });
        return;
      }
      const supplied = Array.isArray(message.findings) ? message.findings.slice(0, VulnscanFindings.limits.findings) : [];
      const findings = VulnscanFindings.dedupe(supplied.map(cleanFinding));
      const summary = VulnscanFindings.summarize(findings);
      const mode = ["passive", "safe", "lab", "full"].includes(message.scanMode) ? message.scanMode : "passive";
      chrome.storage.local.set({
        lastScan: {
          schemaVersion: 8,
          scanId: message.scanId,
          scanMode: mode,
          url: redactUrl(message.url),
          urlFingerprint: urlFingerprint(message.url),
          vaultFingerprint: exactUrlFingerprint(message.url),
          findings: findings,
          timestamp: Date.now(),
          summary: summary,
          risk: VulnscanFindings.risk(findings),
          stageSummary: cleanStageSummary(message.stageSummary, mode),
          checksRun: VulnscanChecks.effective(message.checksRun, mode),
          scanLimits: cleanScanLimits(message.scanLimits),
          surface: VulnscanFindings.normalizeSurface(message.surface),
          coverage: []
        }
      }, function () {
        sendResponse({ ok: true });
      });
    });
    return true;
  }

  if (message.type === "export_secrets") {
    loadScanContext(function () {
      if (!validScanSender(message, sender)) {
        sendResponse({ error: "Scan context mismatch" });
        return;
      }
      const secrets = cleanSecrets(message.secrets);
      const vault = {
        scanId: currentScan.id,
        url: comparableUrl(message.url),
        urlFingerprint: exactUrlFingerprint(message.url),
        secrets: secrets
      };
      chrome.storage.session.set({ [vaultKey]: vault }, function () {
        sendResponse({ ok: true, count: secrets.length });
      });
    });
    return true;
  }

  if (message.type === "get_export_secrets") {
    chrome.storage.session.get(vaultKey, function (data) {
      const vault = data[vaultKey] || null;
      const sameScan = !!message.scanId && vault && vault.scanId === message.scanId;
      const sameUrl = !!message.vaultFingerprint && vault && vault.urlFingerprint === message.vaultFingerprint;
      sendResponse({
        secrets: vault && sameScan && sameUrl ? vault.secrets.slice() : [],
        available: !!(vault && sameScan && sameUrl)
      });
    });
    return true;
  }

  if (message.type === "clear_export_secrets") {
    clearVault(function () { sendResponse({ ok: true }); });
    return true;
  }

  if (message.type === "save_request_log") {
    const requestLog = {
      scanId: message.scanId || null,
      entries: cleanRequestEntries(message.entries),
      summary: message.summary && typeof message.summary === "object" ? cleanRequestSummary(message.summary, "passive") : null
    };
    chrome.storage.session.set({ [requestLogKey]: requestLog }, function () {
      sendResponse({ ok: true, count: requestLog.entries.length });
    });
    return true;
  }

  if (message.type === "get_request_log") {
    chrome.storage.session.get(requestLogKey, function (data) {
      const requestLog = data[requestLogKey] || null;
      const matches = requestLog && (!message.scanId || requestLog.scanId === message.scanId);
      sendResponse(matches ? requestLog : { scanId: null, entries: [], summary: null });
    });
    return true;
  }

  if (message.type === "clear_request_log") {
    chrome.storage.session.remove(requestLogKey, function () { sendResponse({ ok: true }); });
    return true;
  }

  if (message.type === "clear_all_session") {
    currentScan = null;
    clearSessionData(function () { sendResponse({ ok: true }); });
    return true;
  }

  if (message.type === "scan_begin") {
    let origin = "";
    try { origin = new URL(message.origin).origin; } catch (e) {}
    if (!message.scanId || String(message.scanId).length > 100 || !Number.isInteger(message.tabId) || !origin || origin !== message.origin) {
      sendResponse({ error: "Invalid scan context" });
      return true;
    }
    currentScan = {
      id: message.scanId,
      tabId: message.tabId,
      origin: origin
    };
    redirectCache = {};
    clearSessionData(function () {
      chrome.storage.session.set({ [scanContextKey]: currentScan }, function () {
        sendResponse({ ok: true, scanId: currentScan.id });
      });
    });
    return true;
  }

  if (message.type === "scan_end") {
    if (!message.scanId || (currentScan && currentScan.id === message.scanId)) {
      currentScan = null;
    }
    chrome.storage.session.remove(scanContextKey, function () { sendResponse({ ok: true }); });
    return true;
  }

  if (message.type === "get_headers") {
    sendResponse(headerCache[message.tabId] || { headers: [], url: "", statusCode: 0 });
    return true;
  }

  if (message.type === "get_redirects") {
    chrome.storage.session.get(redirectLogKey, function (data) {
      if (!Object.keys(redirectCache).length && data[redirectLogKey]) redirectCache = data[redirectLogKey];
      const out = Object.keys(redirectCache).map(function (key) {
        return redirectCache[key];
      }).filter(function (entry) {
        return !message.scanId || entry.scanId === message.scanId;
      });
      sendResponse({ redirects: out });
    });
    return true;
  }

  if (message.type === "get_cors_probe") {
    chrome.storage.session.get(corsProbeKey, function (data) {
      const evidence = data[corsProbeKey];
      const matches = evidence && message.scanId && evidence.scanId === message.scanId;
      sendResponse(matches ? {
        observed: evidence.observed === true,
        originSent: evidence.originSent === true,
        originMatchesExtension: evidence.originMatchesExtension === true,
        originWasNull: evidence.originWasNull === true
      } : { observed: false, originSent: false, originMatchesExtension: false, originWasNull: false });
    });
    return true;
  }

  if (message.type === "list_tabs") {
    chrome.tabs.query({}, function (tabs) {
      const list = (tabs || []).filter(function (tab) {
        return tab.url &&
          !tab.url.startsWith("chrome://") &&
          !tab.url.startsWith("chrome-extension://") &&
          !tab.url.startsWith("edge://") &&
          !tab.url.startsWith("about:") &&
          !tab.url.startsWith("devtools://");
      }).map(function (tab) {
        return {
          id: tab.id,
          title: tab.title || tab.url,
          url: tab.url,
          active: !!tab.active,
          favIconUrl: tab.favIconUrl || ""
        };
      });
      sendResponse({ tabs: list });
    });
    return true;
  }

  if (message.type === "get_tab") {
    chrome.tabs.get(message.tabId, function (tab) {
      if (chrome.runtime.lastError) {
        sendResponse({ tab: null, error: chrome.runtime.lastError.message });
        return;
      }
      sendResponse({ tab: tab || null });
    });
    return true;
  }
});
