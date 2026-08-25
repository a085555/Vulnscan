importScripts("finding-model.js");

const headerCache = {};
let redirectCache = {};
let currentScan = null;
const vaultKey = "secretVault";
const requestLogKey = "requestLog";

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

function isExtensionPage(sender) {
  const base = chrome.runtime.getURL("");
  return !!(sender && sender.url && sender.url.startsWith(base));
}

function clearVault(callback) {
  chrome.storage.session.remove(vaultKey, function () {
    if (callback) callback();
  });
}

function clearSessionData(callback) {
  chrome.storage.session.remove([vaultKey, requestLogKey], function () {
    if (callback) callback();
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
  if (!scan || !scan.url || !scan.urlFingerprint || ![2, 3, 4].includes(scan.schemaVersion)) return null;
  const findings = VulnscanFindings.dedupe(scan.findings || []);
  const mode = ["passive", "safe", "lab", "full"].includes(scan.scanMode) ? scan.scanMode : "legacy";
  return {
    schemaVersion: 4,
    scanId: scan.scanId || null,
    scanMode: mode,
    url: redactUrl(scan.url),
    urlFingerprint: scan.urlFingerprint,
    findings: findings,
    timestamp: scan.timestamp || Date.now(),
    summary: VulnscanFindings.summarize(findings),
    risk: VulnscanFindings.risk(findings),
    requestSummary: cleanRequestSummary(scan.requestSummary, mode),
    stageSummary: cleanStageSummary(scan.stageSummary, mode)
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

chrome.webRequest.onBeforeRequest.addListener(
  function (details) {
    if (details.tabId >= 0 && details.type === "main_frame") {
      delete headerCache[details.tabId];
    }
  },
  { urls: ["<all_urls>"], types: ["main_frame"] }
);

chrome.webRequest.onHeadersReceived.addListener(
  function (details) {
    if (details.tabId >= 0 && details.type === "main_frame") {
      headerCache[details.tabId] = {
        headers: details.responseHeaders || [],
        url: details.url,
        statusCode: details.statusCode
      };
    }
  },
  { urls: ["<all_urls>"], types: ["main_frame"] },
  ["responseHeaders", "extraHeaders"]
);

chrome.webRequest.onBeforeRedirect.addListener(
  function (details) {
    if (!currentScan || !details.url || !details.redirectUrl) return;
    try {
      const from = new URL(details.url);
      if (currentScan.origin && from.origin !== currentScan.origin) return;
      const entry = {
        from: details.url,
        to: details.redirectUrl,
        status: details.statusCode,
        tabId: details.tabId,
        scanId: currentScan.id,
        ts: Date.now()
      };
      redirectCache[details.url + "->" + details.redirectUrl] = entry;
    } catch (e) {}
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

chrome.action.onClicked.addListener(async function () {
  const url = chrome.runtime.getURL("dashboard.html");
  const tabs = await chrome.tabs.query({ url: url });
  if (tabs && tabs.length > 0) {
    await chrome.tabs.update(tabs[0].id, { active: true });
    await chrome.windows.update(tabs[0].windowId, { focused: true });
  } else {
    await chrome.tabs.create({ url: url });
  }
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
          schemaVersion: 4,
          url: redactUrl(entry.url),
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
          stageSummary: cleanStageSummary(entry.stageSummary, mode)
        };
      }).slice(0, 12);
      chrome.storage.local.set({ scanHistory: history });
    }
  });
});

chrome.runtime.onMessage.addListener(function (message, sender, sendResponse) {
  if (message.type !== "scan_results" && message.type !== "export_secrets" && !isExtensionPage(sender)) {
    sendResponse({ error: "Extension page required" });
    return true;
  }

  if (message.type === "scan_results") {
    const findings = VulnscanFindings.dedupe(message.findings || []);
    const summary = VulnscanFindings.summarize(findings);
    chrome.storage.local.set({
      lastScan: {
        schemaVersion: 4,
        scanId: message.scanId || null,
        scanMode: ["passive", "safe", "lab", "full"].includes(message.scanMode) ? message.scanMode : "passive",
        url: redactUrl(message.url),
        urlFingerprint: urlFingerprint(message.url),
        findings: findings,
        timestamp: Date.now(),
        summary: summary,
        risk: VulnscanFindings.risk(findings),
        stageSummary: cleanStageSummary(message.stageSummary, message.scanMode)
      }
    }, function () {
      sendResponse({ ok: true });
    });
    return true;
  }

  if (message.type === "export_secrets") {
    const secrets = Array.from(new Set((message.secrets || []).map(String)));
    const vault = {
      scanId: message.scanId || (currentScan && currentScan.id) || null,
      url: message.url || "",
      urlFingerprint: urlFingerprint(message.url),
      secrets: secrets
    };
    chrome.storage.session.set({ [vaultKey]: vault }, function () {
      sendResponse({ ok: true, count: secrets.length });
    });
    return true;
  }

  if (message.type === "get_export_secrets") {
    chrome.storage.session.get(vaultKey, function (data) {
      const vault = data[vaultKey] || null;
      const sameScan = !!message.scanId && vault && vault.scanId === message.scanId;
      const sameUrl = !!message.urlFingerprint && vault && vault.urlFingerprint === message.urlFingerprint;
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
    clearSessionData(function () { sendResponse({ ok: true }); });
    return true;
  }

  if (message.type === "scan_begin") {
    currentScan = {
      id: message.scanId || ("s" + Date.now()),
      tabId: Number.isInteger(message.tabId) ? message.tabId : null,
      origin: message.origin || null
    };
    redirectCache = {};
    clearSessionData(function () {
      sendResponse({ ok: true, scanId: currentScan.id });
    });
    return true;
  }

  if (message.type === "scan_end") {
    if (!message.scanId || (currentScan && currentScan.id === message.scanId)) {
      currentScan = null;
    }
    sendResponse({ ok: true });
    return true;
  }

  if (message.type === "get_headers") {
    sendResponse(headerCache[message.tabId] || { headers: [], url: "", statusCode: 0 });
    return true;
  }

  if (message.type === "get_redirects") {
    const out = Object.keys(redirectCache).map(function (key) {
      return redirectCache[key];
    }).filter(function (entry) {
      return !message.scanId || entry.scanId === message.scanId;
    });
    sendResponse({ redirects: out });
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
