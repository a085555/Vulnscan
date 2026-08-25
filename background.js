const headerCache = {};
let redirectCache = {};
let currentScan = null;
let secretVaultMemory = [];

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
  { urls: ["<all_urls>"] },
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
        scanId: currentScan ? currentScan.id : null,
        ts: Date.now()
      };
      const key = details.url + "->" + details.redirectUrl;
      redirectCache[key] = entry;
    } catch (e) {}
  },
  { urls: ["<all_urls>"] }
);

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

chrome.runtime.onMessage.addListener(function (message, sender, sendResponse) {
  if (message.type === "scan_results") {
    // never write raw secrets to storage
    const findings = (message.findings || []).map(function (f) {
      return {
        severity: f.severity,
        type: f.type,
        detail: f.detail
      };
    });
    chrome.storage.local.set({
      lastScan: {
        url: message.url,
        findings: findings,
        timestamp: Date.now(),
        summary: message.summary || {},
        risk: message.risk || "info"
      }
    });
    return;
  }

  if (message.type === "export_secrets") {
    secretVaultMemory = (message.secrets || []).slice();
    return;
  }

  if (message.type === "get_export_secrets") {
    sendResponse({ secrets: secretVaultMemory.slice() });
    return true;
  }

  if (message.type === "clear_export_secrets") {
    secretVaultMemory = [];
    sendResponse({ ok: true });
    return true;
  }

  if (message.type === "scan_begin") {
    secretVaultMemory = [];
    currentScan = {
      id: message.scanId || ("s" + Date.now()),
      tabId: Number.isInteger(message.tabId) ? message.tabId : null,
      origin: message.origin || null
    };
    // drop old redirects
    redirectCache = {};
    sendResponse({ ok: true, scanId: currentScan.id });
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
    const scanId = message.scanId;
    const out = [];
    Object.keys(redirectCache).forEach(function (k) {
      const e = redirectCache[k];
      if (scanId && e.scanId !== scanId) return;
      out.push(e);
    });
    sendResponse({ redirects: out });
    return true;
  }

  if (message.type === "list_tabs") {
    chrome.tabs.query({}, function (tabs) {
      const list = (tabs || [])
        .filter(function (t) {
          return t.url &&
            !t.url.startsWith("chrome://") &&
            !t.url.startsWith("chrome-extension://") &&
            !t.url.startsWith("edge://") &&
            !t.url.startsWith("about:") &&
            !t.url.startsWith("devtools://");
        })
        .map(function (t) {
          return {
            id: t.id,
            title: t.title || t.url,
            url: t.url,
            active: !!t.active,
            favIconUrl: t.favIconUrl || ""
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

  if (message.type === "get_active_tab") {
    chrome.tabs.query({ active: true, lastFocusedWindow: true }, function (tabs) {
      let tab = (tabs || []).find(function (t) {
        return t.url && !t.url.startsWith("chrome://") && !t.url.startsWith("chrome-extension://");
      });
      sendResponse({ tab: tab || null });
    });
    return true;
  }
});
