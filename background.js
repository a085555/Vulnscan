importScripts("finding-model.js");

const headerCache = {};
let redirectCache = {};
let currentScan = null;
const vaultKey = "secretVault";

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
  clearVault();
  chrome.storage.local.get("lastScan", function (data) {
    if (data.lastScan && data.lastScan.schemaVersion !== 2) {
      chrome.storage.local.remove("lastScan");
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
        schemaVersion: 2,
        scanId: message.scanId || null,
        url: redactUrl(message.url),
        urlFingerprint: urlFingerprint(message.url),
        findings: findings,
        timestamp: Date.now(),
        summary: summary,
        risk: VulnscanFindings.risk(findings)
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

  if (message.type === "scan_begin") {
    currentScan = {
      id: message.scanId || ("s" + Date.now()),
      tabId: Number.isInteger(message.tabId) ? message.tabId : null,
      origin: message.origin || null
    };
    redirectCache = {};
    clearVault(function () {
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

