const headerCache = {};

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
  ["responseHeaders"]
);

// Open dashboard as a full tab when icon is clicked
chrome.action.onClicked.addListener(async function () {
  const url = chrome.runtime.getURL("dashboard.html");
  // focus existing dashboard tab if open
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
    chrome.storage.local.set({
      lastScan: {
        url: message.url,
        findings: message.findings,
        timestamp: Date.now(),
        score: message.score || 0,
        summary: message.summary || {}
      }
    });
    return;
  }

  if (message.type === "get_headers") {
    const data = headerCache[message.tabId] || { headers: [], url: "", statusCode: 0 };
    sendResponse(data);
    return true;
  }

  if (message.type === "get_active_tab") {
    chrome.tabs.query({ active: true, lastFocusedWindow: true }, function (tabs) {
      let tab = (tabs || []).find(function (t) {
        return t.url && !t.url.startsWith("chrome://") && !t.url.startsWith("chrome-extension://") && !t.url.startsWith("edge://");
      });
      if (!tab) {
        chrome.tabs.query({}, function (all) {
          tab = (all || []).find(function (t) {
            return t.url && !t.url.startsWith("chrome://") && !t.url.startsWith("chrome-extension://") && !t.url.startsWith("edge://");
          });
          sendResponse({ tab: tab || null });
        });
        return;
      }
      sendResponse({ tab: tab || null });
    });
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
});
