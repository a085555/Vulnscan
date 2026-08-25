const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const test = require("node:test");
const vm = require("node:vm");

const modelSource = fs.readFileSync(path.join(__dirname, "..", "finding-model.js"), "utf8");
const dashboardSource = fs.readFileSync(path.join(__dirname, "..", "dashboard.js"), "utf8");

function createElement(id, attributes) {
  const element = {
    id: id,
    textContent: "",
    innerHTML: "",
    className: "",
    value: "",
    disabled: false,
    src: "",
    style: {},
    listeners: {},
    attributes: attributes || {},
    classList: {
      add: function () {},
      remove: function () {},
      contains: function () { return false; },
      toggle: function () {}
    },
    addEventListener: function (name, listener) { element.listeners[name] = listener; },
    querySelectorAll: function () { return []; },
    removeAttribute: function () {},
    getAttribute: function (name) { return element.attributes[name] || null; },
    setAttribute: function (name, value) { element.attributes[name] = value; },
    click: function () { if (element.listeners.click) element.listeners.click({ preventDefault: function () {} }); }
  };
  return element;
}

function createDashboard() {
  const elements = new Map();
  const element = function (id) {
    if (!elements.has(id)) elements.set(id, createElement(id));
    return elements.get(id);
  };
  const bucketButtons = [
    createElement("bucket-findings", { "data-bucket": "finding" }),
    createElement("bucket-review", { "data-bucket": "review" })
  ];
  const filterButtons = [
    createElement("filter-all", { "data-sev": "all" }),
    createElement("filter-high", { "data-sev": "high" })
  ];
  let runtimeListener = null;
  let onUpdatedListener = null;
  let currentScanId = null;
  let redirectResponse = [];
  let tabsResponse = [{
    id: 3,
    title: "Example",
    url: "https://example.test/",
    active: true,
    favIconUrl: ""
  }];
  let tabResponse = tabsResponse[0];
  let headerResponse = { headers: [], url: "", statusCode: 0 };
  let reloadCount = 0;
  const sentMessages = [];
  const storage = {};

  const document = {
    getElementById: element,
    querySelectorAll: function (selector) {
      if (selector === ".bucket-filter") return bucketButtons;
      if (selector === ".filter") return filterButtons;
      return [];
    },
    addEventListener: function () {},
    createElement: function () { return createElement("download"); }
  };
  const chrome = {
    runtime: {
      lastError: null,
      getManifest: function () { return { version: "5.2.0" }; },
      onMessage: { addListener: function (listener) { runtimeListener = listener; } },
      sendMessage: function (message, callback) {
        sentMessages.push(message);
        let response = {};
        if (message.type === "list_tabs") response = { tabs: tabsResponse };
        if (message.type === "get_tab") response = { tab: tabResponse };
        if (message.type === "get_headers") response = headerResponse;
        if (message.type === "get_redirects") response = { redirects: redirectResponse };
        if (message.type === "get_export_secrets") response = { secrets: [], available: false };
        if (message.type === "scan_begin") currentScanId = message.scanId;
        if (callback) callback(response);
      }
    },
    storage: {
      local: {
        get: function (key, callback) { callback({ [key]: storage[key] }); },
        set: function (value, callback) { Object.assign(storage, value); if (callback) callback(); },
        remove: function (key, callback) { delete storage[key]; if (callback) callback(); }
      }
    },
    tabs: {
      onUpdated: {
        addListener: function (listener) { onUpdatedListener = listener; },
        removeListener: function (listener) { if (onUpdatedListener === listener) onUpdatedListener = null; }
      },
      reload: function (tabId, options, callback) {
        reloadCount++;
        headerResponse = {
          headers: [{ name: "content-security-policy", value: "default-src 'self'; frame-ancestors 'self'" }],
          url: tabResponse.url,
          statusCode: 200
        };
        if (callback) callback();
        if (onUpdatedListener) onUpdatedListener(tabId, { status: "complete" }, tabResponse);
      }
    },
    permissions: { request: async function () { return true; } },
    scripting: {
      executeScript: async function (options) {
        if (options.files && options.files.includes("content.js")) {
          storage.lastScan = {
            schemaVersion: 2,
            scanId: currentScanId,
            url: tabResponse.url,
            urlFingerprint: context.VulnscanFindings.key(tabResponse.url),
            findings: [],
            summary: { high: 0, medium: 0, low: 0, info: 0, review: 0, findings: 0 },
            risk: "info",
            timestamp: Date.now()
          };
        }
      }
    }
  };
  const context = {
    document: document,
    chrome: chrome,
    navigator: { clipboard: { writeText: async function () {} } },
    fetch: async function () {
      return {
        status: 404,
        ok: false,
        text: async function () { return ""; },
        clone: function () { return this; }
      };
    },
    URL: URL,
    Blob: Blob,
    AbortController: AbortController,
    setTimeout: setTimeout,
    clearTimeout: clearTimeout,
    console: console
  };
  vm.createContext(context);
  vm.runInContext(modelSource, context);
  vm.runInContext(dashboardSource, context);
  return {
    context: context,
    element: element,
    bucketButtons: bucketButtons,
    filterButtons: filterButtons,
    runtimeListener: function () { return runtimeListener; },
    sentMessages: sentMessages,
    storage: storage,
    setRedirects: function (value) { redirectResponse = value; },
    setFetch: function (value) { context.fetch = value; },
    setTabResponse: function (value) { tabResponse = value; },
    getReloadCount: function () { return reloadCount; }
  };
}

function response(status, body, ok) {
  return {
    status: status,
    ok: ok === undefined ? status >= 200 && status < 300 : ok,
    text: async function () { return body || ""; },
    clone: function () { return response(status, body, ok); }
  };
}

test("renders actionable and review counts separately", function () {
  const dashboard = createDashboard();
  const model = dashboard.context.VulnscanFindings;
  const review = model.normalize({
    checkId: "source.clue",
    severity: "high",
    confidence: "low",
    bucket: "review",
    category: "source",
    type: "Review clue",
    detail: "clue",
    evidence: "evidence",
    verification: "verify"
  });
  dashboard.context.renderFindings({
    schemaVersion: 2,
    scanId: "scan-1",
    url: "https://example.test/",
    urlFingerprint: model.key("https://example.test/"),
    timestamp: Date.now(),
    findings: [review]
  });
  assert.equal(dashboard.element("score").textContent, "REVIEW");
  assert.equal(dashboard.element("findingsCount").textContent, 0);
  assert.equal(dashboard.element("reviewCount").textContent, 1);
  dashboard.bucketButtons[1].listeners.click();
  assert.match(dashboard.element("results").innerHTML, /Review clue/);
  assert.match(dashboard.element("results").innerHTML, /Evidence &amp; verification/);
});

test("requires exact generated redirect evidence", async function () {
  const dashboard = createDashboard();
  const destination = "https://vxscan-redirect.example/r/scan-1";
  dashboard.setRedirects([{
    from: "https://example.test/ambient",
    to: destination,
    scanId: "scan-1"
  }]);
  let findings = await dashboard.context.runActiveChecks("https://example.test/", "scan-1");
  assert.equal(findings.some(function (finding) { return finding.checkId === "active.open-redirect"; }), false);

  const probe = new URL("https://example.test/");
  probe.searchParams.set("next", destination);
  dashboard.setRedirects([{ from: probe.href, to: destination, scanId: "scan-1" }]);
  findings = await dashboard.context.runActiveChecks("https://example.test/", "scan-1");
  const redirect = findings.find(function (finding) { return finding.checkId === "active.open-redirect"; });
  assert.equal(redirect.bucket, "finding");
  assert.match(redirect.detail, /next/);
});

test("filters dynamic soft-404 templates", async function () {
  const dashboard = createDashboard();
  const common = " The requested page was not found. Return to the home page. ".repeat(12);
  dashboard.setFetch(async function (value) {
    const url = new URL(value);
    if (url.search) return response(200, "ordinary response");
    if (url.pathname.startsWith("/vxscan-not-a-real-path-")) {
      return response(200, "request id AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" + common);
    }
    if (url.pathname === "/robots.txt") {
      return response(200, "request id BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB" + common);
    }
    return response(200, "request id BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB" + common);
  });
  const findings = await dashboard.context.runActiveChecks("https://example.test/", "scan-soft");
  assert.equal(findings.some(function (finding) { return finding.checkId === "active.interesting-paths"; }), false);

  dashboard.setFetch(async function (value) {
    const url = new URL(value);
    if (url.search) return response(200, "ordinary response");
    if (url.pathname.startsWith("/vxscan-not-a-real-path-")) {
      return response(200, "request id AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" + common);
    }
    if (url.pathname === "/admin") {
      return response(200, "Administration console Sign in to manage users roles settings audit logs and deployments");
    }
    return response(200, "request id BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB" + common);
  });
  const distinct = await dashboard.context.runActiveChecks("https://example.test/", "scan-real");
  const paths = distinct.find(function (finding) { return finding.checkId === "active.interesting-paths"; });
  assert.match(paths.detail, /\/admin \(200\)/);
});

test("reloads once for fresh headers and scopes passive results to the scan", async function () {
  const dashboard = createDashboard();
  await dashboard.context.loadTabs();
  await dashboard.context.runScan();
  assert.equal(dashboard.getReloadCount(), 1);
  assert.equal(dashboard.storage.lastScan.schemaVersion, 2);
  assert.equal(dashboard.sentMessages.some(function (message) { return message.type === "scan_begin"; }), true);
  assert.equal(dashboard.sentMessages.some(function (message) { return message.type === "scan_end"; }), true);
});

test("rejects cached v5.1 scan data", function () {
  const dashboard = createDashboard();
  assert.equal(dashboard.context.normalizeScan({
    url: "https://example.test/",
    findings: [{ severity: "high", type: "Possible secret", detail: "raw-value" }]
  }), null);
});

