const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const test = require("node:test");
const vm = require("node:vm");

const modelSource = fs.readFileSync(path.join(__dirname, "..", "finding-model.js"), "utf8");
const urlSource = fs.readFileSync(path.join(__dirname, "..", "url-utils.js"), "utf8");
const guidanceSource = fs.readFileSync(path.join(__dirname, "..", "finding-guidance.js"), "utf8");
const checkSource = fs.readFileSync(path.join(__dirname, "..", "scan-checks.js"), "utf8");
const requestSource = fs.readFileSync(path.join(__dirname, "..", "request-controller.js"), "utf8");
const mapSource = fs.readFileSync(path.join(__dirname, "..", "scan-map.js"), "utf8");
const dashboardSource = fs.readFileSync(path.join(__dirname, "..", "dashboard.js"), "utf8");

function createElement(id, attributes) {
  const element = {
    id: id,
    textContent: "",
    innerHTML: "",
    className: "",
    value: "",
    disabled: false,
    hidden: false,
    checked: false,
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
    querySelector: function () { return null; },
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
  const modeInputs = [
    createElement("mode-passive"),
    createElement("mode-safe"),
    createElement("mode-lab")
  ];
  modeInputs[0].value = "passive";
  modeInputs[0].checked = true;
  modeInputs[1].value = "safe";
  modeInputs[2].value = "lab";
  const checkIds = [
    "passive.inventory", "passive.dom", "passive.secrets", "passive.forms", "passive.transport", "passive.cookies",
    "passive.components", "passive.source", "headers.security", "headers.cookies", "headers.boundaries", "safe.reflection", "safe.redirects",
    "safe.robots", "safe.cors", "safe.source-maps", "lab.paths"
  ];
  const checkToggles = checkIds.map(function (id) {
    const input = createElement("check-" + id);
    input.value = id;
    input.checked = true;
    return input;
  });
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
  let fetchCount = 0;
  const fetchUrls = [];
  let exportSecretsResponse = { secrets: [], available: false };
  let corsProbeResponse = { observed: false, originSent: false, originMatchesExtension: false, originWasNull: false };
  let savedRequestLog = { scanId: null, entries: [], summary: null };
  const sentMessages = [];
  const storage = {};

  const document = {
    getElementById: element,
    querySelectorAll: function (selector) {
      if (selector === ".bucket-filter") return bucketButtons;
      if (selector === ".filter") return filterButtons;
      if (selector === "input[name='scanModeChoice']") return modeInputs;
      if (selector === ".check-toggle") return checkToggles;
      return [];
    },
    addEventListener: function () {},
    createElement: function () { return createElement("download"); }
  };
  const chrome = {
    runtime: {
      lastError: null,
      getURL: function (value) { return "chrome-extension://test/" + (value || ""); },
      getManifest: function () { return { version: "6.4.0" }; },
      onMessage: { addListener: function (listener) { runtimeListener = listener; } },
      sendMessage: function (message, callback) {
        sentMessages.push(message);
        let response = {};
        if (message.type === "list_tabs") response = { tabs: tabsResponse };
        if (message.type === "get_tab") response = { tab: tabResponse };
        if (message.type === "get_headers") response = headerResponse;
        if (message.type === "get_redirects") response = { redirects: redirectResponse };
        if (message.type === "get_export_secrets") response = exportSecretsResponse;
        if (message.type === "get_cors_probe") response = corsProbeResponse;
        if (message.type === "save_request_log") {
          savedRequestLog = { scanId: message.scanId, entries: message.entries, summary: message.summary };
          response = { ok: true };
        }
        if (message.type === "get_request_log") response = savedRequestLog;
        if (message.type === "scan_begin") currentScanId = message.scanId;
        if (callback) callback(response);
      }
    },
    storage: {
      local: {
        get: function (key, callback) { callback({ [key]: storage[key] }); },
        set: function (value, callback) { Object.assign(storage, value); if (callback) callback(); },
        remove: function (key, callback) {
          (Array.isArray(key) ? key : [key]).forEach(function (name) { delete storage[name]; });
          if (callback) callback();
        }
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
            schemaVersion: 8,
            scanId: currentScanId,
            scanMode: "passive",
            url: tabResponse.url,
            urlFingerprint: context.VulnscanFindings.key(tabResponse.url),
            findings: [],
            summary: { high: 0, medium: 0, low: 0, info: 0, review: 0, findings: 0 },
            risk: "info",
            timestamp: Date.now(),
            checksRun: context.VulnscanChecks.effective(checkIds, "passive")
          };
        }
      }
    }
  };
  const context = {
    document: document,
    chrome: chrome,
    navigator: { clipboard: { writeText: async function () {} } },
    fetch: async function (value) {
      fetchCount++;
      fetchUrls.push(String(value || ""));
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
    TextEncoder: TextEncoder,
    TextDecoder: TextDecoder,
    setTimeout: setTimeout,
    clearTimeout: clearTimeout,
    console: console
  };
  vm.createContext(context);
  vm.runInContext(modelSource, context);
  vm.runInContext(urlSource, context);
  vm.runInContext(guidanceSource, context);
  vm.runInContext(checkSource, context);
  vm.runInContext(requestSource, context);
  vm.runInContext(mapSource, context);
  vm.runInContext(dashboardSource, context);
  return {
    context: context,
    element: element,
    bucketButtons: bucketButtons,
    filterButtons: filterButtons,
    modeInputs: modeInputs,
    checkToggles: checkToggles,
    runtimeListener: function () { return runtimeListener; },
    sentMessages: sentMessages,
    storage: storage,
    setRedirects: function (value) { redirectResponse = value; },
    setFetch: function (value) { context.fetch = async function () { fetchCount++; fetchUrls.push(String(arguments[0] || "")); return value.apply(null, arguments); }; },
    setTabResponse: function (value) { tabResponse = value; },
    setExportSecrets: function (value) { exportSecretsResponse = value; },
    setCorsProbe: function (value) { corsProbeResponse = value; },
    getReloadCount: function () { return reloadCount; },
    getFetchCount: function () { return fetchCount; },
    getFetchUrls: function () { return fetchUrls.slice(); }
  };
}

function response(status, body, ok, headers) {
  return {
    status: status,
    ok: ok === undefined ? status >= 200 && status < 300 : ok,
    headers: { get: function (name) { return (headers || {})[String(name).toLowerCase()] || null; } },
    text: async function () { return body || ""; },
    clone: function () { return response(status, body, ok, headers); }
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
    schemaVersion: 4,
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

test("evaluates combined CSP policies and modern cookie constraints", function () {
  const dashboard = createDashboard();
  const findings = dashboard.context.analyzeHeaders([
    { name: "Content-Security-Policy", value: "default-src *; script-src 'unsafe-inline'" },
    { name: "Content-Security-Policy", value: "default-src 'self'; script-src 'self'; frame-ancestors 'self'" },
    { name: "Content-Security-Policy-Report-Only", value: "default-src 'none'" },
    { name: "Strict-Transport-Security", value: "max-age=0" },
    { name: "X-Frame-Options", value: "ALLOW-FROM https://old.example" },
    { name: "Referrer-Policy", value: "unsafe-url" },
    { name: "Set-Cookie", value: "__Host-session=raw-cookie-value; Path=/; SameSite=None" }
  ], "https://example.test/", ["headers.security", "headers.cookies"]);
  assert.equal(findings.some(function (finding) { return finding.checkId === "header.csp.unsafe"; }), false);
  assert.equal(findings.some(function (finding) { return finding.checkId === "header.hsts.disabled"; }), true);
  assert.equal(findings.some(function (finding) { return finding.checkId === "header.framing.invalid"; }), true);
  const cookie = findings.find(function (finding) { return finding.checkId === "header.cookie-flags"; });
  assert.match(cookie.detail, /SameSite=None without Secure|__Host-/);
  assert.doesNotMatch(JSON.stringify(findings), /raw-cookie-value/);
  assert.match(dashboard.element("headerResults").innerHTML, /2 enforced/);
  assert.match(dashboard.element("headerResults").innerHTML, /CSP Report-Only/);
});

test("classifies cross-origin response policies without overstating browser behavior", function () {
  const dashboard = createDashboard();
  const findings = dashboard.context.analyzeHeaders([
    { name: "access-control-allow-origin", value: "*" },
    { name: "access-control-allow-credentials", value: "true" },
    { name: "cross-origin-opener-policy", value: "same-origin" },
    { name: "cross-origin-embedder-policy", value: "unexpected" }
  ], "https://example.test/", ["headers.boundaries"]);
  const contradictory = findings.find(function (finding) { return finding.checkId === "header.cors.wildcard-credentials"; });
  assert.equal(contradictory.bucket, "review");
  assert.match(contradictory.evidence, /reject credentialed reads/i);
  assert.equal(findings.some(function (finding) { return finding.checkId === "header.coep.invalid"; }), true);
  assert.equal(findings.some(function (finding) { return /missing/.test(finding.checkId) && /coop|corp/.test(finding.checkId); }), false);
  assert.match(dashboard.element("headerResults").innerHTML, /status neutral/);
});

test("reports only a browser-observed exact-origin CORS probe", async function () {
  const dashboard = createDashboard();
  dashboard.setCorsProbe({ observed: true, originSent: true, originMatchesExtension: true, originWasNull: false });
  dashboard.setFetch(async function () {
    return response(200, "private response must not be retained", true, {
      "access-control-allow-origin": "chrome-extension://test",
      "access-control-allow-credentials": "true",
      "vary": "Origin"
    });
  });
  const findings = await dashboard.context.runActiveChecks("https://example.test/api", "scan-cors", null, {
    mode: "safe",
    includeSafe: true,
    includeLab: false,
    enabledChecks: ["safe.cors"]
  });
  const cors = findings.find(function (finding) { return finding.checkId === "active.cors.origin-accepted"; });
  assert.equal(cors.bucket, "review");
  assert.doesNotMatch(JSON.stringify(cors), /private response/);
  assert.deepEqual(JSON.parse(JSON.stringify(findings.coverage)), [{
    checkId: "safe.cors", status: "complete", inspected: 1, matched: 1, note: ""
  }]);
});

test("confirms only declared same-origin source maps and retains metadata only", async function () {
  const dashboard = createDashboard();
  const rawSource = "source-content-must-not-be-retained";
  dashboard.setFetch(async function (value) {
    const url = new URL(value);
    if (url.pathname === "/assets/app.js") return response(200, "console.log(1);\n//# sourceMappingURL=app.js.map");
    if (url.pathname === "/assets/app.js.map") return response(200, JSON.stringify({ version: 3, sources: ["src/app.js"], sourcesContent: [rawSource] }));
    return response(404, "");
  });
  const findings = await dashboard.context.runActiveChecks("https://example.test/", "scan-map", null, {
    mode: "safe",
    includeSafe: true,
    includeLab: false,
    enabledChecks: ["safe.source-maps"],
    sourceMapCandidates: { urls: ["https://example.test/assets/app.js"], total: 1, truncated: false }
  });
  const map = findings.find(function (finding) { return finding.checkId === "active.source-map"; });
  assert.equal(map.bucket, "review");
  assert.match(map.detail, /1 source reference/);
  assert.doesNotMatch(JSON.stringify(findings), new RegExp(rawSource));
  assert.equal(dashboard.getFetchCount(), 2);
  assert.equal(findings.coverage[0].status, "complete");
});

test("shows INFO for informational findings and OK only for an empty scan", function () {
  const dashboard = createDashboard();
  const model = dashboard.context.VulnscanFindings;
  const base = {
    schemaVersion: 4,
    scanId: "scan-risk",
    scanMode: "passive",
    url: "https://example.test/",
    urlFingerprint: model.key("https://example.test/"),
    timestamp: Date.now()
  };
  dashboard.context.renderFindings(Object.assign({}, base, { findings: [model.normalize({
    checkId: "info.finding", severity: "info", confidence: "high", bucket: "finding", type: "Informational finding"
  })] }));
  assert.equal(dashboard.element("score").textContent, "INFO");
  dashboard.context.renderFindings(Object.assign({}, base, { findings: [] }));
  assert.equal(dashboard.element("score").textContent, "OK");
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

test("passive mode sends no scanner requests or target reloads", async function () {
  const dashboard = createDashboard();
  await dashboard.context.loadTabs();
  await dashboard.context.runScan();
  assert.equal(dashboard.getReloadCount(), 0);
  assert.equal(dashboard.getFetchCount(), 0);
  assert.equal(dashboard.storage.lastScan.schemaVersion, 8);
  assert.equal(dashboard.storage.lastScan.scanMode, "passive");
  assert.equal(dashboard.sentMessages.some(function (message) { return message.type === "scan_begin"; }), true);
  assert.equal(dashboard.sentMessages.some(function (message) { return message.type === "scan_end"; }), true);
});

test("safe active mode requires confirmation and uses its request budget", async function () {
  const dashboard = createDashboard();
  dashboard.element("scanMode").value = "safe";
  dashboard.element("requestBudget").value = "20";
  await dashboard.context.loadTabs();
  const scan = dashboard.context.runScan();
  await new Promise(function (resolve) { setImmediate(resolve); });
  assert.equal(dashboard.element("authorizationModal").hidden, false);
  assert.equal(dashboard.getFetchCount(), 0);
  dashboard.element("authorizationCheck").checked = true;
  dashboard.element("authorizationCheck").listeners.change();
  dashboard.element("authorizationStart").listeners.click();
  await scan;
  assert.equal(dashboard.getFetchCount(), 14);
  assert.equal(dashboard.storage.lastScan.scanMode, "safe");
  assert.equal(dashboard.storage.lastScan.requestSummary.attempted, 14);
});

test("Full Scan runs Safe Active and Lab once under one shared budget", async function () {
  const dashboard = createDashboard();
  dashboard.element("fullScanToggle").checked = true;
  dashboard.element("fullScanToggle").listeners.change();
  dashboard.element("requestBudget").value = "20";
  assert.equal(dashboard.element("scanMode").value, "full");
  assert.equal(dashboard.element("scanModeSummary").textContent, "Full Scan");

  await dashboard.context.loadTabs();
  const scan = dashboard.context.runScan();
  await new Promise(function (resolve) { setImmediate(resolve); });
  dashboard.element("authorizationCheck").checked = true;
  dashboard.element("authorizationCheck").listeners.change();
  dashboard.element("authorizationStart").listeners.click();
  await scan;

  assert.equal(dashboard.getFetchCount(), 20);
  assert.equal(new Set(dashboard.getFetchUrls()).size, 20);
  assert.equal(dashboard.storage.lastScan.scanMode, "full");
  assert.equal(dashboard.storage.lastScan.requestSummary.mode, "full");
  assert.equal(dashboard.storage.lastScan.stageSummary.safe, "complete");
  assert.equal(dashboard.storage.lastScan.stageSummary.lab, "stopped");
});

test("Lab mode runs path discovery without Safe Active query probes", async function () {
  const dashboard = createDashboard();
  dashboard.element("scanMode").value = "lab";
  dashboard.element("requestBudget").value = "20";
  await dashboard.context.loadTabs();
  const scan = dashboard.context.runScan();
  await new Promise(function (resolve) { setImmediate(resolve); });
  dashboard.element("authorizationCheck").checked = true;
  dashboard.element("authorizationCheck").listeners.change();
  dashboard.element("authorizationStart").listeners.click();
  await scan;

  assert.equal(dashboard.getFetchCount(), 20);
  assert.equal(dashboard.getFetchUrls().every(function (value) { return new URL(value).search === ""; }), true);
  assert.equal(dashboard.storage.lastScan.stageSummary.safe, "skipped");
});

test("selected checks control active requests and the saved check profile", async function () {
  const dashboard = createDashboard();
  dashboard.checkToggles.forEach(function (input) { input.checked = false; });
  dashboard.checkToggles.find(function (input) { return input.value === "passive.secrets"; }).checked = true;
  dashboard.checkToggles.find(function (input) { return input.value === "safe.reflection"; }).checked = true;
  dashboard.checkToggles.find(function (input) { return input.value === "safe.robots"; }).checked = true;
  dashboard.element("scanMode").value = "safe";
  dashboard.element("requestBudget").value = "20";
  await dashboard.context.loadTabs();
  const scan = dashboard.context.runScan();
  await new Promise(function (resolve) { setImmediate(resolve); });
  dashboard.element("authorizationCheck").checked = true;
  dashboard.element("authorizationCheck").listeners.change();
  dashboard.element("authorizationStart").listeners.click();
  await scan;
  assert.equal(dashboard.getFetchCount(), 7);
  assert.deepEqual(Array.from(dashboard.storage.lastScan.checksRun), ["passive.secrets", "safe.reflection", "safe.robots"]);
  assert.equal(dashboard.storage.lastScan.stageSummary.headers, "skipped");
  assert.equal(dashboard.storage.lastScan.stageSummary.lab, "skipped");
});

test("compares with the previous scan using the same target and check profile", function () {
  const dashboard = createDashboard();
  const model = dashboard.context.VulnscanFindings;
  const checks = ["passive.transport"];
  const common = model.normalize({
    checkId: "transport.common", severity: "medium", confidence: "high", bucket: "finding", category: "transport",
    type: "Common", detail: "same", source: "passive"
  });
  const resolved = model.normalize({
    checkId: "transport.old", severity: "medium", confidence: "high", bucket: "finding", category: "transport",
    type: "Old issue", detail: "gone", source: "passive"
  });
  const added = model.normalize({
    checkId: "transport.new", severity: "medium", confidence: "high", bucket: "finding", category: "transport",
    type: "New issue", detail: "appeared", source: "passive"
  });
  const base = {
    schemaVersion: 5,
    scanMode: "passive",
    url: "https://example.test/",
    urlFingerprint: model.key("https://example.test/"),
    checksRun: checks,
    comparisonReady: true,
    requestSummary: { mode: "passive", budget: 0, attempted: 0, completed: 0 },
    stageSummary: { passive: "complete", headers: "skipped", safe: "skipped", lab: "skipped" }
  };
  dashboard.storage.scanHistory = [Object.assign({}, base, {
    scanId: "previous", timestamp: 10, findings: [common, resolved]
  })];
  dashboard.context.renderFindings(Object.assign({}, base, {
    scanId: "current", timestamp: 20, findings: [common, added]
  }));
  assert.match(dashboard.element("comparisonPanel").innerHTML, /1 new/);
  assert.match(dashboard.element("comparisonPanel").innerHTML, /1 resolved/);
  assert.match(dashboard.element("results").innerHTML, /change-badge new/);
  dashboard.element("changeFilter").value = "new";
  dashboard.element("changeFilter").listeners.change();
  assert.match(dashboard.element("results").innerHTML, /New issue/);
  assert.doesNotMatch(dashboard.element("results").innerHTML, /Common/);
  const comparison = model.compare([common, added], [common, resolved]);
  const report = dashboard.context.buildComparisonMarkdown(
    dashboard.context.normalizeScan(Object.assign({}, base, { scanId: "current", timestamp: 20, findings: [common, added] })),
    dashboard.context.normalizeScan(Object.assign({}, base, { scanId: "previous", timestamp: 10, findings: [common, resolved] })),
    { comparison: comparison, comparableStages: ["passive"] }
  );
  assert.match(report, /1 new · 0 changed · 1 resolved/);
  assert.match(report, /New issue/);
  assert.match(report, /Old issue/);
});

test("groups results and applies search, category, confidence, and stage filters", function () {
  const dashboard = createDashboard();
  const model = dashboard.context.VulnscanFindings;
  const first = model.normalize({
    checkId: "one", severity: "medium", confidence: "high", bucket: "finding", category: "transport",
    type: "First result", detail: "mixed content", source: "passive"
  });
  const second = model.normalize({
    checkId: "two", severity: "low", confidence: "medium", bucket: "finding", category: "redirects",
    type: "Second result", detail: "redirect confirmed", source: "safe-active"
  });
  dashboard.context.renderFindings({
    schemaVersion: 4,
    scanId: "scan-filter",
    scanMode: "full",
    url: "https://example.test/",
    urlFingerprint: model.key("https://example.test/"),
    timestamp: Date.now(),
    findings: [first, second]
  });
  assert.match(dashboard.element("results").innerHTML, /Transport/);
  assert.match(dashboard.element("results").innerHTML, /Redirects/);

  dashboard.element("resultSearch").value = "second";
  dashboard.element("resultSearch").listeners.input();
  assert.doesNotMatch(dashboard.element("results").innerHTML, /First result/);
  assert.match(dashboard.element("results").innerHTML, /Second result/);

  dashboard.element("resultSearch").value = "";
  dashboard.element("resultSearch").listeners.input();
  dashboard.element("sourceFilter").value = "passive";
  dashboard.element("sourceFilter").listeners.change();
  assert.match(dashboard.element("results").innerHTML, /First result/);
  assert.doesNotMatch(dashboard.element("results").innerHTML, /Second result/);
});

test("redacted reports never include raw secret values", function () {
  const dashboard = createDashboard();
  const model = dashboard.context.VulnscanFindings;
  const raw = "sk_live_" + "Z".repeat(24);
  const scan = {
    schemaVersion: 4,
    scanId: "scan-export",
    scanMode: "passive",
    url: "https://example.test/",
    urlFingerprint: model.key("https://example.test/"),
    timestamp: Date.now(),
    findings: [model.normalize({
      checkId: "secret.stripe",
      severity: "high",
      confidence: "high",
      bucket: "finding",
      category: "secrets",
      type: "Possible secret",
      detail: "Stripe key (1 distinct value hidden)",
      evidence: "Value hidden"
    })]
  };
  dashboard.context.renderFindings(scan);
  dashboard.setExportSecrets({ secrets: [raw], available: true });
  assert.doesNotMatch(dashboard.context.buildMarkdownReport(scan), new RegExp(raw));
  assert.doesNotMatch(JSON.stringify(dashboard.context.buildJsonReport(scan)), new RegExp(raw));
  assert.equal(dashboard.context.buildJsonReport(scan).reportVersion, "6.4");
  assert.equal(dashboard.sentMessages.some(function (message) { return message.type === "get_export_secrets"; }), false);

  dashboard.element("exportSecretsBtn").listeners.click();
  assert.equal(dashboard.sentMessages.some(function (message) { return message.type === "get_export_secrets"; }), false);
  dashboard.element("secretExportCheck").checked = true;
  dashboard.element("secretExportCheck").listeners.change();
  dashboard.element("secretExportConfirm").listeners.click();
  assert.equal(dashboard.sentMessages.some(function (message) { return message.type === "get_export_secrets"; }), true);
});

test("opens a detailed investigation and persists its local workflow state", function () {
  const dashboard = createDashboard();
  const model = dashboard.context.VulnscanFindings;
  const finding = model.normalize({
    checkId: "active.open-redirect",
    severity: "high",
    confidence: "high",
    bucket: "finding",
    category: "redirects",
    type: "Confirmed open redirect",
    detail: "The next parameter redirected to the controlled destination.",
    evidence: "Exact redirect event matched the scan canary.",
    verification: "Repeat with a controlled HTTPS destination.",
    source: "safe-active"
  });
  const scan = {
    schemaVersion: 6,
    scanId: "scan-investigation",
    scanMode: "safe",
    url: "https://example.test/",
    urlFingerprint: model.key("https://example.test/"),
    timestamp: Date.now(),
    findings: [finding]
  };
  dashboard.context.renderFindings(scan);
  dashboard.context.openFindingDrawer(finding.fingerprint);

  assert.equal(dashboard.element("findingDrawer").hidden, false);
  assert.equal(dashboard.element("findingDrawerTitle").textContent, "Confirmed open redirect");
  assert.match(dashboard.element("findingDrawerBody").innerHTML, /Why it matters/);
  assert.match(dashboard.element("findingDrawerBody").innerHTML, /Recommended action/);
  assert.match(dashboard.element("findingDrawerBody").innerHTML, /Technical details/);

  dashboard.element("findingTriageState").value = "investigating";
  dashboard.element("findingTriageState").listeners.change();
  const saved = Object.values(dashboard.storage.findingTriage);
  assert.equal(saved.length, 1);
  assert.equal(saved[0].status, "investigating");

  dashboard.context.saveWorkflowState(finding, {
    pinned: true,
    note: "local-only context",
    verification: ["complete", "inconclusive"]
  });
  dashboard.context.renderInvestigationQueue();
  assert.match(dashboard.element("investigationQueue").innerHTML, /Confirmed open redirect/);

  const reportFinding = dashboard.context.buildJsonReport(scan).findings[0];
  assert.equal(reportFinding.workflowState, "investigating");
  assert.equal(reportFinding.queued, true);
  assert.deepEqual(Array.from(reportFinding.verificationProgress), ["complete", "inconclusive"]);
  assert.equal(JSON.stringify(reportFinding).includes("local-only context"), false);
  assert.match(reportFinding.impact, /trusted origin|redirect/i);
  assert.match(reportFinding.remediation, /known destinations|relative paths/i);
  assert.equal(reportFinding.investigationSteps.length >= 2, true);
});

test("rejects cached v5.1 scan data", function () {
  const dashboard = createDashboard();
  assert.equal(dashboard.context.normalizeScan({
    url: "https://example.test/",
    findings: [{ severity: "high", type: "Possible secret", detail: "raw-value" }]
  }), null);
});
