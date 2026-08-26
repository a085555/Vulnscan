const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const test = require("node:test");
const vm = require("node:vm");

const modelSource = fs.readFileSync(path.join(__dirname, "..", "finding-model.js"), "utf8");
const checkSource = fs.readFileSync(path.join(__dirname, "..", "scan-checks.js"), "utf8");
const backgroundSource = fs.readFileSync(path.join(__dirname, "..", "background.js"), "utf8");

function createWorker(shared) {
  const state = shared || { local: {}, session: {} };
  const listeners = {};
  const chrome = {
    webRequest: {
      onBeforeRequest: { addListener: function (listener) { listeners.beforeRequest = listener; } },
      onHeadersReceived: { addListener: function (listener) { listeners.headers = listener; } },
      onBeforeRedirect: { addListener: function (listener) { listeners.redirect = listener; } }
    },
    action: { onClicked: { addListener: function () {} } },
    runtime: {
      getURL: function (value) { return "chrome-extension://test/" + value; },
      onMessage: { addListener: function (listener) { listeners.message = listener; } },
      onInstalled: { addListener: function (listener) { listeners.installed = listener; } },
      lastError: null
    },
    storage: {
      local: {
        set: function (value, callback) { Object.assign(state.local, value); if (callback) callback(); },
        get: function (key, callback) {
          const keys = Array.isArray(key) ? key : [key];
          const result = {};
          keys.forEach(function (name) { result[name] = state.local[name]; });
          callback(result);
        },
        remove: function (key, callback) {
          (Array.isArray(key) ? key : [key]).forEach(function (name) { delete state.local[name]; });
          if (callback) callback();
        }
      },
      session: {
        set: function (value, callback) { Object.assign(state.session, value); if (callback) callback(); },
        get: function (key, callback) { callback({ [key]: state.session[key] }); },
        remove: function (key, callback) {
          (Array.isArray(key) ? key : [key]).forEach(function (name) { delete state.session[name]; });
          if (callback) callback();
        }
      }
    },
    tabs: {
      query: async function () { return []; },
      update: async function () {},
      create: async function () {},
      get: function () {},
      onRemoved: { addListener: function (listener) { listeners.removed = listener; } },
      onReplaced: { addListener: function (listener) { listeners.replaced = listener; } }
    },
    windows: { update: async function () {} }
  };
  const context = { chrome: chrome, URL: URL, Date: Date, importScripts: function () {} };
  vm.createContext(context);
  vm.runInContext(modelSource, context);
  vm.runInContext(checkSource, context);
  vm.runInContext(backgroundSource, context);

  function send(message, sender) {
    return new Promise(function (resolve) {
      let resolved = false;
      const response = function (value) {
        resolved = true;
        resolve(value);
      };
      const pending = listeners.message(message, sender || { url: "chrome-extension://test/dashboard.html" }, response);
      if (pending !== true && !resolved) resolve(undefined);
    });
  }
  return { state: state, listeners: listeners, send: send, model: context.VulnscanFindings };
}

function contentSender(tabId, url) {
  return { tab: { id: tabId }, url: url };
}

test("keeps raw secrets in session storage across worker restarts", async function () {
  const shared = { local: {}, session: {} };
  const first = createWorker(shared);
  await first.send({ type: "scan_begin", scanId: "scan-1", tabId: 7, origin: "https://example.test" });
  await first.send({
    type: "export_secrets",
    scanId: "scan-1",
    url: "https://example.test/page",
    secrets: ["Stripe: raw-one", "Stripe: raw-one", "Stripe: raw-two"]
  }, contentSender(7, "https://example.test/page"));
  const second = createWorker(shared);
  const restored = await second.send({
    type: "get_export_secrets",
    scanId: "scan-1",
    vaultFingerprint: second.model.key("https://example.test/page")
  });
  assert.deepEqual(Array.from(restored.secrets), ["Stripe: raw-one", "Stripe: raw-two"]);

  const wrongScan = await second.send({
    type: "get_export_secrets",
    scanId: "scan-2",
    vaultFingerprint: second.model.key("https://example.test/page")
  });
  assert.deepEqual(Array.from(wrongScan.secrets), []);

  await second.send({ type: "scan_begin", scanId: "scan-2", tabId: 7, origin: "https://example.test" });
  assert.equal(shared.session.secretVault, undefined);
});

test("restores the active scan context after a worker restart", async function () {
  const shared = { local: {}, session: {} };
  const first = createWorker(shared);
  await first.send({ type: "scan_begin", scanId: "scan-restart", tabId: 9, origin: "https://example.test" });
  const restarted = createWorker(shared);
  const response = await restarted.send({
    type: "scan_results",
    scanId: "scan-restart",
    scanMode: "passive",
    url: "https://example.test/page",
    findings: []
  }, contentSender(9, "https://example.test/page"));
  assert.equal(response.ok, true);
  assert.equal(shared.local.lastScan.scanId, "scan-restart");
});

test("keeps scan-scoped redirect evidence across worker restarts", async function () {
  const shared = { local: {}, session: {} };
  const first = createWorker(shared);
  await first.send({ type: "scan_begin", scanId: "scan-redirect", tabId: 4, origin: "https://example.test" });
  const listenerWorker = createWorker(shared);
  listenerWorker.listeners.redirect({
    url: "https://example.test/?next=https%3A%2F%2Fcanary.example%2F",
    redirectUrl: "https://canary.example/",
    statusCode: 302,
    tabId: -1
  });
  const restarted = createWorker(shared);
  const response = await restarted.send({ type: "get_redirects", scanId: "scan-redirect" });
  assert.equal(response.redirects.length, 1);
  assert.equal(response.redirects[0].scanId, "scan-redirect");
});

test("does not relay session secrets to a content-script sender", async function () {
  const worker = createWorker();
  await worker.send({ type: "scan_begin", scanId: "scan-1", tabId: 7, origin: "https://example.test" });
  await worker.send({
    type: "export_secrets",
    scanId: "scan-1",
    url: "https://example.test/",
    secrets: ["raw-value"]
  }, contentSender(7, "https://example.test/"));
  const response = await worker.send({
    type: "get_export_secrets",
    scanId: "scan-1",
    vaultFingerprint: worker.model.key("https://example.test/")
  }, contentSender(7, "https://example.test/"));
  assert.equal(response.error, "Extension page required");
  assert.equal(response.secrets, undefined);
});

test("rejects passive results from the wrong tab or URL", async function () {
  const worker = createWorker();
  await worker.send({ type: "scan_begin", scanId: "scan-1", tabId: 7, origin: "https://example.test" });
  const wrongTab = await worker.send({
    type: "scan_results",
    scanId: "scan-1",
    url: "https://example.test/page",
    findings: []
  }, contentSender(8, "https://example.test/page"));
  assert.equal(wrongTab.error, "Scan context mismatch");

  const wrongUrl = await worker.send({
    type: "scan_results",
    scanId: "scan-1",
    url: "https://example.test/other",
    findings: []
  }, contentSender(7, "https://example.test/page"));
  assert.equal(wrongUrl.error, "Scan context mismatch");
  assert.equal(worker.state.local.lastScan, undefined);
});

test("never copies unknown secret fields into local scan storage", async function () {
  const worker = createWorker();
  await worker.send({ type: "scan_begin", scanId: "scan-1", tabId: 7, origin: "https://example.test" });
  await worker.send({
    type: "scan_results",
    scanId: "scan-1",
    url: "https://example.test/?token=raw-value",
    findings: [{
      checkId: "secret.test",
      severity: "high",
      confidence: "high",
      bucket: "finding",
      type: "Possible secret",
      detail: "hidden",
      evidence: "redacted",
      exportDetail: "raw-value",
      full: "raw-value"
    }]
  }, contentSender(7, "https://example.test/?token=raw-value"));
  assert.equal(JSON.stringify(worker.state.local).includes("raw-value"), false);
  assert.equal(worker.state.local.lastScan.schemaVersion, 7);
  assert.equal(worker.state.local.lastScan.scanId, "scan-1");
  assert.match(worker.state.local.lastScan.url, /token=%5Bredacted%5D/);
});

test("stores Full Scan mode and sanitized stage state", async function () {
  const worker = createWorker();
  await worker.send({ type: "scan_begin", scanId: "scan-full", tabId: 7, origin: "https://example.test" });
  await worker.send({
    type: "scan_results",
    schemaVersion: 4,
    scanId: "scan-full",
    scanMode: "full",
    url: "https://example.test/",
    findings: [],
    stageSummary: { passive: "complete", headers: "complete", safe: "running", lab: "invalid", raw: "do-not-copy" }
  }, contentSender(7, "https://example.test/"));
  const stored = worker.state.local.lastScan;
  assert.equal(stored.scanMode, "full");
  assert.equal(stored.stageSummary.safe, "running");
  assert.equal(stored.stageSummary.lab, "pending");
  assert.equal(JSON.stringify(stored).includes("do-not-copy"), false);
});

test("removes incompatible cached scans during an extension update", function () {
  const shared = {
    local: {
      lastScan: {
        url: "https://example.test/",
        findings: [{ type: "Possible secret", detail: "raw-value", exportDetail: "raw-value" }]
      },
      scanHistory: [{ url: "https://example.test/", findingsCount: 1 }]
    },
    session: { secretVault: { secrets: ["raw-value"] } }
  };
  const worker = createWorker(shared);
  worker.listeners.installed({ reason: "update" });
  assert.equal(shared.local.lastScan, undefined);
  assert.equal(shared.session.secretVault, undefined);
  assert.equal(shared.local.scanHistory.length, 1);
});

test("migrates v2 scans and history without copying unknown fields", function () {
  const shared = {
    local: {
      lastScan: {
        schemaVersion: 2,
        scanId: "old-scan",
        url: "https://example.test/?token=%5Bredacted%5D",
        urlFingerprint: "vk-old",
        timestamp: 10,
        findings: [{ type: "Review item", detail: "redacted", bucket: "review", raw: "do-not-copy" }],
        requestSummary: { mode: "safe", attempted: 1, raw: "do-not-copy" }
      },
      scanHistory: [{ schemaVersion: 2, url: "https://example.test/", findingsCount: 1, reviewCount: 2, summary: { high: 1, raw: "do-not-copy" }, raw: "do-not-copy" }]
    },
    session: {}
  };
  const worker = createWorker(shared);
  worker.listeners.installed({ reason: "update" });
  assert.equal(shared.local.lastScan.schemaVersion, 7);
  assert.equal(shared.local.lastScan.scanMode, "legacy");
  assert.equal(shared.local.scanHistory[0].schemaVersion, 7);
  assert.equal(JSON.stringify(shared.local).includes("do-not-copy"), false);
});

test("stores only redacted request-log fields in session storage", async function () {
  const worker = createWorker();
  await worker.send({
    type: "save_request_log",
    scanId: "scan-1",
    entries: [{ method: "GET", url: "https://example.test/path?token=raw#secret", status: 200, durationMs: 12, body: "raw-body" }],
    summary: { mode: "safe", budget: 20, attempted: 1, completed: 1 }
  });
  const log = await worker.send({ type: "get_request_log", scanId: "scan-1" });
  assert.equal(log.entries.length, 1);
  assert.equal(log.entries[0].durationMs, 12);
  assert.doesNotMatch(JSON.stringify(log), /raw|secret|body/);
});

test("clears cached headers at navigation and tab lifecycle boundaries", async function () {
  const worker = createWorker();
  worker.listeners.headers({
    tabId: 4,
    type: "main_frame",
    url: "https://example.test/",
    statusCode: 200,
    responseHeaders: [{ name: "set-cookie", value: "a=1" }, { name: "set-cookie", value: "b=2" }]
  });
  let captured = await worker.send({ type: "get_headers", tabId: 4 });
  assert.equal(captured.headers.length, 2);
  assert.equal(captured.headers[0].value, "a=[redacted]");
  worker.listeners.beforeRequest({ tabId: 4, type: "main_frame" });
  captured = await worker.send({ type: "get_headers", tabId: 4 });
  assert.equal(captured.statusCode, 0);

  worker.listeners.headers({ tabId: 4, type: "main_frame", url: "https://example.test/", statusCode: 200, responseHeaders: [] });
  worker.listeners.removed(4);
  captured = await worker.send({ type: "get_headers", tabId: 4 });
  assert.equal(captured.statusCode, 0);
});
