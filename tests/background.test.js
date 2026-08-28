const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const test = require("node:test");
const vm = require("node:vm");

const modelSource = fs.readFileSync(path.join(__dirname, "..", "finding-model.js"), "utf8");
const urlSource = fs.readFileSync(path.join(__dirname, "..", "url-utils.js"), "utf8");
const checkSource = fs.readFileSync(path.join(__dirname, "..", "scan-checks.js"), "utf8");
const journeySource = fs.readFileSync(path.join(__dirname, "..", "journey-model.js"), "utf8");
const headerSource = fs.readFileSync(path.join(__dirname, "..", "header-analysis.js"), "utf8");
const backgroundSource = fs.readFileSync(path.join(__dirname, "..", "background.js"), "utf8");

function createWorker(shared) {
  const state = shared || { local: {}, session: {} };
  state.alarms = state.alarms || {};
  state.grantedOrigins = state.grantedOrigins || [];
  state.removedOrigins = state.removedOrigins || [];
  const listeners = {};
  const chrome = {
    webRequest: {
      onBeforeRequest: { addListener: function (listener) { listeners.beforeRequest = listener; } },
      onBeforeSendHeaders: { addListener: function (listener) { listeners.beforeSendHeaders = listener; } },
      onHeadersReceived: { addListener: function (listener) { listeners.headers = listener; } },
      onBeforeRedirect: { addListener: function (listener) { listeners.redirect = listener; } },
      onCompleted: { addListener: function (listener) { listeners.completed = listener; } },
      onErrorOccurred: { addListener: function (listener) { listeners.requestError = listener; } }
    },
    action: { onClicked: { addListener: function () {} } },
    alarms: {
      create: function (name, options) { state.alarms[name] = options; },
      clear: function (name, callback) { delete state.alarms[name]; if (callback) callback(true); },
      onAlarm: { addListener: function (listener) { listeners.alarm = listener; } }
    },
    permissions: {
      getAll: function (callback) { callback({ origins: state.grantedOrigins.slice() }); },
      contains: function (options, callback) {
        callback((options.origins || []).every(function (origin) { return state.grantedOrigins.includes(origin); }));
      },
      remove: function (options, callback) {
        if (state.permissionRemoveFailures > 0) {
          state.permissionRemoveFailures--;
          if (callback) callback(false);
          return;
        }
        (options.origins || []).forEach(function (origin) {
          state.grantedOrigins = state.grantedOrigins.filter(function (value) { return value !== origin; });
          state.removedOrigins.push(origin);
        });
        if (callback) callback(true);
      }
    },
    runtime: {
      getURL: function (value) { return "chrome-extension://test/" + value; },
      onMessage: { addListener: function (listener) { listeners.message = listener; } },
      onInstalled: { addListener: function (listener) { listeners.installed = listener; } },
      onStartup: { addListener: function (listener) { listeners.startup = listener; } },
      sendMessage: function (message, callback) { state.broadcasts = (state.broadcasts || []).concat(message); if (callback) callback(); },
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
        get: function (key, callback) {
          const keys = Array.isArray(key) ? key : [key];
          const result = {};
          keys.forEach(function (name) { result[name] = state.session[name]; });
          callback(result);
        },
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
      get: function (tabId, callback) { callback(state.tabs && state.tabs[tabId] || null); },
      onRemoved: { addListener: function (listener) { listeners.removed = listener; } },
      onReplaced: { addListener: function (listener) { listeners.replaced = listener; } },
      onUpdated: { addListener: function (listener) { listeners.updated = listener; } }
    },
    windows: { update: async function () {} },
    scripting: { executeScript: function (options, callback) { if (callback) callback([]); } }
  };
  const context = { chrome: chrome, URL: URL, Date: Date, Math: Math, setTimeout: setTimeout, clearTimeout: clearTimeout, importScripts: function () {} };
  vm.createContext(context);
  vm.runInContext(modelSource, context);
  vm.runInContext(urlSource, context);
  vm.runInContext(checkSource, context);
  vm.runInContext(journeySource, context);
  vm.runInContext(headerSource, context);
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
  return { state: state, listeners: listeners, send: send, model: context.VulnscanFindings, journey: context.VulnscanJourneys };
}

function contentSender(tabId, url) {
  return { tab: { id: tabId }, url: url };
}

function tick() {
  return new Promise(function (resolve) { setTimeout(resolve, 10); });
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
  assert.equal(worker.state.local.lastScan.schemaVersion, 8);
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
  assert.equal(shared.local.lastScan.schemaVersion, 8);
  assert.equal(shared.local.lastScan.scanMode, "legacy");
  assert.equal(shared.local.scanHistory[0].schemaVersion, 8);
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

test("captures headers only for a one-refresh tab and origin lease", async function () {
  const shared = { local: {}, session: {}, grantedOrigins: ["https://example.test/*"] };
  const worker = createWorker(shared);
  worker.listeners.headers({
    tabId: 4,
    type: "main_frame",
    url: "https://example.test/",
    statusCode: 200,
    responseHeaders: [{ name: "set-cookie", value: "a=1" }, { name: "set-cookie", value: "b=2" }]
  });
  let captured = await worker.send({ type: "get_headers", tabId: 4 });
  assert.equal(captured.statusCode, 0);

  await worker.send({ type: "scan_begin", scanId: "scan-headers", tabId: 4, origin: "https://example.test" });
  const retained = await worker.send({
    type: "scan_end",
    scanId: "scan-headers",
    retainHeaderCapture: true,
    tabId: 4,
    url: "https://example.test/"
  });
  assert.equal(retained.siteAccessRetained, true);
  worker.listeners.headers({
    tabId: 9,
    type: "main_frame",
    url: "https://example.test/",
    statusCode: 200,
    responseHeaders: [{ name: "x-frame-options", value: "DENY" }]
  });
  assert.equal((await worker.send({ type: "get_headers", tabId: 9 })).statusCode, 0);

  worker.listeners.headers({
    tabId: 4,
    type: "main_frame",
    url: "https://example.test/",
    statusCode: 302,
    responseHeaders: [{ name: "location", value: "/home" }]
  });
  assert.equal((await worker.send({ type: "get_headers", tabId: 4 })).statusCode, 0);
  worker.listeners.headers({
    tabId: 4,
    type: "main_frame",
    url: "https://example.test/",
    statusCode: 200,
    responseHeaders: [{ name: "set-cookie", value: "a=1" }, { name: "set-cookie", value: "b=2" }]
  });
  captured = await worker.send({ type: "get_headers", tabId: 4 });
  assert.equal(captured.headers.length, 2);
  assert.equal(captured.headers[0].value, "a=[redacted]");
  assert.equal(captured.urlFingerprint, worker.model.key("https://example.test/"));

  const restarted = createWorker(shared);
  captured = await restarted.send({ type: "get_headers", tabId: 4 });
  assert.equal(captured.headers.length, 2);
  await restarted.send({ type: "scan_begin", scanId: "scan-consume", tabId: 4, origin: "https://example.test" });
  const released = await restarted.send({ type: "scan_end", scanId: "scan-consume" });
  assert.equal(released.siteAccessRetained, false);
  assert.equal(shared.removedOrigins.includes("https://example.test/*"), true);
});

test("revokes a pending header lease on tab closure or expiry", async function () {
  const closeState = { local: {}, session: {}, grantedOrigins: ["https://example.test/*"] };
  const closeWorker = createWorker(closeState);
  await closeWorker.send({ type: "scan_begin", scanId: "scan-close", tabId: 4, origin: "https://example.test" });
  await closeWorker.send({ type: "scan_end", scanId: "scan-close", retainHeaderCapture: true, tabId: 4, url: "https://example.test/" });
  closeWorker.listeners.removed(4);
  assert.equal(closeState.removedOrigins.includes("https://example.test/*"), true);
  assert.equal(closeState.session.headerCapture, undefined);

  const expiryState = { local: {}, session: {}, grantedOrigins: ["https://expiry.test/*"] };
  const expiryWorker = createWorker(expiryState);
  await expiryWorker.send({ type: "scan_begin", scanId: "scan-expiry", tabId: 8, origin: "https://expiry.test" });
  await expiryWorker.send({ type: "scan_end", scanId: "scan-expiry", retainHeaderCapture: true, tabId: 8, url: "https://expiry.test/" });
  expiryWorker.listeners.alarm({ name: "vulnscan-site-access" });
  assert.equal(expiryState.removedOrigins.includes("https://expiry.test/*"), true);
  assert.equal(expiryState.session.headerCapture, undefined);
});

test("revokes a pending header lease when the target changes origin", async function () {
  const state = { local: {}, session: {}, grantedOrigins: ["https://example.test/*"] };
  const worker = createWorker(state);
  await worker.send({ type: "scan_begin", scanId: "scan-nav", tabId: 4, origin: "https://example.test" });
  await worker.send({ type: "scan_end", scanId: "scan-nav", retainHeaderCapture: true, tabId: 4, url: "https://example.test/" });
  worker.listeners.updated(4, { url: "https://other.test/" });
  assert.equal(state.removedOrigins.includes("https://example.test/*"), true);
  assert.equal(state.session.headerCapture, undefined);
});

test("Clear all removes every granted site origin", async function () {
  const state = {
    local: {},
    session: { headerCapture: { tabId: 4, origin: "https://example.test", originPattern: "https://example.test/*", state: "waiting", expiresAt: Date.now() + 60000 } },
    grantedOrigins: ["https://example.test/*", "http://lab.test/*"]
  };
  const worker = createWorker(state);
  const response = await worker.send({ type: "clear_all_session" });
  assert.equal(response.siteAccessCleared, true);
  assert.deepEqual(state.grantedOrigins, []);
  assert.equal(state.session.headerCapture, undefined);
});

test("keeps an expiry retry when permission removal fails", async function () {
  const state = {
    local: {},
    session: {},
    grantedOrigins: ["https://example.test/*"],
    permissionRemoveFailures: 1
  };
  const worker = createWorker(state);
  await worker.send({ type: "scan_begin", scanId: "scan-retry", tabId: 4, origin: "https://example.test" });
  const ended = await worker.send({ type: "scan_end", scanId: "scan-retry" });
  assert.equal(ended.siteAccessReleased, false);
  assert.equal(state.grantedOrigins.includes("https://example.test/*"), true);
  assert.equal(!!state.session.scanContext, true);
  assert.equal(!!state.alarms["vulnscan-site-access"], true);
  worker.listeners.alarm({ name: "vulnscan-site-access" });
  assert.equal(state.grantedOrigins.includes("https://example.test/*"), false);
  assert.equal(state.session.scanContext, undefined);
});

test("browser startup revokes grants left after session state is discarded", function () {
  const state = {
    local: {},
    session: {},
    grantedOrigins: ["https://restart.test/*"]
  };
  const worker = createWorker(state);
  worker.listeners.startup();
  assert.deepEqual(state.grantedOrigins, []);
  assert.equal(state.removedOrigins.includes("https://restart.test/*"), true);
});

test("scopes outgoing CORS evidence to the active scan and exact origin", async function () {
  const worker = createWorker();
  await worker.send({ type: "scan_begin", scanId: "scan-cors", tabId: 7, origin: "https://example.test" });
  worker.listeners.beforeSendHeaders({
    url: "https://other.test/api?__vulnscan_cors=scan-cors",
    requestHeaders: [{ name: "Origin", value: "chrome-extension://test" }]
  });
  let evidence = await worker.send({ type: "get_cors_probe", scanId: "scan-cors" });
  assert.equal(evidence.observed, false);

  worker.listeners.beforeSendHeaders({
    url: "https://example.test/api?__vulnscan_cors=scan-cors",
    requestHeaders: [{ name: "Origin", value: "chrome-extension://test" }]
  });
  evidence = await worker.send({ type: "get_cors_probe", scanId: "scan-cors" });
  assert.deepEqual(JSON.parse(JSON.stringify(evidence)), {
    observed: true,
    originSent: true,
    originMatchesExtension: true,
    originWasNull: false
  });
});

test("journey capture requires an exact-origin grant and saves a redacted completed session", async function () {
  const shared = {
    local: {}, session: {}, grantedOrigins: ["https://example.test/*"],
    tabs: { 9: { id: 9, url: "https://example.test/account/123?token=secret", title: "Account" } }
  };
  const worker = createWorker(shared);
  const denied = await worker.send({ type: "journey_begin", journeyId: "denied", tabId: 4, origin: "https://denied.test", url: "https://denied.test/" });
  assert.equal(denied.error, "Exact-origin access is required");

  const started = await worker.send({
    type: "journey_begin", journeyId: "journey-save", tabId: 9, origin: "https://example.test",
    url: "https://example.test/account/123?token=secret", title: "Account"
  });
  assert.equal(started.ok, true);
  await tick();
  const captureId = Object.keys(shared.session.journeyCaptures)[0];
  assert.ok(captureId);
  assert.equal(shared.session.journeyCaptures[captureId].url, undefined);
  assert.doesNotMatch(JSON.stringify(shared.session.journeyCaptures), /token|secret/);
  worker.listeners.headers({
    tabId: 9, type: "main_frame", url: "https://example.test/account/123?token=secret", statusCode: 200,
    responseHeaders: [{ name: "set-cookie", value: "session=raw-cookie; Path=/; SameSite=Lax" }]
  });
  const page = await worker.send({
    type: "journey_page_results", journeyId: "journey-save", captureId: captureId,
    url: "https://example.test/account/123?token=secret", title: "Account", findings: [], surface: { nodes: [], edges: [] }
  }, contentSender(9, "https://example.test/account/123?token=secret"));
  assert.equal(page.ok, true);
  const duplicate = await worker.send({
    type: "journey_page_results", journeyId: "journey-save", captureId: captureId,
    url: "https://example.test/account/123?token=secret", title: "Account", findings: [], surface: { nodes: [], edges: [] }
  }, contentSender(9, "https://example.test/account/123?token=secret"));
  assert.equal(duplicate.error, "Journey capture mismatch");
  await worker.send({
    type: "journey_export_secrets", journeyId: "journey-save", captureId: captureId,
    url: "https://example.test/account/123?token=secret", secrets: ["raw-provider-secret"]
  }, contentSender(9, "https://example.test/account/123?token=secret"));
  const finished = await worker.send({ type: "journey_finish" });
  assert.equal(finished.saved, true);
  assert.equal(shared.local.journeyHistory.length, 1);
  const serialized = JSON.stringify(shared.local.journeyHistory[0]);
  assert.doesNotMatch(serialized, /secret|raw-cookie|raw-provider/);
  assert.match(serialized, /token=%5Bredacted%5D/);
  assert.equal(shared.grantedOrigins.includes("https://example.test/*"), false);
  assert.deepEqual(Array.from(shared.session.secretVault.secrets), ["raw-provider-secret"]);
});

test("restores a live journey after a worker restart", async function () {
  const shared = {
    local: {}, session: {}, grantedOrigins: ["https://example.test/*"],
    tabs: { 5: { id: 5, url: "https://example.test/app", title: "App" } }
  };
  const first = createWorker(shared);
  await first.send({ type: "journey_begin", journeyId: "journey-restart", tabId: 5, origin: "https://example.test", url: "https://example.test/app" });
  const restarted = createWorker(shared);
  const state = await restarted.send({ type: "journey_get_state" });
  assert.equal(state.active, true);
  assert.equal(state.journey.events.some(function (event) { return event.kind === "session" && event.phase === "restored"; }), true);
  await restarted.send({ type: "journey_discard" });
});

test("serializes overlapping API completions and aggregates sanitized endpoints", async function () {
  const shared = {
    local: {}, session: {}, grantedOrigins: ["https://example.test/*"],
    tabs: { 6: { id: 6, url: "https://example.test/app", title: "App" } }
  };
  const worker = createWorker(shared);
  await worker.send({ type: "journey_begin", journeyId: "journey-api", tabId: 6, origin: "https://example.test", url: "https://example.test/app" });
  worker.listeners.beforeRequest({ requestId: "one", tabId: 6, type: "xmlhttprequest", url: "https://example.test/api/users/1?key=one", method: "GET", timeStamp: 1000 });
  worker.listeners.beforeRequest({ requestId: "two", tabId: 6, type: "xmlhttprequest", url: "https://example.test/api/users/2?key=two", method: "GET", timeStamp: 1002 });
  worker.listeners.completed({ requestId: "two", tabId: 6, type: "xmlhttprequest", statusCode: 204, timeStamp: 1020 });
  worker.listeners.completed({ requestId: "one", tabId: 6, type: "xmlhttprequest", statusCode: 200, timeStamp: 1030 });
  await tick();
  const state = await worker.send({ type: "journey_get_state" });
  assert.equal(state.journey.apiEndpoints.length, 1);
  assert.equal(state.journey.apiEndpoints[0].occurrences, 2);
  assert.deepEqual(Object.assign({}, state.journey.apiEndpoints[0].statuses), { 200: 1, 204: 1 });
  const sequences = state.journey.events.map(function (event) { return event.sequence; });
  assert.deepEqual(sequences, sequences.slice().sort(function (left, right) { return left - right; }));
  assert.doesNotMatch(JSON.stringify(state.journey), /key=one|key=two/);
  await worker.send({ type: "journey_discard" });
});

test("finishes a partial journey when its tab leaves the authorized origin", async function () {
  const shared = {
    local: {}, session: {}, grantedOrigins: ["https://example.test/*"],
    tabs: { 7: { id: 7, url: "https://example.test/start", title: "Start" } }
  };
  const worker = createWorker(shared);
  await worker.send({ type: "journey_begin", journeyId: "journey-leave", tabId: 7, origin: "https://example.test", url: "https://example.test/start" });
  worker.listeners.updated(7, { url: "https://outside.test/" }, { id: 7, url: "https://outside.test/" });
  await tick();
  assert.equal(shared.local.journeyHistory.length, 1);
  assert.equal(shared.local.journeyHistory[0].stopReason, "origin-changed");
  assert.equal(shared.session.journeyDraft, undefined);
  assert.equal(shared.grantedOrigins.includes("https://example.test/*"), false);
});

test("ignores late API completions after a journey is discarded", async function () {
  const shared = {
    local: {}, session: {}, grantedOrigins: ["https://example.test/*"],
    tabs: { 8: { id: 8, url: "https://example.test/app", title: "App" } }
  };
  const worker = createWorker(shared);
  await worker.send({ type: "journey_begin", journeyId: "journey-late", tabId: 8, origin: "https://example.test", url: "https://example.test/app" });
  worker.listeners.beforeRequest({ requestId: "late", tabId: 8, type: "xmlhttprequest", url: "https://example.test/api/work", method: "POST", timeStamp: 1000 });
  await tick();
  await worker.send({ type: "journey_discard" });
  worker.listeners.completed({ requestId: "late", tabId: 8, type: "xmlhttprequest", statusCode: 200, timeStamp: 1200 });
  await tick();
  assert.equal(shared.session.journeyDraft, undefined);
  assert.equal(shared.session.journeyInflight, undefined);
  assert.equal(shared.local.journeyHistory, undefined);
});

test("expires and saves a partial journey when state is restored after its time limit", async function () {
  const shared = {
    local: {}, session: {}, grantedOrigins: ["https://example.test/*"],
    tabs: { 10: { id: 10, url: "https://example.test/start", title: "Start" } }
  };
  const worker = createWorker(shared);
  await worker.send({ type: "journey_begin", journeyId: "journey-timeout", tabId: 10, origin: "https://example.test", url: "https://example.test/start" });
  shared.session.journeyDraft.expiresAt = Date.now() - 1;
  const restarted = createWorker(shared);
  const state = await restarted.send({ type: "journey_get_state" });
  assert.equal(state.active, false);
  assert.equal(state.journey.stopReason, "time-limit");
  assert.equal(shared.local.journeyHistory[0].stopReason, "time-limit");
  assert.equal(shared.grantedOrigins.includes("https://example.test/*"), false);
});

test("retries exact-origin removal after a completed journey", async function () {
  const shared = {
    local: {}, session: {}, grantedOrigins: ["https://example.test/*"], permissionRemoveFailures: 1,
    tabs: { 11: { id: 11, url: "https://example.test/start", title: "Start" } }
  };
  const worker = createWorker(shared);
  await worker.send({ type: "journey_begin", journeyId: "journey-retry", tabId: 11, origin: "https://example.test", url: "https://example.test/start" });
  const finished = await worker.send({ type: "journey_finish" });
  assert.equal(finished.siteAccessReleased, false);
  assert.ok(shared.alarms["vulnscan-site-access"]);
  worker.listeners.alarm({ name: "vulnscan-site-access" });
  await tick();
  assert.equal(shared.grantedOrigins.includes("https://example.test/*"), false);
});
