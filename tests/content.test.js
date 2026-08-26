const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const test = require("node:test");
const vm = require("node:vm");

const modelSource = fs.readFileSync(path.join(__dirname, "..", "finding-model.js"), "utf8");
const urlSource = fs.readFileSync(path.join(__dirname, "..", "url-utils.js"), "utf8");
const checkSource = fs.readFileSync(path.join(__dirname, "..", "scan-checks.js"), "utf8");
const contentSource = fs.readFileSync(path.join(__dirname, "..", "content.js"), "utf8");

function scan(options) {
  const settings = options || {};
  const messages = [];
  const scripts = (settings.scripts || []).map(function (textContent) {
    return { src: "", textContent: textContent };
  });
  const html = (settings.html || "") + scripts.map(function (script) {
    return "<script>" + script.textContent + "</script>";
  }).join("");
  const document = {
    documentElement: { innerHTML: html },
    cookie: settings.cookie || "",
    scripts: scripts,
    querySelectorAll: function (selector) {
      if (settings.nodes && settings.nodes[selector]) return settings.nodes[selector];
      return [];
    }
  };
  const pageUrl = new URL(settings.url || "https://example.test/page");
  const context = {
    document: document,
    location: {
      href: pageUrl.href,
      protocol: pageUrl.protocol,
      hostname: pageUrl.hostname
    },
    chrome: { runtime: { sendMessage: function (message) { messages.push(message); } } },
    URL: URL,
    atob: function (value) { return Buffer.from(value, "base64").toString("binary"); },
    localStorage: settings.localStorage,
    sessionStorage: settings.sessionStorage,
    __vulnscanScanId: "scan-1",
    __vulnscanScanMode: settings.mode || "passive",
    __vulnscanEnabledChecks: settings.enabledChecks
  };
  vm.createContext(context);
  vm.runInContext(modelSource, context);
  vm.runInContext(urlSource, context);
  vm.runInContext(checkSource, context);
  vm.runInContext(contentSource, context);
  return messages;
}

function result(messages) {
  return messages.find(function (message) { return message.type === "scan_results"; });
}

test("exports every distinct secret while keeping one redacted type finding", function () {
  const first = "sk_live_" + "A".repeat(24);
  const second = "sk_live_" + "B".repeat(24);
  const messages = scan({ html: first + " " + second + " " + first });
  const findings = result(messages).findings.filter(function (finding) {
    return finding.checkId === "secret.stripe.live.key";
  });
  const vault = messages.find(function (message) { return message.type === "export_secrets"; });
  assert.equal(findings.length, 1);
  assert.equal(findings[0].occurrences, 2);
  assert.equal(findings[0].bucket, "finding");
  assert.equal(findings[0].detail.includes(first), false);
  assert.equal(findings[0].evidence.includes(second), false);
  assert.equal(vault.secrets.length, 2);
  assert.equal(new Set(vault.secrets).size, 2);
  assert.equal(vault.scanId, "scan-1");
  assert.equal(result(messages).schemaVersion, 8);
  assert.equal(result(messages).scanMode, "passive");
});

test("reports source truncation instead of silently treating a partial scan as complete", function () {
  const html = "a".repeat(2 * 1024 * 1024 + 20);
  const stored = result(scan({ html: html }));
  assert.equal(stored.scanLimits.sourceTruncated, true);
  assert.equal(stored.findings.some(function (finding) { return finding.checkId === "scan.limits"; }), true);
});

test("checks SRI on external scripts and stylesheets", function () {
  const script = { tagName: "SCRIPT", src: "https://cdn.example.net/app.js", integrity: "" };
  const style = { tagName: "LINK", href: "https://cdn.example.net/app.css", integrity: "" };
  const findings = result(scan({
    nodes: { "script[src], link[rel~='stylesheet'][href]": [script, style] }
  })).findings;
  assert.equal(findings.some(function (finding) { return finding.checkId === "script.missing-sri"; }), true);
  assert.equal(findings.some(function (finding) { return finding.checkId === "style.missing-sri"; }), true);
  assert.equal(findings.every(function (finding) {
    return !finding.checkId.endsWith("missing-sri") || !!finding.location;
  }), true);
});

test("keeps generic token patterns in review", function () {
  const jwt = "eyJ" + "a".repeat(14) + ".eyJ" + "b".repeat(14) + "." + "c".repeat(14);
  const finding = result(scan({ html: jwt })).findings.find(function (item) {
    return item.checkId === "secret.jwt";
  });
  assert.equal(finding.bucket, "review");
  assert.equal(finding.confidence, "low");
  assert.equal(finding.detail.includes(jwt), false);
});

test("reports bounded JWT metadata without exposing claims or token values", function () {
  const encode = function (value) {
    return Buffer.from(JSON.stringify(value)).toString("base64url");
  };
  const token = encode({ alg: "none", typ: "JWT" }) + "." + encode({ sub: "private-subject-value" }) + ".";
  const messages = scan({ html: "<script>const token = '" + token + "';</script>" });
  const stored = result(messages);
  assert.equal(stored.findings.some(function (finding) { return finding.checkId === "secret.jwt.alg-none"; }), true);
  assert.equal(stored.findings.some(function (finding) { return finding.checkId === "secret.jwt.no-expiry"; }), true);
  assert.doesNotMatch(JSON.stringify(stored), new RegExp(token.replace(/[.*+?^${}()|[\]\\]/g, "\\$&")));
  assert.doesNotMatch(JSON.stringify(stored), /private-subject-value/);
  const vault = messages.find(function (message) { return message.type === "export_secrets"; });
  assert.equal(vault.secrets.some(function (value) { return value.includes(token); }), true);
});

test("runs only selected passive check families", function () {
  const secret = "sk_live_" + "S".repeat(24);
  const messages = scan({
    html: secret + " <script>output.innerHTML = location.hash;</script>",
    scripts: ["output.innerHTML = location.hash;"],
    enabledChecks: ["passive.dom"]
  });
  const findings = result(messages).findings;
  assert.equal(findings.some(function (finding) { return finding.checkId.startsWith("dom."); }), true);
  assert.equal(findings.some(function (finding) { return finding.checkId.startsWith("secret."); }), false);
  assert.equal(messages.some(function (message) { return message.type === "export_secrets"; }), false);
  assert.deepEqual(Array.from(result(messages).checksRun), ["passive.dom"]);
});

test("routes password assignments through the redacted export vault", function () {
  const canary = "v52-raw-password-canary";
  const messages = scan({ html: '<script>const password = "' + canary + '";</script>' });
  const stored = result(messages);
  const password = stored.findings.find(function (finding) {
    return finding.checkId === "secret.password.assignment";
  });
  const vault = messages.find(function (message) { return message.type === "export_secrets"; });
  assert.equal(JSON.stringify(stored).includes(canary), false);
  assert.equal(password.bucket, "review");
  assert.equal(vault.secrets.some(function (value) { return value.includes(canary); }), true);
});

test("matches exact redirect query keys instead of source substrings", function () {
  const findings = result(scan({
    url: "https://example.test/?return_url=%2Fhome&q=next%3Dhttps%3A%2F%2Fother.test&URL=https%3A%2F%2Fsafe.test",
    html: "<div data-note='redirect=https://noise.test'>url= next=</div>"
  })).findings;
  const clue = findings.find(function (finding) { return finding.checkId === "redirect.query-parameter"; });
  assert.equal(clue.occurrences, 2);
  assert.match(clue.detail, /return_url/);
  assert.match(clue.detail, /URL/);
  assert.doesNotMatch(clue.detail, /next/);

  const sourceOnly = result(scan({ html: "<script>const sample = 'redirect=https://noise.test'</script>" }));
  assert.equal(sourceOnly.findings.some(function (finding) {
    return finding.checkId === "redirect.query-parameter";
  }), false);
});

test("separates raw sinks from a source-to-sink flow", function () {
  const direct = result(scan({ scripts: ["const payload = location.hash; output.innerHTML = payload;"] }));
  const sink = direct.findings.find(function (finding) { return finding.checkId === "dom.sinks"; });
  const flow = direct.findings.find(function (finding) { return finding.checkId === "dom.source-to-sink"; });
  assert.equal(sink.bucket, "review");
  assert.equal(flow.bucket, "finding");
  assert.match(flow.detail, /location.hash -> innerHTML/);

  const unrelated = result(scan({ scripts: ["const query = location.search;", "output.innerHTML = '<b>safe</b>';"] }));
  assert.equal(unrelated.findings.some(function (finding) {
    return finding.checkId === "dom.source-to-sink";
  }), false);
});

test("builds passive intelligence without reading values", function () {
  const storageValue = "storage-value-must-not-leak";
  let valueReads = 0;
  const storage = {
    length: 2,
    key: function (index) { return ["theme", "session_state"][index]; },
    getItem: function () { valueReads++; return storageValue; }
  };
  const form = {
    tagName: "FORM",
    method: "post",
    action: "https://example.test/account/save?return=private",
    querySelector: function (selector) {
      if (selector === "input[type='password']") return {};
      return null;
    },
    querySelectorAll: function () { return [{ name: "email" }, { name: "password" }]; }
  };
  const link = { tagName: "A", href: "https://example.test/settings?tab=security" };
  const script = { tagName: "SCRIPT", src: "https://cdn.example.net/app.js" };
  const frame = { tagName: "IFRAME", src: "https://login.example.net/embed" };
  const messages = scan({
    cookie: "session_id=hidden-value",
    localStorage: storage,
    sessionStorage: { length: 0, key: function () { return null; }, getItem: function () { valueReads++; return storageValue; } },
    nodes: {
      "form": [form],
      "a[href], form[action], script[src], link[href], iframe[src]": [link, form, script, frame]
    }
  });
  const findings = result(messages).findings;
  ["inventory.endpoints", "inventory.parameters", "inventory.forms", "inventory.resources", "inventory.storage-names", "inventory.authentication"].forEach(function (checkId) {
    assert.equal(findings.some(function (finding) { return finding.checkId === checkId; }), true, checkId);
  });
  assert.equal(valueReads, 0);
  assert.doesNotMatch(JSON.stringify(messages), new RegExp(storageValue));
  assert.doesNotMatch(JSON.stringify(result(messages)), /hidden-value/);
});

test("surface inventory is bounded, linked, and redacts long path values", function () {
  const rawPathValue = "resetTokenValueThatMustNeverAppear";
  const link = { tagName: "A", href: "https://example.test/reset/" + rawPathValue + "?next=private" };
  const messages = scan({
    nodes: { "a[href], form[action], script[src], link[href], iframe[src]": [link], "form": [] }
  });
  const stored = result(messages);
  assert.equal(stored.surface.nodes.some(function (node) { return node.kind === "target"; }), true);
  assert.equal(stored.surface.nodes.some(function (node) { return node.kind === "route"; }), true);
  assert.equal(stored.surface.edges.length > 0, true);
  assert.equal(stored.findings.some(function (finding) { return finding.surfaceRefs.length > 0; }), true);
  assert.doesNotMatch(JSON.stringify(stored.surface), new RegExp(rawPathValue));
  assert.match(JSON.stringify(stored.surface), /\[redacted\]/);
});
