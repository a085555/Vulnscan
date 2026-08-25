const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const test = require("node:test");
const vm = require("node:vm");

const modelSource = fs.readFileSync(path.join(__dirname, "..", "finding-model.js"), "utf8");
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
    querySelectorAll: function () { return []; }
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
    __vulnscanScanId: "scan-1",
    __vulnscanScanMode: settings.mode || "passive"
  };
  vm.createContext(context);
  vm.runInContext(modelSource, context);
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
  assert.equal(result(messages).schemaVersion, 3);
  assert.equal(result(messages).scanMode, "passive");
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
