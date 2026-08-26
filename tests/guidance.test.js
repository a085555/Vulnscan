const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const test = require("node:test");
const vm = require("node:vm");

const source = fs.readFileSync(path.join(__dirname, "..", "finding-guidance.js"), "utf8");

function loadGuidance() {
  const context = {};
  vm.createContext(context);
  vm.runInContext(source, context);
  return context.VulnscanGuidance;
}

test("provides focused investigation guidance without changing the finding", function () {
  const guidance = loadGuidance();
  const finding = {
    checkId: "active.open-redirect",
    category: "redirects",
    severity: "high",
    confidence: "high",
    bucket: "finding"
  };
  const original = JSON.stringify(finding);
  const result = guidance.get(finding);
  assert.match(result.impact, /redirect/i);
  assert.match(result.remediation, /destinations|relative paths/i);
  assert.equal(result.steps.length >= 3, true);
  assert.equal(JSON.stringify(finding), original);
});

test("uses safe general guidance for unknown checks", function () {
  const guidance = loadGuidance();
  const result = guidance.get({ checkId: "unknown", category: "unknown" });
  assert.match(result.impact, /manual context/i);
  assert.equal(result.steps.length, 3);
});

test("priority reflects severity, confidence, and review status", function () {
  const guidance = loadGuidance();
  const urgent = guidance.priority({ severity: "high", confidence: "high", bucket: "finding" });
  const review = guidance.priority({ severity: "high", confidence: "high", bucket: "review" });
  const context = guidance.priority({ severity: "info", confidence: "low", bucket: "review" });
  assert.equal(urgent.score, 90);
  assert.equal(urgent.label, "Immediate");
  assert.equal(review.score < urgent.score, true);
  assert.equal(context.score, 0);
  assert.equal(context.label, "Context");
});
