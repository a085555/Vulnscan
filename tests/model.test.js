const assert = require("node:assert/strict");
const test = require("node:test");

require("../finding-model.js");

const model = globalThis.VulnscanFindings;

test("normalizes and deduplicates exact findings", function () {
  const finding = {
    checkId: "dom.flow",
    severity: "medium",
    confidence: "medium",
    bucket: "finding",
    category: "dom-xss",
    type: "DOM XSS candidate",
    detail: "location.hash -> innerHTML",
    evidence: "flow",
    verification: "verify",
    source: "passive"
  };
  const first = model.normalize(finding);
  const second = model.normalize(finding);
  assert.equal(first.fingerprint, second.fingerprint);
  const deduped = model.dedupe([first, second]);
  assert.equal(deduped.length, 1);
  assert.equal(deduped[0].occurrences, 2);
});

test("keeps distinct details and derives risk from findings only", function () {
  const review = model.normalize({
    checkId: "source.clue",
    severity: "high",
    confidence: "low",
    bucket: "review",
    type: "Clue",
    detail: "one"
  });
  const otherReview = model.normalize(Object.assign({}, review, { detail: "two", fingerprint: "" }));
  assert.equal(model.dedupe([review, otherReview]).length, 2);
  assert.equal(model.risk([review]), "review");
  assert.deepEqual(model.summarize([review]), {
    high: 0,
    medium: 0,
    low: 0,
    info: 0,
    review: 1,
    findings: 0
  });

  const finding = model.normalize({
    checkId: "redirect.confirmed",
    severity: "high",
    confidence: "high",
    bucket: "finding",
    type: "Open redirect confirmed",
    detail: "next"
  });
  assert.equal(model.risk([review, finding]), "high");
});

test("compares findings by stable fingerprint", function () {
  const first = model.normalize({
    checkId: "transport.mixed", severity: "medium", confidence: "high", bucket: "finding", type: "Mixed content", detail: "one"
  });
  const changed = model.normalize(Object.assign({}, first, { severity: "high", fingerprint: first.fingerprint }));
  const resolved = model.normalize({
    checkId: "form.external", severity: "low", confidence: "low", bucket: "review", type: "External form", detail: "old"
  });
  const added = model.normalize({
    checkId: "redirect.confirmed", severity: "high", confidence: "high", bucket: "finding", type: "Redirect", detail: "new"
  });
  const comparison = model.compare([changed, added], [first, resolved]);
  assert.equal(comparison.new.length, 1);
  assert.equal(comparison.changed.length, 1);
  assert.equal(comparison.resolved.length, 1);
  assert.equal(comparison.unchanged.length, 0);
});
