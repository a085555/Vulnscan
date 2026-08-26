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
  const otherReview = model.normalize(Object.assign({}, review, { detail: "two", fingerprint: "", identityFingerprint: "" }));
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

test("compares findings by stable identity", function () {
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

test("keeps identity stable when evidence and detail change at the same location", function () {
  const first = model.normalize({
    checkId: "header.cookie-flags",
    severity: "low",
    confidence: "medium",
    bucket: "review",
    type: "Cookie flags need review",
    detail: "session: missing Secure",
    evidence: "one missing flag",
    location: "Set-Cookie: session"
  });
  const current = model.normalize(Object.assign({}, first, {
    fingerprint: "",
    identityFingerprint: "",
    detail: "session: missing SameSite",
    evidence: "a different flag is missing"
  }));
  assert.notEqual(first.fingerprint, current.fingerprint);
  assert.equal(first.identityFingerprint, current.identityFingerprint);
  const comparison = model.compare([current], [first]);
  assert.equal(comparison.changed.length, 1);
  assert.equal(comparison.new.length, 0);
  assert.equal(comparison.resolved.length, 0);
});

test("normalizes bounded surface relationships and finding references", function () {
  const target = model.surfaceId("target", "https://example.test/");
  const route = model.surfaceId("route", "https://example.test/account");
  const surface = model.normalizeSurface({
    nodes: [
      { id: target, kind: "target", label: "example.test" },
      { id: route, kind: "route", label: "/account", location: "https://example.test/account" },
      { id: "invalid", kind: "route", label: "ignored" }
    ],
    edges: [
      { from: target, to: route, relation: "contains" },
      { from: route, to: "invalid", relation: "loads" }
    ]
  });
  assert.equal(surface.nodes.length, 2);
  assert.equal(surface.edges.length, 1);
  const finding = model.normalize({ checkId: "test.surface", surfaceRefs: [route, route, "invalid"] });
  assert.deepEqual(finding.surfaceRefs, [route]);
});

test("normalizes active coverage without accepting arbitrary status or notes", function () {
  const coverage = model.normalizeCoverage([
    { checkId: "safe.cors", status: "unavailable", inspected: 1, matched: 0, note: "origin-not-observed" },
    { checkId: "safe.cors", status: "complete", inspected: 2, matched: 2 },
    { checkId: "unsafe", status: "unknown", note: "raw detail" }
  ]);
  assert.deepEqual(coverage, [{ checkId: "safe.cors", status: "unavailable", inspected: 1, matched: 0, note: "origin-not-observed" }]);
});
