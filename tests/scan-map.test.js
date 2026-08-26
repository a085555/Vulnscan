const assert = require("node:assert/strict");
const test = require("node:test");

require("../finding-model.js");
require("../scan-checks.js");
require("../scan-map.js");

const model = globalThis.VulnscanFindings;
const map = globalThis.VulnscanMap;

function sampleScan() {
  const target = model.surfaceId("target", "https://example.test/");
  const route = model.surfaceId("route", "https://example.test/account");
  return {
    url: "https://example.test/",
    scanMode: "safe",
    checksRun: ["passive.inventory", "safe.cors"],
    stageSummary: { passive: "complete", headers: "skipped", safe: "complete", lab: "skipped" },
    coverage: [{ checkId: "safe.cors", status: "complete", inspected: 1, matched: 1, note: "" }],
    surface: {
      nodes: [
        { id: target, kind: "target", label: "example.test" },
        { id: route, kind: "route", label: "/account", location: "https://example.test/account" }
      ],
      edges: [{ from: target, to: route, relation: "contains" }]
    },
    findings: [model.normalize({
      checkId: "inventory.endpoints",
      severity: "info",
      confidence: "high",
      bucket: "review",
      category: "inventory",
      type: "Same-origin route inventory",
      detail: "one route",
      surfaceRefs: [route]
    })]
  };
}

test("surface map links a result to its observed page surface", function () {
  const graph = map.build(sampleScan(), "surface", {});
  const route = graph.nodes.find(function (node) { return node.kind === "route"; });
  const finding = graph.nodes.find(function (node) { return node.kind === "finding"; });
  assert.ok(route);
  assert.ok(finding);
  assert.equal(graph.edges.some(function (edge) { return edge.from === route.id && edge.to === finding.id; }), true);
  assert.equal(graph.available, true);
  assert.equal(graph.width > 0 && graph.height > 0, true);
});

test("scan flow maps selected checks and supports result filters", function () {
  const graph = map.build(sampleScan(), "flow", { bucket: "finding" });
  assert.equal(graph.nodes.some(function (node) { return node.kind === "check" && node.checkId === "safe.cors"; }), true);
  assert.equal(graph.nodes.some(function (node) { return node.kind === "finding"; }), false);
  const searched = map.build(sampleScan(), "surface", { query: "account" });
  assert.equal(searched.nodes.some(function (node) { return node.kind === "route"; }), true);
});

test("confidence filter and coverage status are represented in the graph", function () {
  const filtered = map.build(sampleScan(), "surface", { confidence: "low" });
  assert.equal(filtered.nodes.some(function (node) { return node.kind === "finding"; }), false);
  const flow = map.build(sampleScan(), "flow", {});
  const cors = flow.nodes.find(function (node) { return node.checkId === "safe.cors"; });
  assert.equal(cors.status, "complete");
  assert.equal(cors.subtitle, "complete");
});

test("selection trace follows the evidence path and includes direct relationships", function () {
  const graph = map.build(sampleScan(), "surface", {});
  const route = graph.nodes.find(function (node) { return node.kind === "route"; });
  const finding = graph.nodes.find(function (node) { return node.kind === "finding"; });
  const findingTrace = map.trace(graph, finding.id);
  assert.deepEqual(findingTrace.breadcrumb.map(function (node) { return node.kind; }), ["target", "group", "route", "finding"]);
  assert.equal(findingTrace.edgeIndexes.length, 3);
  const routeTrace = map.trace(graph, route.id);
  assert.equal(routeTrace.nodeIds.includes(finding.id), true);
  assert.equal(routeTrace.nodeIds.includes("map-target"), true);
});

test("map panning starts on the canvas but never on a node", function () {
  assert.equal(map.canPanFrom({ closest: function () { return {}; } }), false);
  assert.equal(map.canPanFrom({ closest: function () { return null; } }), true);
  assert.equal(map.canPanFrom(null), true);
});
