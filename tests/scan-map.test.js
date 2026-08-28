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

test("comparison map includes changed and resolved findings plus surface changes", function () {
  const current = sampleScan();
  const previous = sampleScan();
  previous.timestamp = 10;
  previous.findings = [model.normalize(Object.assign({}, current.findings[0], {
    fingerprint: "",
    detail: "older route evidence"
  })), model.normalize({
    checkId: "transport.old",
    severity: "low",
    confidence: "high",
    bucket: "finding",
    category: "transport",
    type: "Resolved transport issue",
    detail: "previously present",
    source: "passive"
  })];
  previous.surface.nodes.push({ id: model.surfaceId("parameter", "legacy"), kind: "parameter", label: "legacy" });
  const graph = map.buildComparison(current, previous, { comparableStages: ["passive"] });
  assert.equal(graph.nodes.some(function (node) { return node.kind === "finding" && node.change === "changed"; }), true);
  assert.equal(graph.nodes.some(function (node) { return node.kind === "finding" && node.change === "resolved"; }), true);
  assert.equal(graph.comparison.findings.changed, 1);
  assert.equal(graph.comparison.findings.resolved, 1);
  assert.equal(graph.comparison.surface.resolved, 1);
});

test("collapsing a branch hides its descendants while keeping the group", function () {
  const graph = map.build(sampleScan(), "surface", { collapsed: ["map-group-route"] });
  const group = graph.nodes.find(function (node) { return node.id === "map-group-route"; });
  assert.equal(group.collapsed, true);
  assert.equal(group.hiddenCount, 2);
  assert.equal(graph.nodes.some(function (node) { return node.kind === "route"; }), false);
  assert.equal(graph.nodes.some(function (node) { return node.kind === "finding"; }), false);
});

test("sanitized SVG export contains labels but no scripts or finding evidence", function () {
  const scan = sampleScan();
  scan.findings[0].evidence = "sensitive evidence should stay out";
  scan.findings[0].type = "Route <review>";
  const svg = map.exportSvg(map.build(scan, "surface", {}));
  assert.match(svg, /Route &lt;review&gt;/);
  assert.doesNotMatch(svg, /sensitive evidence should stay out|<script/i);
  assert.match(svg, /^<svg/);
});

test("journey maps link pages, API endpoints, and grouped findings", function () {
  const finding = model.normalize({
    checkId: "dom.flow", severity: "medium", confidence: "medium", bucket: "finding", category: "xss",
    type: "DOM flow", detail: "source reaches sink", evidence: "bounded evidence", verification: "trace manually", source: "passive"
  });
  finding.pageRefs = ["jp-11111111"];
  finding.pageCount = 1;
  finding.pageOccurrences = [];
  const journey = {
    origin: "https://example.test",
    name: "Example journey",
    pages: [{ id: "jp-11111111", route: "https://example.test/app", title: "App", firstSeenAt: 1, visits: 2 }],
    apiEndpoints: [{ id: "ja-22222222", method: "GET", route: "https://example.test/api/items/:id", occurrences: 3, statuses: { 200: 3 }, pageRefs: ["jp-11111111"] }],
    findings: [finding],
    surface: { nodes: [], edges: [] },
    limits: {}
  };
  const flow = map.buildJourney(journey, "flow", {});
  const page = flow.nodes.find(function (node) { return node.kind === "page"; });
  const api = flow.nodes.find(function (node) { return node.kind === "api-endpoint"; });
  const findingNode = flow.nodes.find(function (node) { return node.kind === "finding"; });
  assert.ok(page && api && findingNode);
  assert.equal(flow.edges.some(function (edge) { return edge.from === page.id && edge.to === api.id && edge.relation === "requested"; }), true);
  assert.equal(flow.edges.some(function (edge) { return edge.from === page.id && edge.to === findingNode.id && edge.relation === "observed on"; }), true);
  const apiOnly = map.buildJourney(journey, "surface", { kind: "api-endpoint" });
  assert.equal(apiOnly.nodes.some(function (node) { return node.kind === "api-endpoint"; }), true);
  assert.equal(apiOnly.nodes.some(function (node) { return node.kind === "page"; }), true, "page anchors remain visible for endpoint filters");
});
