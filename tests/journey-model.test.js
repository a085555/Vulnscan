const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const test = require("node:test");
const vm = require("node:vm");

const root = path.join(__dirname, "..");
const context = { URL: URL, Date: Date };
vm.createContext(context);
["finding-model.js", "url-utils.js", "scan-checks.js", "journey-model.js", "header-analysis.js"].forEach(function (name) {
  vm.runInContext(fs.readFileSync(path.join(root, name), "utf8"), context);
});

const model = context.VulnscanJourneys;
const findings = context.VulnscanFindings;

function createJourney() {
  return model.create({ journeyId: "journey-1", origin: "https://example.test", tabId: 9, startedAt: 1000 });
}

test("sanitizes routes before they enter journey state", function () {
  const value = model.route("https://user:pass@example.test/users/123/550e8400-e29b-41d4-a716-446655440000/AbCdEf0123456789AbCdEf?token=raw-secret&empty=#private");
  assert.equal(value, "https://example.test/users/:id/:uuid/:token?empty=%5Bredacted%5D&token=%5Bredacted%5D");
  assert.doesNotMatch(value, /user:|pass|raw-secret|private|550e8400|AbCdEf/);
});

test("assigns monotonic sequence numbers and emits one terminal event-limit row", function () {
  const journey = createJourney();
  for (let index = 0; index < model.limits.events + 20; index++) {
    model.appendEvent(journey, { kind: "session", phase: "complete", timestamp: index + 1, details: { reason: "tick" } });
  }
  assert.equal(journey.events.length, model.limits.events);
  assert.equal(journey.events[0].sequence, 1);
  assert.equal(journey.events.at(-1).sequence, model.limits.events);
  assert.equal(journey.events.at(-1).kind, "coverage");
  assert.equal(journey.events.at(-1).details.reason, "capture-event-limit");
  assert.equal(journey.limits.events, true);
});

test("enforces route, endpoint, finding, and surface collection limits", function () {
  const routes = createJourney();
  for (let index = 0; index <= model.limits.pages; index++) {
    model.noteNavigation(routes, { url: "https://example.test/page/route-" + index.toString(36), timestamp: 1100 + index });
  }
  assert.equal(routes.pages.length, model.limits.pages);
  assert.equal(routes.limits.pages, true);
  assert.equal(routes.events.filter(function (event) { return event.details.reason === "page-limit"; }).length, 1);

  const endpoints = createJourney();
  const endpointPage = model.noteNavigation(endpoints, { url: "https://example.test/app", timestamp: 1100 });
  for (let index = 0; index <= model.limits.endpoints; index++) {
    model.recordApi(endpoints, {
      url: "https://example.test/api/route-" + index.toString(36), method: "GET", pageRef: endpointPage.id,
      status: 200, durationMs: 10, timestamp: 1200 + index
    });
  }
  assert.equal(endpoints.apiEndpoints.length, model.limits.endpoints);
  assert.equal(endpoints.limits.endpoints, true);
  assert.equal(endpoints.events.filter(function (event) { return event.details.reason === "api-endpoint-limit"; }).length, 1);

  const grouped = createJourney();
  model.noteNavigation(grouped, { url: "https://example.test/results", timestamp: 1100 });
  const batch = Array.from({ length: model.limits.findings }, function (_, index) {
    return {
      checkId: "journey.limit." + index, severity: "low", confidence: "low", bucket: "review", category: "test",
      type: "Bounded clue", detail: "Bounded clue", location: "slot-" + index, source: "passive"
    };
  });
  model.mergePageResults(grouped, { url: "https://example.test/results", findings: batch, timestamp: 1200 });
  model.mergePageResults(grouped, {
    url: "https://example.test/results", timestamp: 1300,
    findings: [{ checkId: "journey.limit.extra", bucket: "review", type: "Extra clue", location: "extra" }]
  });
  assert.equal(grouped.findings.length, model.limits.findings);
  assert.equal(grouped.limits.findings, true);
  assert.equal(grouped.events.filter(function (event) { return event.details.reason === "finding-limit"; }).length, 1);

  const surface = createJourney();
  const surfacePage = model.noteNavigation(surface, { url: "https://example.test/surface", timestamp: 1100 });
  surface.surface.nodes = Array.from({ length: model.limits.surfaceNodes }, function (_, index) {
    return { id: "vs-" + index.toString(16).padStart(8, "0"), kind: "resource", label: "resource-" + index, detail: "", location: "", occurrences: 1, pageRefs: [surfacePage.id] };
  });
  model.mergePageResults(surface, {
    url: "https://example.test/surface", timestamp: 1200, findings: [],
    surface: { nodes: [{ id: "vs-ffffffff", kind: "resource", label: "extra", occurrences: 1 }], edges: [] }
  });
  assert.equal(surface.surface.nodes.length, model.limits.surfaceNodes);
  assert.equal(surface.limits.surface, true);
  assert.equal(surface.events.filter(function (event) { return event.details.reason === "surface-limit"; }).length, 1);
});

test("groups matching findings while retaining bounded page evidence", function () {
  const journey = createJourney();
  model.noteNavigation(journey, { url: "https://example.test/account/1", timestamp: 1100 });
  const base = {
    checkId: "dom.flow", severity: "medium", confidence: "medium", bucket: "finding", category: "xss",
    type: "DOM source-to-sink flow", detail: "First page", evidence: "A source reaches a sink.", verification: "Trace the flow.", location: "inline script", source: "passive"
  };
  model.mergePageResults(journey, { url: "https://example.test/account/1", findings: [base], timestamp: 1200 });
  model.noteNavigation(journey, { url: "https://example.test/account/2", timestamp: 1300 });
  model.mergePageResults(journey, { url: "https://example.test/account/2", findings: [Object.assign({}, base, { detail: "Second page", evidence: "The same flow appears again." })], timestamp: 1400 });
  assert.equal(journey.pages.length, 1, "numeric route segments share one route template");
  assert.equal(journey.findings.length, 1);
  assert.equal(journey.findings[0].pageCount, 1);
  assert.equal(journey.findings[0].pageOccurrences.length, 2);
  assert.equal(journey.summary.findings, 1);
});

test("aggregates same-origin API outcomes without retaining query values", function () {
  const journey = createJourney();
  const page = model.noteNavigation(journey, { url: "https://example.test/app", timestamp: 1000 });
  model.recordApi(journey, { url: "https://example.test/api/users/42?access_token=secret-one", method: "GET", pageRef: page.id, status: 200, durationMs: 43, timestamp: 1100 });
  model.recordApi(journey, { url: "https://example.test/api/users/89?access_token=secret-two", method: "GET", pageRef: page.id, status: 503, durationMs: 57, timestamp: 1200 });
  assert.equal(journey.apiEndpoints.length, 1);
  const endpoint = journey.apiEndpoints[0];
  assert.equal(endpoint.occurrences, 2);
  assert.equal(endpoint.statuses["200"], 1);
  assert.equal(endpoint.statuses["503"], 1);
  assert.match(endpoint.route, /\/api\/users\/:id\?access_token=%5Bredacted%5D$/);
  assert.doesNotMatch(JSON.stringify(journey), /secret-one|secret-two/);
});

test("normalization drops arbitrary event fields and re-sanitizes stored URLs", function () {
  const journey = createJourney();
  journey.events.push({
    sequence: 4, timestamp: 4, kind: "api", phase: "complete", level: "success", method: "GET",
    route: "https://example.test/api/123?key=raw", requestBody: "never-store", headers: { authorization: "secret" },
    details: { reason: "complete", console: "page supplied", count: 1 }
  });
  const normalized = model.normalize(journey);
  const serialized = JSON.stringify(normalized);
  assert.doesNotMatch(serialized, /never-store|authorization|page supplied|\"key\":\"raw\"/);
  assert.match(normalized.events[0].route, /key=%5Bredacted%5D/);
});

test("page-supplied titles never enter saved journey state", function () {
  const journey = createJourney();
  model.noteNavigation(journey, { url: "https://example.test/account", title: "Private account token raw-title", timestamp: 1100 });
  model.mergePageResults(journey, { url: "https://example.test/account", title: "raw-title", timestamp: 1200, findings: [] });
  const normalized = model.normalize(journey);
  assert.equal(normalized.pages[0].title, "");
  assert.doesNotMatch(JSON.stringify(normalized), /raw-title|Private account/);
});

test("header analysis never carries a Set-Cookie value into findings", function () {
  const result = context.VulnscanHeaders.analyze([
    { name: "set-cookie", value: "session=very-secret-cookie; Path=/; SameSite=Lax" }
  ], "https://example.test/", context.VulnscanChecks.all());
  assert.equal(result.findings.some(function (item) { return item.checkId === "header.cookie-flags"; }), true);
  assert.doesNotMatch(JSON.stringify(result), /very-secret-cookie/);
});

test("finalized journeys preserve schema and calculate risk from actionable findings", function () {
  const journey = createJourney();
  model.noteNavigation(journey, { url: "https://example.test/", timestamp: 1000 });
  model.mergePageResults(journey, {
    url: "https://example.test/",
    findings: [findings.normalize({ checkId: "secret.provider", severity: "high", confidence: "high", bucket: "finding", category: "secret", type: "Provider secret", detail: "Redacted provider credential", evidence: "Pattern matched", verification: "Rotate it" })],
    timestamp: 1200
  });
  const completed = model.finalize(journey, "finished", 1500);
  assert.equal(completed.journeySchemaVersion, 1);
  assert.equal(completed.status, "complete");
  assert.equal(completed.risk, "high");
  assert.match(completed.name, /example\.test/);
});
