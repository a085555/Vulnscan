const assert = require("node:assert/strict");
const test = require("node:test");

require("../request-controller.js");

const requests = globalThis.VulnscanRequests;

function response(status, body, headers) {
  return {
    status: status,
    ok: status >= 200 && status < 300,
    headers: { get: function (name) { return (headers || {})[String(name).toLowerCase()] || null; } },
    text: async function () { return body || ""; }
  };
}

test("enforces mode methods and the exact selected origin", async function () {
  const passive = requests.create({ mode: "passive", origin: "https://example.test", fetchFn: async function () { return response(200); } });
  await assert.rejects(passive.request("https://example.test/"), /not allowed/);

  const safe = requests.create({ mode: "safe", origin: "https://example.test/path", fetchFn: async function () { return response(200, "ok"); } });
  assert.equal((await safe.request("https://example.test/check", { method: "GET" })).status, 200);
  assert.equal((await safe.request("https://example.test/check", { method: "HEAD" })).status, 200);
  assert.equal((await safe.request("https://example.test/check", { method: "OPTIONS" })).status, 200);
  await assert.rejects(safe.request("https://example.test/check", { method: "POST" }), /not allowed/);
  await assert.rejects(safe.request("https://sub.example.test/check"), /outside/);
});

test("clamps and enforces the request budget", async function () {
  const controller = requests.create({
    mode: "safe",
    origin: "https://example.test",
    budget: 1,
    fetchFn: async function () { return response(200); }
  });
  assert.equal(controller.budget, 5);
  for (let index = 0; index < 5; index++) await controller.request("https://example.test/" + index);
  const skipped = await controller.request("https://example.test/6");
  assert.equal(skipped.skipped, true);
  assert.equal(controller.getSummary().stoppedReason, "budget-exhausted");
  assert.equal(controller.getLog().length, 5);
});

test("stops on rate limiting and repeated refusal responses", async function () {
  const rateLimited = requests.create({ mode: "safe", origin: "https://example.test", fetchFn: async function () { return response(429); } });
  await rateLimited.request("https://example.test/a");
  assert.equal(rateLimited.getSummary().stoppedReason, "rate-limited");

  const forbidden = requests.create({ mode: "safe", origin: "https://example.test", fetchFn: async function () { return response(403); } });
  await forbidden.request("https://example.test/a");
  await forbidden.request("https://example.test/b");
  await forbidden.request("https://example.test/c");
  assert.equal(forbidden.getSummary().stoppedReason, "repeated-403");

  const serverErrors = requests.create({ mode: "safe", origin: "https://example.test", fetchFn: async function () { return response(503); } });
  await serverErrors.request("https://example.test/a");
  await serverErrors.request("https://example.test/b");
  await serverErrors.request("https://example.test/c");
  assert.equal(serverErrors.getSummary().stoppedReason, "repeated-5xx");
});

test("times out, caps response bodies, and redacts request logs", async function () {
  const timeout = requests.create({
    mode: "safe",
    origin: "https://example.test",
    timeoutMs: 5,
    fetchFn: function (url, options) {
      return new Promise(function (resolve, reject) {
        options.signal.addEventListener("abort", function () { reject(new Error("aborted")); });
      });
    }
  });
  assert.equal((await timeout.request("https://example.test/wait?token=raw#fragment")).outcome, "timeout");
  assert.doesNotMatch(timeout.getLog()[0].url, /raw|fragment/);

  const capped = requests.create({
    mode: "safe",
    origin: "https://example.test",
    maxResponseBytes: 10,
    fetchFn: async function () { return response(200, "this body is too long"); }
  });
  assert.equal((await capped.request("https://example.test/large")).outcome, "response-too-large");
});
