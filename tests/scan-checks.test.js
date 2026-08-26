const assert = require("node:assert/strict");
const test = require("node:test");

require("../scan-checks.js");

const checks = globalThis.VulnscanChecks;

test("limits selected checks to stages available in the chosen mode", function () {
  const selected = ["passive.secrets", "headers.security", "safe.redirects", "lab.paths", "unknown.check"];
  assert.deepEqual(checks.effective(selected, "passive"), ["passive.secrets", "headers.security"]);
  assert.deepEqual(checks.effective(selected, "safe"), ["passive.secrets", "headers.security", "safe.redirects"]);
  assert.deepEqual(checks.effective(selected, "lab"), ["passive.secrets", "headers.security", "lab.paths"]);
  assert.deepEqual(checks.effective(selected, "full"), ["passive.secrets", "headers.security", "safe.redirects", "lab.paths"]);
});

test("estimates only requests belonging to selected active checks", function () {
  assert.equal(checks.requestEstimate(["passive.secrets"], "full"), 0);
  assert.equal(checks.requestEstimate(["safe.reflection", "safe.robots"], "safe"), 7);
  assert.equal(checks.requestEstimate(["safe.redirects", "lab.paths"], "full"), 31);
  assert.equal(checks.requestEstimate(checks.all(), "safe"), 20);
  assert.equal(checks.requestEstimate(checks.all(), "full"), 45);
});

test("maps passive findings to their selectable check families", function () {
  assert.equal(checks.findingCheck("secret.stripe.live.key"), "passive.secrets");
  assert.equal(checks.findingCheck("dom.source-to-sink"), "passive.dom");
  assert.equal(checks.findingCheck("script.missing-sri"), "passive.source");
  assert.equal(checks.findingCheck("header.cors.null-origin"), "headers.boundaries");
  assert.equal(checks.findingCheck("active.source-map"), "safe.source-maps");
});
