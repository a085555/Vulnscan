const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const test = require("node:test");

const root = path.join(__dirname, "..");

test("manifest and visible version are consistent", function () {
  const manifest = JSON.parse(fs.readFileSync(path.join(root, "manifest.json"), "utf8"));
  const packageJson = JSON.parse(fs.readFileSync(path.join(root, "package.json"), "utf8"));
  const readme = fs.readFileSync(path.join(root, "README.md"), "utf8");
  const releaseNotes = fs.readFileSync(path.join(root, "RELEASE_NOTES.md"), "utf8");
  const dashboard = fs.readFileSync(path.join(root, "dashboard.js"), "utf8");
  assert.equal(manifest.version, "6.1.0");
  assert.equal(manifest.minimum_chrome_version, "102");
  assert.match(readme, /v6\.1\.0/);
  assert.match(releaseNotes, /Vulnscan v6\.1\.0/);
  assert.equal(packageJson.version, manifest.version);
  assert.match(dashboard, /getManifest\(\)\.version/);
  assert.equal(manifest.action.default_popup, undefined);
  assert.equal(manifest.content_security_policy.extension_pages, "script-src 'self'; object-src 'self'");
  const html = fs.readFileSync(path.join(root, "dashboard.html"), "utf8");
  assert.match(html, /request-controller\.js/);
  assert.match(html, /scan-checks\.js/);
  assert.match(html, /finding-guidance\.js/);
  assert.match(html, /id="fullScanToggle"/);
  assert.match(html, /id="checkPicker"/);
  assert.match(html, /id="comparisonPanel"/);
  assert.match(html, /id="findingDrawer"/);
  assert.match(html, /Full Scan/);
});

test("browser manifests share the release version and use supported background formats", function () {
  const rootManifest = JSON.parse(fs.readFileSync(path.join(root, "manifest.json"), "utf8"));
  const chromeManifest = JSON.parse(fs.readFileSync(path.join(root, "manifests", "chrome.json"), "utf8"));
  const firefoxManifest = JSON.parse(fs.readFileSync(path.join(root, "manifests", "firefox.json"), "utf8"));
  assert.deepEqual(rootManifest, chromeManifest);
  assert.equal(chromeManifest.version, firefoxManifest.version);
  assert.equal(chromeManifest.background.service_worker, "background.js");
  assert.deepEqual(firefoxManifest.background.scripts, ["finding-model.js", "scan-checks.js", "background.js"]);
  assert.equal(firefoxManifest.browser_specific_settings.gecko.strict_min_version, "128.0");
  assert.deepEqual(firefoxManifest.browser_specific_settings.gecko.data_collection_permissions.required, ["none"]);
  assert.equal(firefoxManifest.browser_specific_settings.gecko_android, undefined);
});

test("legacy popup assets are absent", function () {
  ["popup.html", "popup.js", "popup.css"].forEach(function (name) {
    assert.equal(fs.existsSync(path.join(root, name)), false);
  });
});

test("project files contain no unwanted authorship markers", function () {
  const blocked = [
    ["Co", "dex"].join(""),
    ["Chat", "GPT"].join(""),
    ["Co-authored", "-by"].join("")
  ];
  const files = ["README.md", "RELEASE_NOTES.md", "manifest.json", "background.js", "content.js", "dashboard.html", "dashboard.js", "dashboard.css", "finding-model.js", "finding-guidance.js", "scan-checks.js", "request-controller.js", "scripts/build-browsers.js", "manifests/chrome.json", "manifests/firefox.json"];
  files.forEach(function (name) {
    const source = fs.readFileSync(path.join(root, name), "utf8");
    blocked.forEach(function (marker) {
      assert.equal(source.toLowerCase().includes(marker.toLowerCase()), false, name + " contains " + marker);
    });
  });
});

test("normal report exports cannot read the raw secret vault", function () {
  const dashboard = fs.readFileSync(path.join(root, "dashboard.js"), "utf8");
  const markdown = dashboard.slice(dashboard.indexOf("function exportRedactedMarkdown"), dashboard.indexOf("function exportRedactedJson"));
  const json = dashboard.slice(dashboard.indexOf("function exportRedactedJson"), dashboard.indexOf("function exportRawSecrets"));
  assert.doesNotMatch(markdown + json, /getExportSecrets|get_export_secrets/);
});

test("passive storage inventory reads names but not values", function () {
  const content = fs.readFileSync(path.join(root, "content.js"), "utf8");
  const helper = content.slice(content.indexOf("function readStorageNames"), content.indexOf("function addPassiveInventory"));
  assert.match(helper, /storage\.key/);
  assert.doesNotMatch(helper, /getItem|storage\s*\[/);
});
