const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const test = require("node:test");

const root = path.join(__dirname, "..");

test("manifest and visible version are consistent", function () {
  const manifest = JSON.parse(fs.readFileSync(path.join(root, "manifest.json"), "utf8"));
  const readme = fs.readFileSync(path.join(root, "README.md"), "utf8");
  const dashboard = fs.readFileSync(path.join(root, "dashboard.js"), "utf8");
  assert.equal(manifest.version, "5.4.0");
  assert.equal(manifest.minimum_chrome_version, "102");
  assert.match(readme, /v5\.4\.0/);
  assert.match(dashboard, /getManifest\(\)\.version/);
  assert.equal(manifest.action.default_popup, undefined);
  const html = fs.readFileSync(path.join(root, "dashboard.html"), "utf8");
  assert.match(html, /request-controller\.js/);
  assert.match(html, /id="fullScanToggle"/);
  assert.match(html, /Full Scan/);
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
  const files = ["README.md", "manifest.json", "background.js", "content.js", "dashboard.html", "dashboard.js", "dashboard.css", "finding-model.js", "request-controller.js"];
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
