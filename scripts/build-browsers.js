const fs = require("node:fs");
const path = require("node:path");

const root = path.resolve(__dirname, "..");
const dist = path.join(root, "dist");
const sharedFiles = [
  "background.js",
  "content.js",
  "dashboard.css",
  "dashboard.html",
  "dashboard.js",
  "finding-guidance.js",
  "finding-model.js",
  "LICENSE",
  "README.md",
  "RELEASE_NOTES.md",
  "request-controller.js",
  "scan-checks.js"
];

function insideRoot(value) {
  const target = path.resolve(value);
  return target === root || target.startsWith(root + path.sep);
}

function build(browser) {
  const target = path.join(dist, browser);
  if (!insideRoot(target)) throw new Error("Build path escaped the project directory");
  fs.mkdirSync(target, { recursive: true });
  sharedFiles.forEach(function (name) {
    fs.copyFileSync(path.join(root, name), path.join(target, name));
  });
  fs.copyFileSync(path.join(root, "manifests", browser + ".json"), path.join(target, "manifest.json"));
}

if (insideRoot(dist)) fs.rmSync(dist, { recursive: true, force: true });
build("chrome");
build("firefox");

console.log("Built Chrome and Firefox extension directories in dist.");
