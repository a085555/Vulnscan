(function (root) {
  "use strict";

  function parsed(value, base) {
    try { return new URL(value, base); } catch (e) { return null; }
  }

  function comparable(value, base) {
    const url = parsed(value, base);
    if (!url) return "";
    url.hash = "";
    return url.href;
  }

  function origin(value, base) {
    const url = parsed(value, base);
    if (!url) return "";
    if (url.origin !== "null") return url.origin;
    return url.host ? url.protocol + "//" + url.host : "";
  }

  function redact(value, base) {
    const url = parsed(value, base);
    if (!url) return "[invalid URL]";
    url.username = "";
    url.password = "";
    url.hash = "";
    url.pathname = url.pathname.split("/").map(function (part) {
      return part.length >= 20 && /^[A-Za-z0-9._~-]+$/.test(part) ? "[redacted]" : part;
    }).join("/");
    Array.from(url.searchParams.keys()).forEach(function (name) {
      url.searchParams.set(name, "[redacted]");
    });
    return url.href;
  }

  function target(value, base) {
    const url = parsed(value, base);
    if (!url) return "";
    const names = Array.from(new Set(Array.from(url.searchParams.keys()))).sort().slice(0, 100);
    return url.origin + url.pathname + (names.length ? "?" + names.map(encodeURIComponent).join("&") : "");
  }

  root.VulnscanUrls = {
    comparable: comparable,
    origin: origin,
    redact: redact,
    target: target
  };
})(globalThis);
