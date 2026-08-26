(function (root) {
  const catalog = [
    { id: "passive.inventory", stage: "passive", label: "Surface inventory", description: "Routes, parameters, forms, resources, storage names, and authentication clues" },
    { id: "passive.dom", stage: "passive", label: "DOM data flows", description: "DOM sinks, inline handlers, and source-to-sink candidates" },
    { id: "passive.secrets", stage: "passive", label: "Secret patterns", description: "Provider-specific and generic credential patterns" },
    { id: "passive.forms", stage: "passive", label: "Form checks", description: "Submission transport, destination, and CSRF-field clues" },
    { id: "passive.transport", stage: "passive", label: "Mixed content", description: "HTTP resources loaded by HTTPS pages" },
    { id: "passive.cookies", stage: "passive", label: "Page-visible cookies", description: "Cookie names exposed to page JavaScript" },
    { id: "passive.components", stage: "passive", label: "Component versions", description: "Neutral library and framework version observations" },
    { id: "passive.source", stage: "passive", label: "Source clues", description: "Comments, technology hints, SRI, redirect keys, and sensitive paths" },
    { id: "headers.security", stage: "headers", label: "Security headers", description: "CSP, HSTS, framing, MIME, referrer, and permissions policies" },
    { id: "headers.cookies", stage: "headers", label: "Response cookie flags", description: "Secure, HttpOnly, and SameSite attributes" },
    { id: "safe.reflection", stage: "safe", label: "Reflection probes", description: "Harmless same-origin query markers" },
    { id: "safe.redirects", stage: "safe", label: "Redirect confirmation", description: "Exact external redirect canary checks" },
    { id: "safe.robots", stage: "safe", label: "robots.txt", description: "Sitemap metadata discovery" },
    { id: "lab.paths", stage: "lab", label: "Path discovery", description: "Budgeted soft-404-aware common-path checks" }
  ];

  const ids = catalog.map(function (check) { return check.id; });
  const idSet = new Set(ids);

  function normalize(selected) {
    if (!Array.isArray(selected)) return ids.slice();
    return ids.filter(function (id) { return selected.includes(id); });
  }

  function stagesForMode(mode) {
    const stages = new Set(["passive", "headers"]);
    if (mode === "safe" || mode === "full") stages.add("safe");
    if (mode === "lab" || mode === "full") stages.add("lab");
    return stages;
  }

  function effective(selected, mode) {
    const stages = stagesForMode(mode);
    return normalize(selected).filter(function (id) {
      const check = catalog.find(function (item) { return item.id === id; });
      return check && stages.has(check.stage);
    });
  }

  function enabled(selected, id) {
    return idSet.has(id) && normalize(selected).includes(id);
  }

  function stageEnabled(selected, mode, stage) {
    return effective(selected, mode).some(function (id) {
      return id.startsWith(stage + ".");
    });
  }

  function findingCheck(checkId) {
    const value = String(checkId || "");
    if (value.startsWith("inventory.")) return "passive.inventory";
    if (value.startsWith("dom.")) return "passive.dom";
    if (value.startsWith("secret.")) return "passive.secrets";
    if (value.startsWith("form.")) return "passive.forms";
    if (value.startsWith("transport.")) return "passive.transport";
    if (value.startsWith("cookie.")) return "passive.cookies";
    if (value.startsWith("library.")) return "passive.components";
    if (value.startsWith("source.") || value.startsWith("redirect.query-") ||
        value.startsWith("script.") || value.startsWith("style.") || value.startsWith("technology.")) return "passive.source";
    return null;
  }

  function requestEstimate(selected, mode) {
    const active = effective(selected, mode);
    let total = 0;
    if (active.includes("safe.reflection")) total += 6;
    if (active.includes("safe.redirects")) total += 6;
    if (active.includes("safe.robots")) total += 1;
    if (active.includes("lab.paths")) total += 25;
    return total;
  }

  root.VulnscanChecks = {
    catalog: catalog,
    all: function () { return ids.slice(); },
    normalize: normalize,
    effective: effective,
    enabled: enabled,
    stageEnabled: stageEnabled,
    findingCheck: findingCheck,
    requestEstimate: requestEstimate
  };
})(globalThis);
