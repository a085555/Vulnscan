(function (root) {
  const severities = ["high", "medium", "low", "info"];
  const confidences = ["high", "medium", "low"];

  function clean(value) {
    return String(value === undefined || value === null ? "" : value).trim();
  }

  function hash(value) {
    let result = 2166136261;
    for (let i = 0; i < value.length; i++) {
      result ^= value.charCodeAt(i);
      result = Math.imul(result, 16777619);
    }
    return (result >>> 0).toString(16).padStart(8, "0");
  }

  function fingerprint(finding) {
    const parts = [
      clean(finding.checkId).toLowerCase(),
      clean(finding.bucket).toLowerCase(),
      clean(finding.type).toLowerCase(),
      clean(finding.detail).toLowerCase()
    ];
    return "vf-" + hash(parts.join("|"));
  }

  function normalize(finding) {
    const item = finding || {};
    const severity = severities.includes(item.severity) ? item.severity : "info";
    const confidence = confidences.includes(item.confidence) ? item.confidence : "low";
    const bucket = item.bucket === "finding" ? "finding" : "review";
    const normalized = {
      checkId: clean(item.checkId) || "general.observation",
      fingerprint: clean(item.fingerprint),
      severity: severity,
      confidence: confidence,
      bucket: bucket,
      category: clean(item.category) || "general",
      type: clean(item.type) || "Observation",
      detail: clean(item.detail),
      evidence: clean(item.evidence),
      verification: clean(item.verification),
      source: clean(item.source) || "passive",
      occurrences: Math.max(1, Number.parseInt(item.occurrences, 10) || 1)
    };
    normalized.fingerprint = normalized.fingerprint || fingerprint(normalized);
    return normalized;
  }

  function dedupe(findings) {
    const unique = new Map();
    (findings || []).forEach(function (finding) {
      const item = normalize(finding);
      const existing = unique.get(item.fingerprint);
      if (existing) {
        existing.occurrences += item.occurrences;
        return;
      }
      unique.set(item.fingerprint, item);
    });
    return Array.from(unique.values());
  }

  function summarize(findings) {
    const summary = { high: 0, medium: 0, low: 0, info: 0, review: 0, findings: 0 };
    dedupe(findings).forEach(function (finding) {
      if (finding.bucket === "review") {
        summary.review++;
        return;
      }
      summary[finding.severity]++;
      summary.findings++;
    });
    return summary;
  }

  function risk(findings) {
    const summary = summarize(findings);
    if (summary.high) return "high";
    if (summary.medium) return "medium";
    if (summary.low) return "low";
    if (summary.findings) return "info";
    if (summary.review) return "review";
    return "info";
  }

  root.VulnscanFindings = {
    normalize: normalize,
    dedupe: dedupe,
    summarize: summarize,
    risk: risk,
    fingerprint: fingerprint,
    key: function (value) { return "vk-" + hash(clean(value)); }
  };
})(globalThis);

