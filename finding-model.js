(function (root) {
  const severities = ["high", "medium", "low", "info"];
  const confidences = ["high", "medium", "low"];
  const limits = Object.freeze({
    pageSourceCharacters: 2 * 1024 * 1024,
    domNodesPerCheck: 1000,
    findings: 250,
    findingsPerCheck: 25,
    secretValues: 100,
    secretValueCharacters: 4096,
    secretVaultCharacters: 256 * 1024,
    messageTextCharacters: 4000,
    surfaceNodes: 200,
    surfaceEdges: 320,
    surfaceRefsPerFinding: 8,
    mapNodes: 200,
    mapEdges: 320
  });

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

  function identityFingerprint(finding) {
    const affected = clean(finding.location || finding.selector).toLowerCase();
    const parts = [
      clean(finding.checkId).toLowerCase(),
      affected || [clean(finding.type).toLowerCase(), clean(finding.detail).toLowerCase()].join("|")
    ];
    return "vi-" + hash(parts.join("|"));
  }

  function normalize(finding) {
    const item = finding || {};
    const severity = severities.includes(item.severity) ? item.severity : "info";
    const confidence = confidences.includes(item.confidence) ? item.confidence : "low";
    const bucket = item.bucket === "finding" ? "finding" : "review";
    const normalized = {
      checkId: clean(item.checkId) || "general.observation",
      fingerprint: clean(item.fingerprint),
      identityFingerprint: clean(item.identityFingerprint),
      severity: severity,
      confidence: confidence,
      bucket: bucket,
      category: clean(item.category) || "general",
      type: clean(item.type) || "Observation",
      detail: clean(item.detail),
      evidence: clean(item.evidence),
      verification: clean(item.verification),
      location: clean(item.location),
      selector: clean(item.selector),
      source: clean(item.source) || "passive",
      surfaceRefs: Array.from(new Set((Array.isArray(item.surfaceRefs) ? item.surfaceRefs : []).map(function (value) {
        return clean(value).slice(0, 80);
      }).filter(function (value) {
        return /^vs-[0-9a-f]{8}$/.test(value);
      }))).slice(0, limits.surfaceRefsPerFinding),
      occurrences: Math.max(1, Number.parseInt(item.occurrences, 10) || 1)
    };
    normalized.fingerprint = normalized.fingerprint || fingerprint(normalized);
    normalized.identityFingerprint = normalized.identityFingerprint || identityFingerprint(normalized);
    return normalized;
  }

  function dedupe(findings) {
    const unique = new Map();
    (findings || []).forEach(function (finding) {
      const item = normalize(finding);
      const existing = unique.get(item.identityFingerprint);
      if (existing) {
        existing.occurrences += item.occurrences;
        existing.surfaceRefs = Array.from(new Set(existing.surfaceRefs.concat(item.surfaceRefs))).slice(0, limits.surfaceRefsPerFinding);
        return;
      }
      unique.set(item.identityFingerprint, item);
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

  function compare(currentFindings, previousFindings) {
    const current = dedupe(currentFindings);
    const previous = dedupe(previousFindings);
    const currentByIdentity = new Map(current.map(function (finding) {
      return [finding.identityFingerprint, finding];
    }));
    const previousByIdentity = new Map(previous.map(function (finding) {
      return [finding.identityFingerprint, finding];
    }));
    const result = { new: [], resolved: [], changed: [], unchanged: [] };

    current.forEach(function (finding) {
      const old = previousByIdentity.get(finding.identityFingerprint);
      if (!old) {
        result.new.push(finding);
        return;
      }
      const changed = finding.severity !== old.severity ||
        finding.confidence !== old.confidence ||
        finding.bucket !== old.bucket ||
        finding.type !== old.type ||
        finding.detail !== old.detail ||
        finding.evidence !== old.evidence ||
        finding.verification !== old.verification ||
        finding.location !== old.location ||
        finding.selector !== old.selector ||
        finding.surfaceRefs.join("|") !== old.surfaceRefs.join("|") ||
        finding.occurrences !== old.occurrences;
      if (changed) result.changed.push({ current: finding, previous: old });
      else result.unchanged.push(finding);
    });

    previous.forEach(function (finding) {
      if (!currentByIdentity.has(finding.identityFingerprint)) result.resolved.push(finding);
    });
    return result;
  }

  function surfaceId(kind, value) {
    return "vs-" + hash(clean(kind).toLowerCase() + "|" + clean(value).toLowerCase());
  }

  function normalizeSurface(surface) {
    const source = surface && typeof surface === "object" ? surface : {};
    const allowedKinds = new Set(["target", "route", "parameter", "form", "resource", "external-origin", "storage", "authentication"]);
    const allowedRelations = new Set(["contains", "observed", "loads", "submits", "uses", "connects"]);
    const nodes = [];
    const seen = new Set();
    (Array.isArray(source.nodes) ? source.nodes : []).some(function (node) {
      if (nodes.length >= limits.surfaceNodes) return true;
      const item = node && typeof node === "object" ? node : {};
      const kind = allowedKinds.has(item.kind) ? item.kind : "";
      const id = clean(item.id).slice(0, 80);
      if (!kind || !/^vs-[0-9a-f]{8}$/.test(id) || seen.has(id)) return false;
      seen.add(id);
      nodes.push({
        id: id,
        kind: kind,
        label: clean(item.label).slice(0, 120) || "Observed surface",
        detail: clean(item.detail).slice(0, 500),
        location: clean(item.location).slice(0, 1000),
        selector: clean(item.selector).slice(0, 240),
        external: item.external === true,
        occurrences: Math.min(10000, Math.max(1, Number.parseInt(item.occurrences, 10) || 1))
      });
      return false;
    });
    const edges = [];
    const edgeKeys = new Set();
    (Array.isArray(source.edges) ? source.edges : []).some(function (edge) {
      if (edges.length >= limits.surfaceEdges) return true;
      const item = edge && typeof edge === "object" ? edge : {};
      const from = clean(item.from).slice(0, 80);
      const to = clean(item.to).slice(0, 80);
      const relation = allowedRelations.has(item.relation) ? item.relation : "observed";
      const key = from + "|" + to + "|" + relation;
      if (!seen.has(from) || !seen.has(to) || from === to || edgeKeys.has(key)) return false;
      edgeKeys.add(key);
      edges.push({ from: from, to: to, relation: relation });
      return false;
    });
    return {
      nodes: nodes,
      edges: edges,
      truncated: source.truncated === true || (Array.isArray(source.nodes) && source.nodes.length > nodes.length) ||
        (Array.isArray(source.edges) && source.edges.length > edges.length)
    };
  }

  function normalizeCoverage(coverage) {
    const allowedStatuses = new Set(["complete", "limited", "unavailable", "stopped"]);
    const allowedNotes = new Set(["", "origin-not-observed", "candidate-limit", "request-budget", "response-limit", "request-stopped"]);
    const seen = new Set();
    return (Array.isArray(coverage) ? coverage : []).reduce(function (result, entry) {
      const item = entry && typeof entry === "object" ? entry : {};
      const checkId = clean(item.checkId).slice(0, 120);
      if (!checkId || seen.has(checkId) || !allowedStatuses.has(item.status)) return result;
      seen.add(checkId);
      result.push({
        checkId: checkId,
        status: item.status,
        inspected: Math.min(10000, Math.max(0, Number.parseInt(item.inspected, 10) || 0)),
        matched: Math.min(10000, Math.max(0, Number.parseInt(item.matched, 10) || 0)),
        note: allowedNotes.has(item.note) ? item.note : ""
      });
      return result;
    }, []).slice(0, 20);
  }

  root.VulnscanFindings = {
    normalize: normalize,
    dedupe: dedupe,
    summarize: summarize,
    risk: risk,
    compare: compare,
    fingerprint: fingerprint,
    identityFingerprint: identityFingerprint,
    surfaceId: surfaceId,
    normalizeSurface: normalizeSurface,
    normalizeCoverage: normalizeCoverage,
    limits: limits,
    key: function (value) { return "vk-" + hash(clean(value)); }
  };
})(globalThis);
