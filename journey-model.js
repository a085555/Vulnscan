(function (root) {
  "use strict";

  const limits = Object.freeze({
    durationMs: 30 * 60 * 1000,
    pages: 25,
    events: 1000,
    endpoints: 200,
    findings: 250,
    surfaceNodes: 600,
    surfaceEdges: 1000,
    pageOccurrences: 25
  });

  const eventKinds = new Set(["session", "navigation", "page", "api", "finding", "coverage", "error"]);
  const eventPhases = new Set(["start", "redirect", "complete", "limited", "stopped", "restored", "error"]);
  const eventLevels = new Set(["info", "success", "warning", "finding", "error"]);
  const detailKeys = new Set(["reason", "findingType", "severity", "findings", "review", "count"]);

  function text(value, limit) {
    return String(value === undefined || value === null ? "" : value)
      .replace(/[\u0000-\u001f\u007f-\u009f\u2028\u2029]+/g, " ")
      .trim()
      .slice(0, limit || 1000);
  }

  function parsed(value, base) {
    try { return new URL(value, base); } catch (e) { return null; }
  }

  function route(value, base) {
    const url = parsed(value, base);
    if (!url || !["http:", "https:"].includes(url.protocol)) return "";
    url.username = "";
    url.password = "";
    url.hash = "";
    url.pathname = url.pathname.split("/").map(function (part) {
      let decoded = part;
      try { decoded = decodeURIComponent(part); } catch (e) {}
      if (/^\d+$/.test(decoded)) return ":id";
      if (/^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i.test(decoded)) return ":uuid";
      if (decoded.length >= 20 && /^[A-Za-z0-9._~-]+$/.test(decoded)) return ":token";
      return part;
    }).join("/");
    const names = Array.from(new Set(Array.from(url.searchParams.keys()))).sort().slice(0, 100);
    url.search = "";
    names.forEach(function (name) { url.searchParams.append(name, "[redacted]"); });
    return url.href;
  }

  function id(prefix, value) {
    const key = VulnscanFindings.key(value).replace(/^vk-/, "");
    return prefix + "-" + key;
  }

  function routeId(value) {
    return id("jp", value);
  }

  function endpointId(method, value) {
    return id("ja", method + "|" + value);
  }

  function blankLimits() {
    return { pages: false, events: false, endpoints: false, findings: false, surface: false };
  }

  function create(options) {
    const item = options || {};
    const origin = VulnscanUrls.origin(item.origin);
    const startedAt = Math.max(0, Number(item.startedAt) || Date.now());
    return {
      journeySchemaVersion: 1,
      journeyId: text(item.journeyId, 100),
      name: text(item.name, 80),
      origin: origin,
      tabId: Number.isInteger(item.tabId) ? item.tabId : -1,
      startedAt: startedAt,
      endedAt: 0,
      expiresAt: startedAt + limits.durationMs,
      status: "recording",
      stopReason: "",
      currentPageRef: "",
      nextSequence: 1,
      pages: [],
      apiEndpoints: [],
      findings: [],
      events: [],
      surface: { nodes: [], edges: [], truncated: false },
      summary: { high: 0, medium: 0, low: 0, info: 0, review: 0, findings: 0 },
      risk: "info",
      limits: blankLimits()
    };
  }

  function cleanDetails(value) {
    const source = value && typeof value === "object" ? value : {};
    const result = {};
    Object.keys(source).forEach(function (key) {
      if (!detailKeys.has(key)) return;
      if (["findings", "review", "count"].includes(key)) {
        result[key] = Math.min(10000, Math.max(0, Number.parseInt(source[key], 10) || 0));
        return;
      }
      result[key] = text(source[key], 240);
    });
    return result;
  }

  function event(value) {
    const item = value && typeof value === "object" ? value : {};
    return {
      sequence: Math.max(1, Number.parseInt(item.sequence, 10) || 1),
      timestamp: Math.max(0, Number(item.timestamp) || Date.now()),
      kind: eventKinds.has(item.kind) ? item.kind : "session",
      phase: eventPhases.has(item.phase) ? item.phase : "complete",
      level: eventLevels.has(item.level) ? item.level : "info",
      pageRef: /^jp-[0-9a-f]{8}$/.test(text(item.pageRef, 20)) ? text(item.pageRef, 20) : "",
      findingRef: /^vi-[0-9a-f]{8}$/.test(text(item.findingRef, 20)) ? text(item.findingRef, 20) : "",
      endpointRef: /^ja-[0-9a-f]{8}$/.test(text(item.endpointRef, 20)) ? text(item.endpointRef, 20) : "",
      method: /^[A-Z]{1,12}$/.test(text(item.method, 12)) ? text(item.method, 12) : "",
      route: item.route ? route(item.route) : "",
      status: Math.min(999, Math.max(0, Number.parseInt(item.status, 10) || 0)),
      durationMs: Math.min(limits.durationMs, Math.max(0, Math.round(Number(item.durationMs) || 0))),
      outcome: text(item.outcome, 40),
      details: cleanDetails(item.details)
    };
  }

  function appendEvent(journey, value) {
    if (!journey || journey.status !== "recording") return null;
    if (journey.events.length >= limits.events) {
      journey.limits.events = true;
      return null;
    }
    if (journey.events.length === limits.events - 1 && !(value.kind === "coverage" && value.phase === "limited")) {
      journey.limits.events = true;
      value = {
        kind: "coverage",
        phase: "limited",
        level: "warning",
        timestamp: value.timestamp,
        details: { reason: "capture-event-limit", count: limits.events }
      };
    }
    const item = event(Object.assign({}, value, { sequence: journey.nextSequence++ }));
    journey.events.push(item);
    return item;
  }

  function markLimit(journey, key, reason, count, timestamp, pageRef, sanitizedRoute) {
    if (journey.limits[key]) return;
    journey.limits[key] = true;
    appendEvent(journey, {
      kind: "coverage", phase: "limited", level: "warning", timestamp: timestamp,
      pageRef: pageRef, route: sanitizedRoute, details: { reason: reason, count: count }
    });
  }

  function pageFor(journey, url, title, now, countVisit) {
    const sanitized = route(url);
    if (!sanitized || VulnscanUrls.origin(sanitized) !== journey.origin) return null;
    const pageRef = routeId(sanitized);
    let page = journey.pages.find(function (item) { return item.id === pageRef; });
    if (!page) {
      if (journey.pages.length >= limits.pages) {
        markLimit(journey, "pages", "page-limit", limits.pages, now, "", sanitized);
        return null;
      }
      page = {
        id: pageRef,
        route: sanitized,
        title: "",
        firstSeenAt: now,
        lastSeenAt: now,
        lastCapturedAt: 0,
        visits: 0,
        findingRefs: [],
        surfaceRefs: []
      };
      journey.pages.push(page);
    }
    page.lastSeenAt = now;
    if (countVisit !== false) page.visits++;
    journey.currentPageRef = pageRef;
    return page;
  }

  function noteNavigation(journey, options) {
    const item = options || {};
    const now = Math.max(0, Number(item.timestamp) || Date.now());
    const page = pageFor(journey, item.url, item.title, now, item.countVisit !== false);
    if (!page) return null;
    appendEvent(journey, {
      kind: "navigation",
      phase: item.phase || "start",
      level: item.level || "info",
      timestamp: now,
      pageRef: page.id,
      method: item.method || "GET",
      route: page.route,
      status: item.status,
      details: item.details
    });
    return page;
  }

  function mergeSurface(journey, page, surface) {
    const source = VulnscanFindings.normalizeSurface(surface);
    const known = new Map(journey.surface.nodes.map(function (node) { return [node.id, node]; }));
    source.nodes.forEach(function (node) {
      let stored = known.get(node.id);
      if (stored) {
        stored.pageRefs = Array.from(new Set(stored.pageRefs.concat(page.id))).slice(0, limits.pages);
        stored.occurrences = Math.min(10000, stored.occurrences + node.occurrences);
        return;
      }
      if (journey.surface.nodes.length >= limits.surfaceNodes) {
        markLimit(journey, "surface", "surface-limit", limits.surfaceNodes, Date.now(), page.id, page.route);
        journey.surface.truncated = true;
        return;
      }
      stored = Object.assign({}, node, { pageRefs: [page.id] });
      journey.surface.nodes.push(stored);
      known.set(node.id, stored);
    });
    const edgeKeys = new Set(journey.surface.edges.map(function (edge) { return edge.from + "|" + edge.to + "|" + edge.relation + "|" + edge.pageRef; }));
    source.edges.forEach(function (edge) {
      if (!known.has(edge.from) || !known.has(edge.to)) return;
      const key = edge.from + "|" + edge.to + "|" + edge.relation + "|" + page.id;
      if (edgeKeys.has(key)) return;
      if (journey.surface.edges.length >= limits.surfaceEdges) {
        markLimit(journey, "surface", "surface-limit", limits.surfaceNodes, Date.now(), page.id, page.route);
        journey.surface.truncated = true;
        return;
      }
      edgeKeys.add(key);
      journey.surface.edges.push({ from: edge.from, to: edge.to, relation: edge.relation, pageRef: page.id });
    });
    page.surfaceRefs = Array.from(new Set(page.surfaceRefs.concat(source.nodes.map(function (node) { return node.id; })))).slice(0, limits.surfaceNodes);
    if (source.truncated) journey.surface.truncated = true;
  }

  function mergeFinding(journey, page, value, timestamp) {
    const finding = VulnscanFindings.normalize(value);
    let group = journey.findings.find(function (item) { return item.identityFingerprint === finding.identityFingerprint; });
    if (!group) {
      if (journey.findings.length >= limits.findings) {
        markLimit(journey, "findings", "finding-limit", limits.findings, timestamp, page.id, page.route);
        return null;
      }
      group = Object.assign({}, finding, { pageRefs: [], pageCount: 0, pageOccurrences: [] });
      journey.findings.push(group);
    }
    group.pageRefs = Array.from(new Set(group.pageRefs.concat(page.id))).slice(0, limits.pages);
    group.pageCount = group.pageRefs.length;
    const existing = group.pageOccurrences.find(function (item) { return item.pageRef === page.id && item.fingerprint === finding.fingerprint; });
    if (existing) {
      existing.occurrences = Math.min(10000, existing.occurrences + finding.occurrences);
      existing.lastSeenAt = timestamp;
    } else if (group.pageOccurrences.length < limits.pageOccurrences) {
      group.pageOccurrences.push({
        pageRef: page.id,
        fingerprint: finding.fingerprint,
        detail: finding.detail,
        evidence: finding.evidence,
        location: finding.location,
        selector: finding.selector,
        occurrences: finding.occurrences,
        lastSeenAt: timestamp
      });
    }
    group.occurrences = group.pageOccurrences.reduce(function (total, item) { return total + item.occurrences; }, 0) || finding.occurrences;
    page.findingRefs = Array.from(new Set(page.findingRefs.concat(group.identityFingerprint))).slice(0, limits.findings);
    appendEvent(journey, {
      kind: "finding",
      phase: "complete",
      level: "finding",
      timestamp: timestamp,
      pageRef: page.id,
      findingRef: group.identityFingerprint,
      route: page.route,
      details: { findingType: finding.type, severity: finding.severity, count: finding.occurrences }
    });
    return group;
  }

  function refreshSummary(journey) {
    journey.summary = VulnscanFindings.summarize(journey.findings);
    journey.risk = VulnscanFindings.risk(journey.findings);
    return journey.summary;
  }

  function mergePageResults(journey, options) {
    const item = options || {};
    const now = Math.max(0, Number(item.timestamp) || Date.now());
    const page = pageFor(journey, item.url, item.title, now, false);
    if (!page) return null;
    page.lastCapturedAt = now;
    mergeSurface(journey, page, item.surface);
    (Array.isArray(item.findings) ? item.findings : []).slice(0, VulnscanFindings.limits.findings).forEach(function (finding) {
      mergeFinding(journey, page, finding, now);
    });
    refreshSummary(journey);
    appendEvent(journey, {
      kind: "page",
      phase: "complete",
      level: "success",
      timestamp: now,
      pageRef: page.id,
      route: page.route,
      details: { findings: journey.summary.findings, review: journey.summary.review }
    });
    const scanLimits = item.scanLimits && typeof item.scanLimits === "object" ? item.scanLimits : {};
    if (Object.keys(scanLimits).some(function (key) { return scanLimits[key] === true; })) {
      appendEvent(journey, { kind: "coverage", phase: "limited", level: "warning", timestamp: now, pageRef: page.id, route: page.route, details: { reason: "page-processing-limit" } });
    }
    return page;
  }

  function recordApi(journey, options) {
    const item = options || {};
    const sanitized = route(item.url);
    if (!sanitized || VulnscanUrls.origin(sanitized) !== journey.origin) return null;
    const method = /^[A-Z]{1,12}$/.test(text(item.method, 12).toUpperCase()) ? text(item.method, 12).toUpperCase() : "OTHER";
    const endpointRef = endpointId(method, sanitized);
    let endpoint = journey.apiEndpoints.find(function (entry) { return entry.id === endpointRef; });
    if (!endpoint) {
      if (journey.apiEndpoints.length >= limits.endpoints) {
        markLimit(journey, "endpoints", "api-endpoint-limit", limits.endpoints, item.timestamp, item.pageRef || journey.currentPageRef, sanitized);
        return null;
      }
      endpoint = {
        id: endpointRef,
        method: method,
        route: sanitized,
        firstSeenAt: Math.max(0, Number(item.timestamp) || Date.now()),
        lastSeenAt: 0,
        occurrences: 0,
        statuses: {},
        durationTotalMs: 0,
        durationMinMs: 0,
        durationMaxMs: 0,
        pageRefs: []
      };
      journey.apiEndpoints.push(endpoint);
    }
    const duration = Math.min(limits.durationMs, Math.max(0, Math.round(Number(item.durationMs) || 0)));
    const status = Math.min(999, Math.max(0, Number.parseInt(item.status, 10) || 0));
    const pageRef = /^jp-[0-9a-f]{8}$/.test(item.pageRef) ? item.pageRef : journey.currentPageRef;
    endpoint.lastSeenAt = Math.max(0, Number(item.timestamp) || Date.now());
    endpoint.occurrences++;
    endpoint.statuses[String(status)] = (endpoint.statuses[String(status)] || 0) + 1;
    endpoint.durationTotalMs += duration;
    endpoint.durationMinMs = endpoint.durationMinMs ? Math.min(endpoint.durationMinMs, duration) : duration;
    endpoint.durationMaxMs = Math.max(endpoint.durationMaxMs, duration);
    endpoint.pageRefs = Array.from(new Set(endpoint.pageRefs.concat(pageRef).filter(Boolean))).slice(0, limits.pages);
    appendEvent(journey, {
      kind: "api",
      phase: item.phase || (item.outcome === "error" ? "error" : "complete"),
      level: item.outcome === "error" || status >= 500 ? "error" : status >= 400 ? "warning" : "success",
      timestamp: item.timestamp,
      pageRef: pageRef,
      endpointRef: endpointRef,
      method: method,
      route: sanitized,
      status: status,
      durationMs: duration,
      outcome: item.outcome || "complete"
    });
    return endpoint;
  }

  function defaultName(journey) {
    let host = journey.origin || "Journey";
    try { host = new URL(journey.origin).hostname || host; } catch (e) {}
    const date = new Date(journey.startedAt);
    return host + " — " + date.toISOString().replace("T", " ").slice(0, 16) + " UTC";
  }

  function finalize(journey, reason, timestamp) {
    if (!journey) return null;
    journey.status = "complete";
    journey.stopReason = text(reason || "finished", 40);
    journey.endedAt = Math.max(journey.startedAt, Number(timestamp) || Date.now());
    journey.name = journey.name || defaultName(journey);
    refreshSummary(journey);
    return journey;
  }

  function logLine(value) {
    const item = event(value);
    const stamp = new Date(item.timestamp).toISOString().slice(11, 23);
    const sequence = String(item.sequence).padStart(4, "0");
    const labels = { session: "SESSION", navigation: "NAV", page: "PAGE", api: item.phase === "start" ? "API →" : "API ←", finding: "FINDING", coverage: "COVERAGE", error: "ERROR" };
    const parts = [stamp, "#" + sequence, (labels[item.kind] || item.kind.toUpperCase()).padEnd(8, " ")];
    if (item.method) parts.push(item.method);
    if (item.status) parts.push(String(item.status));
    if (item.route) parts.push(item.route);
    if (item.durationMs) parts.push(item.durationMs + " ms");
    if (item.details.findingType) parts.push(item.details.severity.toUpperCase() + " " + item.details.findingType);
    if (item.details.reason) parts.push(item.details.reason);
    if (item.outcome && item.outcome !== "complete") parts.push(item.outcome);
    return parts.join("  ");
  }

  function normalize(journey) {
    if (!journey || journey.journeySchemaVersion !== 1 || !journey.journeyId || !VulnscanUrls.origin(journey.origin)) return null;
    const copy = create(journey);
    copy.name = text(journey.name, 80);
    copy.endedAt = Math.max(0, Number(journey.endedAt) || 0);
    copy.expiresAt = Math.max(copy.startedAt, Number(journey.expiresAt) || copy.startedAt + limits.durationMs);
    copy.status = journey.status === "complete" ? "complete" : "recording";
    copy.stopReason = text(journey.stopReason, 40);
    copy.currentPageRef = /^jp-[0-9a-f]{8}$/.test(journey.currentPageRef) ? journey.currentPageRef : "";
    copy.nextSequence = Math.max(1, Number.parseInt(journey.nextSequence, 10) || 1);
    copy.pages = (Array.isArray(journey.pages) ? journey.pages : []).slice(0, limits.pages).map(function (page) {
      return {
        id: /^jp-[0-9a-f]{8}$/.test(page.id) ? page.id : routeId(route(page.route)),
        route: route(page.route),
        title: "",
        firstSeenAt: Math.max(0, Number(page.firstSeenAt) || 0),
        lastSeenAt: Math.max(0, Number(page.lastSeenAt) || 0),
        lastCapturedAt: Math.max(0, Number(page.lastCapturedAt) || 0),
        visits: Math.min(10000, Math.max(0, Number.parseInt(page.visits, 10) || 0)),
        findingRefs: (Array.isArray(page.findingRefs) ? page.findingRefs : []).filter(function (value) { return /^vi-[0-9a-f]{8}$/.test(value); }).slice(0, limits.findings),
        surfaceRefs: (Array.isArray(page.surfaceRefs) ? page.surfaceRefs : []).filter(function (value) { return /^vs-[0-9a-f]{8}$/.test(value); }).slice(0, limits.surfaceNodes)
      };
    }).filter(function (page) { return page.route && page.id; });
    copy.apiEndpoints = (Array.isArray(journey.apiEndpoints) ? journey.apiEndpoints : []).slice(0, limits.endpoints).map(function (endpoint) {
      const method = /^[A-Z]{1,12}$/.test(text(endpoint.method, 12)) ? text(endpoint.method, 12) : "OTHER";
      const sanitized = route(endpoint.route);
      const statuses = {};
      Object.keys(endpoint.statuses || {}).slice(0, 20).forEach(function (status) {
        if (/^\d{1,3}$/.test(status)) statuses[status] = Math.min(10000, Math.max(0, Number(endpoint.statuses[status]) || 0));
      });
      return {
        id: endpointId(method, sanitized), method: method, route: sanitized,
        firstSeenAt: Math.max(0, Number(endpoint.firstSeenAt) || 0), lastSeenAt: Math.max(0, Number(endpoint.lastSeenAt) || 0),
        occurrences: Math.min(10000, Math.max(0, Number(endpoint.occurrences) || 0)), statuses: statuses,
        durationTotalMs: Math.max(0, Math.round(Number(endpoint.durationTotalMs) || 0)),
        durationMinMs: Math.max(0, Math.round(Number(endpoint.durationMinMs) || 0)), durationMaxMs: Math.max(0, Math.round(Number(endpoint.durationMaxMs) || 0)),
        pageRefs: (Array.isArray(endpoint.pageRefs) ? endpoint.pageRefs : []).filter(function (value) { return /^jp-[0-9a-f]{8}$/.test(value); }).slice(0, limits.pages)
      };
    }).filter(function (endpoint) { return endpoint.route; });
    copy.findings = (Array.isArray(journey.findings) ? journey.findings : []).slice(0, limits.findings).map(function (value) {
      const finding = VulnscanFindings.normalize(value);
      finding.pageRefs = (Array.isArray(value.pageRefs) ? value.pageRefs : []).filter(function (pageRef) { return /^jp-[0-9a-f]{8}$/.test(pageRef); }).slice(0, limits.pages);
      finding.pageCount = finding.pageRefs.length;
      finding.pageOccurrences = (Array.isArray(value.pageOccurrences) ? value.pageOccurrences : []).slice(0, limits.pageOccurrences).map(function (occurrence) {
        return {
          pageRef: /^jp-[0-9a-f]{8}$/.test(occurrence.pageRef) ? occurrence.pageRef : "",
          fingerprint: /^vf-[0-9a-f]{8}$/.test(occurrence.fingerprint) ? occurrence.fingerprint : finding.fingerprint,
          detail: text(occurrence.detail, 4000), evidence: text(occurrence.evidence, 4000),
          location: text(occurrence.location, 1000), selector: text(occurrence.selector, 240),
          occurrences: Math.min(10000, Math.max(1, Number(occurrence.occurrences) || 1)), lastSeenAt: Math.max(0, Number(occurrence.lastSeenAt) || 0)
        };
      }).filter(function (occurrence) { return occurrence.pageRef; });
      return finding;
    });
    copy.events = (Array.isArray(journey.events) ? journey.events : []).slice(0, limits.events).map(event).sort(function (left, right) { return left.sequence - right.sequence; });
    copy.surface = { nodes: [], edges: [], truncated: !!(journey.surface && journey.surface.truncated) };
    const surface = journey.surface && typeof journey.surface === "object" ? journey.surface : {};
    copy.surface.nodes = (Array.isArray(surface.nodes) ? surface.nodes : []).slice(0, limits.surfaceNodes).map(function (node) {
      const normalized = VulnscanFindings.normalizeSurface({ nodes: [node], edges: [] }).nodes[0];
      if (!normalized) return null;
      normalized.pageRefs = (Array.isArray(node.pageRefs) ? node.pageRefs : []).filter(function (pageRef) { return /^jp-[0-9a-f]{8}$/.test(pageRef); }).slice(0, limits.pages);
      return normalized;
    }).filter(Boolean);
    const surfaceIds = new Set(copy.surface.nodes.map(function (node) { return node.id; }));
    copy.surface.edges = (Array.isArray(surface.edges) ? surface.edges : []).slice(0, limits.surfaceEdges).map(function (edge) {
      return { from: text(edge.from, 80), to: text(edge.to, 80), relation: text(edge.relation, 40), pageRef: /^jp-[0-9a-f]{8}$/.test(edge.pageRef) ? edge.pageRef : "" };
    }).filter(function (edge) { return surfaceIds.has(edge.from) && surfaceIds.has(edge.to) && edge.pageRef; });
    copy.limits = Object.assign(blankLimits(), Object.keys(blankLimits()).reduce(function (result, key) { result[key] = !!(journey.limits && journey.limits[key]); return result; }, {}));
    refreshSummary(copy);
    return copy;
  }

  root.VulnscanJourneys = {
    limits: limits,
    route: route,
    routeId: routeId,
    endpointId: endpointId,
    create: create,
    normalize: normalize,
    event: event,
    appendEvent: appendEvent,
    noteNavigation: noteNavigation,
    mergePageResults: mergePageResults,
    recordApi: recordApi,
    refreshSummary: refreshSummary,
    finalize: finalize,
    logLine: logLine
  };
})(globalThis);
