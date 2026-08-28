(function (root) {
  "use strict";

  const stageLabels = { passive: "Passive", headers: "Headers", safe: "Safe Active", lab: "Lab" };
  const kindLabels = {
    route: "Routes",
    parameter: "Parameters",
    form: "Forms",
    resource: "Resources",
    "external-origin": "External origins",
    storage: "Storage names",
    authentication: "Authentication"
  };
  const severityWeight = { high: 4, medium: 3, low: 2, info: 1 };

  function text(value) {
    return String(value === undefined || value === null ? "" : value);
  }

  function matches(node, query) {
    if (!query) return true;
    const value = [node.label, node.detail, node.location, node.kind].join(" ").toLowerCase();
    return value.includes(query);
  }

  function findingAllowed(finding, options) {
    if (options.bucket && options.bucket !== "all" && finding.bucket !== options.bucket) return false;
    if (options.severity && options.severity !== "all" && finding.severity !== options.severity) return false;
    if (options.confidence && options.confidence !== "all" && finding.confidence !== options.confidence) return false;
    return matches({
      label: finding.type,
      detail: finding.detail,
      location: finding.location,
      kind: finding.category
    }, options.query);
  }

  function findingStage(finding) {
    if (finding.source === "headers") return "headers";
    if (finding.source === "safe-active" || finding.source === "active") return "safe";
    if (finding.source === "lab") return "lab";
    return "passive";
  }

  function changeDetail(current, previous) {
    if (!current || !previous) return [];
    const fields = ["severity", "confidence", "bucket", "type", "detail", "evidence", "verification", "location", "occurrences"];
    return fields.filter(function (field) { return text(current[field]) !== text(previous[field]); });
  }

  function targetNode(scan) {
    let label = scan.url || "Selected target";
    try { label = new URL(scan.url).hostname || label; } catch (e) {}
    return { id: "map-target", kind: "target", label: label, detail: scan.url || "", location: scan.url || "", depth: 0, data: scan };
  }

  function capGraph(nodes, edges) {
    const nodeLimit = VulnscanFindings.limits.mapNodes;
    const edgeLimit = VulnscanFindings.limits.mapEdges;
    if (nodes.length <= nodeLimit && edges.length <= edgeLimit) {
      return { nodes: nodes, edges: edges.slice(0, edgeLimit), overflow: 0 };
    }
    const fixed = nodes.filter(function (node) { return node.kind === "target" || node.kind === "group" || node.kind === "stage"; });
    const remainder = nodes.filter(function (node) { return !fixed.includes(node); }).sort(function (left, right) {
      const leftFinding = left.kind === "finding" ? 1 : 0;
      const rightFinding = right.kind === "finding" ? 1 : 0;
      if (leftFinding !== rightFinding) return rightFinding - leftFinding;
      const leftWeight = severityWeight[left.severity] || 0;
      const rightWeight = severityWeight[right.severity] || 0;
      if (leftWeight !== rightWeight) return rightWeight - leftWeight;
      return left.label.localeCompare(right.label);
    });
    const kept = fixed.concat(remainder.slice(0, Math.max(0, nodeLimit - fixed.length - 1)));
    const overflow = nodes.length - kept.length;
    if (overflow > 0) {
      kept.push({ id: "map-overflow", kind: "overflow", label: "+" + overflow + " more", detail: "Use search or filters to narrow the map.", depth: 2 });
    }
    const ids = new Set(kept.map(function (node) { return node.id; }));
    const keptEdges = edges.filter(function (edge) { return ids.has(edge.from) && ids.has(edge.to); }).slice(0, edgeLimit);
    if (overflow > 0) keptEdges.push({ from: "map-target", to: "map-overflow", relation: "contains" });
    return { nodes: kept, edges: keptEdges.slice(0, edgeLimit), overflow: overflow };
  }

  function surfaceGraph(scan, options) {
    const source = VulnscanFindings.normalizeSurface(scan.surface);
    const nodes = [targetNode(scan)];
    const edges = [];
    const groupIds = new Map();
    const includedSurface = new Set();
    const requestedKind = options.kind && options.kind !== "all" ? options.kind : "";
    source.nodes.filter(function (node) { return node.kind !== "target"; }).forEach(function (node) {
      if (requestedKind && node.kind !== requestedKind) return;
      if (!matches(node, options.query)) return;
      const groupId = "map-group-" + node.kind;
      if (!groupIds.has(node.kind)) {
        groupIds.set(node.kind, groupId);
        nodes.push({ id: groupId, kind: "group", surfaceKind: node.kind, label: kindLabels[node.kind] || node.kind, detail: "Observed surface group", depth: 1 });
        edges.push({ from: "map-target", to: groupId, relation: "contains" });
      }
      nodes.push({
        id: "map-surface-" + node.id,
        surfaceId: node.id,
        kind: node.kind,
        label: node.label,
        detail: node.detail,
        location: node.location,
        external: node.external,
        occurrences: node.occurrences,
        depth: 2,
        data: node
      });
      includedSurface.add(node.id);
      edges.push({ from: groupId, to: "map-surface-" + node.id, relation: "contains" });
    });

    (scan.findings || []).filter(function (finding) { return findingAllowed(finding, options); }).forEach(function (finding) {
      const id = "map-finding-" + finding.fingerprint;
      nodes.push({
        id: id,
        kind: "finding",
        label: finding.type,
        detail: finding.detail,
        location: finding.location,
        severity: finding.severity,
        bucket: finding.bucket,
        depth: 3,
        data: finding
      });
      const refs = (finding.surfaceRefs || []).filter(function (ref) { return includedSurface.has(ref); });
      if (refs.length) {
        refs.forEach(function (ref) { edges.push({ from: "map-surface-" + ref, to: id, relation: "observed" }); });
      } else {
        edges.push({ from: "map-target", to: id, relation: "observed" });
      }
    });
    const capped = capGraph(nodes, edges);
    capped.available = source.nodes.some(function (node) { return node.kind !== "target"; });
    capped.truncated = source.truncated;
    return capped;
  }

  function flowGraph(scan, options) {
    const nodes = [targetNode(scan)];
    const edges = [];
    const selected = VulnscanChecks.effective(scan.checksRun, scan.scanMode);
    const coverage = new Map((scan.coverage || []).map(function (entry) { return [entry.checkId, entry]; }));
    const stages = ["passive", "headers", "safe", "lab"];
    stages.forEach(function (stage) {
      const checks = VulnscanChecks.catalog.filter(function (check) { return check.stage === stage && selected.includes(check.id); });
      if (!checks.length) return;
      const stageId = "map-stage-" + stage;
      nodes.push({
        id: stageId,
        kind: "stage",
        stage: stage,
        label: stageLabels[stage],
        detail: (scan.stageSummary && scan.stageSummary[stage]) || "unknown",
        status: (scan.stageSummary && scan.stageSummary[stage]) || "unknown",
        depth: 1
      });
      edges.push({ from: "map-target", to: stageId, relation: "contains" });
      checks.forEach(function (check) {
        const checkId = "map-check-" + check.id;
        const checkCoverage = coverage.get(check.id);
        nodes.push({
          id: checkId,
          kind: "check",
          checkId: check.id,
          label: check.label,
          detail: check.description,
          subtitle: checkCoverage ? checkCoverage.status : stageLabels[stage],
          status: checkCoverage ? checkCoverage.status : "unknown",
          stage: stage,
          depth: 2,
          data: check
        });
        edges.push({ from: stageId, to: checkId, relation: "contains" });
      });
    });
    (scan.findings || []).filter(function (finding) { return findingAllowed(finding, options); }).forEach(function (finding) {
      const family = VulnscanChecks.findingCheck(finding.checkId);
      const parent = family && selected.includes(family) ? "map-check-" + family : "map-target";
      const id = "map-finding-" + finding.fingerprint;
      nodes.push({
        id: id,
        kind: "finding",
        label: finding.type,
        detail: finding.detail,
        location: finding.location,
        severity: finding.severity,
        bucket: finding.bucket,
        depth: 3,
        data: finding
      });
      edges.push({ from: parent, to: id, relation: "observed" });
    });
    const capped = capGraph(nodes, edges);
    capped.available = true;
    capped.truncated = false;
    return capped;
  }

  function surfaceComparison(current, previous) {
    const currentNodes = VulnscanFindings.normalizeSurface(current.surface).nodes.filter(function (node) { return node.kind !== "target"; });
    const previousNodes = VulnscanFindings.normalizeSurface(previous.surface).nodes.filter(function (node) { return node.kind !== "target"; });
    const currentById = new Map(currentNodes.map(function (node) { return [node.id, node]; }));
    const previousById = new Map(previousNodes.map(function (node) { return [node.id, node]; }));
    const result = { new: [], changed: [], resolved: [], unchanged: [] };
    currentNodes.forEach(function (node) {
      const old = previousById.get(node.id);
      if (!old) result.new.push({ current: node, previous: null });
      else if (["label", "detail", "location", "external", "occurrences"].some(function (field) { return text(node[field]) !== text(old[field]); })) {
        result.changed.push({ current: node, previous: old });
      } else result.unchanged.push({ current: node, previous: old });
    });
    previousNodes.forEach(function (node) {
      if (!currentById.has(node.id)) result.resolved.push({ current: null, previous: node });
    });
    return result;
  }

  function comparisonGraph(current, previous, filters) {
    const options = Object.assign({ query: "", bucket: "all", severity: "all", confidence: "all", kind: "all", change: "all", comparableStages: ["passive", "headers", "safe", "lab"] }, filters || {});
    options.query = text(options.query).trim().toLowerCase();
    const stages = Array.isArray(options.comparableStages) ? options.comparableStages : ["passive", "headers", "safe", "lab"];
    const currentFindings = (current.findings || []).filter(function (finding) { return stages.includes(findingStage(finding)); });
    const previousFindings = (previous.findings || []).filter(function (finding) { return stages.includes(findingStage(finding)); });
    const findingComparison = VulnscanFindings.compare(currentFindings, previousFindings);
    const surface = stages.includes("passive") ? surfaceComparison(current, previous) : { new: [], changed: [], resolved: [], unchanged: [] };
    const nodes = [targetNode(current)];
    const edges = [];
    const groups = new Map();
    const statuses = ["new", "changed", "resolved", "unchanged"];

    function group(status) {
      if (groups.has(status)) return groups.get(status);
      const id = "map-change-group-" + status;
      groups.set(status, id);
      nodes.push({ id: id, kind: "group", change: status, label: status.charAt(0).toUpperCase() + status.slice(1), detail: "Comparison group", depth: 1 });
      edges.push({ from: "map-target", to: id, relation: "compared as" });
      return id;
    }

    statuses.forEach(function (status) {
      if (options.change !== "all" && options.change !== status) return;
      surface[status].forEach(function (pair) {
        const node = pair.current || pair.previous;
        if (options.kind !== "all" && node.kind !== options.kind) return;
        if (!matches(node, options.query)) return;
        const id = "map-change-surface-" + status + "-" + node.id;
        nodes.push({
          id: id,
          surfaceId: node.id,
          kind: node.kind,
          surfaceKind: node.kind,
          change: status,
          label: node.label,
          detail: node.detail || node.location || node.kind,
          subtitle: status + " · " + node.kind,
          location: node.location,
          depth: 2,
          data: node,
          previous: pair.previous
        });
        edges.push({ from: group(status), to: id, relation: status });
      });
    });

    function addFinding(status, finding, previousFinding) {
      if (options.change !== "all" && options.change !== status) return;
      if (!findingAllowed(finding, options)) return;
      const id = "map-change-finding-" + status + "-" + finding.identityFingerprint;
      nodes.push({
        id: id,
        kind: "finding",
        change: status,
        label: finding.type,
        detail: finding.detail,
        subtitle: status + " · " + finding.severity,
        location: finding.location,
        severity: finding.severity,
        bucket: finding.bucket,
        depth: 3,
        data: finding,
        previous: previousFinding || null,
        changedFields: changeDetail(finding, previousFinding),
        resolved: status === "resolved"
      });
      edges.push({ from: group(status), to: id, relation: status });
    }

    findingComparison.new.forEach(function (finding) { addFinding("new", finding, null); });
    findingComparison.changed.forEach(function (pair) { addFinding("changed", pair.current, pair.previous); });
    findingComparison.resolved.forEach(function (finding) { addFinding("resolved", finding, null); });
    findingComparison.unchanged.forEach(function (finding) { addFinding("unchanged", finding, finding); });

    const capped = capGraph(nodes, edges);
    capped.available = true;
    capped.truncated = false;
    capped.comparison = {
      findings: statuses.reduce(function (counts, status) { counts[status] = findingComparison[status].length; return counts; }, {}),
      surface: statuses.reduce(function (counts, status) { counts[status] = surface[status].length; return counts; }, {})
    };
    return capped;
  }

  function collapseGraph(graph, collapsedIds) {
    const collapsed = new Set(Array.isArray(collapsedIds) ? collapsedIds : []);
    if (!collapsed.size) return graph;
    const outgoing = new Map();
    graph.edges.forEach(function (edge) {
      if (!outgoing.has(edge.from)) outgoing.set(edge.from, []);
      outgoing.get(edge.from).push(edge.to);
    });
    const reachable = new Set(["map-target"]);
    const queue = ["map-target"];
    while (queue.length) {
      const id = queue.shift();
      if (collapsed.has(id)) continue;
      (outgoing.get(id) || []).forEach(function (child) {
        if (reachable.has(child)) return;
        reachable.add(child);
        queue.push(child);
      });
    }
    const nodes = graph.nodes.filter(function (node) { return reachable.has(node.id); });
    nodes.forEach(function (node) {
      if (!collapsed.has(node.id)) return;
      const descendants = new Set();
      const pending = (outgoing.get(node.id) || []).slice();
      while (pending.length) {
        const id = pending.shift();
        if (descendants.has(id)) continue;
        descendants.add(id);
        pending.push.apply(pending, outgoing.get(id) || []);
      }
      node.collapsed = true;
      node.hiddenCount = Array.from(descendants).filter(function (id) { return !reachable.has(id); }).length;
      node.subtitle = node.hiddenCount + " nodes hidden";
    });
    const ids = new Set(nodes.map(function (node) { return node.id; }));
    return Object.assign({}, graph, {
      nodes: nodes,
      edges: graph.edges.filter(function (edge) { return ids.has(edge.from) && ids.has(edge.to) && !collapsed.has(edge.from); })
    });
  }

  function layout(graph) {
    const columns = new Map();
    const incoming = new Map();
    const positions = new Map();
    graph.edges.forEach(function (edge) {
      if (!incoming.has(edge.to)) incoming.set(edge.to, []);
      incoming.get(edge.to).push(edge.from);
    });
    graph.nodes.forEach(function (node) {
      const depth = Math.max(0, Number(node.depth) || 0);
      if (!columns.has(depth)) columns.set(depth, []);
      columns.get(depth).push(node);
    });
    let maxHeight = 0;
    Array.from(columns.keys()).sort(function (a, b) { return a - b; }).forEach(function (depth) {
      const column = columns.get(depth).sort(function (left, right) {
        const leftParents = incoming.get(left.id) || [];
        const rightParents = incoming.get(right.id) || [];
        const leftPosition = leftParents.length ? Math.min.apply(null, leftParents.map(function (id) { return positions.get(id) || 0; })) : 0;
        const rightPosition = rightParents.length ? Math.min.apply(null, rightParents.map(function (id) { return positions.get(id) || 0; })) : 0;
        if (leftPosition !== rightPosition) return leftPosition - rightPosition;
        if (left.kind !== right.kind) return left.kind.localeCompare(right.kind);
        return left.label.localeCompare(right.label);
      });
      const height = Math.max(1, column.length) * 86;
      maxHeight = Math.max(maxHeight, height);
      column.forEach(function (node, index) {
        node.x = 40 + depth * 275;
        node.y = 40 + index * 86;
        node.width = depth === 0 ? 200 : 220;
        node.height = 58;
        positions.set(node.id, index);
      });
    });
    return {
      nodes: graph.nodes,
      edges: graph.edges,
      overflow: graph.overflow,
      available: graph.available,
      truncated: graph.truncated,
      comparison: graph.comparison || null,
      width: Math.max(320, (Math.max.apply(null, graph.nodes.map(function (node) { return node.depth || 0; })) + 1) * 275),
      height: Math.max(180, maxHeight + 40)
    };
  }

  function journeyTargetNode(journey) {
    let label = journey.origin || "Journey";
    try { label = new URL(journey.origin).hostname || label; } catch (e) {}
    return { id: "map-target", kind: "target", label: label, detail: journey.name || journey.origin, location: journey.origin, depth: 0, data: journey };
  }

  function journeyGraph(journey, view, filters) {
    const options = Object.assign({ query: "", bucket: "all", severity: "all", confidence: "all", kind: "all" }, filters || {});
    options.query = text(options.query).trim().toLowerCase();
    const nodes = [journeyTargetNode(journey)];
    const edges = [];
    const includedPages = new Set();
    const relatedPages = new Set();
    if (options.query && options.kind === "all") {
      (journey.apiEndpoints || []).filter(function (endpoint) { return matches(endpoint, options.query); }).forEach(function (endpoint) {
        (endpoint.pageRefs || []).forEach(function (pageRef) { relatedPages.add(pageRef); });
      });
      (journey.findings || []).filter(function (finding) { return findingAllowed(finding, options); }).forEach(function (finding) {
        (finding.pageRefs || []).forEach(function (pageRef) { relatedPages.add(pageRef); });
      });
      ((journey.surface && journey.surface.nodes) || []).filter(function (surface) { return matches(surface, options.query); }).forEach(function (surface) {
        (surface.pageRefs || []).forEach(function (pageRef) { relatedPages.add(pageRef); });
      });
    }
    const pages = (journey.pages || []).slice().sort(function (left, right) { return left.firstSeenAt - right.firstSeenAt; });
    pages.forEach(function (page) {
      const relationshipAnchor = !["all", "page"].includes(options.kind);
      if (!relationshipAnchor && !matches(page, options.query) && !relatedPages.has(page.id)) return;
      const id = "map-journey-page-" + page.id;
      includedPages.add(page.id);
      nodes.push({
        id: id, kind: "page", pageRef: page.id, label: page.title || page.route, detail: page.route,
        location: page.route, occurrences: page.visits, subtitle: page.visits + " visit" + (page.visits === 1 ? "" : "s"), depth: 1, data: page
      });
      edges.push({ from: "map-target", to: id, relation: "visited" });
    });
    if (view === "flow") {
      const visitRefs = (journey.events || []).filter(function (event) {
        return event.kind === "navigation" && event.phase === "complete" && includedPages.has(event.pageRef);
      }).map(function (event) { return event.pageRef; });
      const orderedRefs = visitRefs.length ? visitRefs : pages.filter(function (page) { return includedPages.has(page.id); }).map(function (page) { return page.id; });
      const visitEdges = new Set();
      for (let index = 1; index < orderedRefs.length; index++) {
        const key = orderedRefs[index - 1] + "|" + orderedRefs[index];
        if (orderedRefs[index - 1] !== orderedRefs[index] && !visitEdges.has(key)) {
          visitEdges.add(key);
          edges.push({ from: "map-journey-page-" + orderedRefs[index - 1], to: "map-journey-page-" + orderedRefs[index], relation: "visited next" });
        }
      }
    }

    const apiAllowed = options.kind === "all" || options.kind === "api-endpoint";
    if (apiAllowed) {
      (journey.apiEndpoints || []).forEach(function (endpoint) {
        if (!matches(endpoint, options.query)) return;
        const refs = (endpoint.pageRefs || []).filter(function (pageRef) { return includedPages.has(pageRef); });
        if (!refs.length) return;
        const id = "map-journey-api-" + endpoint.id;
        nodes.push({
          id: id, kind: "api-endpoint", endpointRef: endpoint.id, label: endpoint.method + " " + endpoint.route,
          detail: endpoint.occurrences + " captured request" + (endpoint.occurrences === 1 ? "" : "s"), location: endpoint.route,
          occurrences: endpoint.occurrences, subtitle: Object.keys(endpoint.statuses || {}).join(", ") || "No response", depth: 2, data: endpoint
        });
        refs.forEach(function (pageRef) { edges.push({ from: "map-journey-page-" + pageRef, to: id, relation: "requested" }); });
      });
    }

    const surfaceAllowed = view !== "flow" && options.kind !== "page" && options.kind !== "api-endpoint";
    const includedSurface = new Set();
    if (surfaceAllowed) {
      ((journey.surface && journey.surface.nodes) || []).forEach(function (surface) {
        if (options.kind !== "all" && options.kind !== surface.kind) return;
        if (!matches(surface, options.query)) return;
        const refs = (surface.pageRefs || []).filter(function (pageRef) { return includedPages.has(pageRef); });
        if (!refs.length) return;
        const id = "map-journey-surface-" + surface.id;
        includedSurface.add(surface.id);
        nodes.push({
          id: id, kind: surface.kind, surfaceId: surface.id, label: surface.label, detail: surface.detail,
          location: surface.location, occurrences: surface.occurrences, external: surface.external, depth: 2, data: surface
        });
        refs.forEach(function (pageRef) { edges.push({ from: "map-journey-page-" + pageRef, to: id, relation: "observed" }); });
      });
    }

    (journey.findings || []).filter(function (finding) {
      return ["all", "finding"].includes(options.kind) && findingAllowed(finding, options);
    }).forEach(function (finding) {
      const refs = (finding.pageRefs || []).filter(function (pageRef) { return includedPages.has(pageRef); });
      if (!refs.length) return;
      const id = "map-journey-finding-" + finding.identityFingerprint;
      nodes.push({
        id: id, kind: "finding", findingRef: finding.identityFingerprint, label: finding.type, detail: finding.detail,
        location: finding.location, severity: finding.severity, bucket: finding.bucket, subtitle: finding.pageCount + " page" + (finding.pageCount === 1 ? "" : "s"),
        depth: view === "flow" ? 2 : 3, data: finding
      });
      const surfaces = (finding.surfaceRefs || []).filter(function (surfaceRef) { return includedSurface.has(surfaceRef); });
      if (surfaces.length) surfaces.forEach(function (surfaceRef) { edges.push({ from: "map-journey-surface-" + surfaceRef, to: id, relation: "observed" }); });
      else refs.forEach(function (pageRef) { edges.push({ from: "map-journey-page-" + pageRef, to: id, relation: "observed on" }); });
    });
    const capped = capGraph(nodes, edges);
    capped.available = pages.length > 0;
    capped.truncated = !!(journey.limits && Object.keys(journey.limits).some(function (key) { return journey.limits[key]; }));
    capped.journey = true;
    return capped;
  }

  function build(scan, view, filters) {
    const options = Object.assign({ query: "", bucket: "all", severity: "all", confidence: "all", kind: "all" }, filters || {});
    options.query = text(options.query).trim().toLowerCase();
    return layout(collapseGraph(view === "flow" ? flowGraph(scan, options) : surfaceGraph(scan, options), options.collapsed));
  }

  function buildComparison(current, previous, filters) {
    const options = Object.assign({}, filters || {});
    return layout(collapseGraph(comparisonGraph(current, previous, options), options.collapsed));
  }

  function buildJourney(journey, view, filters) {
    return layout(collapseGraph(journeyGraph(journey, view === "surface" ? "surface" : "flow", filters), filters && filters.collapsed));
  }

  function createSvg(name) {
    return document.createElementNS("http://www.w3.org/2000/svg", name);
  }

  function trace(graph, nodeId) {
    const byId = new Map(graph.nodes.map(function (node) { return [node.id, node]; }));
    if (!byId.has(nodeId)) return { nodeIds: [], edgeIndexes: [], breadcrumb: [] };
    const nodeIds = new Set([nodeId]);
    const edgeIndexes = new Set();
    const trail = [nodeId];
    let current = nodeId;
    const visited = new Set([current]);
    while (current !== "map-target") {
      const edgeIndex = graph.edges.findIndex(function (edge) { return edge.to === current && !visited.has(edge.from); });
      if (edgeIndex < 0) break;
      const edge = graph.edges[edgeIndex];
      edgeIndexes.add(edgeIndex);
      nodeIds.add(edge.from);
      trail.unshift(edge.from);
      visited.add(edge.from);
      current = edge.from;
    }
    graph.edges.forEach(function (edge, index) {
      if (edge.from !== nodeId) return;
      edgeIndexes.add(index);
      nodeIds.add(edge.to);
    });
    return {
      nodeIds: Array.from(nodeIds),
      edgeIndexes: Array.from(edgeIndexes),
      breadcrumb: trail.map(function (id) { return byId.get(id); }).filter(Boolean)
    };
  }

  function canPanFrom(target) {
    return !(target && typeof target.closest === "function" && target.closest(".scan-map-node"));
  }

  function highlight(svg, graph, nodeId, focusMode) {
    const selected = trace(graph, nodeId);
    const nodeIds = new Set(selected.nodeIds);
    const edgeIndexes = new Set(selected.edgeIndexes);
    const layer = svg.querySelector(".scan-map-layer");
    if (!layer) return selected;
    layer.classList.toggle("has-selection", Boolean(nodeId) && focusMode !== false);
    layer.querySelectorAll(".scan-map-node").forEach(function (node) {
      const id = node.getAttribute("data-node-id");
      node.classList.toggle("map-selected", id === nodeId);
      node.classList.toggle("map-related", nodeIds.has(id));
      node.setAttribute("aria-pressed", id === nodeId ? "true" : "false");
    });
    layer.querySelectorAll(".scan-map-edge").forEach(function (edge) {
      edge.classList.toggle("map-related", edgeIndexes.has(Number(edge.getAttribute("data-edge-index"))));
    });
    return selected;
  }

  function render(svg, graph, handlers) {
    const callbacks = typeof handlers === "function" ? { select: handlers } : handlers || {};
    while (svg.firstChild) svg.removeChild(svg.firstChild);
    svg.setAttribute("viewBox", "0 0 " + graph.width + " " + graph.height);
    const layer = createSvg("g");
    layer.setAttribute("class", "scan-map-layer");
    svg.appendChild(layer);
    const byId = new Map(graph.nodes.map(function (node) { return [node.id, node]; }));
    graph.edges.forEach(function (edge, edgeIndex) {
      const from = byId.get(edge.from);
      const to = byId.get(edge.to);
      if (!from || !to) return;
      const path = createSvg("path");
      const startX = from.x + from.width;
      const startY = from.y + from.height / 2;
      const endX = to.x;
      const endY = to.y + to.height / 2;
      const middle = startX + Math.max(30, (endX - startX) / 2);
      path.setAttribute("d", "M" + startX + " " + startY + " C" + middle + " " + startY + " " + middle + " " + endY + " " + endX + " " + endY);
      path.setAttribute("class", "scan-map-edge");
      path.setAttribute("data-edge-index", edgeIndex);
      path.setAttribute("data-from", edge.from);
      path.setAttribute("data-to", edge.to);
      path.setAttribute("data-relation", edge.relation || "related");
      layer.appendChild(path);
    });
    graph.nodes.forEach(function (node) {
      const group = createSvg("g");
      group.setAttribute("class", "scan-map-node " + node.kind + (node.severity ? " " + node.severity : "") + (node.bucket ? " " + node.bucket : "") + (node.status ? " status-" + node.status : "") + (node.change ? " change-" + node.change : "") + (node.collapsed ? " collapsed" : ""));
      group.setAttribute("transform", "translate(" + node.x + " " + node.y + ")");
      group.setAttribute("data-node-id", node.id);
      group.setAttribute("tabindex", "0");
      group.setAttribute("role", "button");
      group.setAttribute("aria-label", node.label);
      group.setAttribute("aria-pressed", "false");
      if (node.kind === "group" || node.kind === "stage") group.setAttribute("aria-expanded", node.collapsed ? "false" : "true");
      const halo = createSvg("rect");
      halo.setAttribute("class", "scan-map-node-halo");
      halo.setAttribute("width", node.width);
      halo.setAttribute("height", node.height);
      halo.setAttribute("rx", "9");
      group.appendChild(halo);
      const rect = createSvg("rect");
      rect.setAttribute("class", "scan-map-node-frame");
      rect.setAttribute("width", node.width);
      rect.setAttribute("height", node.height);
      rect.setAttribute("rx", "9");
      group.appendChild(rect);
      const title = createSvg("text");
      title.setAttribute("x", "13");
      title.setAttribute("y", "24");
      title.setAttribute("class", "scan-map-node-title");
      title.textContent = text(node.label).slice(0, 32) + (text(node.label).length > 32 ? "…" : "");
      group.appendChild(title);
      const subtitle = createSvg("text");
      subtitle.setAttribute("x", "13");
      subtitle.setAttribute("y", "43");
      subtitle.setAttribute("class", "scan-map-node-subtitle");
      subtitle.textContent = text(node.subtitle || (node.kind === "finding" ? text(node.bucket) + " · " + text(node.severity) : node.detail || node.kind)).slice(0, 38);
      group.appendChild(subtitle);
      const select = function () { if (typeof callbacks.select === "function") callbacks.select(node); };
      group.addEventListener("click", select);
      group.addEventListener("dblclick", function (event) {
        event.preventDefault();
        if (typeof callbacks.center === "function") callbacks.center(node);
      });
      group.addEventListener("keydown", function (event) {
        if (event.key === "Enter" || event.key === " ") {
          event.preventDefault();
          select();
          if (event.key === "Enter" && event.shiftKey && typeof callbacks.center === "function") callbacks.center(node);
          return;
        }
        if (!["ArrowUp", "ArrowDown", "ArrowLeft", "ArrowRight"].includes(event.key)) return;
        event.preventDefault();
        let next;
        if (event.key === "ArrowLeft") {
          const edge = graph.edges.find(function (item) { return item.to === node.id; });
          next = edge && byId.get(edge.from);
        } else if (event.key === "ArrowRight") {
          const edge = graph.edges.find(function (item) { return item.from === node.id; });
          next = edge && byId.get(edge.to);
        } else {
          const column = graph.nodes.filter(function (item) { return item.depth === node.depth; }).sort(function (left, right) { return left.y - right.y; });
          const index = column.findIndex(function (item) { return item.id === node.id; });
          next = column[index + (event.key === "ArrowUp" ? -1 : 1)];
        }
        if (!next) return;
        const nextElement = Array.from(layer.querySelectorAll(".scan-map-node")).find(function (item) { return item.getAttribute("data-node-id") === next.id; });
        if (nextElement && typeof nextElement.focus === "function") nextElement.focus();
      });
      layer.appendChild(group);
    });
    return layer;
  }

  function renderMiniMap(svg, graph) {
    while (svg.firstChild) svg.removeChild(svg.firstChild);
    svg.setAttribute("viewBox", "0 0 " + graph.width + " " + graph.height);
    graph.nodes.forEach(function (node) {
      const rect = createSvg("rect");
      rect.setAttribute("x", node.x);
      rect.setAttribute("y", node.y);
      rect.setAttribute("width", node.width);
      rect.setAttribute("height", node.height);
      rect.setAttribute("rx", "5");
      rect.setAttribute("data-node-id", node.id);
      rect.setAttribute("class", "scan-map-mini-node " + node.kind + (node.change ? " change-" + node.change : ""));
      svg.appendChild(rect);
    });
    const windowRect = createSvg("rect");
    windowRect.setAttribute("class", "scan-map-mini-window");
    svg.appendChild(windowRect);
  }

  function updateMiniMap(svg, graph, transform, selectedId) {
    if (!svg || !graph) return;
    const scale = Math.max(0.01, Number(transform.scale) || 1);
    const windowRect = svg.querySelector(".scan-map-mini-window");
    if (windowRect) {
      windowRect.setAttribute("x", Math.max(0, -(Number(transform.x) || 0) / scale));
      windowRect.setAttribute("y", Math.max(0, -(Number(transform.y) || 0) / scale));
      windowRect.setAttribute("width", Math.min(graph.width, graph.width / scale));
      windowRect.setAttribute("height", Math.min(graph.height, graph.height / scale));
    }
    svg.querySelectorAll(".scan-map-mini-node").forEach(function (node) {
      node.classList.toggle("selected", node.getAttribute("data-node-id") === selectedId);
    });
  }

  function xml(value) {
    return text(value).replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;").replace(/"/g, "&quot;");
  }

  function exportSvg(graph) {
    const byId = new Map(graph.nodes.map(function (node) { return [node.id, node]; }));
    const edges = graph.edges.map(function (edge) {
      const from = byId.get(edge.from);
      const to = byId.get(edge.to);
      if (!from || !to) return "";
      const startX = from.x + from.width;
      const startY = from.y + from.height / 2;
      const endX = to.x;
      const endY = to.y + to.height / 2;
      const middle = startX + Math.max(30, (endX - startX) / 2);
      return '<path d="M' + startX + " " + startY + " C" + middle + " " + startY + " " + middle + " " + endY + " " + endX + " " + endY + '" fill="none" stroke="#405776" stroke-width="1.4"/>';
    }).join("");
    const colors = { target: "#173557", finding: "#2e1921", group: "#17273d", stage: "#17273d" };
    const nodes = graph.nodes.map(function (node) {
      const fill = colors[node.kind] || "#152132";
      const stroke = node.change === "new" ? "#64b5f6" : node.change === "changed" ? "#e9b44c" : node.change === "resolved" ? "#61c98b" : node.kind === "finding" ? "#d95d75" : "#55759e";
      const subtitle = text(node.subtitle || (node.kind === "finding" ? node.bucket + " · " + node.severity : node.detail || node.kind)).slice(0, 42);
      return '<g transform="translate(' + node.x + " " + node.y + ')"><rect width="' + node.width + '" height="' + node.height + '" rx="9" fill="' + fill + '" stroke="' + stroke + '"/><text x="13" y="24" fill="#dce7f5" font-family="Arial,sans-serif" font-size="11" font-weight="600">' + xml(text(node.label).slice(0, 36)) + '</text><text x="13" y="43" fill="#8ea1ba" font-family="monospace" font-size="9">' + xml(subtitle) + "</text></g>";
    }).join("");
    return '<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 ' + graph.width + " " + graph.height + '" width="' + graph.width + '" height="' + graph.height + '"><rect width="100%" height="100%" fill="#09101a"/>' + edges + nodes + "</svg>";
  }

  root.VulnscanMap = {
    build: build,
    buildComparison: buildComparison,
    buildJourney: buildJourney,
    render: render,
    renderMiniMap: renderMiniMap,
    updateMiniMap: updateMiniMap,
    exportSvg: exportSvg,
    trace: trace,
    highlight: highlight,
    canPanFrom: canPanFrom
  };
})(globalThis);
