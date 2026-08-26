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
      width: Math.max(320, (Math.max.apply(null, graph.nodes.map(function (node) { return node.depth || 0; })) + 1) * 275),
      height: Math.max(180, maxHeight + 40)
    };
  }

  function build(scan, view, filters) {
    const options = Object.assign({ query: "", bucket: "all", severity: "all", confidence: "all", kind: "all" }, filters || {});
    options.query = text(options.query).trim().toLowerCase();
    return layout(view === "flow" ? flowGraph(scan, options) : surfaceGraph(scan, options));
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
      group.setAttribute("class", "scan-map-node " + node.kind + (node.severity ? " " + node.severity : "") + (node.bucket ? " " + node.bucket : "") + (node.status ? " status-" + node.status : ""));
      group.setAttribute("transform", "translate(" + node.x + " " + node.y + ")");
      group.setAttribute("data-node-id", node.id);
      group.setAttribute("tabindex", "0");
      group.setAttribute("role", "button");
      group.setAttribute("aria-label", node.label);
      group.setAttribute("aria-pressed", "false");
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
      subtitle.textContent = node.kind === "finding" ? text(node.bucket) + " · " + text(node.severity) : text(node.subtitle || node.detail || node.kind).slice(0, 38);
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

  root.VulnscanMap = {
    build: build,
    render: render,
    trace: trace,
    highlight: highlight,
    canPanFrom: canPanFrom
  };
})(globalThis);
