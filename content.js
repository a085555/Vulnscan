(function () {
  function collectPageSource(limit) {
    if (!document.createTreeWalker || typeof NodeFilter === "undefined") {
      const html = String(document.documentElement.innerHTML || "");
      return { text: html.slice(0, limit), truncated: html.length > limit };
    }
    let text = "";
    let truncated = false;
    const append = function (value) {
      const part = String(value || "");
      const remaining = limit - text.length;
      if (part.length > remaining) {
        text += part.slice(0, Math.max(0, remaining));
        truncated = true;
        return false;
      }
      text += part;
      return true;
    };
    const appendNode = function (node) {
      if (node.nodeType === 1) {
        if (!append("<" + String(node.tagName || "").toLowerCase())) return false;
        Array.from(node.attributes || []).some(function (attribute) {
          return !append(" " + attribute.name + '="' + attribute.value + '"');
        });
        return !truncated && append(">");
      }
      return append(node.nodeValue || "");
    };
    const walker = document.createTreeWalker(document.documentElement, NodeFilter.SHOW_ELEMENT | NodeFilter.SHOW_TEXT | NodeFilter.SHOW_COMMENT);
    if (!appendNode(document.documentElement)) return { text: text, truncated: true };
    let node;
    while ((node = walker.nextNode())) {
      if (!appendNode(node)) break;
    }
    return { text: text, truncated: truncated || !!node };
  }

  const findings = [];
  const pageUrl = location.href;
  const scanId = globalThis.__vulnscanScanId || null;
  const journeyId = globalThis.__vulnscanJourneyId || null;
  const captureId = globalThis.__vulnscanCaptureId || null;
  const scanMode = globalThis.__vulnscanScanMode || "passive";
  const enabledChecks = VulnscanChecks.normalize(globalThis.__vulnscanEnabledChecks);
  const limits = VulnscanFindings.limits;
  const sourceChecks = ["passive.dom", "passive.secrets", "passive.components", "passive.source"];
  const sourceNeeded = sourceChecks.some(function (id) { return enabledChecks.includes(id); });
  const sourceSnapshot = sourceNeeded ? collectPageSource(limits.pageSourceCharacters) : { text: "", truncated: false };
  const pageText = sourceSnapshot.text;
  const pageLower = pageText.toLowerCase();
  const findingCounts = Object.create(null);
  const scanLimits = {
    sourceTruncated: sourceSnapshot.truncated,
    domTruncated: false,
    findingsTruncated: false,
    secretsTruncated: false,
    surfaceTruncated: false
  };

  function checkEnabled(id) {
    return VulnscanChecks.enabled(enabledChecks, id);
  }

  function selectedNodes(selector) {
    const nodes = document.querySelectorAll(selector);
    if (nodes.length > limits.domNodesPerCheck) scanLimits.domTruncated = true;
    return Array.prototype.slice.call(nodes, 0, limits.domNodesPerCheck);
  }

  function add(severity, type, detail, options) {
    const item = options || {};
    const check = VulnscanChecks.findingCheck(item.checkId);
    if (check && !checkEnabled(check)) return;
    const checkId = String(item.checkId || "general.observation");
    findingCounts[checkId] = findingCounts[checkId] || 0;
    if (findings.length >= limits.findings - 1 || findingCounts[checkId] >= limits.findingsPerCheck) {
      scanLimits.findingsTruncated = true;
      return;
    }
    findingCounts[checkId]++;
    findings.push(VulnscanFindings.normalize({
      checkId: checkId,
      severity: severity,
      confidence: item.confidence,
      bucket: item.bucket,
      category: item.category,
      type: type,
      detail: detail,
      evidence: item.evidence,
      verification: item.verification,
      location: item.location,
      selector: item.selector,
      source: "passive",
      surfaceRefs: item.surfaceRefs,
      occurrences: item.occurrences
    }));
  }

  function redactUrl(value) {
    return VulnscanUrls.redact(value, pageUrl);
  }

  function safeName(value) {
    const name = String(value || "").trim();
    if (!name || name.length > 60 || !/^[A-Za-z][A-Za-z0-9_.:\[\]-]*$/.test(name)) return "";
    if (/[A-Za-z0-9_-]{28,}/.test(name)) return "[long name hidden]";
    return name;
  }

  function elementSelector(element) {
    const parts = [];
    let current = element;
    while (current && parts.length < 8) {
      const tag = String(current.tagName || "").toLowerCase();
      if (!/^[a-z][a-z0-9-]*$/.test(tag)) break;
      const id = String(current.id || "");
      if (/^[A-Za-z][A-Za-z0-9_-]{0,39}$/.test(id)) {
        parts.unshift(tag + "#" + id);
        break;
      }
      const parent = current.parentElement;
      if (parent && parent.children) {
        const siblings = Array.from(parent.children).filter(function (child) {
          return String(child.tagName || "").toLowerCase() === tag;
        });
        parts.unshift(tag + ":nth-of-type(" + (siblings.indexOf(current) + 1) + ")");
      } else {
        parts.unshift(tag);
      }
      current = parent;
    }
    const selector = parts.join(" > ");
    try {
      return selector && document.querySelectorAll(selector).length === 1 ? selector : "";
    } catch (e) {
      return "";
    }
  }

  function unique(values, limit) {
    return Array.from(new Set(values.filter(Boolean))).slice(0, limit);
  }

  const surfaceNodes = [];
  const surfaceEdges = [];
  const surfaceNodeIds = new Set();
  const surfaceEdgeIds = new Set();
  const elementSurfaceRefs = typeof WeakMap === "function" ? new WeakMap() : null;
  const targetSurfaceId = VulnscanFindings.surfaceId("target", VulnscanUrls.target(pageUrl));

  function addSurfaceNode(kind, value, label, options) {
    const item = options || {};
    const id = VulnscanFindings.surfaceId(kind, value);
    if (surfaceNodeIds.has(id)) return id;
    if (surfaceNodes.length >= limits.surfaceNodes) {
      scanLimits.surfaceTruncated = true;
      return "";
    }
    surfaceNodeIds.add(id);
    surfaceNodes.push({
      id: id,
      kind: kind,
      label: label,
      detail: item.detail || "",
      location: item.location || "",
      selector: item.selector || "",
      external: item.external === true,
      occurrences: item.occurrences || 1
    });
    return id;
  }

  function addSurfaceEdge(from, to, relation) {
    if (!from || !to || from === to) return;
    const key = from + "|" + to + "|" + relation;
    if (surfaceEdgeIds.has(key)) return;
    if (surfaceEdges.length >= limits.surfaceEdges) {
      scanLimits.surfaceTruncated = true;
      return;
    }
    surfaceEdgeIds.add(key);
    surfaceEdges.push({ from: from, to: to, relation: relation });
  }

  function rememberSurface(element, id) {
    if (elementSurfaceRefs && element && id) elementSurfaceRefs.set(element, id);
    return id;
  }

  function refsFor(element, fallback) {
    const id = elementSurfaceRefs && element ? elementSurfaceRefs.get(element) : "";
    return [id || fallback].filter(function (value) { return surfaceNodeIds.has(value); });
  }

  function readStorageNames(storage) {
    const names = [];
    try {
      for (let i = 0; i < storage.length; i++) names.push(safeName(storage.key(i)));
    } catch (e) {}
    return unique(names, 20);
  }

  function addPassiveInventory() {
    const endpoints = [];
    const parameterNames = [];
    const thirdPartyHosts = [];
    const routeRefs = [];
    const parameterRefs = [];
    const formRefs = [];
    const resourceRefs = [];
    const externalRefs = [];
    const storageRefs = [];
    const authRefs = [];
    let scriptCount = 0;
    let styleCount = 0;
    let frameCount = 0;

    addSurfaceNode("target", VulnscanUrls.target(pageUrl), new URL(pageUrl).hostname, {
      detail: "Selected page",
      location: redactUrl(pageUrl)
    });

    try {
      const current = new URL(pageUrl);
      current.searchParams.forEach(function (value, name) {
        const safe = safeName(name);
        parameterNames.push(safe);
        if (safe) {
          const ref = addSurfaceNode("parameter", "query|" + safe, safe, { detail: "Query parameter name", location: "query: " + safe });
          parameterRefs.push(ref);
          addSurfaceEdge(targetSurfaceId, ref, "uses");
        }
      });
      selectedNodes("a[href], form[action], script[src], link[href], iframe[src]").forEach(function (element) {
        const value = element.href || element.action || element.src;
        if (!value) return;
        let target;
        try { target = new URL(value, pageUrl); } catch (e) { return; }
        if (!/^https?:$/.test(target.protocol)) return;
        const tag = String(element.tagName || "").toLowerCase();
        target.searchParams.forEach(function (value, name) {
          const safe = safeName(name);
          parameterNames.push(safe);
          if (safe) {
            const ref = addSurfaceNode("parameter", "observed|" + safe, safe, { detail: "Query or form parameter name", location: "parameter: " + safe });
            parameterRefs.push(ref);
            addSurfaceEdge(targetSurfaceId, ref, "uses");
          }
        });
        if (target.origin === current.origin) {
          const safeTarget = redactUrl(target.href);
          endpoints.push(safeTarget);
          if (tag === "a") {
            let routeLabel = "/";
            try { routeLabel = new URL(safeTarget).pathname || "/"; } catch (e) {}
            const route = addSurfaceNode("route", safeTarget, routeLabel, { detail: "Observed same-origin link", location: safeTarget, selector: elementSelector(element) });
            routeRefs.push(route);
            rememberSurface(element, route);
            addSurfaceEdge(targetSurfaceId, route, "contains");
          }
        } else {
          thirdPartyHosts.push(target.hostname);
          const external = addSurfaceNode("external-origin", target.origin, target.hostname, { detail: "Observed external origin", location: target.origin, external: true });
          externalRefs.push(external);
          addSurfaceEdge(targetSurfaceId, external, "connects");
        }
        if (tag === "script" || tag === "link" || tag === "iframe") {
          const kind = tag === "link" ? "stylesheet" : tag;
          const safeResource = redactUrl(target.href);
          let resourceLabel = kind;
          try { resourceLabel = new URL(safeResource).pathname.split("/").pop() || kind; } catch (e) {}
          const resource = addSurfaceNode("resource", kind + "|" + safeResource, resourceLabel, {
            detail: kind + (target.origin === current.origin ? " · same origin" : " · external"),
            location: safeResource,
            selector: elementSelector(element),
            external: target.origin !== current.origin
          });
          resourceRefs.push(resource);
          rememberSurface(element, resource);
          const external = target.origin === current.origin ? targetSurfaceId : VulnscanFindings.surfaceId("external-origin", target.origin);
          addSurfaceEdge(external, resource, "loads");
        }
        if (tag === "script") scriptCount++;
        if (tag === "link" && String(element.rel || "").toLowerCase().includes("stylesheet")) styleCount++;
        if (tag === "iframe") frameCount++;
      });
    } catch (e) {}

    const forms = selectedNodes("form");
    let postForms = 0;
    let passwordForms = 0;
    let fileForms = 0;
    forms.forEach(function (form, index) {
      if (String(form.method || "get").toLowerCase() === "post") postForms++;
      const method = String(form.method || "get").toUpperCase();
      const safeAction = redactUrl(form.action || pageUrl);
      const formRef = addSurfaceNode("form", method + "|" + safeAction + "|" + index, method + " form", {
        detail: "Submission to " + safeAction,
        location: safeAction,
        selector: elementSelector(form)
      });
      formRefs.push(formRef);
      rememberSurface(form, formRef);
      addSurfaceEdge(targetSurfaceId, formRef, "contains");
      try {
        if (form.querySelector("input[type='password']")) passwordForms++;
        if (form.querySelector("input[type='file']")) fileForms++;
        form.querySelectorAll("input[name], select[name], textarea[name], button[name]").forEach(function (field) {
          const safe = safeName(field.name);
          parameterNames.push(safe);
          if (safe) {
            const ref = addSurfaceNode("parameter", "field|" + safe, safe, { detail: "Form field name", location: "field: " + safe });
            parameterRefs.push(ref);
            addSurfaceEdge(formRef, ref, "uses");
          }
        });
      } catch (e) {}
    });

    const endpointList = unique(endpoints, 16);
    if (endpointList.length) {
      add("info", "Same-origin route inventory", endpointList.length + " unique route(s) mapped", {
        checkId: "inventory.endpoints",
        confidence: "high",
        bucket: "review",
        category: "inventory",
        evidence: "Routes: " + endpointList.join(", ") + ". Query values are hidden.",
        verification: "Review the routes as a coverage map and confirm which ones are intended to be public.",
        location: "current page",
        surfaceRefs: unique(routeRefs, 8),
        occurrences: endpointList.length
      });
    }

    const parameters = unique(parameterNames, 24);
    if (parameters.length) {
      add("info", "Parameter and field names", parameters.join(", "), {
        checkId: "inventory.parameters",
        confidence: "high",
        bucket: "review",
        category: "inventory",
        evidence: parameters.length + " unique query or form field name(s) were observed. Values were not collected.",
        verification: "Use the names to check validation, authorization, and server-side handling on approved targets.",
        location: "current page",
        surfaceRefs: unique(parameterRefs, 8),
        occurrences: parameters.length
      });
    }

    if (forms.length) {
      add("info", "Form surface map", forms.length + " form(s): " + postForms + " POST, " + passwordForms + " password, " + fileForms + " file upload", {
        checkId: "inventory.forms",
        confidence: "high",
        bucket: "review",
        category: "inventory",
        evidence: "Only form methods and field types were counted; field values were not read.",
        verification: "Review sensitive forms for access control, anti-CSRF handling, validation, and secure transport.",
        location: "current page",
        surfaceRefs: unique(formRefs, 8),
        occurrences: forms.length
      });
    }

    const thirdParties = unique(thirdPartyHosts, 12);
    if (scriptCount || styleCount || frameCount || thirdParties.length) {
      add("info", "Loaded resource map", scriptCount + " script(s), " + styleCount + " stylesheet(s), " + frameCount + " frame(s), " + thirdParties.length + " third-party host(s)", {
        checkId: "inventory.resources",
        confidence: "high",
        bucket: "review",
        category: "inventory",
        evidence: thirdParties.length ? "Third-party hosts: " + thirdParties.join(", ") : "No third-party hosts were observed in the mapped elements.",
        verification: "Confirm each external dependency and embedded origin is expected and still required.",
        location: "current page",
        surfaceRefs: unique(resourceRefs.concat(externalRefs), 8),
        occurrences: scriptCount + styleCount + frameCount
      });
    }

    const localNames = typeof localStorage === "undefined" ? [] : readStorageNames(localStorage);
    const sessionNames = typeof sessionStorage === "undefined" ? [] : readStorageNames(sessionStorage);
    localNames.forEach(function (name) {
      const ref = addSurfaceNode("storage", "local|" + name, name, { detail: "localStorage key name", location: "localStorage" });
      storageRefs.push(ref);
      addSurfaceEdge(targetSurfaceId, ref, "uses");
    });
    sessionNames.forEach(function (name) {
      const ref = addSurfaceNode("storage", "session|" + name, name, { detail: "sessionStorage key name", location: "sessionStorage" });
      storageRefs.push(ref);
      addSurfaceEdge(targetSurfaceId, ref, "uses");
    });
    if (localNames.length || sessionNames.length) {
      add("info", "Browser storage names", "localStorage: " + (localNames.join(", ") || "none") + "; sessionStorage: " + (sessionNames.join(", ") || "none"), {
        checkId: "inventory.storage-names",
        confidence: "high",
        bucket: "review",
        category: "inventory",
        evidence: "Storage key names were read. Storage values were never accessed.",
        verification: "Review whether the named entries are necessary and whether sensitive state is stored in the browser.",
        location: "browser storage",
        surfaceRefs: unique(storageRefs, 8),
        occurrences: localNames.length + sessionNames.length
      });
    }

    const authCookies = document.cookie ? unique(document.cookie.split(";").map(function (cookie) {
      const name = safeName(cookie.trim().split("=")[0]);
      return /auth|session|token|login|sid/i.test(name) ? name : "";
    }), 12) : [];
    if (passwordForms) {
      const ref = addSurfaceNode("authentication", "password-forms", "Password forms", { detail: passwordForms + " password form(s)", location: "current page", occurrences: passwordForms });
      authRefs.push(ref);
      addSurfaceEdge(targetSurfaceId, ref, "contains");
    }
    authCookies.forEach(function (name) {
      const ref = addSurfaceNode("authentication", "cookie|" + name, name, { detail: "Authentication-style cookie name", location: "document.cookie" });
      authRefs.push(ref);
      addSurfaceEdge(targetSurfaceId, ref, "uses");
    });
    if (passwordForms || authCookies.length) {
      add("info", "Authentication surface clues", passwordForms + " password form(s), " + authCookies.length + " authentication-style cookie name(s)", {
        checkId: "inventory.authentication",
        confidence: "medium",
        bucket: "review",
        category: "authentication",
        evidence: authCookies.length ? "Cookie names: " + authCookies.join(", ") + ". Cookie values were not collected." : "Password fields were observed; no cookie values were collected.",
        verification: "Review login, recovery, session rotation, logout, and reauthentication behavior manually.",
        location: "current page",
        surfaceRefs: unique(authRefs, 8),
        occurrences: passwordForms + authCookies.length
      });
    }
  }

  if (checkEnabled("passive.inventory")) addPassiveInventory();

  const sinks = [
    "innerHTML", "outerHTML", "document.write", "document.writeln", "eval(",
    "Function(", "setTimeout(", "setInterval(", "location.href",
    "location.assign", "location.replace", "element.src", ".insertAdjacentHTML"
  ];
  const foundSinks = sinks.filter(function (sink) {
    return pageText.indexOf(sink) !== -1;
  });
  if (foundSinks.length) {
    add("medium", "DOM sinks present", foundSinks.join(", "), {
      checkId: "dom.sinks",
      confidence: "low",
      bucket: "review",
      category: "dom-xss",
      evidence: foundSinks.length + " sink name(s) appear in the serialized page source.",
      verification: "Trace whether data controlled by the URL, storage, messages, or user input reaches any listed sink.",
      location: "serialized page source",
      surfaceRefs: refsFor(null, targetSurfaceId),
      occurrences: foundSinks.length
    });
  }

  function decodeJwtPart(value) {
    if (!value || value.length > 4096 || typeof atob !== "function") return null;
    try {
      const padded = value.replace(/-/g, "+").replace(/_/g, "/") + "===".slice((value.length + 3) % 4);
      const binary = atob(padded);
      let escaped = "";
      for (let i = 0; i < binary.length; i++) escaped += "%" + binary.charCodeAt(i).toString(16).padStart(2, "0");
      const parsed = JSON.parse(decodeURIComponent(escaped));
      return parsed && typeof parsed === "object" && !Array.isArray(parsed) ? parsed : null;
    } catch (e) {
      return null;
    }
  }

  function inspectJwtValues(values) {
    const metadata = { decoded: 0, none: 0, noExpiry: 0, invalidExpiry: 0, malformed: 0, algorithms: new Set() };
    values.slice(0, 20).forEach(function (token) {
      const parts = token.split(".");
      const header = decodeJwtPart(parts[0]);
      const payload = decodeJwtPart(parts[1]);
      if (!header || !payload) {
        metadata.malformed++;
        return;
      }
      metadata.decoded++;
      const algorithm = typeof header.alg === "string" && /^[A-Za-z0-9_-]{1,24}$/.test(header.alg) ? header.alg : "unrecognized";
      metadata.algorithms.add(algorithm);
      if (algorithm.toLowerCase() === "none") metadata.none++;
      if (!Object.prototype.hasOwnProperty.call(payload, "exp")) metadata.noExpiry++;
      else if (!Number.isFinite(Number(payload.exp))) metadata.invalidExpiry++;
    });
    const refs = refsFor(null, targetSurfaceId);
    const algorithmText = Array.from(metadata.algorithms).sort().join(", ") || "not decoded";
    if (metadata.none) {
      add("medium", "JWT declares no signing algorithm", metadata.none + " token(s) use alg=none; values remain hidden.", {
        checkId: "secret.jwt.alg-none",
        confidence: "high",
        bucket: "review",
        category: "authentication",
        evidence: "Decoded JWT metadata declared alg=none. No signature or claim value was displayed.",
        verification: "Confirm whether the server accepts this token type and rejects unsigned tokens on every protected endpoint.",
        location: "serialized page source",
        surfaceRefs: refs,
        occurrences: metadata.none
      });
    }
    if (metadata.noExpiry) {
      add("low", "JWT has no expiry claim", metadata.noExpiry + " decoded token(s) omit exp; algorithms: " + algorithmText + ".", {
        checkId: "secret.jwt.no-expiry",
        confidence: "medium",
        bucket: "review",
        category: "authentication",
        evidence: "Only standard claim presence and algorithm names were inspected; claim values remain hidden.",
        verification: "Determine the token purpose and confirm whether server-side expiry or revocation provides an equivalent lifetime control.",
        location: "serialized page source",
        surfaceRefs: refs,
        occurrences: metadata.noExpiry
      });
    }
    if (metadata.invalidExpiry) {
      add("low", "JWT expiry claim is not numeric", metadata.invalidExpiry + " decoded token(s) contain a non-numeric exp claim.", {
        checkId: "secret.jwt.invalid-expiry",
        confidence: "high",
        bucket: "review",
        category: "authentication",
        evidence: "The exp claim type was inspected without retaining its value.",
        verification: "Confirm how the token library parses exp and whether invalid values are rejected.",
        location: "serialized page source",
        surfaceRefs: refs,
        occurrences: metadata.invalidExpiry
      });
    }
    if (metadata.malformed) {
      add("info", "JWT metadata could not be decoded", metadata.malformed + " token-like value(s) were malformed or exceeded decoding limits.", {
        checkId: "secret.jwt.malformed",
        confidence: "medium",
        bucket: "review",
        category: "authentication",
        evidence: "The scanner stopped at bounded base64url and JSON decoding; raw values remain hidden.",
        verification: "Confirm whether the value is a JWT before drawing conclusions from it.",
        location: "serialized page source",
        surfaceRefs: refs,
        occurrences: metadata.malformed
      });
    }
  }

  const secretPatterns = [
    { name: "AWS Access Key", re: /AKIA[0-9A-Z]{16}/g, bucket: "finding", confidence: "high" },
    { name: "AWS Secret Key", re: /aws[_-]?secret[_-]?access[_-]?key['"]?\s*[:=]\s*['"][A-Za-z0-9\/+\=]{30,}/gi, bucket: "finding", confidence: "high" },
    { name: "Stripe live key", re: /sk_live_[0-9a-zA-Z]{20,}/g, bucket: "finding", confidence: "high" },
    { name: "Stripe test key", re: /sk_test_[0-9a-zA-Z]{20,}/g, bucket: "finding", confidence: "high" },
    { name: "Google API key", re: /AIza[0-9A-Za-z\-_]{35}/g, bucket: "finding", confidence: "high" },
    { name: "Firebase key", re: /AAAA[A-Za-z0-9_-]{7}:[A-Za-z0-9_-]{140}/g, bucket: "finding", confidence: "high" },
    { name: "GitHub token", re: /gh[pousr]_[A-Za-z0-9_]{36,}/g, bucket: "finding", confidence: "high" },
    { name: "Slack token", re: /xox[baprs]-[0-9a-zA-Z-]{10,}/g, bucket: "finding", confidence: "high" },
    { name: "Discord bot token", re: /[MN][A-Za-z\d]{23}\.[\w-]{6}\.[\w-]{27}/g, bucket: "finding", confidence: "high" },
    { name: "Twilio SID", re: /AC[a-f0-9]{32}/g, bucket: "finding", confidence: "high" },
    { name: "SendGrid key", re: /SG\.[a-zA-Z0-9_-]{22}\.[a-zA-Z0-9_-]{43}/g, bucket: "finding", confidence: "high" },
    { name: "Private key block", re: /-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----/g, bucket: "finding", confidence: "high" },
    { name: "Password assignment", re: /password\s*[:=]\s*['"][^'"\r\n]{3,}['"]/gi, bucket: "review", confidence: "low" },
    { name: "Generic API key", re: /api[_-]?key['"]?\s*[:=]\s*['"][a-zA-Z0-9_\-]{16,}/gi, bucket: "review", confidence: "low" },
    { name: "JWT", re: /eyJ[a-zA-Z0-9_-]{10,}\.eyJ[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9_-]*/g, bucket: "review", confidence: "low" }
  ];

  const secretVault = [];
  let secretVaultCharacters = 0;
  const seenSecrets = new Set();
  secretPatterns.forEach(function (pattern) {
    if (!checkEnabled("passive.secrets")) return;
    const values = [];
    for (const match of pageText.matchAll(pattern.re)) {
      const raw = match[0];
      if (seenSecrets.has(raw)) continue;
      seenSecrets.add(raw);
      const entry = pattern.name + ": " + raw;
      if (raw.length > limits.secretValueCharacters || secretVault.length >= limits.secretValues ||
          secretVaultCharacters + entry.length > limits.secretVaultCharacters) {
        scanLimits.secretsTruncated = true;
        continue;
      }
      values.push(raw);
      secretVault.push(entry);
      secretVaultCharacters += entry.length;
    }
    if (!values.length) return;
    add("high", "Possible secret", pattern.name + " (" + values.length + " distinct value" + (values.length === 1 ? "" : "s") + " hidden — use export to view)", {
      checkId: "secret." + pattern.name.toLowerCase().replace(/[^a-z0-9]+/g, "."),
      confidence: pattern.confidence,
      bucket: pattern.bucket,
      category: "secrets",
      evidence: values.length + " distinct value" + (values.length === 1 ? "" : "s") + " matched the " + pattern.name + " pattern. Values are redacted here.",
      verification: "Confirm whether the value is active, scoped appropriately, and safe to expose in client-delivered source.",
      location: "serialized page source",
      surfaceRefs: refsFor(null, targetSurfaceId),
      occurrences: values.length
    });
    if (pattern.name === "JWT") inspectJwtValues(values);
  });

  selectedNodes("form").forEach(function (form) {
    const method = (form.method || "get").toLowerCase();
    const action = form.action || pageUrl;
    const safeAction = redactUrl(action);
    if (method === "post") {
      const hasToken = form.querySelector("input[name*='csrf' i], input[name*='token' i], input[name*='_token' i], input[name*='authenticity' i], input[name*='nonce' i]");
      if (!hasToken) {
        add("medium", "No visible CSRF field", safeAction, {
          checkId: "form.csrf-field",
          confidence: "low",
          bucket: "review",
          category: "forms",
          evidence: "A POST form has no obvious CSRF or nonce input.",
          verification: "Check server-side SameSite, Origin/Referer, and CSRF-token validation before treating this as vulnerable.",
          location: safeAction,
          selector: elementSelector(form),
          surfaceRefs: refsFor(form, targetSurfaceId)
        });
      }
    }
    if (action.indexOf("http://") === 0 && location.protocol === "https:") {
      add("high", "Form submits over HTTP", safeAction, {
        checkId: "form.insecure-action",
        confidence: "high",
        bucket: "finding",
        category: "transport",
        evidence: "An HTTPS page contains a form action using plain HTTP.",
        verification: "Submit only in a safe test environment and confirm the browser sends the form over an unencrypted connection.",
        location: safeAction,
        selector: elementSelector(form),
        surfaceRefs: refsFor(form, targetSurfaceId)
      });
    }
    try {
      const actionHost = new URL(action, pageUrl).hostname;
      if (actionHost && actionHost !== location.hostname) {
        add("medium", "Form posts to another domain", safeAction, {
          checkId: "form.external-action",
          confidence: "low",
          bucket: "review",
          category: "forms",
          evidence: "The form action host differs from the current page host.",
          verification: "Confirm that the destination is an expected and trusted service.",
          location: safeAction,
          selector: elementSelector(form),
          surfaceRefs: refsFor(form, targetSurfaceId)
        });
      }
    } catch (e) {}
  });

  selectedNodes("img, script, link, iframe, source, video, audio, embed, object").forEach(function (element) {
    const source = element.src || element.href || element.data;
    if (source && source.indexOf("http://") === 0 && location.protocol === "https:") {
      add("medium", "Mixed content", redactUrl(source), {
        checkId: "transport.mixed-content",
        confidence: "high",
        bucket: "finding",
        category: "transport",
        evidence: "An HTTPS page references a resource over plain HTTP.",
        verification: "Confirm the request is not upgraded or blocked and replace it with an HTTPS resource.",
        location: redactUrl(source),
        selector: elementSelector(element),
        surfaceRefs: refsFor(element, targetSurfaceId)
      });
    }
  });

  if (document.cookie) {
    const cookieNames = Array.from(new Set(document.cookie.split(";").map(function (cookie) {
      return safeName(cookie.trim().split("=")[0]);
    }).filter(Boolean)));
    if (cookieNames.length) {
      add("low", "Cookies visible to JavaScript", cookieNames.join(", "), {
        checkId: "cookie.javascript-visible",
        confidence: "medium",
        bucket: "review",
        category: "cookies",
        evidence: cookieNames.length + " cookie name(s) are exposed through document.cookie.",
        verification: "Determine whether any listed cookie carries authentication or other sensitive state that should use HttpOnly.",
        location: "document.cookie",
        surfaceRefs: refsFor(null, targetSurfaceId),
        occurrences: cookieNames.length
      });
    }
  }

  const libraryPatterns = [
    { name: "jQuery", re: /jquery[.-]?([0-9]+\.[0-9]+(?:\.[0-9]+)?)/i },
    { name: "AngularJS", re: /angular(?:\.js)?[.-\/]([0-9]+\.[0-9]+)/i },
    { name: "Bootstrap", re: /bootstrap[.-]?([0-9]+\.[0-9]+)/i },
    { name: "Lodash", re: /lodash[.-]?([0-9]+\.[0-9]+)/i },
    { name: "Moment.js", re: /moment[.-]?([0-9]+\.[0-9]+)/i },
    { name: "React", re: /react[.-]?([0-9]+\.[0-9]+)/i },
    { name: "Vue", re: /vue[.-]?([0-9]+\.[0-9]+)/i }
  ];
  libraryPatterns.forEach(function (library) {
    const match = pageText.match(library.re);
    if (!match) return;
    add("info", "Library version observed", library.name + " " + match[1], {
      checkId: "library.version." + library.name.toLowerCase().replace(/[^a-z0-9]+/g, "."),
      confidence: "medium",
      bucket: "review",
      category: "components",
      evidence: "A source reference resembles a versioned " + library.name + " asset.",
      verification: "Confirm the loaded version in browser developer tools and compare it with the vendor's supported releases.",
      location: library.name,
      surfaceRefs: refsFor(null, targetSurfaceId)
    });
  });

  const commentPatterns = [
    { re: /todo[:\s].{8,90}/i, label: "TODO source text" },
    { re: /fixme[:\s].{8,90}/i, label: "FIXME source text" },
    { re: /hack[:\s].{8,80}/i, label: "HACK source text" },
    { re: /secret[:\s].{8,70}/i, label: "Secret-related source text" }
  ];
  commentPatterns.forEach(function (pattern) {
    const match = pageText.match(pattern.re);
    if (!match) return;
    add("low", pattern.label, "Matching text hidden; inspect the original source context.", {
      checkId: "source.comment." + pattern.label.toLowerCase().replace(/[^a-z0-9]+/g, "."),
      confidence: "low",
      bucket: "review",
      category: "source",
      evidence: "Matching text appears in the serialized page source.",
      verification: "Inspect the original source context and confirm whether the text exposes useful internal information.",
      location: "serialized page source",
      surfaceRefs: refsFor(null, targetSurfaceId)
    });
  });

  const redirectNames = new Set([
    "url", "redirect", "next", "return", "returnto", "goto", "dest",
    "destination", "redir", "redirect_uri", "continue", "return_url"
  ]);
  try {
    const matchedParams = Array.from(new Set(Array.from(new URL(pageUrl).searchParams.keys()).filter(function (name) {
      return redirectNames.has(name.toLowerCase());
    })));
    if (matchedParams.length) {
      add("medium", "Redirect-style query parameter", matchedParams.join(", "), {
        checkId: "redirect.query-parameter",
        confidence: "low",
        bucket: "review",
        category: "redirects",
        evidence: "The current URL contains " + matchedParams.length + " exact redirect-style query key" + (matchedParams.length === 1 ? "" : "s") + ".",
        verification: "Change the parameter to a controlled external HTTPS destination and confirm whether the application redirects there.",
        location: "query: " + matchedParams.join(", "),
        surfaceRefs: unique(matchedParams.map(function (name) {
          const direct = VulnscanFindings.surfaceId("parameter", "query|" + name);
          const observed = VulnscanFindings.surfaceId("parameter", "observed|" + name);
          return surfaceNodeIds.has(direct) ? direct : observed;
        }), 8),
        occurrences: matchedParams.length
      });
    }
  } catch (e) {}

  selectedNodes("meta[http-equiv]").forEach(function (meta) {
    if (!checkEnabled("passive.source")) return;
    const httpEquiv = meta.httpEquiv || (typeof meta.getAttribute === "function" ? meta.getAttribute("http-equiv") : "");
    if (String(httpEquiv || "").toLowerCase() !== "content-security-policy") return;
    const directives = unique(String(meta.content || "").split(";").map(function (part) {
      return part.trim().split(/\s+/)[0];
    }), 20);
    add("info", "CSP meta policy observed", directives.length ? directives.join(", ") : "Policy content is empty", {
      checkId: "source.csp-meta",
      confidence: "high",
      bucket: "review",
      category: "headers",
      evidence: "A Content-Security-Policy meta element was found. Directive values were not retained.",
      verification: "Compare it with the response headers. Remember that frame-ancestors is not enforced when delivered through a meta element.",
      location: "meta http-equiv=Content-Security-Policy",
      selector: elementSelector(meta),
      surfaceRefs: refsFor(meta, targetSurfaceId)
    });
  });

  selectedNodes("script[src], link[rel~='stylesheet'][href]").forEach(function (element) {
    try {
      const isStylesheet = String(element.tagName || "").toLowerCase() === "link";
      const source = new URL(element.src || element.href, pageUrl);
      if (source.origin !== new URL(pageUrl).origin && !element.integrity) {
        add("low", "External " + (isStylesheet ? "stylesheet" : "script") + " without SRI", redactUrl(source.href), {
          checkId: isStylesheet ? "style.missing-sri" : "script.missing-sri",
          confidence: "medium",
          bucket: "review",
          category: "supply-chain",
          evidence: "A cross-origin " + (isStylesheet ? "stylesheet" : "script") + " element has no integrity attribute.",
          verification: "Confirm that the resource is immutable and whether Subresource Integrity is appropriate for this deployment.",
          location: redactUrl(source.href),
          selector: elementSelector(element),
          surfaceRefs: refsFor(element, targetSurfaceId)
        });
      }
    } catch (e) {}
  });

  const technologies = [
    { name: "WordPress", re: /wp-content|wp-includes|wordpress/i },
    { name: "Drupal", re: /drupal|sites\/default\/files/i },
    { name: "Laravel", re: /laravel|csrf-token/i },
    { name: "React", re: /react|__NEXT_DATA__|data-reactroot/i },
    { name: "Vue.js", re: /vue\.js|data-v-|__vue__/i },
    { name: "Angular", re: /ng-version|angular/i },
    { name: "Cloudflare", re: /cloudflare|cf-ray|__cfduid/i },
    { name: "Shopify", re: /cdn\.shopify|shopify/i },
    { name: "Magento", re: /magento|mage\//i },
    { name: "Next.js", re: /__NEXT_DATA__|_next\//i }
  ];
  const foundTechnologies = technologies.filter(function (technology) {
    return technology.re.test(pageText) || technology.re.test(pageUrl);
  }).map(function (technology) { return technology.name; });
  if (foundTechnologies.length) {
    add("info", "Technology hints", Array.from(new Set(foundTechnologies)).join(", "), {
      checkId: "technology.hints",
      confidence: "low",
      bucket: "review",
      category: "recon",
      evidence: "Names or asset paths associated with these technologies appear in the page.",
      verification: "Confirm each technology from response headers, loaded assets, or framework-specific runtime markers.",
      location: "current page",
      surfaceRefs: refsFor(null, targetSurfaceId)
    });
  }

  const sensitiveHints = [".git", ".env", ".bak", ".old", ".swp", "phpinfo", "adminer", "server-status", "wp-config", ".DS_Store", "web.config"];
  const foundHints = sensitiveHints.filter(function (hint) {
    return pageLower.indexOf(hint.toLowerCase()) !== -1;
  });
  if (foundHints.length) {
    add("medium", "Sensitive path references", foundHints.join(", "), {
      checkId: "source.sensitive-paths",
      confidence: "low",
      bucket: "review",
      category: "disclosure",
      evidence: "Potentially sensitive file or path names appear in the page source.",
      verification: "Check whether the referenced paths are reachable and return content distinct from the site's normal not-found response.",
      location: "serialized page source",
      surfaceRefs: refsFor(null, targetSurfaceId),
      occurrences: foundHints.length
    });
  }

  const inlineEvents = selectedNodes("[onclick], [onerror], [onload], [onmouseover], [onfocus], [onblur]");
  if (inlineEvents.length) {
    add("low", "Inline event handlers present", inlineEvents.length + " element(s)", {
      checkId: "dom.inline-events",
      confidence: "high",
      bucket: "review",
      category: "dom-xss",
      evidence: inlineEvents.length + " element(s) use inline JavaScript event attributes.",
      verification: "Review whether untrusted values can enter these handlers or whether CSP blocks their execution.",
      location: "inline event attributes",
      selector: elementSelector(inlineEvents[0]),
      surfaceRefs: refsFor(inlineEvents[0], targetSurfaceId),
      occurrences: inlineEvents.length
    });
  }

  const sources = [
    { name: "location.search", re: /\b(?:window\.)?location\.search\b/ },
    { name: "location.hash", re: /\b(?:window\.)?location\.hash\b/ },
    { name: "location.href", re: /\b(?:window\.)?location\.href\b/ },
    { name: "document.URL", re: /\bdocument\.URL\b/ },
    { name: "document.referrer", re: /\bdocument\.referrer\b/ },
    { name: "postMessage data", re: /\b(?:event|e)\.data\b/ },
    { name: "localStorage", re: /\blocalStorage\.getItem\s*\(/ },
    { name: "sessionStorage", re: /\bsessionStorage\.getItem\s*\(/ }
  ];
  const flowSinks = [
    { name: "innerHTML", re: /\.innerHTML\s*=/ },
    { name: "outerHTML", re: /\.outerHTML\s*=/ },
    { name: "insertAdjacentHTML", re: /\.insertAdjacentHTML\s*\(/ },
    { name: "document.write", re: /document\.write(?:ln)?\s*\(/ },
    { name: "eval", re: /\beval\s*\(/ },
    { name: "Function", re: /\b(?:new\s+)?Function\s*\(/ }
  ];

  function escapeRegExp(value) {
    return value.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
  }

  function findSource(value) {
    return sources.find(function (source) { return source.re.test(value); }) || null;
  }

  const flows = [];
  let flowSelector = "";
  const inlineScripts = Array.prototype.slice.call(document.scripts || [], 0, limits.domNodesPerCheck);
  if ((document.scripts || []).length > inlineScripts.length) scanLimits.domTruncated = true;
  inlineScripts.forEach(function (script) {
    if (script.src) return;
    const statements = String(script.textContent || "").split(/[;\n]+/).map(function (statement) {
      return statement.trim();
    }).filter(Boolean);
    const taintedVariables = Object.create(null);

    statements.forEach(function (statement) {
      const assignment = statement.match(/^\s*(?:const|let|var)?\s*([A-Za-z_$][\w$]*)\s*=\s*([\s\S]+)$/);
      if (assignment) {
        const rhs = assignment[2];
        const directSource = findSource(rhs);
        if (directSource) {
          taintedVariables[assignment[1]] = directSource.name;
        } else {
          Object.keys(taintedVariables).some(function (name) {
            if (new RegExp("\\b" + escapeRegExp(name) + "\\b").test(rhs)) {
              taintedVariables[assignment[1]] = taintedVariables[name];
              return true;
            }
            return false;
          });
        }
      }

      const sink = flowSinks.find(function (item) { return item.re.test(statement); });
      if (!sink) return;
      const directSource = findSource(statement);
      if (directSource) {
        flows.push(directSource.name + " -> " + sink.name);
        flowSelector = flowSelector || elementSelector(script);
        return;
      }
      Object.keys(taintedVariables).some(function (name) {
        if (new RegExp("\\b" + escapeRegExp(name) + "\\b").test(statement)) {
          flows.push(taintedVariables[name] + " -> " + sink.name);
          flowSelector = flowSelector || elementSelector(script);
          return true;
        }
        return false;
      });
    });
  });

  const uniqueFlows = Array.from(new Set(flows)).slice(0, 4);
  if (uniqueFlows.length) {
    add("medium", "DOM XSS candidate", uniqueFlows.join(" | "), {
      checkId: "dom.source-to-sink",
      confidence: "medium",
      bucket: "finding",
      category: "dom-xss",
      evidence: "An inline script moves a recognized browser-controlled source into an HTML or code execution sink.",
      verification: "Trace the complete data flow and test with a harmless marker to determine whether encoding or sanitization blocks execution.",
      location: "inline script",
      selector: flowSelector,
      surfaceRefs: refsFor(null, targetSurfaceId),
      occurrences: uniqueFlows.length
    });
  }

  const limitNotes = [];
  if (scanLimits.sourceTruncated) limitNotes.push("page source capped at " + limits.pageSourceCharacters + " characters");
  if (scanLimits.domTruncated) limitNotes.push("DOM element processing limit reached");
  if (scanLimits.findingsTruncated) limitNotes.push("finding limit reached");
  if (scanLimits.secretsTruncated) limitNotes.push("secret export limit reached");
  if (scanLimits.surfaceTruncated) limitNotes.push("surface map collection limit reached");
  if (limitNotes.length) {
    findings.push(VulnscanFindings.normalize({
      checkId: "scan.limits",
      severity: "info",
      confidence: "high",
      bucket: "review",
      category: "scan-health",
      type: "Scan limits reached",
      detail: limitNotes.join("; ") + ".",
      evidence: "The scanner stopped collecting affected data at its configured safety limit.",
      verification: "Narrow the page or selected checks and scan again if complete coverage is required.",
      location: "current page",
      source: "passive"
    }));
  }

  const normalizedFindings = VulnscanFindings.dedupe(findings);
  chrome.runtime.sendMessage({
    type: journeyId ? "journey_page_results" : "scan_results",
    schemaVersion: 8,
    scanId: scanId,
    journeyId: journeyId,
    captureId: captureId,
    scanMode: scanMode,
    checksRun: VulnscanChecks.effective(enabledChecks, scanMode),
    url: pageUrl,
    title: document.title || "",
    findings: normalizedFindings,
    summary: VulnscanFindings.summarize(normalizedFindings),
    risk: VulnscanFindings.risk(normalizedFindings),
    scanLimits: scanLimits,
    surface: VulnscanFindings.normalizeSurface({ nodes: surfaceNodes, edges: surfaceEdges, truncated: scanLimits.surfaceTruncated })
  });

  if (secretVault.length) {
    chrome.runtime.sendMessage({
      type: journeyId ? "journey_export_secrets" : "export_secrets",
      scanId: scanId,
      journeyId: journeyId,
      captureId: captureId,
      url: pageUrl,
      secrets: secretVault
    });
  }

  delete globalThis.__vulnscanScanId;
  delete globalThis.__vulnscanScanMode;
  delete globalThis.__vulnscanEnabledChecks;
  delete globalThis.__vulnscanJourneyId;
  delete globalThis.__vulnscanCaptureId;
})();
