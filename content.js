(function () {
  const findings = [];
  const pageText = document.documentElement.innerHTML;
  const pageUrl = location.href;
  const pageLower = pageText.toLowerCase();
  const scanId = globalThis.__vulnscanScanId || null;

  function add(severity, type, detail, options) {
    const item = options || {};
    findings.push(VulnscanFindings.normalize({
      checkId: item.checkId,
      severity: severity,
      confidence: item.confidence,
      bucket: item.bucket,
      category: item.category,
      type: type,
      detail: detail,
      evidence: item.evidence,
      verification: item.verification,
      source: "passive",
      occurrences: item.occurrences
    }));
  }

  function redactUrl(value) {
    try {
      const url = new URL(value, pageUrl);
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
    } catch (e) {
      return "[invalid URL]";
    }
  }

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
      occurrences: foundSinks.length
    });
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
    { name: "JWT", re: /eyJ[a-zA-Z0-9_-]{10,}\.eyJ[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9_-]{10,}/g, bucket: "review", confidence: "low" }
  ];

  const secretVault = [];
  const seenSecrets = new Set();
  secretPatterns.forEach(function (pattern) {
    const values = [];
    for (const match of pageText.matchAll(pattern.re)) {
      const raw = match[0];
      if (seenSecrets.has(raw)) continue;
      seenSecrets.add(raw);
      values.push(raw);
      secretVault.push(pattern.name + ": " + raw);
    }
    if (!values.length) return;
    add("high", "Possible secret", pattern.name + " (" + values.length + " distinct value" + (values.length === 1 ? "" : "s") + " hidden — use export to view)", {
      checkId: "secret." + pattern.name.toLowerCase().replace(/[^a-z0-9]+/g, "."),
      confidence: pattern.confidence,
      bucket: pattern.bucket,
      category: "secrets",
      evidence: values.length + " distinct value" + (values.length === 1 ? "" : "s") + " matched the " + pattern.name + " pattern. Values are redacted here.",
      verification: "Confirm whether the value is active, scoped appropriately, and safe to expose in client-delivered source.",
      occurrences: values.length
    });
  });

  document.querySelectorAll("form").forEach(function (form) {
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
          verification: "Check server-side SameSite, Origin/Referer, and CSRF-token validation before treating this as vulnerable."
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
        verification: "Submit only in a safe test environment and confirm the browser sends the form over an unencrypted connection."
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
          verification: "Confirm that the destination is an expected and trusted service."
        });
      }
    } catch (e) {}
  });

  document.querySelectorAll("img, script, link, iframe, source, video, audio, embed, object").forEach(function (element) {
    const source = element.src || element.href || element.data;
    if (source && source.indexOf("http://") === 0 && location.protocol === "https:") {
      add("medium", "Mixed content", redactUrl(source), {
        checkId: "transport.mixed-content",
        confidence: "high",
        bucket: "finding",
        category: "transport",
        evidence: "An HTTPS page references a resource over plain HTTP.",
        verification: "Confirm the request is not upgraded or blocked and replace it with an HTTPS resource."
      });
    }
  });

  if (document.cookie) {
    const cookieNames = Array.from(new Set(document.cookie.split(";").map(function (cookie) {
      return cookie.trim().split("=")[0];
    }).filter(Boolean)));
    if (cookieNames.length) {
      add("low", "Cookies visible to JavaScript", cookieNames.join(", "), {
        checkId: "cookie.javascript-visible",
        confidence: "medium",
        bucket: "review",
        category: "cookies",
        evidence: cookieNames.length + " cookie name(s) are exposed through document.cookie.",
        verification: "Determine whether any listed cookie carries authentication or other sensitive state that should use HttpOnly.",
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
      verification: "Confirm the loaded version in browser developer tools and compare it with the vendor's supported releases."
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
      verification: "Inspect the original source context and confirm whether the text exposes useful internal information."
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
        occurrences: matchedParams.length
      });
    }
  } catch (e) {}

  document.querySelectorAll("script[src]").forEach(function (script) {
    try {
      const source = new URL(script.src, pageUrl);
      if (source.hostname !== location.hostname && !script.integrity) {
        add("low", "External script without SRI", redactUrl(source.href), {
          checkId: "script.missing-sri",
          confidence: "medium",
          bucket: "review",
          category: "supply-chain",
          evidence: "A cross-origin script element has no integrity attribute.",
          verification: "Confirm that the script is immutable and whether Subresource Integrity is appropriate for this deployment."
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
      verification: "Confirm each technology from response headers, loaded assets, or framework-specific runtime markers."
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
      occurrences: foundHints.length
    });
  }

  const inlineEvents = document.querySelectorAll("[onclick], [onerror], [onload], [onmouseover], [onfocus], [onblur]");
  if (inlineEvents.length) {
    add("low", "Inline event handlers present", inlineEvents.length + " element(s)", {
      checkId: "dom.inline-events",
      confidence: "high",
      bucket: "review",
      category: "dom-xss",
      evidence: inlineEvents.length + " element(s) use inline JavaScript event attributes.",
      verification: "Review whether untrusted values can enter these handlers or whether CSP blocks their execution.",
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
  Array.from(document.scripts).forEach(function (script) {
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
        return;
      }
      Object.keys(taintedVariables).some(function (name) {
        if (new RegExp("\\b" + escapeRegExp(name) + "\\b").test(statement)) {
          flows.push(taintedVariables[name] + " -> " + sink.name);
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
      occurrences: uniqueFlows.length
    });
  }

  const normalizedFindings = VulnscanFindings.dedupe(findings);
  chrome.runtime.sendMessage({
    type: "scan_results",
    schemaVersion: 2,
    scanId: scanId,
    url: pageUrl,
    findings: normalizedFindings,
    summary: VulnscanFindings.summarize(normalizedFindings),
    risk: VulnscanFindings.risk(normalizedFindings)
  });

  if (secretVault.length) {
    chrome.runtime.sendMessage({
      type: "export_secrets",
      scanId: scanId,
      url: pageUrl,
      secrets: secretVault
    });
  }

  delete globalThis.__vulnscanScanId;
})();

