(function () {
  const findings = [];
  const summary = { high: 0, medium: 0, low: 0, info: 0 };

  function add(severity, type, detail) {
    findings.push({ severity: severity, type: type, detail: detail });
    summary[severity] = (summary[severity] || 0) + 1;
  }

  const pageText = document.documentElement.innerHTML;
  const pageURL = location.href;
  const pageLower = pageText.toLowerCase();

  // sinks
  const sinks = [
    "innerHTML",
    "outerHTML",
    "document.write",
    "document.writeln",
    "eval(",
    "Function(",
    "setTimeout(",
    "setInterval(",
    "location.href",
    "location.assign",
    "location.replace",
    "element.src",
    ".insertAdjacentHTML"
  ];

  sinks.forEach(function (sink) {
    if (pageText.indexOf(sink) !== -1) {
      add("medium", "DOM XSS sink", "Found usage of " + sink);
    }
  });

  // secrets
  const secretPatterns = [
    { name: "AWS Access Key", re: /AKIA[0-9A-Z]{16}/ },
    { name: "AWS Secret Key", re: /aws[_-]?secret[_-]?access[_-]?key['"]?\s*[:=]\s*['"][A-Za-z0-9\/+=]{30,}/i },
    { name: "Stripe live key", re: /sk_live_[0-9a-zA-Z]{20,}/ },
    { name: "Stripe test key", re: /sk_test_[0-9a-zA-Z]{20,}/ },
    { name: "Google API key", re: /AIza[0-9A-Za-z\-_]{35}/ },
    { name: "Firebase key", re: /AAAA[A-Za-z0-9_-]{7}:[A-Za-z0-9_-]{140}/ },
    { name: "GitHub token", re: /gh[pousr]_[A-Za-z0-9_]{36,}/ },
    { name: "Slack token", re: /xox[baprs]-[0-9a-zA-Z-]{10,}/ },
    { name: "Discord bot token", re: /[MN][A-Za-z\d]{23}\.[\w-]{6}\.[\w-]{27}/ },
    { name: "Twilio SID", re: /AC[a-f0-9]{32}/ },
    { name: "SendGrid key", re: /SG\.[a-zA-Z0-9_-]{22}\.[a-zA-Z0-9_-]{43}/ },
    { name: "Generic API key", re: /api[_-]?key['"]?\s*[:=]\s*['"][a-zA-Z0-9_\-]{16,}/i },
    { name: "JWT", re: /eyJ[a-zA-Z0-9_-]{10,}\.eyJ[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9_-]{10,}/ },
    { name: "Private key block", re: /-----BEGIN (RSA |EC |OPENSSH )?PRIVATE KEY-----/ }
  ];

  const secretVault = [];
  secretPatterns.forEach(function (p) {
    const match = pageText.match(p.re);
    if (match) {
      const raw = match[0];
      findings.push({
        severity: "high",
        type: "Possible secret",
        detail: p.name + " (hidden — use export to view)"
      });
      secretVault.push(p.name + ": " + raw);
      summary.high = (summary.high || 0) + 1;
    }
  });

  // forms
  document.querySelectorAll("form").forEach(function (form) {
    const method = (form.method || "get").toLowerCase();
    if (method === "post") {
      const hasToken = form.querySelector("input[name*='csrf' i], input[name*='token' i], input[name*='_token' i], input[name*='authenticity' i], input[name*='nonce' i]");
      if (!hasToken) {
        add("medium", "Possible missing CSRF token", "Form action: " + (form.action || pageURL));
      }
    }
    if (form.action && form.action.indexOf("http://") === 0 && location.protocol === "https:") {
      add("high", "Form submits over HTTP", form.action);
    }
    // external form action
    try {
      if (form.action) {
        const formHost = new URL(form.action, pageURL).hostname;
        if (formHost && formHost !== location.hostname) {
          add("medium", "Form posts to external domain", form.action);
        }
      }
    } catch (e) {}
  });

  // mixed content
  document.querySelectorAll("img, script, link, iframe, source, video, audio, embed, object").forEach(function (el) {
    const src = el.src || el.href || el.data;
    if (src && src.indexOf("http://") === 0 && location.protocol === "https:") {
      add("medium", "Mixed content", src);
    }
  });

  // document.cookie
  if (document.cookie) {
    document.cookie.split(";").forEach(function (c) {
      const name = c.trim().split("=")[0];
      if (name) {
        add("low", "Cookie visible to JavaScript", name);
      }
    });
  }

  // framing
  if (pageText.indexOf("top.location") === -1 &&
      pageText.indexOf("self === top") === -1 &&
      pageText.indexOf("window.top") === -1 &&
      pageText.indexOf("parent.location") === -1) {
    add("info", "No frame-busting script detected", "May be vulnerable to clickjacking if headers are also missing");
  }

  // libs
  const libChecks = [
    { name: "jQuery", re: /jquery[.-]?([0-9]+\.[0-9]+(?:\.[0-9]+)?)/i, bad: ["1.", "2.0", "2.1", "2.2"] },
    { name: "AngularJS", re: /angular(?:\.js)?[.-/]([0-9]+\.[0-9]+)/i, bad: ["1."] },
    { name: "Bootstrap", re: /bootstrap[.-]?([0-9]+\.[0-9]+)/i, bad: ["3.", "4.0", "4.1", "4.2"] },
    { name: "Lodash", re: /lodash[.-]?([0-9]+\.[0-9]+)/i, bad: ["4.0", "4.1", "4.2", "4.3", "4.4", "4.5", "4.6", "4.7", "4.8", "4.9", "4.10", "4.11", "4.12", "4.13", "4.14", "4.15", "4.16"] },
    { name: "Moment.js", re: /moment[.-]?([0-9]+\.[0-9]+)/i, bad: ["2.0", "2.1", "2.2", "2.3", "2.4", "2.5", "2.6", "2.7", "2.8", "2.9", "2.10", "2.11", "2.12", "2.13", "2.14", "2.15", "2.16", "2.17", "2.18", "2.19", "2.20", "2.21", "2.22", "2.23", "2.24", "2.25", "2.26", "2.27", "2.28"] },
    { name: "React", re: /react[.-]?([0-9]+\.[0-9]+)/i, bad: [] },
    { name: "Vue", re: /vue[.-]?([0-9]+\.[0-9]+)/i, bad: ["1."] }
  ];

  libChecks.forEach(function (lib) {
    const m = pageText.match(lib.re);
    if (m) {
      const ver = m[1] || "";
      let isBad = false;
      for (let i = 0; i < lib.bad.length; i++) {
        if (ver.indexOf(lib.bad[i]) === 0) { isBad = true; break; }
      }
      if (isBad) {
        add("medium", "Outdated library", lib.name + " " + ver + " may have known vulnerabilities");
      } else if (ver) {
        add("info", "Library detected", lib.name + " " + ver);
      }
    }
  });

  // comments
  const commentPatterns = [
    { re: /password\s*[:=]\s*['"][^'"]{3,}['"]/i, label: "Password in comment/code" },
    { re: /todo[:\s].{8,90}/i, label: "TODO comment" },
    { re: /fixme[:\s].{8,90}/i, label: "FIXME comment" },
    { re: /hack[:\s].{8,80}/i, label: "HACK comment" },
    { re: /secret[:\s].{8,70}/i, label: "Secret mention" },
    { re: /api[_-]?key\s*[:=]\s*['"][^'"]+['"]/i, label: "API key in source" }
  ];

  commentPatterns.forEach(function (p) {
    const m = pageText.match(p.re);
    if (m) {
      add("low", p.label, m[0].substring(0, 80));
    }
  });

  // redirect params
  const redirectParams = ["url=", "redirect=", "next=", "return=", "returnto=", "goto=", "dest=", "destination=", "redir=", "redirect_uri=", "continue=", "return_url="];
  redirectParams.forEach(function (p) {
    if (pageURL.toLowerCase().indexOf(p) !== -1 || pageLower.indexOf(p) !== -1) {
      add("medium", "Possible open redirect parameter", "Found: " + p.replace("=", ""));
    }
  });

  // passwords
  document.querySelectorAll("input[type='password']").forEach(function (input) {
    const ac = (input.getAttribute("autocomplete") || "").toLowerCase();
    if (ac === "on" || ac === "") {
      add("low", "Password field may allow autocomplete", input.name || input.id || "unnamed field");
    }
  });

  // sri
  document.querySelectorAll("script[src]").forEach(function (script) {
    const src = script.src;
    if (src && (src.indexOf("http://") === 0 || src.indexOf("https://") === 0)) {
      try {
        const host = new URL(src).hostname;
        if (host !== location.hostname && !script.integrity) {
          add("low", "External script without SRI", src);
        }
      } catch (e) {}
    }
  });

  // stack hints
  const tech = [
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

  tech.forEach(function (t) {
    if (t.re.test(pageText) || t.re.test(pageURL)) {
      add("info", "Technology detected", t.name);
    }
  });

  // path strings
  const sensitiveHints = [".git", ".env", ".bak", ".old", ".swp", "phpinfo", "adminer", "server-status", "wp-config", ".DS_Store", "web.config"];
  sensitiveHints.forEach(function (h) {
    if (pageLower.indexOf(h.toLowerCase()) !== -1) {
      add("medium", "Sensitive path/file reference", "Found reference to: " + h);
    }
  });

  // on* handlers
  const inlineEvents = document.querySelectorAll("[onclick], [onerror], [onload], [onmouseover], [onfocus], [onblur]");
  if (inlineEvents.length > 0) {
    add("low", "Inline event handlers present", inlineEvents.length + " element(s) with inline JS events");
  }


  // inline source-to-sink check
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
    const statements = String(script.textContent || "")
      .split(/[;\n]+/)
      .map(function (statement) { return statement.trim(); })
      .filter(Boolean);
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
    add("medium", "DOM XSS candidate", "Inline script flow: " + uniqueFlows.join(" | ") + " (heuristic)");
  }

  let risk = "info";
  if ((summary.high || 0) > 0) risk = "high";
  else if ((summary.medium || 0) > 0) risk = "medium";
  else if ((summary.low || 0) > 0) risk = "low";

  chrome.runtime.sendMessage({
    type: "scan_results",
    url: pageURL,
    findings: findings,
    summary: summary,
    risk: risk
  });

  if (secretVault.length) {
    chrome.runtime.sendMessage({
      type: "export_secrets",
      url: pageURL,
      secrets: secretVault
    });
  }
})();
