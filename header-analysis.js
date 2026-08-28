(function (root) {
  "use strict";

  function clean(value, limit) {
    return String(value === undefined || value === null ? "" : value).replace(/[\u0000-\u001f\u007f-\u009f]+/g, " ").trim().slice(0, limit || 1000);
  }

  function finding(checkId, severity, type, detail, confidence, evidence, verification, location, category) {
    return VulnscanFindings.normalize({
      checkId: checkId, severity: severity, confidence: confidence, bucket: "review", category: category || "headers",
      type: type, detail: detail, evidence: evidence, verification: verification,
      location: location || checkId, source: "headers"
    });
  }

  function csp(value) {
    const directives = new Map();
    String(value || "").split(";").forEach(function (part) {
      const tokens = part.trim().split(/\s+/).filter(Boolean);
      if (tokens.length) directives.set(tokens.shift().toLowerCase(), tokens.map(function (token) { return token.toLowerCase(); }));
    });
    return directives;
  }

  function cookie(value) {
    const parts = String(value || "").split(";");
    const pair = parts.shift() || "";
    let name = pair.slice(0, pair.indexOf("=") < 0 ? pair.length : pair.indexOf("=")).trim();
    if (!name || name.length > 80 || !/^[A-Za-z0-9!#$%&'*+.^_`|~-]+$/.test(name)) name = "[cookie name hidden]";
    if (/[A-Za-z0-9_-]{40,}/.test(name)) name = "[long cookie name hidden]";
    const attributes = new Map();
    parts.forEach(function (part) {
      const separator = part.indexOf("=");
      const key = (separator < 0 ? part : part.slice(0, separator)).trim().toLowerCase();
      if (key) attributes.set(key, separator < 0 ? "" : part.slice(separator + 1).trim());
    });
    return { name: name, attributes: attributes };
  }

  function analyze(headerList, pageUrl, enabledChecks) {
    const values = {};
    (headerList || []).slice(0, 200).forEach(function (header) {
      const name = clean(header && header.name, 120).toLowerCase();
      if (!name) return;
      if (!values[name]) values[name] = [];
      values[name].push(clean(header.value, VulnscanFindings.limits.messageTextCharacters));
    });
    const first = function (name) { return values[name] && values[name][0] || ""; };
    const selected = VulnscanChecks.normalize(enabledChecks);
    const findings = [];
    const rows = [];

    if (VulnscanChecks.enabled(selected, "headers.security")) {
      const policies = (values["content-security-policy"] || []).map(csp);
      if (!policies.length) {
        rows.push(["Content-Security-Policy", "missing", "Missing"]);
        findings.push(finding("header.csp.missing", "low", "Content Security Policy missing", "No Content-Security-Policy response header was captured.", "low", "The final main-frame response did not include an enforced CSP header.", "Confirm the final response and define the sources the application needs to allow.", "Content-Security-Policy"));
      } else {
        const unsafe = [];
        const allows = function (token, element) {
          return policies.every(function (policy) {
            const sources = element && policy.get("script-src-elem") || policy.get("script-src") || policy.get("default-src");
            return !sources || sources.includes(token);
          });
        };
        if (allows("'unsafe-inline'", true)) unsafe.push("unsafe-inline");
        if (allows("'unsafe-eval'", false)) unsafe.push("unsafe-eval");
        rows.push(["Content-Security-Policy", unsafe.length ? "weak" : "ok", policies.length + " enforced" + (unsafe.length ? " · " + unsafe.join(", ") : "")]);
        if (unsafe.length) findings.push(finding("header.csp.unsafe", "medium", "Content Security Policy allows unsafe script behavior", "Every enforced CSP policy permits " + unsafe.join(" and ") + " for scripts.", "medium", "The enforced policies were evaluated together.", "Confirm which directive permits this behavior and whether nonces or hashes can replace it.", "Content-Security-Policy"));
      }

      const hsts = first("strict-transport-security");
      if (!String(pageUrl || "").startsWith("https://")) rows.push(["Strict-Transport-Security", "ok", "Not applicable"]);
      else if (!hsts || !/\bmax-age\s*=\s*[1-9][0-9]*\b/i.test(hsts)) {
        rows.push(["Strict-Transport-Security", hsts ? "weak" : "missing", hsts ? "Disabled or invalid max-age" : "Missing"]);
        findings.push(finding(hsts ? "header.hsts.disabled" : "header.hsts.missing", "low", hsts ? "HSTS is not active" : "HSTS missing", hsts ? "Strict-Transport-Security does not contain a positive max-age." : "The HTTPS response has no Strict-Transport-Security header.", "high", hsts ? "The captured value does not enable HSTS." : "No HSTS header was captured on the final HTTPS response.", "Confirm the host is ready for HTTPS-only access before setting a positive max-age.", "Strict-Transport-Security"));
      } else rows.push(["Strict-Transport-Security", "ok", "Present"]);

      const xfo = first("x-frame-options").trim().toUpperCase();
      const protectedByCsp = policies.some(function (policy) {
        const sources = policy.get("frame-ancestors");
        return sources && sources.length && !sources.includes("*");
      });
      if (["DENY", "SAMEORIGIN"].includes(xfo) || protectedByCsp) rows.push(["Framing protection", "ok", protectedByCsp ? "CSP frame-ancestors" : xfo]);
      else {
        rows.push(["Framing protection", xfo ? "weak" : "missing", xfo ? "Invalid X-Frame-Options" : "Missing"]);
        findings.push(finding(xfo ? "header.framing.invalid" : "header.framing.missing", "medium", xfo ? "Framing header needs review" : "Framing protection missing", xfo ? "X-Frame-Options does not use DENY or SAMEORIGIN." : "Neither X-Frame-Options nor CSP frame-ancestors was captured.", xfo ? "medium" : "low", "The final response lacks a recognized framing control.", "Attempt to frame the page from a controlled origin and confirm sensitive actions are protected.", "X-Frame-Options"));
      }

      [["x-content-type-options", "X-Content-Type-Options", "header.content-type-options", "MIME sniffing protection missing"], ["referrer-policy", "Referrer-Policy", "header.referrer-policy", "Referrer-Policy missing"], ["permissions-policy", "Permissions-Policy", "header.permissions-policy", "Permissions-Policy missing"]].forEach(function (item) {
        const value = first(item[0]);
        const valid = item[0] === "x-content-type-options" ? value.toLowerCase() === "nosniff" : !!value;
        rows.push([item[1], valid ? "ok" : "missing", valid ? "Present" : "Missing"]);
        if (!valid) findings.push(finding(item[2], "info", item[3], item[1] + " was not captured with a recognized value.", "low", "The final main-frame response did not provide this protection.", "Review the intended browser policy and the final response.", item[1]));
      });
    }

    if (VulnscanChecks.enabled(selected, "headers.boundaries")) {
      const origins = values["access-control-allow-origin"] || [];
      const origin = origins.length === 1 ? origins[0].trim() : "";
      const credentials = first("access-control-allow-credentials").trim().toLowerCase() === "true";
      let corsIssue = null;
      if (origins.length > 1 || origin.includes(",")) corsIssue = ["header.cors.multiple-origins", "CORS origin policy is invalid", "Multiple origin values were captured."];
      else if (origin === "null") corsIssue = ["header.cors.null-origin", "CORS allows the null origin", "The null origin is allowed" + (credentials ? " with credentials." : ".")];
      else if (origin === "*" && credentials) corsIssue = ["header.cors.wildcard-credentials", "CORS credentials policy is contradictory", "A wildcard origin is combined with credentials."];
      rows.push(["CORS policy", corsIssue ? "weak" : "neutral", corsIssue ? "Needs review" : origins.length ? "Advertised" : "Not advertised"]);
      if (corsIssue) findings.push(finding(corsIssue[0], "low", corsIssue[1], corsIssue[2], "high", "Only the final main-document CORS headers were assessed.", "Confirm the policy on sensitive response paths from controlled origins.", "Access-Control-Allow-Origin", "cross-origin"));
    }

    if (VulnscanChecks.enabled(selected, "headers.cookies")) {
      (values["set-cookie"] || []).forEach(function (value) {
        const parsed = cookie(value);
        const missing = ["secure", "httponly", "samesite"].filter(function (name) { return !parsed.attributes.has(name); });
        rows.push([parsed.name, missing.length ? "weak" : "ok", missing.length ? "Missing " + missing.join(", ") : "Secure + HttpOnly + SameSite"]);
        if (missing.length) findings.push(finding("header.cookie-flags", "low", "Cookie flags need review", parsed.name + ": missing " + missing.join(", "), "medium", "Only the cookie name and attributes were assessed; its value was not retained.", "Determine whether the cookie carries sensitive state and which flags are appropriate.", "Set-Cookie: " + parsed.name));
      });
    }
    return { rows: rows, findings: VulnscanFindings.dedupe(findings) };
  }

  root.VulnscanHeaders = { analyze: analyze };
})(globalThis);
