(function (root) {
  const categoryGuidance = {
    secrets: {
      impact: "A credential delivered to the browser may be copied and used outside the application if it is active and insufficiently restricted.",
      remediation: "Remove the value from client-delivered content, rotate it when exposure is confirmed, and restrict replacement credentials to the smallest required scope.",
      steps: ["Confirm the value type without placing it in notes or reports.", "Check whether the value is active and what it can access.", "Rotate or revoke exposed credentials and review access logs."]
    },
    "dom-xss": {
      impact: "Browser-controlled input reaching an HTML or code-execution sink can create a client-side injection path when encoding or sanitization is missing.",
      remediation: "Prefer text-only DOM APIs, validate untrusted input, and use a well-maintained context-aware sanitizer where HTML rendering is required.",
      steps: ["Trace the complete source-to-sink path.", "Identify the output context and any sanitizer in the path.", "Use a harmless marker to confirm whether the browser interprets the value as markup."]
    },
    transport: {
      impact: "Plain HTTP resources or form submissions can expose or alter data despite the main page using HTTPS.",
      remediation: "Serve every resource and form destination over HTTPS and remove dependencies that cannot provide a trusted encrypted endpoint.",
      steps: ["Confirm the final request URL in the network panel.", "Check whether the browser upgrades or blocks the request.", "Retest after replacing the HTTP endpoint."]
    },
    redirects: {
      impact: "Unrestricted redirects can make a trusted origin send users to an attacker-controlled destination and may support phishing or token leakage chains.",
      remediation: "Allow only known destinations, prefer relative paths, and reject URLs with an unexpected scheme or origin.",
      steps: ["Repeat with a controlled HTTPS destination.", "Check alternate encodings and nested redirect parameters.", "Confirm that validation occurs before any redirect response is returned."]
    },
    headers: {
      impact: "Missing or weak browser security policies can increase the impact of another flaw, although a header observation alone does not prove exploitability.",
      remediation: "Define policies from the application’s actual requirements, deploy them gradually, and verify them on every relevant response path.",
      steps: ["Confirm the final response headers in browser developer tools.", "Check redirects and error responses for inconsistent policies.", "Test the intended browser behavior after changing the policy."]
    },
    "cross-origin": {
      impact: "Cross-origin policies shape which documents can read, embed, open, or load a response. An unusual policy matters only when it crosses an unintended trust boundary.",
      remediation: "Define the origins and resource relationships the application actually needs, then use valid policies that allow only those relationships.",
      steps: ["Confirm the final policy on the affected response.", "Identify the intended caller, opener, embedder, or resource consumer.", "Retest the browser behavior from a controlled origin."]
    },
    forms: {
      impact: "Form destination and anti-CSRF clues can reveal trust-boundary or request-integrity problems that require server-side verification.",
      remediation: "Keep sensitive submissions on trusted HTTPS origins and enforce appropriate server-side request-integrity controls.",
      steps: ["Confirm the effective form method and destination.", "Review server-side Origin, SameSite, and token validation.", "Verify the behavior with an authorized test account."]
    },
    cookies: {
      impact: "Cookies available to page JavaScript or missing defensive flags may be more exposed during a separate client-side or cross-site weakness.",
      remediation: "Apply Secure, HttpOnly, and an appropriate SameSite policy to sensitive cookies while preserving required application flows.",
      steps: ["Determine what each named cookie controls.", "Inspect the complete Set-Cookie header.", "Retest login, logout, and cross-site flows after changing flags."]
    },
    "supply-chain": {
      impact: "An externally hosted script without integrity pinning relies entirely on the remote host and transport path remaining trustworthy.",
      remediation: "Pin immutable third-party assets with Subresource Integrity or serve controlled copies when the update model permits it.",
      steps: ["Confirm whether the asset URL is immutable.", "Review the provider and update process.", "Test an integrity attribute against the exact deployed file."]
    },
    components: {
      impact: "A version observation helps identify components that may be unsupported or require advisory review; it is not a vulnerability claim by itself.",
      remediation: "Confirm the exact runtime version, compare it with vendor support information, and update through the project’s normal dependency process.",
      steps: ["Confirm the loaded file and runtime version.", "Check the component’s official support and advisory information.", "Regression-test the application before upgrading."]
    },
    authentication: {
      impact: "Authentication surface clues identify areas where session lifecycle, recovery, and reauthentication controls deserve focused review.",
      remediation: "Apply consistent server-side authentication and session controls across login, recovery, logout, and sensitive account actions.",
      steps: ["Map login, recovery, logout, and session refresh flows.", "Verify session rotation and invalidation.", "Check reauthentication on sensitive actions."]
    },
    disclosure: {
      impact: "References to sensitive paths can expose implementation details or lead to files that were not intended for public access.",
      remediation: "Remove public references that are unnecessary and block deployment of backups, configuration files, and repository metadata.",
      steps: ["Confirm the reference in the original source.", "Compare any response with the site’s normal not-found page.", "Remove or restrict genuinely exposed content."]
    },
    inventory: {
      impact: "Surface inventory is context for coverage planning, not a vulnerability. It can highlight routes and inputs that deserve manual authorization and validation review.",
      remediation: "Use the inventory to document intended public surfaces and remove routes, inputs, or dependencies that are no longer required.",
      steps: ["Confirm which surfaces are expected to be public.", "Prioritize sensitive and state-changing routes.", "Record coverage without placing secrets in notes."]
    },
    recon: {
      impact: "Technology and route clues can improve assessment coverage but require confirmation before they support a security conclusion.",
      remediation: "Reduce unnecessary public metadata and restrict administrative or diagnostic surfaces that do not need to be internet-accessible.",
      steps: ["Confirm the clue using a second source.", "Decide whether the exposed information is necessary.", "Review any discovered surface manually before escalating it."]
    },
    source: {
      impact: "Source comments and implementation hints may reveal internal context, but their security importance depends on the surrounding code and deployment.",
      remediation: "Remove stale internal comments and avoid shipping operational details that are not required by the client application.",
      steps: ["Inspect the original unredacted source context.", "Determine whether the clue reveals a reachable surface.", "Remove unnecessary production comments or metadata."]
    },
    general: {
      impact: "This signal needs manual context before its security importance can be determined.",
      remediation: "Confirm the behavior, document the affected trust boundary, and apply the narrowest fix that addresses the verified cause.",
      steps: ["Reproduce the signal consistently.", "Identify the affected component and trust boundary.", "Retest after the proposed change."]
    }
  };

  const exactGuidance = {
    "active.open-redirect": categoryGuidance.redirects,
    "dom.source-to-sink": categoryGuidance["dom-xss"],
    "form.insecure-action": categoryGuidance.transport,
    "transport.mixed-content": categoryGuidance.transport
  };

  const glossary = {
    canary: "A harmless, unique marker used to prove that data reached a specific location.",
    origin: "A scheme, hostname, and port considered together as one browser security boundary.",
    sink: "An API or operation that can interpret data as HTML, script, a URL, or executable code.",
    source: "A location where attacker-controlled or browser-controlled data may enter an application.",
    reflection: "Input returned in a response or document without necessarily being executed.",
    credential: "A secret that may authenticate a user, service, or API request.",
    cors: "Browser rules and response headers that decide which origins may read a response.",
    csp: "A browser policy that limits which scripts, styles, frames, and connections a page may use.",
    sri: "A cryptographic integrity value that lets a browser reject an unexpectedly changed external asset.",
    jwt: "A signed or unsigned compact token made of base64url-encoded metadata, claims, and a signature.",
    sourceMap: "Metadata that maps transformed JavaScript back to its original source files.",
    clickjacking: "Tricking a user into interacting with a framed page while seeing a misleading interface.",
    soft404: "A response that looks like a missing page but returns a normal or misleading HTTP status."
  };

  const categoryLearning = {
    secrets: {
      level: "conditional",
      plainLanguage: "The browser received a value shaped like a credential. It becomes exploitable only if the value is real, active, and useful outside its intended context.",
      observed: "A credential pattern was found in client-delivered source; Vulnscan did not test or use it.",
      prerequisites: ["The value is genuine rather than sample data.", "It is still active.", "Its provider or API accepts it from an attacker-controlled environment."],
      attackPath: ["An attacker reads the public client response.", "They extract the exposed value.", "They attempt to use it against the associated service."],
      possibleImpact: ["Unauthorized API use", "Data access within the credential scope", "Usage charges or service abuse"],
      weakens: ["The value is a documented public identifier.", "Provider-side restrictions prevent use from other origins, networks, or applications.", "The credential has already been revoked."],
      lab: null,
      terms: ["credential"]
    },
    "dom-xss": {
      level: "conditional",
      plainLanguage: "Browser-controlled input may reach an API that interprets markup or code. Exploitation requires the value to arrive without effective encoding or sanitization.",
      observed: "A source, sink, or possible path between them was visible in the loaded page source.",
      prerequisites: ["An attacker can influence the identified source.", "The application moves that value into the reported sink.", "No context-appropriate encoding or sanitizer neutralizes it."],
      attackPath: ["Place a harmless marker in the reported source.", "Follow the value through page scripts.", "Observe whether the sink treats it as text or markup."],
      possibleImpact: ["Actions in the victim's browser session", "Sensitive page data exposure", "Interface manipulation"],
      weakens: ["The value is converted to text before reaching the sink.", "A trusted sanitizer removes unsafe markup.", "The detected source and sink occur in unrelated code paths."],
      lab: {
        title: "Harmless DOM interpretation check",
        template: "GET {TEST_PATH}?q=%3Cvxscan-marker%3E HTTP/1.1\nHost: {TARGET_HOST}\n\nMarker: <vxscan-marker>\nDo not replace the marker with executable script.",
        safeResult: "The marker is encoded or appears only as text.",
        riskyResult: "The browser creates a vxscan-marker element, showing that markup interpretation is possible.",
        safety: "Use only a disposable lab account and a non-executable marker."
      },
      terms: ["source", "sink", "canary"]
    },
    headers: {
      level: "contextual",
      plainLanguage: "A browser defense is missing, invalid, or permissive. That usually increases the impact of another flaw rather than creating an exploit by itself.",
      observed: "The final page response did not provide the expected effective policy.",
      prerequisites: ["A separate injection, framing, content-type, or cross-origin weakness exists.", "The affected browser behavior is relevant to this page."],
      attackPath: ["Confirm the final response policy.", "Identify the separate weakness the policy should contain.", "Compare browser behavior with and without the defense."],
      possibleImpact: ["A separate vulnerability becomes easier to exploit", "Browser isolation or containment is weaker"],
      weakens: ["The control is delivered through another effective mechanism.", "The protected behavior is not used by this application.", "A stronger policy is applied on the sensitive response path."],
      lab: null,
      terms: ["csp", "origin"]
    },
    inventory: {
      level: "contextual",
      plainLanguage: "This is a map of exposed application surface, not a vulnerability. It helps decide where authorized testing should focus.",
      observed: "A route, input name, form, resource, or browser-storage name was visible on the selected page.",
      prerequisites: ["A mapped surface has unintended access, validation, or authorization behavior."],
      attackPath: ["Confirm the surface is intended to be public.", "Identify the trust boundary it crosses.", "Test its controls separately with authorization."],
      possibleImpact: ["Improved assessment coverage"],
      weakens: ["The surface is expected, documented, and protected."],
      lab: null,
      terms: ["origin"]
    },
    general: {
      level: "contextual",
      plainLanguage: "The observation needs more context before an exploitability claim can be made.",
      observed: "Vulnscan recorded a bounded signal from the selected page or response.",
      prerequisites: ["The behavior must be reproducible.", "An attacker-controlled input and meaningful security boundary must be identified."],
      attackPath: ["Reproduce the observation.", "Identify what an attacker controls.", "Determine what protected action or data could be affected."],
      possibleImpact: ["Depends on the verified behavior"],
      weakens: ["The observation is expected behavior.", "No attacker-controlled path reaches a protected boundary."],
      lab: null,
      terms: []
    }
  };

  categoryLearning.transport = {
    level: "conditional",
    plainLanguage: "Data or resources may cross an unencrypted transport boundary. Exploitation requires the browser to send or load the HTTP request and an attacker to control or observe the network path.",
    observed: "An HTTP destination was referenced from an HTTPS page.",
    prerequisites: ["The browser does not block or upgrade the request.", "An attacker can observe or alter the network path."],
    attackPath: ["Confirm the final request URL in developer tools.", "Determine whether the request is blocked, upgraded, or sent.", "Assess what data or executable content crosses the connection."],
    possibleImpact: ["Data exposure", "Content modification", "Session or interface compromise when executable resources are affected"],
    weakens: ["The browser upgrades the request to HTTPS.", "The request is blocked before use.", "No sensitive data or executable content crosses the connection."],
    lab: null,
    terms: ["origin"]
  };
  categoryLearning.redirects = Object.assign({}, categoryLearning.general, {
    level: "conditional",
    plainLanguage: "A redirect-related signal may let an attacker influence where a trusted link sends a user. A clue is not confirmation until the exact external destination is observed.",
    terms: ["origin", "canary"]
  });
  categoryLearning.forms = Object.assign({}, categoryLearning.general, {
    level: "conditional",
    plainLanguage: "The form crosses a trust or request-integrity boundary. Server-side behavior determines whether another site or network attacker can abuse it.",
    terms: ["origin"]
  });
  categoryLearning.cookies = Object.assign({}, categoryLearning.headers, {
    level: "conditional",
    plainLanguage: "A cookie may be more exposed to client-side or cross-site attacks. Exploitability depends on what the cookie controls and which separate weakness is present.",
    terms: ["credential", "origin"]
  });
  categoryLearning.authentication = Object.assign({}, categoryLearning.general, {
    level: "conditional",
    plainLanguage: "The observation affects a token, login, or session boundary. Its impact depends on whether the server trusts the identified behavior for authentication or authorization.",
    terms: ["credential", "jwt"]
  });
  categoryLearning["cross-origin"] = Object.assign({}, categoryLearning.headers, {
    plainLanguage: "A cross-origin browser policy is missing, invalid, or unusually permissive. Exploitability depends on whether an untrusted origin can cross a boundary the application meant to protect.",
    observed: "Vulnscan inspected policy metadata on the selected response; it did not use another user's session or data.",
    terms: ["origin", "cors"]
  });
  categoryLearning["supply-chain"] = Object.assign({}, categoryLearning.headers, {
    level: "conditional",
    plainLanguage: "The page trusts an external asset without a local integrity guarantee. Exploitation requires that asset or its delivery path to be changed unexpectedly.",
    terms: ["sri", "origin"]
  });
  ["components", "recon", "source", "disclosure"].forEach(function (category) {
    categoryLearning[category] = Object.assign({}, categoryLearning.inventory, {
      plainLanguage: "This observation can improve an attacker's understanding of the application, but it is not a vulnerability without a related exposed or unsafe behavior."
    });
  });

  const exactLearning = {
    "active.open-redirect": {
      level: "demonstrated",
      plainLanguage: "The target returned a redirect to the exact controlled destination supplied by the scanner. This can make a trusted link send a user to an attacker-controlled site.",
      observed: "A unique HTTPS destination was supplied and the matching redirect was captured for that exact probe request.",
      prerequisites: ["An attacker can place the vulnerable URL in a message or page.", "A victim trusts the target origin or an upstream flow includes sensitive data in the redirect."],
      attackPath: ["Construct a target URL containing a controlled destination.", "Send the trusted-looking target URL to a victim.", "The target redirects the victim to the controlled site."],
      possibleImpact: ["Phishing through a trusted hostname", "Token or authorization-code leakage in chained flows", "Bypass of redirect allowlists"],
      weakens: ["A warning interstitial clearly identifies the external destination.", "Only a strict allowlist of trusted origins is accepted.", "Sensitive parameters are removed before redirecting."],
      lab: {
        title: "Controlled redirect reproduction",
        template: "GET {TEST_PATH}?next=https%3A%2F%2Fcontrolled.example%2Flanding HTTP/1.1\nHost: {TARGET_HOST}\n\nExpected redirect evidence:\nHTTP/1.1 3xx\nLocation: https://controlled.example/landing",
        safeResult: "The external value is rejected, converted to a safe relative path, or requires an explicit user decision.",
        riskyResult: "The response redirects directly to the exact controlled.example destination.",
        safety: "Use a domain you control or the reserved .example domain; do not imitate a real login page."
      },
      terms: ["origin", "canary"]
    },
    "active.reflection": {
      level: "conditional",
      plainLanguage: "A harmless query marker appeared in the response. Reflection alone is not script execution; the output context and encoding decide whether it is dangerous.",
      observed: "The response body contained the exact scanner marker.",
      prerequisites: ["An attacker controls the reflected parameter.", "The marker reaches an HTML, attribute, URL, style, or script context.", "Context-appropriate encoding is absent."],
      attackPath: ["Repeat with a unique non-executable marker.", "Locate the marker in the raw response.", "Identify its parser context and encoding."],
      possibleImpact: ["Reflected client-side injection if unsafe interpretation is confirmed"],
      weakens: ["The marker appears in a JSON or text context with correct encoding.", "A trusted sanitizer prevents parser interpretation."],
      lab: {
        title: "Reflection context check",
        template: "GET {TEST_PATH}?q=vxscan-marker-123 HTTP/1.1\nHost: {TARGET_HOST}\n\nSearch the raw response for: vxscan-marker-123",
        safeResult: "The marker is absent or safely encoded for its output context.",
        riskyResult: "The marker appears unencoded inside an executable or markup-sensitive context.",
        safety: "Keep the marker alphanumeric while locating the reflection."
      },
      terms: ["reflection", "canary", "sink"]
    },
    "header.framing.missing": {
      level: "conditional",
      plainLanguage: "The page may be frameable. Clickjacking becomes possible only if a framed sensitive action can be visually disguised and completed by a victim.",
      observed: "Neither a valid X-Frame-Options value nor an enforced CSP frame-ancestors directive was captured.",
      prerequisites: ["The page can be embedded by an untrusted origin.", "A sensitive action is available in the frame.", "An attacker can align misleading controls over the framed interface."],
      attackPath: ["Embed the authorized test page in a controlled frame.", "Confirm the browser permits rendering.", "Assess whether a sensitive interaction could be misrepresented."],
      possibleImpact: ["Unintended clicks or account actions", "Consent or transaction manipulation"],
      weakens: ["The page has no sensitive interactive actions.", "JavaScript or platform controls reliably prevent untrusted framing.", "Protection is present on the actual sensitive route."],
      lab: {
        title: "Controlled framing check",
        template: "<!doctype html>\n<title>Framing check</title>\n<iframe src=\"{TARGET_URL}\" width=\"900\" height=\"650\"></iframe>",
        safeResult: "The browser refuses to render the target in the frame.",
        riskyResult: "The sensitive page renders and remains interactive inside the controlled frame.",
        safety: "Do not add overlays or attempt to trick another person into interacting with the page."
      },
      terms: ["clickjacking", "csp", "origin"]
    },
    "transport.mixed-content": {
      level: "conditional",
      plainLanguage: "Part of an HTTPS page references plain HTTP. If the browser loads it, a network attacker may read or alter that resource.",
      observed: "An HTTP resource URL was present on an HTTPS page.",
      prerequisites: ["The browser does not block or upgrade the request.", "An attacker can observe or modify the network path."],
      attackPath: ["Open the page in a controlled environment.", "Inspect the final resource request in developer tools.", "Confirm whether it was blocked, upgraded, or loaded over HTTP."],
      possibleImpact: ["Page content manipulation", "Sensitive data exposure", "Script injection when the resource is executable"],
      weakens: ["The browser upgrades the request to HTTPS.", "The request is blocked before content is used."],
      lab: null,
      terms: ["origin"]
    },
    "active.source-map": {
      level: "contextual",
      plainLanguage: "A declared production source map was reachable. Maps can expose original filenames and source, but their presence is not automatically a vulnerability.",
      observed: "A same-origin script declared a map and the response contained valid source-map metadata.",
      prerequisites: ["The map contains source or internal paths not otherwise public.", "That information materially helps another attack or reveals sensitive implementation details."],
      attackPath: ["Request only the declared map in an authorized lab.", "Review metadata without copying secrets into notes.", "Determine whether sourcesContent or internal paths should be public."],
      possibleImpact: ["Source disclosure", "Internal route or component discovery", "Faster analysis of client-side logic"],
      weakens: ["The same source is already public and intentionally distributed.", "The map contains no embedded sources or sensitive paths."],
      lab: {
        title: "Declared map validation",
        template: "GET {DECLARED_MAP_PATH} HTTP/1.1\nHost: {TARGET_HOST}\n\nValidate only these fields:\nversion, sources count, sourcesContent presence",
        safeResult: "The map is unavailable, access-controlled, or contains no sensitive source material.",
        riskyResult: "The map exposes original source or internal paths that were not intended for production users.",
        safety: "Do not paste source content or embedded credentials into reports."
      },
      terms: ["sourceMap"]
    },
    "secret.jwt.alg-none": {
      level: "conditional",
      plainLanguage: "The token declares that it has no signing algorithm. It is exploitable only if the server accepts unsigned tokens for a protected action.",
      observed: "The decoded JWT header declared alg=none; Vulnscan did not alter or submit the token.",
      prerequisites: ["The value is used as an authentication or authorization token.", "The server accepts alg=none rather than enforcing an expected algorithm and signature."],
      attackPath: ["Confirm the token's purpose offline.", "Inspect server or library configuration in an authorized lab.", "Verify that unsigned tokens are rejected without constructing a privileged token."],
      possibleImpact: ["Authentication or authorization bypass if unsigned tokens are accepted"],
      weakens: ["The value is sample data.", "The server pins an expected algorithm and verifies signatures.", "The token is never accepted by a protected endpoint."],
      lab: {
        title: "Offline JWT policy review",
        template: "Decoded header shape:\n{\"alg\":\"none\",\"typ\":\"JWT\"}\n\nRequired server policy:\n- Reject alg=none\n- Pin the expected algorithm\n- Verify issuer, audience, lifetime, and signature",
        safeResult: "Unsigned tokens are rejected before claims are trusted.",
        riskyResult: "The application accepts unsigned claims for a protected operation.",
        safety: "Do not generate privileged claims or submit modified tokens outside a disposable authorized lab."
      },
      terms: ["jwt"]
    }
  };

  function cloneLearning(value) {
    const item = value || categoryLearning.general;
    return {
      level: item.level,
      plainLanguage: item.plainLanguage,
      observed: item.observed,
      prerequisites: item.prerequisites.slice(),
      attackPath: item.attackPath.slice(),
      possibleImpact: item.possibleImpact.slice(),
      weakens: item.weakens.slice(),
      lab: item.lab ? Object.assign({}, item.lab) : null,
      terms: item.terms.map(function (term) { return { term: term, definition: glossary[term] || "" }; })
    };
  }

  function learningFor(finding) {
    const item = finding || {};
    if (exactLearning[item.checkId]) return cloneLearning(exactLearning[item.checkId]);
    if (String(item.checkId || "").startsWith("active.source-map")) return cloneLearning(exactLearning["active.source-map"]);
    if (String(item.checkId || "").startsWith("active.cors") || String(item.checkId || "").startsWith("header.cors")) {
      const cors = cloneLearning(categoryLearning.headers);
      cors.level = "conditional";
      cors.plainLanguage = "The response may allow an unexpected origin to read data. Exploitation depends on the exact allowed origin, credentials policy, endpoint sensitivity, and browser behavior.";
      cors.observed = "Vulnscan inspected returned CORS policy evidence without sending credentials.";
      cors.prerequisites = ["An attacker-controlled web origin is accepted.", "The response contains data the attacker should not read.", "The browser permits the relevant credential and origin combination."];
      cors.attackPath = ["Send a credential-free request with a controlled Origin in an authorized lab.", "Compare Access-Control-Allow-Origin with the supplied origin.", "Verify credential handling separately without using a real victim session."];
      cors.possibleImpact = ["Cross-origin reading of sensitive responses when all prerequisites hold"];
      cors.weakens = ["The endpoint is intentionally public.", "Only a fixed trusted origin is allowed.", "The browser rejects the returned header combination."];
      cors.lab = {
        title: "Controlled CORS policy check",
        template: "GET {TEST_PATH} HTTP/1.1\nHost: {TARGET_HOST}\nOrigin: https://controlled.example\n\nInspect:\nAccess-Control-Allow-Origin\nAccess-Control-Allow-Credentials\nVary: Origin",
        safeResult: "The origin is rejected or only an explicitly trusted origin is returned.",
        riskyResult: "An arbitrary controlled origin is echoed for a sensitive response under a browser-valid credential policy.",
        safety: "Use a disposable account and a controlled origin; never collect another user's response."
      };
      cors.terms = [{ term: "cors", definition: glossary.cors }, { term: "origin", definition: glossary.origin }];
      return cors;
    }
    return cloneLearning(categoryLearning[item.category] || categoryLearning.general);
  }

  function get(finding) {
    const item = finding || {};
    const guidance = exactGuidance[item.checkId] || categoryGuidance[item.category] || categoryGuidance.general;
    return {
      impact: guidance.impact,
      remediation: guidance.remediation,
      steps: guidance.steps.slice(),
      exploitability: learningFor(item)
    };
  }

  function priority(finding) {
    const item = finding || {};
    const severity = { high: 80, medium: 55, low: 30, info: 10 }[item.severity] || 10;
    const confidence = { high: 10, medium: 0, low: -10 }[item.confidence] || 0;
    const reviewAdjustment = item.bucket === "review" ? -15 : 0;
    const score = Math.max(0, Math.min(100, severity + confidence + reviewAdjustment));
    const label = score >= 80 ? "Immediate" : score >= 55 ? "Elevated" : score >= 30 ? "Standard" : "Context";
    return { score: score, label: label };
  }

  root.VulnscanGuidance = {
    get: get,
    priority: priority
  };
})(globalThis);
