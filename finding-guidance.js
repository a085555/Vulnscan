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

  function get(finding) {
    const item = finding || {};
    const guidance = exactGuidance[item.checkId] || categoryGuidance[item.category] || categoryGuidance.general;
    return {
      impact: guidance.impact,
      remediation: guidance.remediation,
      steps: guidance.steps.slice()
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
