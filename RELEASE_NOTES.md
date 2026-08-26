# Vulnscan v6.1.0

Vulnscan v6.1 improves result stability, scan transparency, and extension-side trust boundaries without broadening active behavior.

## Accuracy

- Stable finding identities are separate from mutable report fingerprints.
- Comparisons now classify evidence and detail changes at the same affected location as changed.
- Enforced CSP headers are evaluated together; report-only policies are shown separately.
- Header review recognizes disabled HSTS, invalid X-Frame-Options, weak or invalid referrer policies, CSP framing protection, and modern cookie constraints.
- Cross-origin stylesheet SRI is reviewed alongside script SRI.

## Evidence and reliability

- Results can include a sanitized affected location and safe DOM selector.
- The investigation drawer can highlight an affected element in the selected target tab.
- Source traversal, DOM inspection, findings, secret exports, captured headers, and incoming message fields have explicit limits.
- Scan health notices make partial coverage visible whenever a limit is reached.

## Extension hardening

- Passive results and secret-vault updates must match the current scan ID, tab, origin, and exact page URL.
- Captured cookie values are removed before header analysis.
- Chrome and Firefox manifests declare the extension-page content security policy explicitly.

## Safety and privacy

- Raw secret values remain available only through the separately confirmed full-secret export.
- Visible results, history, copied text, redacted reports, and request logs remain free of raw secret values.
- Active modes remain exact-origin, credential-free, budgeted, and limited to GET, HEAD, and OPTIONS requests.
