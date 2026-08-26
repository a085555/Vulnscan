# Vulnscan

Desktop browser security workspace for controlled passive and safe-active webpage checks.

**Tool by a085** · v6.1.0

## What is new in v6.1

- Stable result identities keep workflow states and comparisons attached when evidence wording changes
- Bounded source, DOM, finding, secret, header, and message processing with visible Scan health notices
- Combined enforced CSP analysis, separate report-only recognition, and stricter HSTS, framing, referrer, and cookie checks
- Affected locations in results and reports, with page highlighting where a safe DOM selector is available
- Subresource Integrity review now covers cross-origin stylesheets as well as scripts
- Passive results and raw-secret updates must match the active scan, tab, origin, and exact page URL

## Features

- Actionable Findings and lower-confidence Review clues kept separate
- Confidence, evidence, and manual verification guidance for every result
- Stable finding identity separated from mutable report evidence
- Passive checks for DOM flows, secret patterns, forms, mixed content, headers, cookies, component versions, and source clues
- Passive route, parameter, form, resource, storage-name, and authentication-surface inventory
- Passive, Safe Active, Lab, and staged Full Scan modes
- Selectable check families and accurate scanner-request estimates
- Exact-origin request controller with a configurable 5–50 request budget
- Same-origin reflection probes, scan-scoped redirect confirmation, and `robots.txt` metadata checks
- Soft-404-aware path discovery in Lab mode
- Safety stops for timeouts, rate limits, repeated refusals, server errors, oversized responses, and budget exhaustion
- Comparison with the previous scan using the same target and check profile
- New, changed, resolved, and unchanged result filters
- Session-only redacted request log
- Search and filters for category, confidence, severity, stage, change, and workflow state
- Secrets hidden throughout the workspace and redacted reports; distinct full values remain available through a separate confirmed export
- Visible coverage warnings whenever a scanner processing limit is reached

## Install a packaged build

### Chrome

1. Extract the Chrome ZIP.
2. Open `chrome://extensions`.
3. Enable Developer mode and choose **Load unpacked**.
4. Select the extracted folder.

### Firefox

The Firefox ZIP is prepared for signing and distribution. For a temporary local test:

1. Open `about:debugging#/runtime/this-firefox`.
2. Choose **Load Temporary Add-on**.
3. Select `manifest.json` from the extracted Firefox build.

Firefox removes a temporary add-on when the browser closes. A normal persistent install requires a signed package.

## Build from source

Node.js is the only build requirement; the project has no package dependencies.

```text
npm run verify
```

This validates the source, runs the test suite, and creates:

- `dist/chrome`
- `dist/firefox`

The root `manifest.json` remains the Chrome development manifest. Browser-specific manifests are maintained in `manifests/`.

## Usage

1. Open a normal website tab.
2. Open Vulnscan and select the tab.
3. Choose a mode, check families, and request budget.
4. Run the assessment. The browser may request access to that exact site.
5. Confirm authorization for Safe Active, Lab, or Full Scan.
6. Use **Investigate** to review evidence, priority, impact, remediation, and technical context.
7. Assign a local workflow state and export a redacted report when needed.

Shortcuts: `S` scan · `C` clear · `E` Markdown export

## Scan modes

- **Passive** analyzes the loaded DOM and captured response headers without scanner-generated network requests or page reloads.
- **Safe Active** adds controlled same-origin GET, HEAD, and OPTIONS requests for reflection, redirect, and `robots.txt` checks.
- **Lab** runs budgeted common-path discovery with soft-404 filtering. It is intended for controlled test environments and explicitly authorized targets.
- **Full Scan** runs Passive, Safe Active, and Lab in sequence under one shared request budget.

Active modes show the exact origin, methods, planned request count, and budget before starting. Requests omit credentials, do not follow redirects, and stop when a configured safety limit is reached.

## Investigation workflow

Each result has a report fingerprint and a stable identity. The fingerprint describes the current observation; the identity is based on the check and sanitized affected location so a wording or evidence change can be reported as changed. The investigation view combines recorded evidence with check-specific impact, remediation, and verification guidance. The priority score is an operational sorting aid, not a replacement for manual validation.

Workflow states are stored locally against the target and stable identity. They do not alter the original scanner result or its risk calculation.

## Scan comparison

Vulnscan keeps redacted findings for the 12 most recent scans. Target matching uses the origin, path, and query-parameter names rather than query values. A completed scan is compared with the newest earlier scan that has the same target fingerprint and check profile. Only stages completed in both scans are compared, so unavailable headers or a stopped active stage are not reported as resolved.

## Data handling

- Visible findings, evidence, history, copied text, Markdown, and JSON never include raw secret values.
- Raw values are kept in browser session storage, matched to the scan and target URL, and cleared on a new scan, Clear, extension reload/update, or browser exit.
- Full values remain available after a scan through the separate **Full secret values** export, which requires an extra confirmation.
- Request logs contain only the method, redacted URL, status, duration, and outcome for the current browser session.
- Captured Set-Cookie values are replaced before header analysis; only names and attributes are assessed.
- Workflow states contain only the target fingerprint, finding identity, state, and update time.
- Scan health records whether source, DOM, finding, or secret collection reached a configured limit.
- If response headers were not captured for the selected page load, refresh the target tab manually and scan again. Passive mode never reloads it.

## Browser support

- Chrome 102 or newer
- Firefox 128 or newer on desktop

## Notes

- Use only on targets you own or have explicit permission to test.
- Findings are investigation signals, not automatically confirmed exploits.
- MIT licensed.

Built by **a085**
