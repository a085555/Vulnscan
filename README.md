# Vulnscan

Desktop browser security workspace for controlled passive and safe-active webpage checks.

**Tool by a085** · v6.5.0

## What is new in v6.5.0

- Passive Journey Capture for one authorized tab and exact origin
- Ordered Live Capture Console for navigation, page, same-origin API, finding, coverage, and lifecycle events
- Journey Flow and Surface maps with console-to-map and map-to-console focus
- Redacted Journey Markdown, JSON, and capture-log exports
- Background recovery, automatic partial saves, six-entry journey history, and strict 30-minute collection limits

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
- Passive journey recording with redacted route templates and same-origin fetch/XHR metadata
- Resizable Live Capture Console with filtering, search, paused rendering, and follow-at-bottom behavior
- Search and filters for category, confidence, severity, stage, change, and workflow state
- Searchable interactive scan maps with evidence-path focus for current and historical scans
- Comparison maps, collapsible branches, and a large-map overview navigator
- Local investigation queue and verification checklist states
- Plain-language exploitability guidance with non-executable lab templates where a safe reproduction is useful
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
6. Use **Investigate** to review evidence, exploitability conditions, remediation, and technical context, or open the scan map to explore relationships.
7. Assign a local workflow state and export a redacted report when needed.

### Journey Capture

1. Select a normal website tab and open **Journey**.
2. Choose **Start journey** and approve access to the exact displayed origin.
3. Browse that site normally. Vulnscan passively assesses completed pages and records redacted same-origin request metadata.
4. Use the Live Capture Console and Journey map to move between the timeline, pages, API endpoints, and grouped findings.
5. Choose **Finish and save** to keep the redacted journey, or **Discard** to remove the draft. Site access is released either way.

Journey Capture does not crawl, submit forms, run active checks, or create scanner traffic. Cross-origin API traffic remains outside the authorized capture scope.

Shortcuts: `S` scan · `C` clear · `E` Markdown export

## Scan modes

- **Passive** analyzes the loaded DOM and captured response headers without scanner-generated network requests or page reloads.
- **Safe Active** adds controlled same-origin GET, HEAD, and OPTIONS requests for reflection, redirects, `robots.txt`, CORS policy evidence, and declared source maps.
- **Lab** runs budgeted common-path discovery with soft-404 filtering. It is intended for controlled test environments and explicitly authorized targets.
- **Full Scan** runs Passive, Safe Active, and Lab in sequence under one shared request budget.

Active modes show the exact origin, methods, planned request count, and budget before starting. Requests omit credentials, do not follow redirects, and stop when a configured safety limit is reached.

## Investigation workflow

Each result has a report fingerprint and a stable identity. The fingerprint describes the current observation; the identity is based on the check and sanitized affected location so a wording or evidence change can be reported as changed. The investigation view combines recorded evidence with check-specific impact, remediation, exploitability conditions, weakening evidence, and verification guidance. Optional lab templates use harmless markers and reserved example hosts. The priority score is an operational sorting aid, not a replacement for manual validation.

Workflow states, verification progress, queue membership, and notes are stored locally against the target and stable identity. They do not alter the original scanner result or its risk calculation. Notes are intentionally omitted from exported reports.

## Scan map

The Surface view links results to bounded observations such as routes, parameter names, forms, resources, external origins, storage names, and authentication clues. The Scan flow view shows which selected stage and check produced each result, including limited or unavailable active-check coverage. When a compatible baseline exists, the Changes view groups new, changed, resolved, and unchanged findings and surface nodes. Branches can be collapsed, and larger graphs display an overview navigator. Selecting a node highlights its evidence route, while double-clicking centres it at a readable scale. Arrow keys move between neighbouring nodes. Journey maps add page and API nodes with visited-next, requested, and observed-on relationships. Compatible v6.2–v6.5 history keeps its redacted map data; earlier history can still use Scan flow view.

## Scan comparison

Vulnscan keeps redacted findings for the 12 most recent scans. Target matching uses the origin, path, and query-parameter names rather than query values. A completed scan is compared with the newest earlier scan that has the same target fingerprint and check profile. Only stages completed in both scans are compared, so unavailable headers or a stopped active stage are not reported as resolved.

## Data handling

- Visible findings, evidence, history, copied text, Markdown, and JSON never include raw secret values.
- Page-controlled text is encoded at the Markdown export boundary while JSON retains the original redacted evidence fields.
- Raw values are kept in browser session storage, matched to the scan and target URL, and cleared on a new scan, Clear, extension reload/update, or browser exit.
- Full values remain available after a scan through the separate **Full secret values** export, which requires an extra confirmation.
- Request logs contain only the method, redacted URL, status, duration, and outcome for the current browser session.
- Live journey drafts, event queues, in-flight request metadata, and raw journey secrets stay in browser session storage. Only finalized redacted journeys are saved locally.
- Journey URLs lose credentials and fragments before storage. Query names remain visible while values are redacted; numeric, UUID, and opaque path segments are replaced with templates.
- Journey Capture never stores request or response bodies, form values, API header values, authorization data, or cookie values.
- Exact-origin site access is released when a journey finishes, is discarded, times out, loses its tab, or leaves its authorized origin.
- Captured Set-Cookie values are replaced before header analysis; only names and attributes are assessed.
- Workflow records contain the target fingerprint, finding identity, state, verification progress, queue membership, a bounded local note, and update time. Notes are not exported.
- Scan health records whether source, DOM, finding, or secret collection reached a configured limit.
- Exact-origin site access is released after a completed scan. If response headers were not captured, access is retained only for the selected tab's next same-origin refresh, expires after 10 minutes, and is revoked when the browser restarts.
- Refresh the target tab manually and scan again to use captured headers. Passive mode never reloads it. **Clear data and site access** revokes pending grants immediately.

## Browser support

- Chrome 102 or newer
- Firefox 128 or newer on desktop

## Notes

- Use only on targets you own or have explicit permission to test.
- Findings are investigation signals, not automatically confirmed exploits.
- MIT licensed.

Built by **a085**
