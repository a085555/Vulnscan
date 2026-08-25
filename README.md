# Vulnscan

Chrome extension (Manifest V3) for controlled passive and safe-active webpage checks.

**Tool by a085** · v5.3.0

## Features

- Findings and lower-confidence Review clues kept separate
- Confidence, evidence, and manual verification guidance for every result
- Passive checks: DOM flows, secrets, forms, mixed content, and source hints
- Header and cookie flag analysis (`extraHeaders`)
- Inline-script source→sink heuristic for DOM XSS candidates
- Passive, Safe Active, and Lab scan modes
- Exact-origin request controller with a configurable 5–50 request budget
- Reflected-input clues and scan-scoped open-redirect confirmation in active modes
- Soft-404-aware path discovery in Lab mode
- Automatic stops on timeouts, rate limiting, repeated refusals, repeated server errors, and oversized responses
- Session-only redacted request log
- Secrets hidden in the UI; distinct full values remain exportable from memory-only session storage
- Optional host permissions (asked when you scan a site)
- Separate redacted Markdown, redacted JSON, and confirmed full-secret exports
- Dashboard with tab picker, summary history, installed version, update link, and local-data controls

## Install

1. Clone or download
2. `chrome://extensions` → Developer mode → Load unpacked
3. Select this folder
4. Click the extension icon

## Usage

1. Open a normal website tab
2. Open Vulnscan, pick the tab
3. Choose a mode and request budget
4. Scan Selected Tab (Chrome may ask for site permission)
5. Confirm authorization when using Safe Active or Lab
6. Review Findings and Review clues, then export if needed

Shortcuts: `S` scan · `C` clear · `E` Markdown export

## Scan modes

- **Passive** is the default. It analyzes the loaded DOM and captured response headers without sending scanner-generated network requests or reloading the target.
- **Safe Active** adds same-origin GET, HEAD, and OPTIONS checks for reflection, redirects, and `robots.txt` metadata.
- **Lab** adds budgeted common-path discovery with soft-404 filtering. It is intended for controlled test environments and explicitly authorized targets.

Active scans show their exact origin, methods, planned request count, and budget before starting. Requests omit credentials, do not follow redirects, and stop when the budget or a safety threshold is reached.

## Data handling

- Visible findings, history, copied text, Markdown, and JSON never include raw secret values.
- Raw values are kept in `chrome.storage.session`, matched to the scan and target URL, and cleared on a new scan, Clear, extension reload/update, or browser exit.
- Full values remain available after a scan through the separate **Full secret values** export, which requires an extra confirmation.
- Request logs contain only method, redacted URL, status, duration, and outcome. They are kept for the current browser session.
- If response headers were not captured for the selected page load, refresh the target tab manually and scan again. Passive mode never reloads it for you.

## Notes

- Authorized testing only
- Findings are investigation clues, not auto-confirmed exploits
- Requires Chrome 102 or newer
- No Heroku-UUID false positive rule
- MIT licensed

Built by **a085**
