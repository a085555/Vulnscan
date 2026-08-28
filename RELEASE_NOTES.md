# Vulnscan v6.5.0

Vulnscan v6.5.0 adds Journey Capture: a passive workspace for following one authorized browser tab through a same-origin testing session.

## Journey Capture

- Records the initial page, completed navigations, and debounced single-page application route changes for up to 30 minutes.
- Groups revisits under redacted route templates while keeping visit counts and first- and last-seen times.
- Reuses the existing passive page and response-header checks on each captured route.
- Observes same-origin fetch and XHR metadata without collecting bodies, form values, cookies, authorization data, or API header values.
- Continues while the dashboard is closed and restores the live draft after a background-worker restart.
- Saves a partial journey when the selected tab closes, is replaced, leaves the origin, or reaches the time limit.
- Retains up to six redacted completed journeys with rename and delete controls.

## Live Capture Console

- Adds a resizable DevTools-style console with ordered session, navigation, page, API, finding, coverage, and error events.
- Supports category filters, text search, wrapping, collapse, full-height view, paused rendering, and follow-at-bottom behavior.
- Assigns event sequence numbers in the background process so overlapping request completions cannot reorder the timeline.
- Stops retaining event rows at 1,000 and reports the coverage limit while continuing aggregate page, API, and finding collection.
- Links console events to the Journey Flow and Surface maps; selecting a map node can filter the console back to related evidence.

## Privacy and exports

- Removes credentials and fragments from captured URLs, redacts query values, and templates numeric, UUID, and opaque path segments before storage.
- Stores live drafts, in-flight request metadata, capture state, and raw secrets in browser session storage only.
- Saves only finalized redacted journeys to local history and releases exact-origin access on every terminal condition.
- Adds redacted journey Markdown, JSON, and capture-log exports. Journey JSON uses `reportVersion: "6.5"`, `reportType: "journey"`, and `journeySchemaVersion: 1`.
- Standard scan reports advance to report version 6.5 while keeping scan schema version 8 and v6.4.1 history compatibility.
- Full secret values remain available only for the latest matching journey in the current browser session and still require confirmation.

## Limits and compatibility

- One selected top-level tab and one exact scheme, host, and port per journey.
- Limits: 25 route templates, 200 API endpoints, 250 grouped findings, 600 surface nodes, 1,000 console events, and the existing 100-value secret vault.
- Chrome 102 or newer and Firefox 128 or newer remain supported from the same source with no package dependencies.
- Journey Capture is passive and does not crawl, schedule scans, run active checks, or generate network requests.
