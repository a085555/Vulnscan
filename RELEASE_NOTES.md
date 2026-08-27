# Vulnscan v6.4.1

Vulnscan v6.4.1 is a focused reporting and permission-lifecycle patch. Scan checks, request limits, finding classification, and saved-history compatibility are unchanged.

## Safer, cleaner exports

- Markdown reports encode every dynamic value at the export boundary, including page-derived evidence, locations, URLs, and comparison text.
- Raw HTML, headings, links, lists, tables, and code fences supplied by a scanned page remain inert report text.
- Assessment reports now start with a compact summary and coverage section, followed by numbered Findings and Review entries.
- JSON remains pretty-printed and keeps the original redacted evidence fields for integrations.
- Export filenames include the target host, export type, and readable UTC timestamp.
- Full-secret text exports include a handling warning, scan context, value count, and clearly separated values.

## Site-access lifecycle

- Exact-origin access is released when a scan completes, is cancelled, fails, or loses its selected target.
- When response headers need a manual refresh, capture is limited to one selected tab and origin rather than every tab at a granted origin.
- The pending header response is kept in browser session storage so a background-worker restart does not lose it.
- Temporary access expires after 10 minutes and is also revoked when the browser restarts, the tab closes, is replaced, or navigates to another origin.
- **Clear data and site access** removes local results, session data, and all optional site grants.
- The `alarms` permission is used only to enforce the 10-minute site-access expiry.

## Compatibility

- Chrome 102 or newer and Firefox 128 or newer remain supported from the same source.
- The scan schema remains version 8 and the JSON report format remains 6.4, so v6.2–v6.4 history and report consumers remain compatible.
- No active checks or package dependencies were added.
