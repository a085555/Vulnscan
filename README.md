# Vulnscan

Chrome extension (Manifest V3) for passive and light-active webpage checks.

**Tool by a085** · v5.2.0

## Features

- Findings and lower-confidence Review clues kept separate
- Confidence, evidence, and manual verification guidance for every result
- Passive checks: DOM flows, secrets, forms, mixed content, and source hints
- Header and cookie flag analysis (`extraHeaders`)
- Inline-script source→sink heuristic for DOM XSS candidates
- Reflected-input clues and scan-scoped open-redirect confirmation
- Soft-404 aware path probes
- Secrets hidden in the UI; distinct full values remain exportable from memory-only session storage
- Optional host permissions (asked when you scan a site)
- Dashboard with tab picker, summary history, Markdown export, and JSON export

## Install

1. Clone or download
2. `chrome://extensions` → Developer mode → Load unpacked
3. Select this folder
4. Click the extension icon

## Usage

1. Open a normal website tab
2. Open Vulnscan, pick the tab
3. Scan Selected Tab (Chrome may ask for site permission)
4. Review Findings and Review clues, then export if needed

Shortcuts: `S` scan · `C` clear · `E` Markdown export

Right-click **Export** for JSON.

## Notes

- Authorized testing only
- Findings are investigation clues, not auto-confirmed exploits
- Requires Chrome 102 or newer
- No Heroku-UUID false positive rule
- MIT licensed

Built by **a085**

