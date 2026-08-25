# Vulnscan

Chrome extension (Manifest V3) for passive and light-active webpage checks.

**Tool by a085** · v5.1.0

## Features

- Passive checks: sinks, secrets, forms, mixed content, stack hints
- Header + cookie flag analysis (`extraHeaders`)
- Inline-script source→sink flow heuristic for DOM XSS candidates
- Reflected input clues
- Open-redirect test with injected destination + `webRequest` correlation
- Soft-404 aware path probes
- Secrets hidden in UI; full values remain exportable from RAM only (never `chrome.storage`)
- Optional host permissions (asked when you scan a site)
- Dashboard with tab picker, history, export

## Install

1. Clone or download
2. `chrome://extensions` → Developer mode → Load unpacked
3. Select this folder
4. Click the extension icon

## Usage

1. Open a normal website tab
2. Open Vulnscan, pick the tab
3. Scan Selected Tab (Chrome may ask for site permission)
4. Review findings · export if needed

Shortcuts: `S` scan · `C` clear · `E` export

## Notes

- Authorized testing only
- Findings are investigation clues, not auto-confirmed exploits
- No Heroku-UUID false positive rule
- MIT licensed

Built by **a085**
