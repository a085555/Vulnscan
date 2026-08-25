# VulnScan Ultimate

Browser extension (Chrome MV3) for passive + light-active page checks.

Built by a085.

## Install

1. Open `chrome://extensions`
2. Enable Developer mode
3. Load unpacked → select this folder
4. Click the extension icon to open the dashboard

## What it does

- DOM sink / secret pattern checks
- Security headers + cookie flags
- Light reflection / open-redirect / CORS probes
- Common path probes
- Export report (markdown / json)

Only use on targets you own or have permission to test.

## Files

- `manifest.json` – extension config
- `background.js` – service worker, tab helpers, header cache
- `content.js` – injected page checks
- `dashboard.html` / `dashboard.css` / `dashboard.js` – main UI
