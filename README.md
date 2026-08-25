# Vulnscan

Chrome extension (Manifest V3) for passive and light-active webpage security checks.

**Tool by a085** · v5.0

---

## Features

- **Passive checks** — DOM sinks, secret patterns (redacted), CSRF clues, mixed content, tech fingerprinting
- **Header analysis** — CSP, HSTS, X-Frame-Options, and related headers
- **Cookie flags** — Secure, HttpOnly, SameSite via `webRequest` + `extraHeaders`
- **Light active probes** — reflected input clues, soft-404-aware path discovery
- **Dashboard UI** — full-page UI with tab picker, history, filters, export
- **Secrets** — hidden in the UI; full values only appear in export
- **Privacy** — no third-party favicon requests

---

## Install

1. Download or clone this repository
2. Open Chrome → `chrome://extensions`
3. Enable **Developer mode**
4. Click **Load unpacked** and select this folder
5. Click the extension icon to open the dashboard

---

## Usage

1. Open a normal website tab
2. Open Vulnscan
3. Select the tab from the dropdown
4. Click **Scan Selected Tab**
5. Review findings and headers
6. Export if needed

**Shortcuts:** `S` scan · `C` clear · `E` export

---

## Notes

- Use only on systems you own or have permission to test
- Findings are clues for investigation, not automatic proof of exploitability
- WAF-protected sites may return mostly 403s on path probes
- Risk level is derived from finding severities (not a fake 0–100 score)

---

## License

MIT

---

Built by **a085**
