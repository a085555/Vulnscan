# Vulnscan v6.0.0

Vulnscan v6 turns the dashboard into a focused security investigation workspace while preserving the existing passive and safe-active boundaries.

## Highlights

- Redesigned assessment workspace with a professional dark interface and clearer information hierarchy
- Detailed investigation drawer for every Finding and Review item
- Check-specific impact, remediation, and investigation guidance
- Operational priority indicator based on severity, confidence, and result class
- Local Open, Investigating, Accepted risk, False positive, and Resolved workflow states
- Investigation context included in redacted Markdown and JSON reports
- Workflow-state filtering alongside the existing search, severity, category, confidence, stage, and comparison filters
- Desktop Chrome and Firefox builds generated from the same maintained source

## Compatibility

- Chrome 102 or newer
- Firefox 128 or newer on desktop

## Safety and privacy

- Raw secret values remain excluded from visible results, history, copied finding briefs, and redacted exports.
- The separate full-secret export remains available after an explicit confirmation.
- Active modes remain exact-origin, budgeted, credential-free, and limited to GET, HEAD, and OPTIONS requests.
- Firefox support does not broaden requested site access or active-scan behavior.
