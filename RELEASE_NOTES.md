# Vulnscan v6.2.0

Vulnscan v6.2 adds a clearer assessment map, deeper result guidance, and bounded web-boundary checks while keeping active behavior exact-origin, credential-free, and budgeted.

## Scan map

- Surface view links findings and review items to observed routes, parameter names, forms, resources, external origins, storage names, and authentication clues.
- Scan flow view shows the stages and checks that produced each result.
- Search, surface, result-bucket, and severity filters keep large maps readable.
- Current and historical v6.2 reports can be opened in the map; older compatible history falls back to Scan flow.
- Map collection and rendering have fixed node and relationship limits.

## Guided investigation

- Investigation details explain what was observed, which conditions are needed for exploitation, a likely attack path, possible impact, and evidence that would weaken the finding.
- Safe lab walkthroughs use non-executable markers, placeholders, and reserved example domains.
- Redacted Markdown and JSON reports include concise exploitability guidance and active-check coverage.

## Web boundaries

- Header review now covers CORS, Cross-Origin-Opener-Policy, Cross-Origin-Embedder-Policy, and Cross-Origin-Resource-Policy.
- Missing optional cross-origin policies are shown neutrally; contradictory wildcard-with-credentials CORS is not reported as a browser bypass.
- Safe Active can send one credential-free CORS probe and reports only exact extension-origin acceptance observed by the browser.
- Safe Active can confirm declared same-origin source maps for up to three scripts with strict request and response limits.
- Passive JWT review decodes bounded header and expiry metadata without showing claims or raw token values.

## Safety and compatibility

- Raw response bodies, source-map contents, query values, storage values, and JWT claims are not stored in findings or history.
- New coverage records distinguish complete, limited, unavailable, and stopped checks.
- Chrome and Firefox builds use the same shared scanner source and require no new broad permissions or package dependencies.
