# Vulnscan v6.4.0

Vulnscan v6.4 adds scan-change intelligence and a more complete local investigation workflow. Scanner permissions, request behavior, safety limits, and secret handling are unchanged.

## Change map

- Compatible scans can be viewed as new, changed, resolved, and unchanged branches.
- Finding comparison uses stable identities and reports which evidence fields changed.
- Observed surface nodes are compared when Passive completed in both scans.
- The map respects comparable scan stages so incomplete coverage is not presented as a reliable resolution.
- Change filters can isolate regressions, retest changes, or resolved results.

## Large-map navigation

- Surface groups, scan stages, and change groups can be collapsed and expanded from the details panel.
- Reachability-aware collapsing keeps nodes visible when another open branch still connects to them.
- Larger maps show a clickable overview navigator with the current viewport and selected node.
- Existing evidence-path focus, keyboard navigation, stable hover behavior, and readable node centring remain available.

## Investigation workflow

- Findings can be pinned to a visible investigation queue.
- Every investigation step has a local Pending, Complete, Failed, or Inconclusive state.
- Bounded local notes can be stored against the target and stable finding identity.
- Queue membership and verification progress are included in redacted JSON reports; notes remain local and are never exported.

## Reporting

- Comparison results can be exported as sanitized Markdown with current and previous timestamps, comparable stages, finding changes, and surface-change counts.
- The visible map can be exported as a standalone sanitized SVG containing labels and relationships but no finding evidence or raw secret values.
- The scan schema remains version 8, so compatible v6.2 and v6.3 history remains usable.

## Compatibility

- Chrome and Firefox packages continue to share the same scanner implementation.
- No permissions, active checks, or package dependencies were added.
