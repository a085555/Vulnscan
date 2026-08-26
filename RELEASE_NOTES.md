# Vulnscan v6.3.0

Vulnscan v6.3 makes the scan map more stable, readable, and useful during an investigation. Scanner behavior, request limits, permissions, and secret handling remain unchanged.

## Stable interaction

- Map nodes keep the same geometry on hover and focus, preventing scaled SVG boxes from shifting or flickering.
- Panning no longer begins on a node, and canvas dragging starts only after a deliberate pointer movement.
- Edge and node strokes remain visually consistent at every zoom level.
- Zoom follows the pointer position and supports the additional range needed to inspect dense graphs.

## Evidence-path focus

- Selecting a node keeps it highlighted and emphasizes its route back to the target.
- Directly related child nodes remain visible so connected findings and surfaces can be followed without losing context.
- Focus path can be disabled when the complete graph needs to stay equally visible.
- The details panel shows a breadcrumb for the selected evidence route and can centre the node at a readable scale.

## Navigation and clarity

- Finding cards and the investigation drawer can open the corresponding map node directly.
- Confidence filtering joins the existing surface, result-type, severity, and text filters.
- Scan-flow checks display their recorded coverage state.
- Nodes are ordered with their parent branches to reduce unnecessary edge crossings.
- Double-click centring and arrow-key navigation provide faster movement around large maps.

## Compatibility

- Existing compatible scan history remains usable; the scan schema is unchanged.
- Chrome and Firefox packages continue to use the same scanner implementation.
- No permissions, active checks, or package dependencies were added.
