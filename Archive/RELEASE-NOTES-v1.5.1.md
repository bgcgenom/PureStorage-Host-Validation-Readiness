# Pure Storage Host Validation / Readiness v1.5.1

## Highlights

- Reorganizes the **Pure Device MPIO / ALUA Summary** for easier multi-host review.
- Adds collapsible **Host -> Device** grouping.
- Keeps each device's path-health and policy-assessment findings together.
- Shows a host-level summary badge and a device-level summary badge using the most significant finding for that scope.
- Preserves all existing v1.5.0 MPIO, ALUA, RRWS, ActiveCluster, and read-only validation behavior.
- No configuration or remediation behavior was added.

## Report organization

The Pure Device MPIO / ALUA Summary now renders as:

1. Host
2. Pure MPIO device
3. Device findings
   - Path health
   - Policy assessment

This is intentionally organized by **device rather than severity** because path health and policy assessment describe the same MPIO device and should remain adjacent even when their statuses differ (for example, PASS path health with INFO RRWS policy assessment).

## Safety

v1.5.1 remains fully read-only. It does not:

- change MPIO policy
- add or remove iSCSI portals or sessions
- modify ALUA state
- initialize or format disks
- create cluster disks or CSVs
- change Pure Storage objects or preferred-array settings

## Compatibility

No audit-input changes are required. Existing v1.5.0 environment profiles and validation settings can be used unchanged.
