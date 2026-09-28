# Pure Storage Host Validation / Readiness v1.5.2

## Highlights

- Corrects iSCSI reboot-persistence validation.
- Uses Microsoft persistent target registrations as the authoritative host-side persistence evidence.
- Correlates persistent registrations to the configured/active Pure target addresses.
- Stops treating `Get-IscsiSession.IsPersistent=False` by itself as a persistence failure.
- Reports live-session `IsPersistent=False` as INFO when complete persistent target registrations exist.
- Preserves all existing v1.5.1 MPIO, ALUA, ActiveCluster, path-count, drift, network, Hyper-V, and Failover Cluster validation behavior.
- Remains fully read-only.

## Why this changed

Live validation after controlled host reboots showed that Windows can report `Get-IscsiSession.IsPersistent=False` for active Pure iSCSI sessions even when Microsoft persistent target registrations exist and the required storage sessions return after restart.

v1.5.2 therefore separates:

1. **Persistent target registration** — the startup reconnect configuration.
2. **Live session IsPersistent state** — supporting runtime metadata.

## Validation behavior

### PASS
Every required Pure target address has a Microsoft iSCSI persistent-login registration.

### WARNING
One or more required Pure target addresses are missing a persistent-login registration.

### INFO
- Persistent target enumeration is unavailable; or
- live session objects report `IsPersistent=False` while all required persistent target registrations are present.

## Safety

The validator does not:

- register or unregister iSCSI sessions
- add or remove target portals
- disconnect or reconnect storage paths
- change MPIO policy
- modify ALUA state
- initialize or format disks
- create cluster disks or CSVs
- change Pure Storage objects

## Compatibility

No audit-input changes are required. Existing v1.5.1 profiles and settings can be reused unchanged.
