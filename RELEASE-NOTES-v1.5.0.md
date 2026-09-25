# Pure Storage Host Validation / Readiness v1.5.0

## Highlights

- Adds a dedicated **Pure Device MPIO / ALUA Summary** to the HTML report.
- Reports the actual Windows/MSDSM load-balance policy name for each safely identified Pure MPIO device.
- Reports actual per-device path count and ALUA state counts:
  - Active/Optimized
  - Active/Unoptimized
  - Standby
  - Unavailable
  - Not Used
  - Failed
- Preserves the Windows maximum of 32 MPIO paths per device as a hard validation limit.
- Keeps pre-presentation/no-Pure-disk states informational rather than failures.
- Explicitly reports **Round Robin with Subset (RRWS)** when Windows exposes it.
- Separates device path-health status from per-device MPIO policy assessment so a healthy path set does not imply that RRWS itself has been policy-approved.
- Does not silently equate the host/global RR default with the existing per-device policy.
- Does not automatically remediate or classify RRWS against the RR/LQD baseline until the applicable Pure Storage Windows + ALUA/ActiveCluster guidance is confirmed for the topology.
- Uses DSM_QueryLBPolicy_V2 policy evidence when Get-MSDSMLoadBalancePolicy does not expose per-disk policy, avoiding a contradictory "policy unavailable" message.
- Keeps detailed per-path ALUA evidence in the existing read-only findings.
- Remains fully read-only and environment-agnostic.

## Reporting changes

The HTML report now contains:

1. Host Drift Summary
2. MPIO Summary
3. Pure Device MPIO / ALUA Summary
4. Detailed Results
5. Remediation Items

The new device summary is built from Windows/MSDSM runtime evidence. It does not infer device state when Pure disks are not visible or when runtime MPIO/ALUA data cannot be safely correlated.

## Safety

No configuration behavior was added. The validator still does not:

- change MPIO policy
- add or remove iSCSI portals/sessions
- modify ALUA state
- initialize or format disks
- create cluster disks or CSVs
- change Pure Storage objects or preferred-array settings

## Notes

Microsoft documents `DSM_QueryLBPolicy_V2` as the WMI interface for querying the load-balance policy applied to an MPIO disk, including path-state data exposed through `MPIO_DSM_Path_V2`.

This release reports that evidence directly and avoids treating a host/global default policy as authoritative for an already-present Pure device.
