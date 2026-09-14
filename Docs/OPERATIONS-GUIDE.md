# Operations Guide

## Product

Pure Storage Host Validation / Readiness v1.4.11

## Operating objective

Use the tool to determine whether one or more Windows hosts are correctly prepared for, and correctly operating with, Pure Storage FlashArray connectivity.

The validator is read-only. It does not perform storage provisioning or host remediation.

## Standard operating workflow

1. Start Windows PowerShell 5.1 as Administrator.
2. Launch `PureStorage-Host-Validation-Readiness-v1.4.11.ps1`.
3. Enter target hosts, one per line.
4. Enter all Pure iSCSI target addresses that are expected to be reachable.
5. Confirm the iSCSI NIC naming pattern.
6. Set the expected storage MTU.
7. Select the required validation scopes.
8. Configure ActiveCluster expectations only when ActiveCluster is actually part of the design.
9. Select credentials or current-user authentication.
10. Run the read-only audit.
11. Review results in this order:
    - FAIL
    - WARNING
    - Host Drift Summary
    - MPIO Summary
    - INFO
    - PASS
12. Export the HTML report.
13. Record approved remediation in the organization's change-management system.
14. Make changes outside this validator.
15. Re-run the audit and retain the post-change report.

## ActiveCluster configuration

ActiveCluster values are environmental inputs, not product constants.

Configure:

- Uniform or Non-Uniform topology
- Array A and Array B display names
- target-to-array assignments
- host local-array mappings
- MPIO expectation
- minimum target-path expectation

Do not encode site names, host names, preferred arrays, or path counts into the script for a particular deployment.

## MPIO operations

Use `Pure Recommended (Auto)` unless a deliberate documented override is required.

Runtime logic:

- 1-10 paths per Pure device: RR or LQD is valid; RR is preferred.
- 11-32 paths: LQD is expected.
- More than 32 paths: hard FAIL for the Windows MPIO supported path limit.
- If runtime correlation is unavailable, the validator reports INFO rather than guessing.

Per-device validation becomes authoritative after Pure volumes are visible to Windows.

## Pre-connection audits

The following can be normal before storage is presented:

- zero configured portals
- zero active sessions
- zero Pure disks
- zero cluster physical disks
- zero CSVs
- ALUA = INFO
- Max Paths / Device = Not available

A pre-connection audit is still useful for validating host preparation and target reachability.

## Post-connection audits

After storage is connected, verify:

- expected target portals and sessions
- correct source NIC/source IP selection
- no unexpected target addresses
- visible Pure disks
- per-device MPIO path count
- per-device MPIO policy
- ALUA path states
- ActiveCluster topology expectations
- cluster/CSV state where applicable

## Report retention

Store exported audit reports in the location approved by the organization. Reports can contain host names, IP addresses, driver versions, topology labels, and other environment-specific information. Generated reports are excluded from the public repository by `.gitignore`.

## Change control

The validation report is evidence, not authorization to make a production change. Any remediation should follow the local change-management process and should include:

- finding
- affected host/NIC/device
- intended change
- risk
- rollback
- verification
- maintenance window when required
