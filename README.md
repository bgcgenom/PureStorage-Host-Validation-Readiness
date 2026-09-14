# Pure Storage Host Validation / Readiness

**Current release:** v1.4.11

Pure Storage Host Validation / Readiness is a Windows PowerShell 5.1/WPF audit tool for validating Windows hosts that use **Pure Storage FlashArray** storage. It is deliberately Pure Storage-specific while remaining configurable across supported Windows host environments.

> **Independent community project:** This repository is not an official Pure Storage product, is not affiliated with or endorsed by Pure Storage, Inc., and is provided without vendor support or warranty.

## What the tool does

The tool performs a read-only readiness and runtime audit of Windows hosts for Pure Storage connectivity. It can validate:

- Windows host and network configuration
- Dedicated iSCSI interfaces
- Microsoft iSCSI Initiator
- Windows Multipath I/O (MPIO)
- PURE FlashArray MSDSM registration
- Pure target TCP/3260 connectivity and source-interface selection
- Hyper-V host integration
- Windows Failover Cluster integration
- NIC driver/offload/RSS/Jumbo configuration
- Cross-host configuration drift
- Optional Pure ActiveCluster host-side topology
- Runtime iSCSI state
- Per-device MPIO policy
- Windows MPIO path-count limits
- Read-only ALUA path-state information when Windows exposes safely correlatable data

The tool exports a standalone HTML audit report and includes integrated HTML Help directly in the GUI.

## Pure Storage-specific scope

This is not a generic storage-vendor validator. Pure Storage requirements and recommendations define the storage-side validation logic.

The tool is still generic across host environments: site names, array names, target IPs, path expectations, topology, host-to-array locality, and other environment-specific values are entered or selected by the operator rather than hardcoded.

## Current release

`PureStorage-Host-Validation-Readiness-v1.4.11.ps1`

The GUI displays the current tool version and provides a **Help** button beside the version number.

## Validation and remediation model

The validator is **read-only**.

It follows this boundary:

**Detect → Report → Explain → Verify outside the validator → Re-run**

The HTML report can include advisory remediation commands, risk statements, verification steps, and rollback guidance. The validation tool does not execute those changes.

Configuration/remediation belongs in the companion Pure Storage iSCSI Host Tool or in an approved manual change workflow.

## Prerequisites

- Windows PowerShell 5.1
- Elevated administrator session
- Windows remoting/WinRM to remote hosts when auditing remotely
- Administrative credentials for the audited hosts, or current-user access with sufficient rights
- Pure iSCSI target IPs when Pure target-connectivity validation is selected
- Hyper-V / Failover Cluster roles only when the corresponding validation scopes are selected

## Quick start

1. Launch `PureStorage-Host-Validation-Readiness-v1.4.11.ps1` from an elevated Windows PowerShell 5.1 session.
2. Enter one target host per line.
3. Enter the Pure iSCSI target addresses that should be reachable from those hosts.
4. Confirm the iSCSI NIC naming pattern and expected storage MTU.
5. Select the audit scopes required for the environment.
6. If ActiveCluster is used, configure topology, array names, target-to-array assignments, host-local-array mappings, MPIO policy expectation, and minimum target paths.
7. Set credentials or select **Use Current User**.
8. Run **Read-Only Audit**.
9. Review FAIL and WARNING findings first.
10. Review the Host Drift Summary and MPIO Summary.
11. Export the HTML report.
12. Perform approved remediation separately, then re-run the audit.

See [Docs/USER-GUIDE.html](Docs/USER-GUIDE.html) for the full integrated guide.

## MPIO and path-policy logic

When **Pure Recommended (Auto)** is selected:

| Observed paths per Pure device | Validation |
| --- | --- |
| 1-10 | RR or LQD is valid; RR is identified as preferred |
| 11-32 | LQD is expected |
| More than 32 | FAIL: exceeds the Windows-supported MPIO path maximum |
| Runtime count unavailable | Host/default policy is evaluated provisionally; per-device validation becomes authoritative when storage is connected |

The validator separates:

- host/global MSDSM policy readiness; and
- actual per-Pure-device MPIO policy.

A path itself does not have a load-balancing policy. Policy applies to the MPIO device/LUN.

## Validation status meanings

| Status | Meaning |
| --- | --- |
| PASS | The observed state meets the validation rule |
| INFO | Informational/build-stage state, or the condition cannot yet be validated authoritatively |
| WARNING | The observed state differs from the expected/recommended configuration but is not a hard failure |
| FAIL | The observed state violates a required validation rule or supported limit |

The validator does not guess when Windows data cannot be safely correlated. Ambiguous runtime states are reported as INFO.

## Configuration and remediation behavior

The current release does **not** make host, network, MPIO, cluster, or FlashArray configuration changes.

Examples of report guidance:

- Microsoft network bindings on dedicated iSCSI NICs can be identified for later confirmed remediation.
- Persistent default routes can be identified and documented.
- MTU/Jumbo changes remain guided-only because the complete end-to-end network path must be validated first.
- ActiveCluster topology/pathing and ALUA corrections remain guided-only.
- MPIO policy changes belong in the configuration tool and require explicit approval.

## Logging and export behavior

The tool provides an on-screen result grid and can export a standalone HTML report containing:

- audit metadata and tool version
- overall status
- PASS / INFO / WARNING / FAIL totals
- Host Drift Summary
- MPIO Summary
- detailed findings grouped by severity and host
- remediation guidance where applicable

Generated reports, local state, logs, credentials, build output, and backups are intentionally excluded by `.gitignore`.

## Security model

- Read-only audit behavior
- No embedded credentials
- No silent remediation
- No automatic FlashArray configuration changes
- No disk initialization or formatting
- No LUN, volume, pod, host-group, or CSV creation
- Uses operator-supplied/current-user Windows credentials only for the active audit session
- Environment-specific topology data remains operator-configurable

See [Docs/SECURITY-SCOPE.md](Docs/SECURITY-SCOPE.md).

## Explicitly out of scope

The validator does not:

- create/delete Pure hosts
- create/modify Pure host groups
- create Pods or Protection Groups
- create volumes or assign LUNs
- connect volumes to hosts/host groups
- create iSCSI target portals or sessions
- initialize or format disks
- create Windows Failover Clusters
- create Cluster Shared Volumes
- change MPIO policy
- change MTU or Jumbo Packet settings
- modify FlashArray preferred-array settings
- hardcode a particular datacenter, host naming scheme, site mapping, path count, or ActiveCluster layout

## Repository structure

```text
PureStorage-Host-Validation-Readiness/
├── PureStorage-Host-Validation-Readiness-v1.4.11.ps1
├── README.md
├── LICENSE
├── .gitignore
└── Docs/
    ├── USER-GUIDE.html
    ├── OPERATIONS-GUIDE.md
    ├── TROUBLESHOOTING.md
    ├── SECURITY-SCOPE.md
    └── CHANGE-CHECKLIST.md
```

## Documentation

- [Full User Guide](Docs/USER-GUIDE.html)
- [Operations Guide](Docs/OPERATIONS-GUIDE.md)
- [Troubleshooting](Docs/TROUBLESHOOTING.md)
- [Security and Scope](Docs/SECURITY-SCOPE.md)
- [Change Checklist](Docs/CHANGE-CHECKLIST.md)

## License

Released under the [MIT License](LICENSE).

## Disclaimer

This is an independent community project. It is not an official Pure Storage product and is not affiliated with, maintained by, supported by, or endorsed by Pure Storage, Inc.

Use the tool in accordance with your organization's change-control, security, and support requirements. Validate all recommendations against the applicable Pure Storage and Microsoft documentation for the software and hardware versions in your environment.
