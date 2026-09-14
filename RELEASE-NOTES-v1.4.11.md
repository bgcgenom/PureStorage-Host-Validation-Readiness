# Pure Storage Host Validation / Readiness v1.4.11

Initial public release of the Pure Storage Host Validation / Readiness tool.

## Highlights

- Read-only Windows host validation for Pure Storage FlashArray environments
- Windows/network readiness checks
- Microsoft iSCSI Initiator and Windows MPIO validation
- PURE FlashArray MSDSM validation
- Pure target TCP/3260 connectivity with source NIC/source IP verification
- Hyper-V and Windows Failover Cluster validation scopes
- Extended NIC checks including RSS, driver, offload, RDMA observation, MTU, and Jumbo Packet state
- Cross-host drift detection
- Optional Pure ActiveCluster host-side topology validation
- Read-only runtime iSCSI and ALUA inspection
- Pure-aware MPIO policy validation
- Windows maximum MPIO path-count validation (32 paths per device)
- HTML audit reports with PASS / INFO / WARNING / FAIL severity
- Advisory remediation guidance with risk, verification, and rollback information
- Integrated HTML Help in the GUI
- Complete public documentation under `Docs/`

## Requirements

- Windows PowerShell 5.1
- Elevated administrator session
- WinRM / PowerShell remoting for remote-host audits
- Appropriate Windows administrative permissions
- Pure iSCSI target information for target-connectivity testing

## Safety scope

This release is read-only. It does not configure iSCSI sessions, change MPIO policy, modify NIC/MTU settings, initialize disks, provision Pure Storage objects, or create Failover Cluster storage.

Environment-specific expectations remain configurable rather than hardcoded.

## Documentation

Included:

- `Docs/USER-GUIDE.html`
- `Docs/OPERATIONS-GUIDE.md`
- `Docs/TROUBLESHOOTING.md`
- `Docs/SECURITY-SCOPE.md`
- `Docs/CHANGE-CHECKLIST.md`

## License

MIT License.

## Disclaimer

This is an independent community project. It is not an official Pure Storage product and is not affiliated with, maintained by, supported by, or endorsed by Pure Storage, Inc.
