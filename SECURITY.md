# Security Policy

## Supported Versions

Security fixes are provided for the current release of Pure Storage Host Validation / Readiness.

| Version | Supported |
| ------- | --------- |
| 1.5.x   | Yes |
| 1.4.x   | No |
| < 1.4   | No |

Older releases remain available for reference but are not actively maintained for security fixes.

## Reporting a Vulnerability

Do not open a public GitHub issue for a suspected security vulnerability.

Use GitHub private vulnerability reporting for this repository when available.

Include:

- affected tool version
- Windows Server version
- PowerShell version
- affected audit scope
- steps required to reproduce the issue
- expected behavior
- observed behavior
- whether credentials, host information, network information, storage topology, or reports could be exposed
- sanitized logs or screenshots when useful

Do not include:

- passwords
- API tokens
- private keys
- authentication cookies
- unredacted production infrastructure data
- customer-confidential information

## Security Scope

Security-sensitive areas include:

- runtime Windows credential handling
- WinRM-based remote audit access
- host and network inventory collection
- Pure Storage target information
- MPIO and iSCSI runtime data
- Failover Cluster and Hyper-V inventory
- exported HTML reports
- local logs and generated files

The validator is read-only by design.

It must not:

- change Windows host configuration
- change network configuration
- change MPIO policy
- create or modify iSCSI sessions
- create or modify FlashArray objects
- initialize or format disks
- create or modify Windows Failover Cluster configuration

## Safe Design Principles

Changes should preserve these safeguards:

- read-only audit behavior
- no embedded credentials
- no persistent credential storage
- no silent remediation
- no FlashArray configuration changes
- no disk or filesystem changes
- environment-specific expectations remain configurable
- ambiguous runtime state is reported rather than guessed

## Response

Confirmed security issues should be reproduced, corrected, validated, and documented in the applicable release notes.

This is an independent community project and is not an official Pure Storage product.
