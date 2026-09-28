# Contributing

Thank you for your interest in contributing to Pure Storage Host Validation / Readiness.

This project is Pure Storage-specific while remaining configurable across supported Windows host environments.

## Project Scope

Contributions should preserve these design principles:

- Pure Storage-specific validation and best practices
- read-only operation
- no assumptions tied to one customer environment
- no hardcoded host names, array names, IP addresses, VLANs, site mappings, or path counts
- environment-specific topology and expectations must remain configurable
- no support for non-Pure storage vendors
- ambiguous runtime data should be reported as informational rather than guessed
- validation should distinguish host/global defaults from effective device runtime state

## Out of Scope

The validator must not:

- create or delete Pure hosts
- create or modify Pure host groups
- create Pods or Protection Groups
- create volumes or assign LUNs
- create iSCSI target portals or sessions
- initialize or format disks
- create Windows Failover Clusters
- create Cluster Shared Volumes
- change MPIO policy
- change MTU or Jumbo Packet settings
- change preferred-array settings
- automatically remediate detected findings

Configuration and remediation belong in the companion Pure Storage iSCSI Host Tool or an approved manual change workflow.

## Requirements

Development and testing should account for:

- Windows PowerShell 5.1
- Windows Presentation Foundation (WPF)
- PowerShell remoting / WinRM
- Microsoft iSCSI Initiator
- Microsoft Multipath-IO (MPIO)
- Hyper-V and Failover Clustering when those scopes are selected

## Coding Guidelines

### PowerShell

- keep compatibility with Windows PowerShell 5.1 unless a version change is explicitly approved
- avoid reserved or automatic variable names such as `$Host`
- use explicit error handling
- do not suppress errors unless failure is intentionally best-effort
- do not store credentials, API tokens, or secrets
- keep audit operations read-only

### WPF

- keep UI behavior consistent with existing controls
- preserve resizing and scrolling behavior
- keep status text clear and operationally meaningful
- preserve report and Help integration

## Validation Requirements

Before submitting a change:

1. Confirm the PowerShell script parses without errors.
2. Confirm embedded WPF/XAML loads successfully.
3. Confirm the audit remains read-only.
4. Test PASS, INFO, WARNING, and FAIL handling.
5. Verify ambiguous runtime states do not produce unsupported conclusions.
6. Confirm no configuration-changing commands were introduced.
7. Verify HTML report generation still succeeds.

Repository CI validates PowerShell parser correctness and embedded WPF/XAML validity.

## Pull Requests

Pull requests should include:

- a concise description of the change
- why the change is needed
- affected validation scopes
- validation/testing performed
- screenshots for UI changes when useful
- sample sanitized report output when relevant

## Security

Do not include credentials, production secrets, unredacted customer data, or confidential infrastructure exports.

Security issues should be reported according to `SECURITY.md`.

## License

By contributing, you agree that your contribution may be distributed under the MIT License used by this project.

This is an independent community project and is not an official Pure Storage product.
