# Security and Scope

## Security model

Pure Storage Host Validation / Readiness is designed as a read-only audit utility.

The tool does not intentionally modify Windows host, storage, cluster, or FlashArray configuration.

## Credentials

- Credentials are supplied by the operator at runtime or the current Windows user context is used.
- Credentials must not be committed to the repository.
- Credential exports, secrets, keys, certificates, tokens, and local environment files are excluded by `.gitignore`.
- Do not modify the public source to embed passwords, API tokens, service-account secrets, or environment-specific credentials.

## Remote access

Remote host validation can require WinRM/PowerShell remoting and administrative privileges. Grant only the access needed under the organization's administrative model.

## Data in reports

Audit reports can contain environment-specific information such as:

- host names
- IP addresses and subnets
- array display names
- cluster names
- driver/OS versions
- NIC names
- MPIO/session/path state
- topology mappings

Treat generated reports according to the organization's information-classification rules. Reports are intentionally excluded from source control.

## Safety boundaries

The validator does not:

- execute remediation commands
- create iSCSI sessions
- modify MPIO policy
- change NIC bindings
- change routes
- change MTU/Jumbo settings
- initialize or format disks
- create or map Pure volumes
- create/delete Pure hosts or host groups
- create Pods or Protection Groups
- change preferred-array configuration
- create Failover Clusters or CSVs

Where the report provides a remediation command, it is advisory only.

## Environmental portability

The application is Pure Storage-specific but must not be deployment-specific.

The following are operator-configurable and must not be hardcoded for a single environment:

- target hosts
- Pure array labels
- target IP addresses
- storage subnets
- iSCSI NIC naming pattern
- MTU expectation
- ActiveCluster topology
- target-to-array mapping
- host local/preferred-array mapping
- minimum target-path expectation
- MPIO expectation

## Unsupported assumptions

Do not infer:

- array identity from arbitrary list order
- device identity from index position
- site identity from a host-name suffix
- preferred array from geography unless explicitly configured
- path health only from reachability
- ALUA health when correlation is ambiguous

Ambiguous states should remain INFO or be documented as unvalidated.

## Disclaimer

This is an independent community project and is not an official Pure Storage product. It is not affiliated with, maintained by, supported by, or endorsed by Pure Storage, Inc.
