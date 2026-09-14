# Change Checklist

Use this checklist when preparing or validating a new public release.

## Source baseline

- [ ] Start from the actual completed tool file, not reconstructed code.
- [ ] Confirm `$script:ToolVersion` matches the intended release.
- [ ] Confirm the GUI displays the same version.
- [ ] Confirm integrated Help is present and opens the current documentation.
- [ ] Confirm no historical fixer/test scripts are included.

## Functional review

- [ ] Read-only audit behavior preserved.
- [ ] Pure Storage-specific scope preserved.
- [ ] Environment-specific values remain configurable.
- [ ] No current deployment host names, site names, array names, IPs, or path counts are hardcoded as product defaults.
- [ ] MPIO policy logic is current.
- [ ] Windows 32-path maximum validation is present.
- [ ] ALUA logic does not guess when device correlation is ambiguous.
- [ ] Hyper-V and Failover Cluster checks remain optional scopes.
- [ ] ActiveCluster remains optional and configurable.

## Safety review

- [ ] No embedded credentials or tokens.
- [ ] No automatic MTU/Jumbo changes.
- [ ] No automatic route or NIC-binding changes.
- [ ] No MPIO policy changes.
- [ ] No FlashArray write operations.
- [ ] No disk initialization or formatting.
- [ ] No cluster/CSV creation.
- [ ] Report remediation remains advisory only.

## Documentation review

- [ ] `README.md` matches the current release.
- [ ] `Docs/USER-GUIDE.html` matches integrated Help.
- [ ] `Docs/OPERATIONS-GUIDE.md` is current.
- [ ] `Docs/TROUBLESHOOTING.md` is current.
- [ ] `Docs/SECURITY-SCOPE.md` is current.
- [ ] Disclaimer is present.
- [ ] MIT license is present.

## Repository hygiene

- [ ] `.gitignore` excludes logs.
- [ ] `.gitignore` excludes audit/report exports.
- [ ] `.gitignore` excludes local state/profiles.
- [ ] `.gitignore` excludes credentials/secrets.
- [ ] `.gitignore` excludes build/release output.
- [ ] `.gitignore` excludes backups/temp files.

## Release

- [ ] Repository is public.
- [ ] Default branch is `main`.
- [ ] Tag is `v1.4.11`.
- [ ] Release title is `Pure Storage Host Validation / Readiness v1.4.11`.
- [ ] Release targets `main`.
- [ ] Release is normal, not pre-release.
- [ ] Release notes describe feature set, prerequisites, safety scope, documentation, license, and disclaimer.
