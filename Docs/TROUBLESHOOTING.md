# Troubleshooting

## The GUI does not open

- Confirm Windows PowerShell 5.1 is being used.
- Start PowerShell as Administrator.
- Confirm the downloaded `.ps1` is not blocked by Windows.
- Check the effective PowerShell execution policy.
- Run the script from a local path if execution from a network share is restricted.

## No host results are returned

Check:

- target host spelling
- DNS resolution
- WinRM / PowerShell remoting
- Windows Firewall rules
- credentials
- local/remote administrator rights
- whether the target host is reachable from the management workstation

## Pure target TCP/3260 validation fails

Check:

- target IP is correct
- Pure iSCSI interface is enabled
- host routing selects the intended iSCSI NIC
- source address is on the expected storage subnet
- VLAN and switching configuration
- ACL/firewall rules
- TCP/3260 reachability

Do not create persistent default gateways on dedicated iSCSI NICs to work around routing problems.

## MTU or Jumbo Packet warnings

The tool intentionally treats these as guided findings.

Before changing MTU:

1. Verify the Pure target interface MTU.
2. Verify every switch/VLAN path supports the intended frame size.
3. Verify the NIC driver's supported Jumbo Packet values.
4. Change the NIC Jumbo Packet value first.
5. Change Windows IP MTU second.
6. For a 9000-byte IPv4 MTU, validate with a DF ping using 8972 bytes of payload.

Do not change only one component of the path.

## MPIO path count is "Not available"

This is expected before Pure volumes are presented.

If Pure disks are visible and the value still cannot be determined, inspect Detailed Results for MSDSM/ALUA correlation information. The validator intentionally does not infer a path count from unrelated array ordering or incomplete data.

## ALUA remains INFO

ALUA validation requires Windows to expose data that can be safely associated with a Pure device.

If the validator cannot make that association, INFO is the correct result. Do not interpret INFO as proof that ALUA is healthy or unhealthy.

## MPIO policy reports FAIL

Review the actual path count for the Pure device:

- 1-10: RR or LQD is valid.
- 11-32: LQD is expected.
- More than 32: path design itself is unsupported by the Windows MPIO limit and must be reduced.

Policy remediation should be performed in the configuration tool or an approved manual workflow, not in this validator.

## Target connectivity works but there are no iSCSI sessions

TCP/3260 reachability proves the target service is reachable. It does not mean an iSCSI session has been configured.

Before the connection phase, zero sessions is an INFO condition.

## Host drift appears

Compare only equivalent hosts. A legitimate role difference can produce intentional drift. Environment-specific role/topology values should be supplied as configuration rather than added to the code.

## HTML report cannot be opened

- Export the report first.
- Verify the destination path exists.
- Confirm the user can read the file.
- If the default browser is restricted by policy, open the file manually with an approved browser.

## Help does not open

The integrated Help button generates a local HTML file under the current user's `%LOCALAPPDATA%` area and opens it in the default browser.

Check:

- `%LOCALAPPDATA%` is writable
- endpoint security is not blocking local HTML creation
- a default browser is configured
