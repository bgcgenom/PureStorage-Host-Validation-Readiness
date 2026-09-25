#requires -Version 5.1
<#
.SYNOPSIS
    Pure Storage Host Validation / Readiness Tool

.DESCRIPTION
    Read-only Windows host validation tool for Pure FlashArray iSCSI environments.

    Capabilities:
      - Audit one or more Windows Server hosts
      - Validate dedicated iSCSI NIC configuration
      - Validate MSiSCSI and MPIO prerequisites
      - Test Pure FlashArray iSCSI target connectivity on TCP 3260
      - Optional Hyper-V checks
      - Optional Windows Failover Cluster checks
      - Optional extended NIC/offload checks
      - Compare selected configuration values across hosts
      - Export a standalone HTML report with PASS / INFO / WARNING / FAIL results
      - Include remediation guidance and verification steps in the HTML report

    SAFETY:
      - Audit only.
      - No configuration changes are made.
      - No iSCSI portals are added.
      - No iSCSI sessions are created.
      - No disks are initialized, formatted, or added to a cluster.
      - No Hyper-V or Failover Cluster settings are changed.

.NOTES
    Intended as a companion / future tab for the iSCSI Host Tool.`n    v1.0.1: Fix single-host PowerShell 5.1 array handling and add GUI audit error handling.`n    v1.0.2: Fix remote MTU detection and add View HTML Report button.`n    v1.0.3: Harden remote MTU detection by querying each interface directly with netsh.`n    v1.0.4: Fix Failover Cluster network validation helper scope and complete cluster-network checks.`n    v1.0.7: Rebuild HTML report layout from the last known-good script using PowerShell 5.1-safe string construction.`n    v1.0.8: Explicitly bind WPF button click handlers as RoutedEventHandler delegates for Windows PowerShell 5.1.`n    v1.0.9: Add majority-baseline Host Drift Summary and include persistent default routes in drift detection.`n    v1.1.0: Add guided remediation with exact commands, verification, rollback, risk, and automation classification while remaining read-only.`n    v1.1.1: Correct NIC binding remediation CheckId matching and add host-name/duplicate preflight validation.`n    v1.1.2: Add configurable expected storage MTU; evaluate Windows MTU and NIC Jumbo Packet against the storage design; keep jumbo remediation guided-only.`n    v1.2.0: Add Pure Storage ActiveCluster host-side validation profile and checks for topology, Pure array target groups, host locality mapping, MPIO policy, and runtime array connectivity.`n    v1.3.0: Add Pure runtime iSCSI validation for live session persistence, source-NIC symmetry, Pure device identity, configurable array display names, and stronger per-host path topology checks.`n    v1.4.0: Add read-only Windows MSDSM ALUA path-state inspection using DSM_QueryLBPolicy_V2, validate Active/Optimized and Active/Unoptimized path states by ActiveCluster topology, and remove duplicate pre-connection runtime messaging.`n    v1.4.1: Populate ActiveCluster host and target-array assignments from the existing Target Hosts and Pure iSCSI Target IP lists to eliminate duplicate data entry.`n    v1.4.2: Replace ActiveCluster host/target array drop-downs with per-row A/B radio buttons for faster, always-visible assignment while preserving mutual exclusivity and unassigned validation.`n    v1.4.3: Start with an empty Target Hosts field instead of automatically inserting the local computer name.`n    v1.4.4: Increase the ActiveCluster target-assignment grid height so typical eight-target Pure iSCSI configurations are visible without scrolling.`n    v1.4.5: Make Pure Recommended MPIO validation path-count aware. RR or LQD is accepted at 10 or fewer paths, with RR preferred; LQD is required when more than 10 paths are present. Validation remains read-only.`n    v1.4.6: Add a dedicated MPIO Summary section near the top of the HTML report so host MPIO readiness and policy are easy to find without opening PASS/INFO sections.`n    v1.4.7: Fix HTML MPIO Summary rendering by generating the summary rows in PowerShell before inserting them into the single-quoted HTML template.`n    v1.4.8: Validate the Windows MPIO maximum of 32 paths per Pure device and surface observed path counts in the MPIO Summary. More than 32 paths is a hard FAIL; unknown runtime path count remains INFO.`n    v1.4.9: Display the tool version in the GUI and add integrated Full User Documentation, modeled after the iSCSI Host Tool Help/Operations Guide pattern.`n    v1.4.10: Rename the integrated documentation control to Help and move it beside the GUI version display.`n    v1.4.11: Replace the plain-text WPF Help window with integrated HTML Full User Documentation opened in the default browser, matching the iSCSI Host Tool documentation style.`n    v1.5.0: Add explicit read-only Pure device MPIO/ALUA runtime summaries, report actual per-device Windows MPIO policy names and path-state counts from MSDSM V2 data, treat no-Pure-disk state as informational, and report RRWS without automatic remediation while topology-specific Pure guidance is reviewed.
    Windows PowerShell 5.1 and WPF are required.
#>

Add-Type -AssemblyName PresentationFramework
Add-Type -AssemblyName PresentationCore
Add-Type -AssemblyName WindowsBase

$script:ToolVersion = "1.5.0"
$script:WindowsMpioMaxPathsPerDevice = 32
$script:WindowsCredential = $null
$script:Results = New-Object System.Collections.ObjectModel.ObservableCollection[object]
$script:LastAuditHosts = @()
$script:AuditStarted = $null
$script:AuditCompleted = $null
$script:LastHtmlReportPath = $null

function New-Finding {
    param(
        [string]$HostName,
        [string]$Category,
        [string]$CheckId,
        [string]$Check,
        [ValidateSet("PASS","INFO","WARNING","FAIL")]
        [string]$Result,
        [string]$Current = "",
        [string]$Expected = "",
        [string]$Details = "",
        [string]$Remediation = "",
        [string]$Verification = "",
        [string]$RecommendedAction = "",
        [string]$RemediationCommand = "",
        [string]$RollbackCommand = "",
        [string]$Risk = "",
        [string]$AutomationClass = ""
    )

    [pscustomobject]@{
        Host               = $HostName
        Category           = $Category
        CheckId            = $CheckId
        Check              = $Check
        Result             = $Result
        Current            = $Current
        Expected           = $Expected
        Details            = $Details
        Remediation        = $Remediation
        Verification       = $Verification
        RecommendedAction  = $RecommendedAction
        RemediationCommand = $RemediationCommand
        RollbackCommand    = $RollbackCommand
        Risk               = $Risk
        AutomationClass    = $AutomationClass
    }
}

function Test-HostNameSyntax {
    param([string]$HostName)

    if ([string]::IsNullOrWhiteSpace($HostName)) { return $false }
    if ($HostName.Length -gt 253) { return $false }
    if ($HostName -match '\s') { return $false }

    $labels = @($HostName.TrimEnd('.') -split '\.')
    foreach ($label in $labels) {
        if ([string]::IsNullOrWhiteSpace($label)) { return $false }
        if ($label.Length -gt 63) { return $false }
        if ($label -notmatch '^[A-Za-z0-9](?:[A-Za-z0-9-]*[A-Za-z0-9])?$') { return $false }
    }

    return $true
}

function Get-HostList {
    param([string]$Text)

    @(
        $Text -split "[`r`n,; ]+" |
            ForEach-Object { $_.Trim() } |
            Where-Object { $_ } |
            Select-Object -Unique
    )
}

function Get-TargetList {
    param([string]$Text)

    @(
        $Text -split "[`r`n,; ]+" |
            ForEach-Object { $_.Trim() } |
            Where-Object { $_ } |
            Select-Object -Unique
    )
}

function Invoke-RemoteReadOnly {
    param(
        [string]$ComputerName,
        [scriptblock]$ScriptBlock,
        [object[]]$ArgumentList = @()
    )

    if ($ComputerName -ieq $env:COMPUTERNAME -or
        $ComputerName -ieq "localhost" -or
        $ComputerName -eq ".") {
        & $ScriptBlock @ArgumentList
        return
    }

    $params = @{
        ComputerName = $ComputerName
        ScriptBlock  = $ScriptBlock
        ArgumentList = $ArgumentList
        ErrorAction  = "Stop"
    }

    if ($script:WindowsCredential) {
        $params.Credential = $script:WindowsCredential
    }

    Invoke-Command @params
}

function ConvertTo-NetworkAddress {
    param(
        [string]$IPAddress,
        [int]$PrefixLength
    )

    try {
        $bytes = [System.Net.IPAddress]::Parse($IPAddress).GetAddressBytes()
        $mask = [byte[]](0,0,0,0)

        for ($i = 0; $i -lt 4; $i++) {
            $bits = [Math]::Max(0, [Math]::Min(8, $PrefixLength - ($i * 8)))
            if ($bits -eq 0) {
                $mask[$i] = 0
            }
            else {
                $mask[$i] = [byte](256 - [Math]::Pow(2, 8 - $bits))
            }
        }

        $network = [byte[]](0,0,0,0)
        for ($i = 0; $i -lt 4; $i++) {
            $network[$i] = $bytes[$i] -band $mask[$i]
        }

        return ("{0}/{1}" -f ([System.Net.IPAddress]::new($network)).ToString(), $PrefixLength)
    }
    catch {
        return ""
    }
}

$InventoryScript = {
    param(
        [string]$NicPattern,
        [bool]$DoWindowsNetwork,
        [bool]$DoIscsiMpio,
        [bool]$DoHyperV,
        [bool]$DoCluster,
        [bool]$DoExtended,
        [int]$ExpectedStorageMtu = 9000,
        [bool]$DoActiveCluster = $false,
        [string]$ActiveClusterTopology = "Disabled",
        [string[]]$ArrayATargets = @(),
        [string[]]$ArrayBTargets = @(),
        [string]$PreferredArrayMapping = "",
        [string]$ExpectedMpioPolicy = "Auto",
        [int]$MinimumPathsPerArray = 2,
        [string]$ArrayAName = "Array A",
        [string]$ArrayBName = "Array B",
        [string[]]$ExpectedPureTargets = @()
    )

    $ErrorActionPreference = "SilentlyContinue"

    function Get-NetworkAddressLocal {
        param([string]$IPAddress,[int]$PrefixLength)
        try {
            $bytes = [System.Net.IPAddress]::Parse($IPAddress).GetAddressBytes()
            $mask = [byte[]](0,0,0,0)
            for ($i = 0; $i -lt 4; $i++) {
                $bits = [Math]::Max(0, [Math]::Min(8, $PrefixLength - ($i * 8)))
                if ($bits -eq 0) { $mask[$i] = 0 }
                else { $mask[$i] = [byte](256 - [Math]::Pow(2, 8 - $bits)) }
            }
            $network = [byte[]](0,0,0,0)
            for ($i = 0; $i -lt 4; $i++) { $network[$i] = $bytes[$i] -band $mask[$i] }
            "{0}/{1}" -f ([System.Net.IPAddress]::new($network)).ToString(), $PrefixLength
        }
        catch { "" }
    }

    $out = [ordered]@{
        Host                = $env:COMPUTERNAME
        OS                  = ""
        IsAdmin             = $false
        Nics                = @()
        MSiSCSI             = $null
        MPIO                = $null
        PureDSM             = $false
        MpioPolicy          = ""
        Portals             = @()
        Targets             = @()
        Sessions            = @()
        Connections         = @()
        PureDisks           = @()
        DiskMpioPolicies    = @()
        AluaDevices         = @()
        HyperV              = $null
        Cluster             = $null
    }

    try {
        $os = Get-CimInstance Win32_OperatingSystem
        $out.OS = "{0} ({1})" -f $os.Caption, $os.Version
    } catch {}

    try {
        $id = [Security.Principal.WindowsIdentity]::GetCurrent()
        $principal = New-Object Security.Principal.WindowsPrincipal($id)
        $out.IsAdmin = $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
    } catch {}

    if ($DoWindowsNetwork -or $DoExtended -or $DoHyperV -or $DoCluster) {
        $adapters = @(Get-NetAdapter | Where-Object { $_.Name -like $NicPattern })

        function Get-InterfaceMtuLocal {
            param([string]$InterfaceName)

            # First try CIM directly.
            try {
                $cfg = Get-CimInstance -Namespace root/StandardCimv2 -ClassName MSFT_NetIPInterface -ErrorAction Stop |
                    Where-Object {
                        $_.InterfaceAlias -eq $InterfaceName -and
                        $_.AddressFamily -eq 2
                    } |
                    Select-Object -First 1

                if ($cfg -and [int]$cfg.NlMtu -gt 0) {
                    return [int]$cfg.NlMtu
                }
                if ($cfg -and [int]$cfg.NlMtuBytes -gt 0) {
                    return [int]$cfg.NlMtuBytes
                }
            } catch {}

            # Then query this interface directly with netsh and parse its row.
            try {
                $raw = (netsh interface ipv4 show subinterfaces) -join "`n"
                $escaped = [regex]::Escape($InterfaceName)
                $m = [regex]::Match(
                    $raw,
                    "(?m)^\s*(\d+)\s+\d+\s+\d+\s+\d+\s+$escaped\s*$"
                )
                if ($m.Success) {
                    return [int]$m.Groups[1].Value
                }
            } catch {}

            return 0
        }

        foreach ($a in $adapters) {
            $ipv4 = @(Get-NetIPAddress -InterfaceIndex $a.ifIndex -AddressFamily IPv4 |
                Where-Object { $_.IPAddress -notlike "169.254*" } |
                Select-Object -First 1)

            $ip = if ($ipv4) { [string]$ipv4.IPAddress } else { "" }
            $prefix = if ($ipv4) { [int]$ipv4.PrefixLength } else { 0 }

            $defaultRoutes = @(Get-NetRoute -InterfaceIndex $a.ifIndex -AddressFamily IPv4 -DestinationPrefix "0.0.0.0/0" -ErrorAction SilentlyContinue)
            $persistentRoutes = @(Get-NetRoute -PolicyStore PersistentStore -InterfaceIndex $a.ifIndex -AddressFamily IPv4 -DestinationPrefix "0.0.0.0/0" -ErrorAction SilentlyContinue)

            $dnsServers = @()
            try {
                $dnsServers = @((Get-DnsClientServerAddress -InterfaceIndex $a.ifIndex -AddressFamily IPv4).ServerAddresses)
            } catch {}

            $dnsClient = $null
            try { $dnsClient = Get-DnsClient -InterfaceIndex $a.ifIndex } catch {}

            $ipif = $null
            try { $ipif = Get-NetIPInterface -InterfaceIndex $a.ifIndex -AddressFamily IPv4 } catch {}

            $rss = $null
            try { $rss = Get-NetAdapterRss -Name $a.Name } catch {}

            $rdma = $null
            try { $rdma = Get-NetAdapterRdma -Name $a.Name } catch {}

            $smb = $null
            try { $smb = Get-SmbClientNetworkInterface | Where-Object { $_.InterfaceIndex -eq $a.ifIndex } | Select-Object -First 1 } catch {}

            $bindings = @()
            try {
                $bindings = @(Get-NetAdapterBinding -Name $a.Name |
                    Where-Object { $_.ComponentID -in @("ms_msclient","ms_server","ms_tcpip6") } |
                    Select-Object DisplayName,ComponentID,Enabled)
            } catch {}

            $adv = @()
            if ($DoExtended) {
                try {
                    $adv = @(Get-NetAdapterAdvancedProperty -Name $a.Name |
                        Where-Object {
                            $_.DisplayName -match "Jumbo|Flow Control|Large Send Offload|Checksum Offload"
                        } |
                        Select-Object DisplayName,DisplayValue)
                } catch {}
            }

            $out.Nics += [pscustomobject]@{
                Name                      = $a.Name
                Description               = $a.InterfaceDescription
                Status                    = [string]$a.Status
                LinkSpeed                 = [string]$a.LinkSpeed
                DriverVersion             = [string]$a.DriverVersion
                DriverDate                = [string]$a.DriverDate
                IfIndex                   = [int]$a.ifIndex
                IPAddress                 = $ip
                PrefixLength              = $prefix
                Network                   = if ($ip) { Get-NetworkAddressLocal $ip $prefix } else { "" }
                DefaultRoutes             = @($defaultRoutes | ForEach-Object { "{0} -> {1} ({2})" -f $_.DestinationPrefix,$_.NextHop,$_.Store })
                PersistentDefaultRoutes   = @($persistentRoutes | ForEach-Object { "{0} -> {1}" -f $_.DestinationPrefix,$_.NextHop })
                DNSServers                = @($dnsServers)
                RegisterDNS               = if ($dnsClient) { [bool]$dnsClient.RegisterThisConnectionsAddress } else { $null }
                UseSuffix                 = if ($dnsClient) { [bool]$dnsClient.UseSuffixWhenRegistering } else { $null }
                MTU                       = Get-InterfaceMtuLocal -InterfaceName $a.Name
                RSS                       = if ($rss) { [bool]$rss.Enabled } else { $null }
                RSSQueues                 = if ($rss) { [int]$rss.NumberOfReceiveQueues } else { 0 }
                RSSProfile                = if ($rss) { [string]$rss.Profile } else { "" }
                RDMAEnabled               = if ($rdma) { [bool]$rdma.Enabled } else { $null }
                SMBRdmaCapable            = if ($smb) { [bool]$smb.RdmaCapable } else { $false }
                SMBRSSCapable             = if ($smb) { [bool]$smb.RSSCapable } else { $false }
                Bindings                  = $bindings
                Advanced                  = $adv
            }
        }
    }

    if ($DoIscsiMpio) {
        try {
            $svc = Get-Service MSiSCSI
            $out.MSiSCSI = [pscustomobject]@{
                Status    = [string]$svc.Status
                StartType = [string]$svc.StartType
            }
        } catch {}

        try {
            $feature = Get-WindowsFeature Multipath-IO
            $out.MPIO = [pscustomobject]@{
                Installed = [bool]$feature.Installed
            }
        } catch {}

        try {
            Import-Module MPIO -ErrorAction SilentlyContinue
            $pure = @(Get-MSDSMSupportedHW | Where-Object {
                ([string]$_.VendorId).Trim() -eq "PURE" -and
                ([string]$_.ProductId).Trim() -eq "FlashArray"
            })
            $out.PureDSM = ($pure.Count -gt 0)
        } catch {}

        try {
            $out.MpioPolicy = [string](Get-MSDSMGlobalDefaultLoadBalancePolicy)
        } catch {}

        try { $out.Portals = @(Get-IscsiTargetPortal | Select-Object TargetPortalAddress,TargetPortalPortNumber,InitiatorPortalAddress) } catch {}
        try { $out.Targets = @(Get-IscsiTarget | Select-Object NodeAddress,IsConnected) } catch {}
        try {
            $out.Sessions = @(Get-IscsiSession | Select-Object `
                TargetNodeAddress,InitiatorNodeAddress,IsConnected,IsPersistent,NumberOfConnections, `
                InitiatorPortalAddress,TargetPortalAddress)
        } catch {}

        try {
            $out.Connections = @(Get-IscsiConnection | Select-Object `
                ConnectionIdentifier,InitiatorAddress,InitiatorPortNumber,TargetAddress,TargetPortNumber)
        } catch {}

        try {
            $out.PureDisks = @(Get-Disk | Where-Object {
                $_.FriendlyName -match "PURE|FlashArray"
            } | Select-Object Number,FriendlyName,SerialNumber,OperationalStatus,HealthStatus,PartitionStyle,Size)
        } catch {}

        # Best-effort per-device MPIO policy inspection. Some Windows builds do not expose
        # Get-MSDSMLoadBalancePolicy or may not return a policy before Pure disks are present.
        try {
            if (Get-Command Get-MSDSMLoadBalancePolicy -ErrorAction SilentlyContinue) {
                foreach ($d in @($out.PureDisks)) {
                    try {
                        $policyObj = Get-MSDSMLoadBalancePolicy -Path ("\\?\PhysicalDrive{0}" -f $d.Number) -ErrorAction Stop
                        $out.DiskMpioPolicies += [pscustomobject]@{
                            DiskNumber = [int]$d.Number
                            Policy     = [string]$policyObj.LoadBalancePolicy
                        }
                    } catch {}
                }
            }
        } catch {}

        # Read-only ALUA / MSDSM path-state inspection.
        # DSM_QueryLBPolicy_V2 exposes MPIO_DSM_Path_V2 path records including
        # TargetPortGroup_State:
        #   0 = Active/Optimized
        #   1 = Active/Unoptimized
        #   2 = Standby
        #   3 = Unavailable
        #  16 = Not Used
        #
        # This query is best-effort. Some DSM/Windows combinations may not expose
        # the V2 class or may expose no instances until an MPIO device is present.
        try {
            $lbPolicies = @(Get-CimInstance -Namespace root/wmi -ClassName DSM_QueryLBPolicy_V2 -ErrorAction Stop)

            foreach ($lb in $lbPolicies) {
                try {
                    $policy = $lb.LoadBalancePolicy
                    if (-not $policy) { continue }

                    $paths = @()
                    foreach ($p in @($policy.DSM_Paths)) {
                        if (-not $p) { continue }

                        $paths += [pscustomobject]@{
                            DsmPathId                  = [string]$p.DsmPathId
                            PrimaryPath                = [int]$p.PrimaryPath
                            OptimizedPath              = [int]$p.OptimizedPath
                            PreferredPath              = [int]$p.PreferredPath
                            FailedPath                 = [int]$p.FailedPath
                            TargetPortGroupState       = [int]$p.TargetPortGroup_State
                            ALUASupport                = [int]$p.ALUASupport
                            SymmetricLUA               = [int]$p.SymmetricLUA
                            TargetPortGroupPreferred   = [int]$p.TargetPortGroup_Preferred
                            TargetPortGroupIdentifier  = [int]$p.TargetPortGroup_Identifier
                            TargetPortIdentifier       = [int]$p.TargetPort_Identifier
                        }
                    }

                    $policyCode = [int]$policy.LoadBalancePolicy
                    $policyName = switch ($policyCode) {
                        1 { "Fail Over Only" }
                        2 { "Round Robin" }
                        3 { "Round Robin with Subset" }
                        4 { "Dynamic Least Queue Depth" }
                        5 { "Weighted Paths" }
                        6 { "Least Blocks" }
                        7 { "Vendor Specific" }
                        default { "Unknown($policyCode)" }
                    }

                    $out.AluaDevices += [pscustomobject]@{
                        InstanceName      = [string]$lb.InstanceName
                        Active            = [bool]$lb.Active
                        LoadBalancePolicy     = $policyCode
                        LoadBalancePolicyName = $policyName
                        DSMPathCount      = [int]$policy.DSMPathCount
                        Paths             = @($paths)
                    }
                } catch {}
            }
        } catch {}
    }

    if ($DoHyperV) {
        $hv = [ordered]@{
            Installed          = $false
            VMMS               = ""
            Switches           = @()
            MigrationNetworks  = @()
        }

        try {
            $role = Get-WindowsFeature Hyper-V
            $hv.Installed = [bool]$role.Installed
        } catch {}

        try {
            $vmms = Get-Service vmms
            $hv.VMMS = "{0}/{1}" -f $vmms.StartType,$vmms.Status
        } catch {}

        try {
            $hv.Switches = @(Get-VMSwitch | Select-Object Name,SwitchType,NetAdapterInterfaceDescription)
        } catch {}

        try {
            $hv.MigrationNetworks = @(Get-VMMigrationNetwork | Select-Object Subnet,Priority)
        } catch {}

        $out.HyperV = [pscustomobject]$hv
    }

    if ($DoCluster) {
        $clusterObj = [ordered]@{
            Installed   = $false
            ClusterName = ""
            NodeState   = ""
            QuorumType  = ""
            Witness     = ""
            Networks    = @()
            Disks       = @()
            CSV         = @()
        }

        try {
            $fc = Get-WindowsFeature Failover-Clustering
            $clusterObj.Installed = [bool]$fc.Installed
        } catch {}

        try {
            Import-Module FailoverClusters -ErrorAction Stop
            $cluster = Get-Cluster -ErrorAction Stop
            $clusterObj.ClusterName = [string]$cluster.Name

            $node = Get-ClusterNode -Name $env:COMPUTERNAME -ErrorAction SilentlyContinue
            if ($node) { $clusterObj.NodeState = [string]$node.State }

            try {
                $q = Get-ClusterQuorum
                $clusterObj.QuorumType = [string]$q.QuorumType
                $clusterObj.Witness = [string]$q.QuorumResource.Name
            } catch {}

            try {
                $clusterObj.Networks = @(Get-ClusterNetwork |
                    Select-Object Name,Address,AddressMask,Role,Metric,AutoMetric,State)
            } catch {}

            try {
                $clusterObj.Disks = @(Get-ClusterResource |
                    Where-Object { $_.ResourceType -eq "Physical Disk" } |
                    Select-Object Name,State,OwnerGroup,OwnerNode)
            } catch {}

            try {
                $clusterObj.CSV = @(Get-ClusterSharedVolume |
                    Select-Object Name,State,OwnerNode)
            } catch {}
        } catch {}

        $out.Cluster = [pscustomobject]$clusterObj
    }

    [pscustomobject]$out
}

$TargetTestScript = {
    param([string[]]$Targets)

    $results = @()
    foreach ($target in $Targets) {
        $tcp = $false
        try {
            $tcp = Test-NetConnection $target -Port 3260 -InformationLevel Quiet -WarningAction SilentlyContinue
        } catch {}

        $routeInterface = ""
        $sourceAddress = ""
        $nextHop = ""

        try {
            $route = Find-NetRoute -RemoteIPAddress $target -ErrorAction Stop |
                Select-Object -First 1

            $routeInterface = [string]$route.InterfaceAlias
            $sourceAddress  = [string]$route.IPAddress
            $nextHop        = [string]$route.NextHop
        } catch {}

        $results += [pscustomobject]@{
            Target         = $target
            TCP3260        = [bool]$tcp
            RouteInterface = $routeInterface
            SourceAddress  = $sourceAddress
            NextHop        = $nextHop
        }
    }

    $results
}

function Add-Result {
    param([object]$Finding)
    $script:Results.Add($Finding)
}


function Get-ConfiguredIpList {
    param([string]$Text)

    if ([string]::IsNullOrWhiteSpace($Text)) { return @() }

    return @(
        $Text -split "[,;`r`n`t ]+" |
            ForEach-Object { $_.Trim() } |
            Where-Object { $_ -and $_ -match '^\d{1,3}(\.\d{1,3}){3}$' } |
            Select-Object -Unique
    )
}

function Get-PreferredArrayForHost {
    param(
        [string]$HostName,
        [string]$MappingText
    )

    if ([string]::IsNullOrWhiteSpace($MappingText)) { return "" }

    foreach ($line in @($MappingText -split "`r?`n")) {
        $trimmed = $line.Trim()
        if (-not $trimmed -or $trimmed.StartsWith("#")) { continue }

        $parts = @($trimmed -split "=",2)
        if ($parts.Count -ne 2) { continue }

        $pattern = $parts[0].Trim()
        $value = $parts[1].Trim()

        if ($pattern -and $value -and $HostName -like $pattern) {
            return $value
        }
    }

    return ""
}

function Test-MpioPolicyForPure {
    param(
        [string]$Policy,
        [string]$ExpectedPolicy = "Pure Recommended (Auto)",
        [int]$PathCount = 0
    )

    $p = ([string]$Policy).Trim().ToUpperInvariant()
    $expected = ([string]$ExpectedPolicy).Trim()

    $isRR = ($p -eq "RR" -or $p -match "ROUND\s*ROBIN")
    $isLQD = ($p -eq "LQD" -or $p -match "LEAST\s*QUEUE")

    if ($expected -eq "RR") {
        return $isRR
    }

    if ($expected -eq "LQD") {
        return $isLQD
    }

    # Pure Recommended (Auto):
    # - Before runtime path count is known, accept RR or LQD.
    # - At 10 or fewer paths, RR and LQD are supported.
    # - Above 10 paths, require LQD.
    if ($PathCount -gt 10) {
        return $isLQD
    }

    return ($isRR -or $isLQD)
}

function Get-PureRecommendedMpioPolicy {
    param([int]$PathCount)

    if ($PathCount -le 0) {
        return [pscustomobject]@{
            Recommended = "RR or LQD"
            Preferred   = "RR"
            Severity    = "INFO"
            Details     = "Runtime path count is not yet available. RR or LQD is acceptable until the actual Pure device path count is known."
        }
    }

    if ($PathCount -le 10) {
        return [pscustomobject]@{
            Recommended = "RR or LQD"
            Preferred   = "RR"
            Severity    = "PASS"
            Details     = "Pure Storage supports RR or LQD at 10 or fewer paths. RR is preferred for this path count."
        }
    }

    return [pscustomobject]@{
        Recommended = "LQD"
        Preferred   = "LQD"
        Severity    = "PASS"
        Details     = "Pure Storage recommends Least Queue Depth when more than 10 paths are presented to a volume."
    }
}

function Get-ActiveConnectionTargets {
    param($Inventory)

    return @(
        @($Inventory.Connections) |
            ForEach-Object { [string]$_.TargetAddress } |
            Where-Object { $_ } |
            Select-Object -Unique
    )
}


function Get-ArrayDisplayName {
    param(
        [string]$Key,
        [string]$ArrayAName,
        [string]$ArrayBName
    )

    if ($Key -eq "ArrayA") {
        if ([string]::IsNullOrWhiteSpace($ArrayAName)) { return "Array A" }
        return $ArrayAName.Trim()
    }

    if ($Key -eq "ArrayB") {
        if ([string]::IsNullOrWhiteSpace($ArrayBName)) { return "Array B" }
        return $ArrayBName.Trim()
    }

    return $Key
}

function Add-PureRuntimeConnectivityFindings {
    param(
        $Inventory,
        [string[]]$ExpectedTargets,
        [string[]]$ArrayATargets,
        [string[]]$ArrayBTargets,
        [string]$ArrayAName,
        [string]$ArrayBName,
        [int]$MinimumPathsPerArray = 2
    )

    $hostName = [string]$Inventory.Host
    $connections = @($Inventory.Connections)
    $sessions = @($Inventory.Sessions)
    $pureDisks = @($Inventory.PureDisks)

    if ($sessions.Count -eq 0 -and $connections.Count -eq 0) {
        Add-Result (New-Finding -HostName $hostName -Category "Pure Runtime Connectivity" `
            -CheckId "PureRuntime.State" -Check "Runtime Pure iSCSI state" `
            -Result "INFO" -Current "No active sessions or connections" `
            -Expected "Expected only after Pure storage is connected" `
            -Details "The host remains in readiness/pre-connection state.")
        return
    }

    # Session persistence
    if ($sessions.Count -gt 0) {
        $persistentKnown = @($sessions | Where-Object { $null -ne $_.IsPersistent })
        if ($persistentKnown.Count -gt 0) {
            $nonPersistent = @($persistentKnown | Where-Object { -not [bool]$_.IsPersistent })
            Add-Result (New-Finding -HostName $hostName -Category "Pure Runtime Connectivity" `
                -CheckId "PureRuntime.SessionPersistence" -Check "Persistent Pure iSCSI sessions" `
                -Result $(if ($nonPersistent.Count -eq 0) {"PASS"} else {"WARNING"}) `
                -Current ("Persistent={0}; NonPersistent={1}" -f ($persistentKnown.Count-$nonPersistent.Count),$nonPersistent.Count) `
                -Expected "Production Pure iSCSI sessions are persistent" `
                -Details $(if ($nonPersistent.Count -eq 0) {
                    "All sessions exposing persistence state are persistent."
                } else {
                    "One or more live iSCSI sessions are not persistent and may not return automatically after reboot."
                }) `
                -Remediation $(if ($nonPersistent.Count -gt 0) {
                    "Review the Pure iSCSI session configuration and reconnect the required sessions persistently using the approved Pure host workflow."
                } else {""}) `
                -Verification "Confirm required Pure iSCSI sessions return after restart and report persistent.")
        }
        else {
            Add-Result (New-Finding -HostName $hostName -Category "Pure Runtime Connectivity" `
                -CheckId "PureRuntime.SessionPersistence" -Check "Persistent Pure iSCSI sessions" `
                -Result "INFO" -Current "Persistence property unavailable" `
                -Expected "Production Pure iSCSI sessions are persistent")
        }
    }

    # Source NIC/IP symmetry and unexpected targets
    $iscsiIps = @($Inventory.Nics | ForEach-Object { [string]$_.IPAddress } | Where-Object { $_ })
    $sourceCounts = @{}
    foreach ($ip in $iscsiIps) { $sourceCounts[$ip] = 0 }

    $unexpectedTargets = @()
    foreach ($c in $connections) {
        $src = [string]$c.InitiatorAddress
        $tgt = [string]$c.TargetAddress

        if ($src -and $sourceCounts.ContainsKey($src)) {
            $sourceCounts[$src] = [int]$sourceCounts[$src] + 1
        }

        if (@($ExpectedTargets).Count -gt 0 -and $tgt -and ($ExpectedTargets -notcontains $tgt)) {
            $unexpectedTargets += $tgt
        }
    }

    if ($connections.Count -gt 0 -and $sourceCounts.Count -gt 0) {
        $unusedSources = @($sourceCounts.GetEnumerator() | Where-Object { $_.Value -eq 0 } | ForEach-Object { $_.Key })
        $summary = @($sourceCounts.GetEnumerator() | Sort-Object Name | ForEach-Object { "{0}={1}" -f $_.Key,$_.Value }) -join "; "

        Add-Result (New-Finding -HostName $hostName -Category "Pure Runtime Connectivity" `
            -CheckId "PureRuntime.SourceSymmetry" -Check "iSCSI source-NIC participation" `
            -Result $(if ($unusedSources.Count -eq 0) {"PASS"} else {"WARNING"}) `
            -Current $summary `
            -Expected "Every configured Pure iSCSI host interface participates in live storage connectivity" `
            -Details $(if ($unusedSources.Count -eq 0) {
                "All discovered iSCSI source addresses participate in live Pure iSCSI connections."
            } else {
                "One or more dedicated iSCSI host interfaces have no live Pure iSCSI connections: {0}" -f ($unusedSources -join ", ")
            }) `
            -Remediation $(if ($unusedSources.Count -gt 0) {
                "Review portal/session binding and confirm each dedicated iSCSI interface is used for the intended Pure target paths."
            } else {""}) `
            -Verification "Review Get-IscsiConnection and confirm each dedicated iSCSI source address has expected target connections.")
    }

    if (@($unexpectedTargets | Select-Object -Unique).Count -gt 0) {
        $bad = @($unexpectedTargets | Select-Object -Unique)
        Add-Result (New-Finding -HostName $hostName -Category "Pure Runtime Connectivity" `
            -CheckId "PureRuntime.UnexpectedTargets" -Check "Unexpected iSCSI target addresses" `
            -Result "WARNING" -Current ($bad -join ", ") `
            -Expected "Live Pure iSCSI connections use only configured Pure target addresses" `
            -Details "The host has live iSCSI connections to target addresses outside the configured Pure target list." `
            -Remediation "Verify whether these sessions are expected. Remove only after confirming they are not required by another approved Pure configuration." `
            -Verification "Confirm all remaining Get-IscsiConnection target addresses are part of the configured Pure target list.")
    }
    elseif ($connections.Count -gt 0 -and @($ExpectedTargets).Count -gt 0) {
        Add-Result (New-Finding -HostName $hostName -Category "Pure Runtime Connectivity" `
            -CheckId "PureRuntime.UnexpectedTargets" -Check "Unexpected iSCSI target addresses" `
            -Result "PASS" -Current "None" `
            -Expected "Only configured Pure target addresses")
    }

    # Array-level live target counts
    if ($connections.Count -gt 0 -and @($ArrayATargets).Count -gt 0 -and @($ArrayBTargets).Count -gt 0) {
        $aSeen = @($connections | Where-Object { $ArrayATargets -contains ([string]$_.TargetAddress) } |
            ForEach-Object { [string]$_.TargetAddress } | Select-Object -Unique)
        $bSeen = @($connections | Where-Object { $ArrayBTargets -contains ([string]$_.TargetAddress) } |
            ForEach-Object { [string]$_.TargetAddress } | Select-Object -Unique)

        $aLabel = Get-ArrayDisplayName -Key "ArrayA" -ArrayAName $ArrayAName -ArrayBName $ArrayBName
        $bLabel = Get-ArrayDisplayName -Key "ArrayB" -ArrayAName $ArrayAName -ArrayBName $ArrayBName

        Add-Result (New-Finding -HostName $hostName -Category "Pure Runtime Connectivity" `
            -CheckId "PureRuntime.ArrayTargetSummary" -Check "Live Pure array target summary" `
            -Result "INFO" `
            -Current ("{0}={1}; {2}={3}" -f $aLabel,$aSeen.Count,$bLabel,$bSeen.Count) `
            -Expected ("Configured topology/path minimum = {0} target address(es) per required array" -f $MinimumPathsPerArray))
    }

    # Pure device identity
    if ($pureDisks.Count -gt 0) {
        $badDisks = @($pureDisks | Where-Object { [string]$_.FriendlyName -notmatch "PURE|FlashArray" })
        Add-Result (New-Finding -HostName $hostName -Category "Pure Runtime Connectivity" `
            -CheckId "PureRuntime.DeviceIdentity" -Check "Pure device identity" `
            -Result $(if ($badDisks.Count -eq 0) {"PASS"} else {"FAIL"}) `
            -Current ("Pure disks detected={0}" -f $pureDisks.Count) `
            -Expected "Presented storage identifies as Pure Storage / FlashArray" `
            -Details $(if ($badDisks.Count -eq 0) {
                "All disks classified by the tool as Pure devices identify with a Pure/FlashArray friendly name."
            } else {
                "One or more disks classified as Pure storage do not expose the expected Pure device identity."
            }))
    }
    else {
        Add-Result (New-Finding -HostName $hostName -Category "Pure Runtime Connectivity" `
            -CheckId "PureRuntime.DeviceIdentity" -Check "Pure device identity" `
            -Result "INFO" -Current "No Pure disks visible" `
            -Expected "Expected after Pure volumes are presented")
    }

    # Per-Pure-disk MPIO policy with Pure path-count-aware guidance.
    $diskPolicies = @($Inventory.DiskMpioPolicies)
    if ($pureDisks.Count -gt 0) {
        if ($diskPolicies.Count -gt 0) {
            $pureAluaDevices = @(Get-PureAluaDevices -Inventory $Inventory)
            $canCorrelateCounts = (
                $pureAluaDevices.Count -gt 0 -and
                $pureAluaDevices.Count -eq $pureDisks.Count
            )

            foreach ($dp in $diskPolicies) {
                $pathCount = 0

                if ($canCorrelateCounts) {
                    $diskIndex = -1
                    for ($i = 0; $i -lt $pureDisks.Count; $i++) {
                        if ([int]$pureDisks[$i].Number -eq [int]$dp.DiskNumber) {
                            $diskIndex = $i
                            break
                        }
                    }

                    if ($diskIndex -ge 0 -and $diskIndex -lt $pureAluaDevices.Count) {
                        $pathCount = @($pureAluaDevices[$diskIndex].Paths).Count
                    }
                }

                $recommendation = Get-PureRecommendedMpioPolicy -PathCount $pathCount
                $good = Test-MpioPolicyForPure `
                    -Policy ([string]$dp.Policy) `
                    -ExpectedPolicy "Pure Recommended (Auto)" `
                    -PathCount $pathCount

                $currentText = if ($pathCount -gt 0) {
                    "Policy={0}; Paths={1}" -f ([string]$dp.Policy),$pathCount
                } else {
                    "Policy={0}; Paths=Not correlated" -f ([string]$dp.Policy)
                }

                $expectedText = if ($pathCount -gt $script:WindowsMpioMaxPathsPerDevice) {
                    "Path count exceeds Windows maximum; reduce to <=32 paths. LQD remains the Pure policy expectation above 10 paths."
                }
                elseif ($pathCount -gt 10) {
                    "LQD required by Pure recommendation for 11-32 paths"
                }
                elseif ($pathCount -gt 0) {
                    "RR or LQD supported at <=10 paths; RR preferred"
                }
                else {
                    "RR or LQD until actual Pure device path count is available"
                }

                if ($pathCount -gt 0) {
                    $pathLimitGood = ($pathCount -le $script:WindowsMpioMaxPathsPerDevice)

                    Add-Result (New-Finding -HostName $hostName -Category "Pure Runtime Connectivity" `
                        -CheckId ("PureRuntime.DiskMpioPathCount.{0}" -f $dp.DiskNumber) `
                        -Check ("Pure disk {0} MPIO path count" -f $dp.DiskNumber) `
                        -Result $(if ($pathLimitGood) {"PASS"} else {"FAIL"}) `
                        -Current ([string]$pathCount) `
                        -Expected ("1-{0} paths per device" -f $script:WindowsMpioMaxPathsPerDevice) `
                        -Details $(if ($pathLimitGood) {
                            "The observed Pure device path count is within the Windows MPIO supported maximum."
                        } else {
                            "The observed Pure device path count exceeds the Windows MPIO supported maximum. Paths above the supported limit can be dropped by Windows and can produce incomplete or uneven storage-path access."
                        }) `
                        -Remediation $(if (-not $pathLimitGood) {
                            "Reduce the number of presented iSCSI paths to this Pure device to 32 or fewer. Review host NIC, target-port, and ActiveCluster connectivity before changing the production path design."
                        } else {""}) `
                        -Risk $(if (-not $pathLimitGood) {
                            "High. An unsupported path count can result in Windows dropping paths and can affect expected multipath behavior."
                        } else {""}) `
                        -Verification ("Confirm the device exposes no more than {0} MPIO paths, then re-run the audit." -f $script:WindowsMpioMaxPathsPerDevice))
                }
                else {
                    Add-Result (New-Finding -HostName $hostName -Category "Pure Runtime Connectivity" `
                        -CheckId ("PureRuntime.DiskMpioPathCount.{0}" -f $dp.DiskNumber) `
                        -Check ("Pure disk {0} MPIO path count" -f $dp.DiskNumber) `
                        -Result "INFO" `
                        -Current "Not correlated" `
                        -Expected ("1-{0} paths per device" -f $script:WindowsMpioMaxPathsPerDevice) `
                        -Details "The validator could not safely correlate an MSDSM/ALUA path count to this Pure device, so it does not guess at Windows path-limit compliance.")
                }

                $isRrws = ([string]$dp.Policy) -match "(?i)RRWS|ROUND\s*ROBIN\s*WITH\s*SUBSET"
                $policyResult = if ($isRrws) { "INFO" } elseif ($good) { "PASS" } else { "FAIL" }
                $policyDetails = if ($isRrws) {
                    "Windows reports Round Robin with Subset (RRWS) for this Pure device. RRWS is an ALUA-aware Windows MPIO policy and is reported explicitly. This validator does not automatically classify or remediate RRWS against the RR/LQD baseline until the applicable Pure Storage Windows + ALUA/ActiveCluster guidance is confirmed for the topology."
                } else {
                    $recommendation.Details
                }
                if ($isRrws) {
                    $expectedText = $expectedText + "; RRWS observed - report-only pending topology-specific Pure guidance"
                }

                Add-Result (New-Finding -HostName $hostName -Category "Pure Runtime Connectivity" `
                    -CheckId ("PureRuntime.DiskMpioPolicy.{0}" -f $dp.DiskNumber) `
                    -Check ("Pure disk {0} MPIO policy" -f $dp.DiskNumber) `
                    -Result $policyResult `
                    -Current $currentText `
                    -Expected $expectedText `
                    -Details $policyDetails `
                    -Remediation $(if (-not $good -and -not $isRrws) {
                        "Review the Pure device MPIO policy. This validation tool does not change MPIO policy."
                    } else {""}) `
                    -Verification "Re-run the audit after any approved policy change and confirm the per-device policy matches the approved Pure recommendation for the observed path count and topology.")
            }
        }
        else {
            Add-Result (New-Finding -HostName $hostName -Category "Pure Runtime Connectivity" `
                -CheckId "PureRuntime.DiskMpioPolicy" -Check "Per-Pure-disk MPIO policy" `
                -Result "INFO" -Current "Not exposed by this Windows build/cmdlet set" `
                -Expected "Pure Recommended: RR or LQD at <=10 paths; LQD above 10 paths")
        }
    }
}


function Get-AluaStateName {
    param([int]$State)

    switch ($State) {
        0  { return "Active/Optimized" }
        1  { return "Active/Unoptimized" }
        2  { return "Standby" }
        3  { return "Unavailable" }
        16 { return "Not Used" }
        default { return "Unknown($State)" }
    }
}

function Get-AluaSupportName {
    param([int]$Support)

    switch ($Support) {
        0 { return "ALUA Not Supported" }
        1 { return "ALUA Implicit Only" }
        2 { return "ALUA Explicit Only" }
        3 { return "ALUA Implicit and Explicit" }
        default { return "Unknown($Support)" }
    }
}

function Get-MpioPolicyName {
    param([int]$PolicyCode)

    switch ($PolicyCode) {
        1 { return "Fail Over Only" }
        2 { return "Round Robin" }
        3 { return "Round Robin with Subset" }
        4 { return "Dynamic Least Queue Depth" }
        5 { return "Weighted Paths" }
        6 { return "Least Blocks" }
        7 { return "Vendor Specific" }
        default { return "Unknown($PolicyCode)" }
    }
}

function Get-PureAluaDevices {
    param($Inventory)

    $all = @($Inventory.AluaDevices)
    if ($all.Count -eq 0) {
        return @()
    }

    # Prefer explicit Pure/FlashArray instance names when Windows exposes them.
    $pure = @($all | Where-Object {
        ([string]$_.InstanceName) -match "PURE|FlashArray"
    })

    if ($pure.Count -gt 0) {
        return @($pure)
    }

    # If Pure disks are present but the V2 WMI instance name does not include the
    # vendor/product string, use the available DSM V2 devices only when the count
    # exactly matches the visible Pure disk count. This avoids silently classifying
    # unrelated MPIO devices as Pure storage on mixed-storage hosts.
    $pureDiskCount = @($Inventory.PureDisks).Count
    if ($pureDiskCount -gt 0 -and $all.Count -eq $pureDiskCount) {
        return @($all)
    }

    return @()
}

function Add-PureAluaFindings {
    param(
        $Inventory,
        [string]$Topology,
        [int]$MinimumPathsPerArray = 2
    )

    $hostName = [string]$Inventory.Host
    $topologyMode = if ($Topology) { $Topology.Trim() } else { "Disabled" }
    $pureDisks = @($Inventory.PureDisks)

    if ($pureDisks.Count -eq 0) {
        Add-Result (New-Finding -HostName $hostName -Category "Pure ActiveCluster" `
            -CheckId "ActiveCluster.ALUAInspection" `
            -Check "ALUA path-state inspection" `
            -Result "INFO" `
            -Current "No Pure disks visible" `
            -Expected "ALUA validation begins after Pure volumes are presented" `
            -Details "No per-device ALUA judgment is made during the pre-connection/readiness stage.")
        return
    }

    $devices = @(Get-PureAluaDevices -Inventory $Inventory)
    if ($devices.Count -eq 0) {
        Add-Result (New-Finding -HostName $hostName -Category "Pure ActiveCluster" `
            -CheckId "ActiveCluster.ALUAInspection" `
            -Check "ALUA path-state inspection" `
            -Result "INFO" `
            -Current "MSDSM ALUA V2 data not correlated to Pure devices" `
            -Expected "DSM_QueryLBPolicy_V2 path data for each visible Pure MPIO device" `
            -Details "Windows did not expose correlatable DSM_QueryLBPolicy_V2 data. The tool does not infer ALUA state when device correlation is ambiguous.")
        return
    }

    Add-Result (New-Finding -HostName $hostName -Category "Pure ActiveCluster" `
        -CheckId "ActiveCluster.ALUAInspection" `
        -Check "ALUA path-state inspection" `
        -Result "PASS" `
        -Current ("Pure MPIO device(s) with ALUA data={0}" -f $devices.Count) `
        -Expected "Read-only MSDSM V2 path-state data available")

    $deviceIndex = 0
    foreach ($device in $devices) {
        $deviceIndex++
        $paths = @($device.Paths)
        $ao = @($paths | Where-Object { [int]$_.TargetPortGroupState -eq 0 }).Count
        $au = @($paths | Where-Object { [int]$_.TargetPortGroupState -eq 1 }).Count
        $sb = @($paths | Where-Object { [int]$_.TargetPortGroupState -eq 2 }).Count
        $ua = @($paths | Where-Object { [int]$_.TargetPortGroupState -eq 3 }).Count
        $nu = @($paths | Where-Object { [int]$_.TargetPortGroupState -eq 16 }).Count
        $unknown = @($paths | Where-Object { [int]$_.TargetPortGroupState -notin @(0,1,2,3,16) }).Count
        $failed = @($paths | Where-Object { [int]$_.FailedPath -ne 0 }).Count

        $aluaSupportValues = @(
            $paths |
                ForEach-Object { [int]$_.ALUASupport } |
                Select-Object -Unique
        )
        $aluaSupportText = @(
            $aluaSupportValues |
                ForEach-Object { Get-AluaSupportName -Support $_ }
        ) -join ", "

        $instance = [string]$device.InstanceName
        if ($instance.Length -gt 80) {
            $instance = $instance.Substring(0,77) + "..."
        }

        $stateSummary = "AO={0}; AU={1}; Standby={2}; Unavailable={3}; NotUsed={4}; Unknown={5}; Failed={6}; Total={7}" -f `
            $ao,$au,$sb,$ua,$nu,$unknown,$failed,$paths.Count

        $minimumUniformPaths = [Math]::Max(2, ($MinimumPathsPerArray * 2))
        $minimumNonUniformPaths = [Math]::Max(1, $MinimumPathsPerArray)

        $devicePolicyName = if (
            $device.PSObject.Properties.Name -contains "LoadBalancePolicyName" -and
            -not [string]::IsNullOrWhiteSpace([string]$device.LoadBalancePolicyName)
        ) {
            [string]$device.LoadBalancePolicyName
        } else {
            Get-MpioPolicyName -PolicyCode ([int]$device.LoadBalancePolicy)
        }

        $deviceSummaryResult = "PASS"
        if ($paths.Count -gt $script:WindowsMpioMaxPathsPerDevice) {
            $deviceSummaryResult = "FAIL"
        }
        elseif ($failed -gt 0 -or $ua -gt 0 -or $unknown -gt 0) {
            $deviceSummaryResult = "WARNING"
        }

        Add-Result (New-Finding -HostName $hostName -Category "Pure Device MPIO / ALUA" `
            -CheckId ("PureDevice.RuntimeSummary.Device{0}" -f $deviceIndex) `
            -Check ("Pure MPIO device {0} runtime summary" -f $deviceIndex) `
            -Result $deviceSummaryResult `
            -Current ("Policy={0}; PolicyCode={1}; Paths={2}; AO={3}; AU={4}; Standby={5}; Unavailable={6}; NotUsed={7}; Failed={8}" -f `
                $devicePolicyName,[int]$device.LoadBalancePolicy,$paths.Count,$ao,$au,$sb,$ua,$nu,$failed) `
            -Expected ("<= {0} Windows MPIO paths/device; healthy ALUA path states consistent with the configured topology" -f $script:WindowsMpioMaxPathsPerDevice) `
            -Details ("MSDSM V2 instance: {0}; ALUA support: {1}. This is read-only device evidence. Policy, path count, and ALUA state are reported independently of the host/global default policy." -f $instance,$aluaSupportText) `
            -Remediation $(if ($deviceSummaryResult -eq "FAIL") {
                "Reduce the presented path count to the Windows-supported maximum or lower after reviewing the approved Pure topology. The validator does not change pathing."
            } elseif ($deviceSummaryResult -eq "WARNING") {
                "Review failed, unavailable, or unknown paths and confirm the intended Pure ActiveCluster topology. Do not manually force ALUA states."
            } else {""}) `
            -Verification "Re-run the audit and compare the per-device policy, path count, and ALUA state summary.")

        if ($topologyMode -eq "Uniform") {
            $good = (
                $ao -ge 1 -and
                $au -ge 1 -and
                $paths.Count -ge $minimumUniformPaths -and
                $sb -eq 0 -and
                $ua -eq 0 -and
                $unknown -eq 0 -and
                $failed -eq 0
            )

            Add-Result (New-Finding -HostName $hostName -Category "Pure ActiveCluster" `
                -CheckId ("ActiveCluster.ALUA.Device{0}" -f $deviceIndex) `
                -Check ("Pure MPIO device {0} ALUA state" -f $deviceIndex) `
                -Result $(if ($good) {"PASS"} else {"FAIL"}) `
                -Current $stateSummary `
                -Expected ("Uniform ActiveCluster: Active/Optimized local paths + Active/Unoptimized remote paths; at least {0} total paths; no failed/standby/unavailable paths" -f $minimumUniformPaths) `
                -Details ("MSDSM instance: {0}; ALUA support: {1}. Pure ActiveCluster uses ALUA so local paths are Active/Optimized and remote paths are Active/Unoptimized." -f $instance,$aluaSupportText) `
                -Remediation $(if (-not $good) {
                    "Review Pure preferred-array configuration, host-to-volume connections, iSCSI sessions, and MPIO path health. Do not manually force path states."
                } else {""}) `
                -Verification "Re-run the audit and confirm the Pure device reports both Active/Optimized and Active/Unoptimized paths with no failed, standby, or unavailable paths.")
        }
        elseif ($topologyMode -eq "Non-Uniform") {
            $good = (
                $ao -ge $minimumNonUniformPaths -and
                $au -eq 0 -and
                $paths.Count -ge $minimumNonUniformPaths -and
                $sb -eq 0 -and
                $ua -eq 0 -and
                $unknown -eq 0 -and
                $failed -eq 0
            )

            Add-Result (New-Finding -HostName $hostName -Category "Pure ActiveCluster" `
                -CheckId ("ActiveCluster.ALUA.Device{0}" -f $deviceIndex) `
                -Check ("Pure MPIO device {0} ALUA state" -f $deviceIndex) `
                -Result $(if ($good) {"PASS"} else {"FAIL"}) `
                -Current $stateSummary `
                -Expected ("Non-Uniform ActiveCluster: available local paths Active/Optimized only; at least {0} path(s); no Active/Unoptimized/failed/standby/unavailable paths" -f $minimumNonUniformPaths) `
                -Details ("MSDSM instance: {0}; ALUA support: {1}. Non-uniform hosts should access the stretched volume only through the local Pure array." -f $instance,$aluaSupportText) `
                -Remediation $(if (-not $good) {
                    "Review local-only host-to-array connectivity, Pure host-to-volume connections, iSCSI sessions, and MPIO path health."
                } else {""}) `
                -Verification "Re-run the audit and confirm only the expected local Active/Optimized paths are present.")
        }
        else {
            Add-Result (New-Finding -HostName $hostName -Category "Pure ActiveCluster" `
                -CheckId ("ActiveCluster.ALUA.Device{0}" -f $deviceIndex) `
                -Check ("Pure MPIO device {0} ALUA state" -f $deviceIndex) `
                -Result "INFO" `
                -Current $stateSummary `
                -Expected "Configure Uniform or Non-Uniform topology for deterministic ALUA validation" `
                -Details ("MSDSM instance: {0}; ALUA support: {1}" -f $instance,$aluaSupportText))
        }

        # Detailed path inventory remains INFO so the report preserves the raw
        # state evidence without duplicating severity findings per individual path.
        $pathNumber = 0
        foreach ($path in $paths) {
            $pathNumber++
            $stateName = Get-AluaStateName -State ([int]$path.TargetPortGroupState)

            Add-Result (New-Finding -HostName $hostName -Category "Pure ALUA Path Detail" `
                -CheckId ("ActiveCluster.ALUA.Device{0}.Path{1}" -f $deviceIndex,$pathNumber) `
                -Check ("Pure device {0} path {1}" -f $deviceIndex,$pathNumber) `
                -Result "INFO" `
                -Current ("State={0}; PathId={1}; TPG={2}; TargetPort={3}; PreferredTPG={4}; Primary={5}; OptimizedFlag={6}; Failed={7}" -f `
                    $stateName,
                    [string]$path.DsmPathId,
                    [string]$path.TargetPortGroupIdentifier,
                    [string]$path.TargetPortIdentifier,
                    [string]$path.TargetPortGroupPreferred,
                    [string]$path.PrimaryPath,
                    [string]$path.OptimizedPath,
                    [string]$path.FailedPath) `
                -Expected "State consistent with the configured Pure ActiveCluster topology")
        }
    }
}

function Add-ActiveClusterHostFindings {
    param(
        $Inventory,
        [string]$Topology,
        [string[]]$ArrayATargets,
        [string[]]$ArrayBTargets,
        [string]$PreferredArrayMapping,
        [string]$ExpectedMpioPolicy,
        [int]$MinimumPathsPerArray = 2,
        [string]$ArrayAName = "Array A",
        [string]$ArrayBName = "Array B"
    )

    $hostName = [string]$Inventory.Host
    $topologyMode = if ($Topology) { $Topology.Trim() } else { "Disabled" }
    if ($topologyMode -eq "Disabled") { return }

    Add-Result (New-Finding -HostName $hostName -Category "Pure ActiveCluster" `
        -CheckId "ActiveCluster.Topology" -Check "ActiveCluster topology profile" `
        -Result "INFO" -Current $topologyMode `
        -Expected "Uniform or Non-Uniform according to the approved Pure Storage design" `
        -Details "This is the configured validation profile. ActiveCluster topology is determined by host-to-array connectivity.")

    $preferred = Get-PreferredArrayForHost -HostName $hostName -MappingText $PreferredArrayMapping
    $arrayALabel = Get-ArrayDisplayName -Key "ArrayA" -ArrayAName $ArrayAName -ArrayBName $ArrayBName
    $arrayBLabel = Get-ArrayDisplayName -Key "ArrayB" -ArrayAName $ArrayAName -ArrayBName $ArrayBName
    $preferredDisplay = if ($preferred -eq "ArrayA") { $arrayALabel } elseif ($preferred -eq "ArrayB") { $arrayBLabel } else { $preferred }

    Add-Result (New-Finding -HostName $hostName -Category "Pure ActiveCluster" `
        -CheckId "ActiveCluster.PreferredArrayProfile" -Check "Host local/preferred-array mapping" `
        -Result "INFO" -Current $(if ($preferredDisplay) {$preferredDisplay} else {"Not configured"}) `
        -Expected "Optional host-side locality mapping for topology validation" `
        -Details $(if ($preferred) {
            "The mapping tells the validator which Pure array is expected to be local to this host. It does not modify the FlashArray preferred-array setting."
        } else {
            "No host locality mapping was supplied. Array reachability can still be evaluated, but local-versus-remote path locality cannot be inferred."
        }))

    $policy = [string]$Inventory.MpioPolicy
    if ($policy) {
        $policyGood = Test-MpioPolicyForPure -Policy $policy -ExpectedPolicy $ExpectedMpioPolicy
        $policyExpected = if ($ExpectedMpioPolicy -and $ExpectedMpioPolicy -ne "Auto") {
            $ExpectedMpioPolicy
        } else {
            "Pure Recommended: RR or LQD before runtime path count is known; LQD required above 10 paths"
        }

        Add-Result (New-Finding -HostName $hostName -Category "Pure ActiveCluster" `
            -CheckId "ActiveCluster.MpioPolicy" -Check "Pure MPIO load-balancing policy" `
            -Result $(if ($policyGood) {"PASS"} else {"WARNING"}) `
            -Current $policy -Expected $policyExpected `
            -Details $(if ($policyGood) {
                "The detected Microsoft DSM load-balancing policy is valid for the current Pure Storage validation stage. Per-device path-count-aware validation becomes authoritative after Pure volumes are presented."
            } else {
                "Review the Microsoft DSM load-balancing policy against the approved Pure Storage host standard."
            }) `
            -Remediation $(if (-not $policyGood) {
                "Review and set the Pure Storage MPIO policy according to the approved host standard. Do not change production path policy without change control."
            } else {""}) `
            -Verification "Confirm the Microsoft DSM load-balancing policy after any approved change.")
    }
    else {
        Add-Result (New-Finding -HostName $hostName -Category "Pure ActiveCluster" `
            -CheckId "ActiveCluster.MpioPolicy" -Check "Pure MPIO load-balancing policy" `
            -Result "INFO" -Current "Unable to determine" `
            -Expected "RR or LQD, or an explicitly configured Pure Storage host standard")
    }

    $activeTargets = Get-ActiveConnectionTargets -Inventory $Inventory
    $connectionCount = @($Inventory.Connections).Count

    if ($connectionCount -eq 0) {
        Add-PureAluaFindings -Inventory $Inventory `
            -Topology $topologyMode `
            -MinimumPathsPerArray $MinimumPathsPerArray
        return
    }

    if (@($ArrayATargets).Count -eq 0 -or @($ArrayBTargets).Count -eq 0) {
        Add-Result (New-Finding -HostName $hostName -Category "Pure ActiveCluster" `
            -CheckId "ActiveCluster.RuntimeConnectivity" -Check "ActiveCluster runtime array connectivity" `
            -Result "WARNING" -Current (($activeTargets) -join ", ") `
            -Expected "Array A and Array B Pure target groups configured" `
            -Details "Active iSCSI connections exist, but array-level ActiveCluster topology cannot be evaluated because one or both target groups are not configured.")
        return
    }

    $aConnections = @(@($Inventory.Connections) | Where-Object { $ArrayATargets -contains ([string]$_.TargetAddress) })
    $bConnections = @(@($Inventory.Connections) | Where-Object { $ArrayBTargets -contains ([string]$_.TargetAddress) })

    $aTargetsSeen = @($aConnections | ForEach-Object { [string]$_.TargetAddress } | Select-Object -Unique)
    $bTargetsSeen = @($bConnections | ForEach-Object { [string]$_.TargetAddress } | Select-Object -Unique)

    if ($topologyMode -eq "Uniform") {
        $good = ($aTargetsSeen.Count -ge $MinimumPathsPerArray -and $bTargetsSeen.Count -ge $MinimumPathsPerArray)

        Add-Result (New-Finding -HostName $hostName -Category "Pure ActiveCluster" `
            -CheckId "ActiveCluster.UniformArrayConnectivity" -Check "Uniform ActiveCluster array connectivity" `
            -Result $(if ($good) {"PASS"} else {"FAIL"}) `
            -Current ("{0} active targets={1}; {2} active targets={3}" -f $arrayALabel,$aTargetsSeen.Count,$arrayBLabel,$bTargetsSeen.Count) `
            -Expected ("At least {0} active Pure target address(es) from each array" -f $MinimumPathsPerArray) `
            -Details $(if ($good) {
                "The host has active iSCSI connectivity to both Pure ActiveCluster arrays, consistent with a uniform-access topology."
            } else {
                "Uniform ActiveCluster access requires host connectivity to both Pure arrays. One or both configured target groups do not meet the expected minimum."
            }) `
            -Remediation $(if (-not $good) {
                "Review Pure iSCSI portals, sessions, storage-network reachability, and FlashArray host/volume presentation for the missing paths."
            } else {""}) `
            -Verification "Confirm active iSCSI connections include the expected Pure target addresses from both arrays.")
    }
    elseif ($topologyMode -eq "Non-Uniform") {
        if (-not $preferred) {
            Add-Result (New-Finding -HostName $hostName -Category "Pure ActiveCluster" `
                -CheckId "ActiveCluster.NonUniformArrayConnectivity" -Check "Non-Uniform ActiveCluster array connectivity" `
                -Result "WARNING" `
                -Current ("{0} active targets={1}; {2} active targets={3}" -f $arrayALabel,$aTargetsSeen.Count,$arrayBLabel,$bTargetsSeen.Count) `
                -Expected "Per-host local-array mapping for deterministic non-uniform validation" `
                -Details "The validator cannot determine which Pure array should be local because no host mapping was supplied.")
        }
        else {
            $prefUpper = $preferred.Trim().ToUpperInvariant()
            $localCount = 0
            $remoteCount = 0

            if ($prefUpper -eq "ARRAYA") {
                $localCount = $aTargetsSeen.Count
                $remoteCount = $bTargetsSeen.Count
            }
            elseif ($prefUpper -eq "ARRAYB") {
                $localCount = $bTargetsSeen.Count
                $remoteCount = $aTargetsSeen.Count
            }

            if ($prefUpper -notin @("ARRAYA","ARRAYB")) {
                Add-Result (New-Finding -HostName $hostName -Category "Pure ActiveCluster" `
                    -CheckId "ActiveCluster.NonUniformArrayConnectivity" -Check "Non-Uniform ActiveCluster array connectivity" `
                    -Result "WARNING" -Current $preferred `
                    -Expected "Mapping value must be ArrayA or ArrayB" `
                    -Details "The configured host mapping could not be interpreted.")
            }
            else {
                $good = ($localCount -ge $MinimumPathsPerArray -and $remoteCount -eq 0)
                Add-Result (New-Finding -HostName $hostName -Category "Pure ActiveCluster" `
                    -CheckId "ActiveCluster.NonUniformArrayConnectivity" -Check "Non-Uniform ActiveCluster array connectivity" `
                    -Result $(if ($good) {"PASS"} else {"FAIL"}) `
                    -Current ("Local active targets={0}; Remote active targets={1}" -f $localCount,$remoteCount) `
                    -Expected ("At least {0} local target address(es) and no active remote-array targets" -f $MinimumPathsPerArray) `
                    -Details $(if ($good) {
                        "The host's active iSCSI connectivity matches the configured non-uniform Pure ActiveCluster topology."
                    } else {
                        "Non-uniform ActiveCluster hosts should access storage through their local Pure array only."
                    }) `
                    -Remediation $(if (-not $good) {
                        "Review iSCSI portals/sessions and Pure host-to-volume connections against the intended non-uniform topology."
                    } else {""}) `
                    -Verification "Confirm active iSCSI connections exist only to the configured local Pure array.")
            }
        }
    }

    if ($preferred) {
        $prefUpper = $preferred.Trim().ToUpperInvariant()
        $localTargets = @()
        $remoteTargets = @()

        if ($prefUpper -eq "ARRAYA") {
            $localTargets = $aTargetsSeen
            $remoteTargets = $bTargetsSeen
        }
        elseif ($prefUpper -eq "ARRAYB") {
            $localTargets = $bTargetsSeen
            $remoteTargets = $aTargetsSeen
        }

        if (@($localTargets).Count -gt 0) {
            Add-Result (New-Finding -HostName $hostName -Category "Pure ActiveCluster" `
                -CheckId "ActiveCluster.LocalityEvidence" -Check "Local-array connectivity evidence" `
                -Result "PASS" `
                -Current ("Local active targets={0}; Remote active targets={1}" -f @($localTargets).Count,@($remoteTargets).Count) `
                -Expected "Connectivity aligns with the configured local-array mapping" `
                -Details "This validates array reachability only. Actual ALUA Active/Optimized versus Active/Non-Optimized state requires per-device path-state inspection.")
        }
    }

    Add-PureAluaFindings -Inventory $Inventory `
        -Topology $topologyMode `
        -MinimumPathsPerArray $MinimumPathsPerArray
}

function Add-InventoryFindings {
    param(
        [object]$Inventory,
        [string]$NicPattern,
        [bool]$DoWindowsNetwork,
        [bool]$DoIscsiMpio,
        [bool]$DoHyperV,
        [bool]$DoCluster,
        [bool]$DoExtended
    )

    function Get-NetworkAddressFromMask {
        param(
            [string]$IPAddress,
            [string]$SubnetMask
        )

        try {
            $ipBytes = [System.Net.IPAddress]::Parse($IPAddress).GetAddressBytes()
            $maskBytes = [System.Net.IPAddress]::Parse($SubnetMask).GetAddressBytes()

            $network = [byte[]](0,0,0,0)
            $prefix = 0

            for ($i = 0; $i -lt 4; $i++) {
                $network[$i] = $ipBytes[$i] -band $maskBytes[$i]

                $b = $maskBytes[$i]
                for ($bit = 7; $bit -ge 0; $bit--) {
                    if ($b -band (1 -shl $bit)) { $prefix++ }
                }
            }

            return ("{0}/{1}" -f ([System.Net.IPAddress]::new($network)).ToString(), $prefix)
        }
        catch {
            return ""
        }
    }

    $hostName = [string]$Inventory.Host

    Add-Result (New-Finding -HostName $hostName -Category "Host" -CheckId "Host.OS" -Check "Operating system" `
        -Result "INFO" -Current $Inventory.OS -Expected "Supported Windows Server" `
        -Details "Operating system detected during the read-only audit.")

    if (-not $Inventory.IsAdmin) {
        Add-Result (New-Finding -HostName $hostName -Category "Host" -CheckId "Host.Admin" -Check "Administrative context" `
            -Result "WARNING" -Current "Not elevated" -Expected "Elevated administrator" `
            -Details "Some read-only checks can return incomplete data without administrative rights." `
            -Remediation "Run the audit with an account that has local administrative rights on the target host." `
            -Verification "Run the audit again and confirm all requested checks return data.")
    }
    else {
        Add-Result (New-Finding -HostName $hostName -Category "Host" -CheckId "Host.Admin" -Check "Administrative context" `
            -Result "PASS" -Current "Elevated" -Expected "Elevated administrator")
    }

    if ($DoWindowsNetwork -or $DoExtended -or $DoHyperV -or $DoCluster) {
        $nics = @($Inventory.Nics)

        if ($nics.Count -eq 0) {
            Add-Result (New-Finding -HostName $hostName -Category "Network" -CheckId "NIC.Discovery" -Check "iSCSI NIC discovery" `
                -Result "FAIL" -Current "No interfaces matched '$NicPattern'" -Expected "At least one dedicated iSCSI NIC" `
                -Details "The audit could not identify any iSCSI interfaces using the configured NIC name pattern." `
                -Remediation "Review the NIC name pattern or rename/select the intended dedicated storage interfaces." `
                -Verification "Run the audit again and confirm the intended iSCSI interfaces are discovered.")
        }
        else {
            Add-Result (New-Finding -HostName $hostName -Category "Network" -CheckId "NIC.Discovery" -Check "iSCSI NIC discovery" `
                -Result "PASS" -Current ("{0} interface(s): {1}" -f $nics.Count, (($nics.Name) -join ", ")) `
                -Expected "Dedicated iSCSI interfaces discovered")
        }

        foreach ($nic in $nics) {
            $nicPrefix = "{0}: " -f $nic.Name

            Add-Result (New-Finding -HostName $hostName -Category "Network" -CheckId "NIC.Status.$($nic.Name)" -Check "$($nic.Name) link state" `
                -Result $(if ($nic.Status -eq "Up") {"PASS"} else {"FAIL"}) `
                -Current $nic.Status -Expected "Up" `
                -Remediation $(if ($nic.Status -ne "Up") {"Restore the storage NIC link and verify the switch port, cabling, VLAN, and adapter state."} else {""}) `
                -Verification "Confirm the adapter reports Up.")

            Add-Result (New-Finding -HostName $hostName -Category "Network" -CheckId "NIC.LinkSpeed.$($nic.Name)" -Check "$($nic.Name) link speed" `
                -Result "INFO" -Current $nic.LinkSpeed -Expected "Match the storage network design")

            Add-Result (New-Finding -HostName $hostName -Category "Network" -CheckId "NIC.IP.$($nic.Name)" -Check "$($nic.Name) IPv4 configuration" `
                -Result $(if ($nic.IPAddress) {"PASS"} else {"FAIL"}) `
                -Current $(if ($nic.IPAddress) {"$($nic.IPAddress)/$($nic.PrefixLength)"} else {"No IPv4 address"}) `
                -Expected "Static address on the intended iSCSI subnet" `
                -Remediation $(if (-not $nic.IPAddress) {"Configure the intended static IPv4 address for the dedicated iSCSI interface."} else {""}) `
                -Verification "Confirm the expected IPv4 address and prefix are present.")

            $persistentDefaults = @($nic.PersistentDefaultRoutes)
            if ($persistentDefaults.Count -gt 0) {
                Add-Result (New-Finding -HostName $hostName -Category "Network" -CheckId "NIC.DefaultRoute.$($nic.Name)" -Check "$($nic.Name) persistent default route" `
                    -Result "FAIL" -Current ($persistentDefaults -join "; ") -Expected "No default route on a dedicated iSCSI NIC" `
                    -Details "A dedicated iSCSI interface normally should not contain a persistent default route." `
                    -Remediation "Remove the persistent default route from the dedicated storage interface after the configuration owner reviews the finding." `
                    -Verification "Confirm no 0.0.0.0/0 route remains on the dedicated iSCSI interface.")
            }
            else {
                Add-Result (New-Finding -HostName $hostName -Category "Network" -CheckId "NIC.DefaultRoute.$($nic.Name)" -Check "$($nic.Name) persistent default route" `
                    -Result "PASS" -Current "None" -Expected "None")
            }

            if ($nic.RegisterDNS -eq $false) {
                Add-Result (New-Finding -HostName $hostName -Category "Network" -CheckId "NIC.DNSRegister.$($nic.Name)" -Check "$($nic.Name) DNS registration" `
                    -Result "PASS" -Current "Disabled" -Expected "Disabled")
            }
            elseif ($null -eq $nic.RegisterDNS) {
                Add-Result (New-Finding -HostName $hostName -Category "Network" -CheckId "NIC.DNSRegister.$($nic.Name)" -Check "$($nic.Name) DNS registration" `
                    -Result "INFO" -Current "Unable to determine" -Expected "Disabled")
            }
            else {
                Add-Result (New-Finding -HostName $hostName -Category "Network" -CheckId "NIC.DNSRegister.$($nic.Name)" -Check "$($nic.Name) DNS registration" `
                    -Result "WARNING" -Current "Enabled" -Expected "Disabled on dedicated iSCSI interfaces" `
                    -Remediation "Disable DNS registration on the dedicated iSCSI interface unless the environment requires it." `
                    -Verification "Confirm RegisterThisConnectionsAddress is False.")
            }

            if (@($nic.DNSServers).Count -eq 0) {
                Add-Result (New-Finding -HostName $hostName -Category "Network" -CheckId "NIC.DNSServers.$($nic.Name)" -Check "$($nic.Name) DNS servers" `
                    -Result "PASS" -Current "None" -Expected "None on dedicated iSCSI interfaces")
            }
            else {
                Add-Result (New-Finding -HostName $hostName -Category "Network" -CheckId "NIC.DNSServers.$($nic.Name)" -Check "$($nic.Name) DNS servers" `
                    -Result "WARNING" -Current (@($nic.DNSServers) -join ", ") -Expected "None on dedicated iSCSI interfaces" `
                    -Remediation "Remove DNS server assignments from the dedicated storage interface unless specifically required." `
                    -Verification "Confirm no DNS servers are assigned to the iSCSI interface.")
            }

            if ($nic.MTU -and ([int]$nic.MTU -eq $ExpectedStorageMtu)) {
                Add-Result (New-Finding -HostName $hostName -Category "Network" -CheckId "NIC.MTU.$($nic.Name)" -Check "$($nic.Name) MTU" `
                    -Result "PASS" -Current ([string]$nic.MTU) -Expected ([string]$ExpectedStorageMtu))
            }
            elseif ($nic.MTU) {
                Add-Result (New-Finding -HostName $hostName -Category "Network" -CheckId "NIC.MTU.$($nic.Name)" -Check "$($nic.Name) MTU" `
                    -Result "WARNING" -Current ([string]$nic.MTU) -Expected ([string]$ExpectedStorageMtu) `
                    -Details "The Windows IP interface MTU does not match the configured storage-network MTU." `
                    -Remediation "Validate jumbo-frame support end to end before changing the Windows IP interface MTU." `
                    -Verification "After any approved change, confirm the interface MTU and perform a do-not-fragment jumbo-frame test to a Pure target on the same storage subnet.")
            }
            else {
                Add-Result (New-Finding -HostName $hostName -Category "Network" -CheckId "NIC.MTU.$($nic.Name)" -Check "$($nic.Name) MTU" `
                    -Result "INFO" -Current "Unable to determine" -Expected ([string]$ExpectedStorageMtu))
            }

            $clientBinding = @($nic.Bindings | Where-Object ComponentID -eq "ms_msclient" | Select-Object -First 1)
            if ($clientBinding -and $clientBinding.Enabled) {
                Add-Result (New-Finding -HostName $hostName -Category "Network" -CheckId "NIC.MSClient.$($nic.Name)" -Check "$($nic.Name) Client for Microsoft Networks" `
                    -Result "WARNING" -Current "Enabled" -Expected "Usually disabled on dedicated iSCSI NICs" `
                    -Details "This binding is normally unnecessary on a dedicated storage interface." `
                    -Remediation "Review the design and disable Client for Microsoft Networks on the dedicated iSCSI interface if it is not required." `
                    -Verification "Confirm the binding is disabled after the change is approved.")
            }
            elseif ($clientBinding) {
                Add-Result (New-Finding -HostName $hostName -Category "Network" -CheckId "NIC.MSClient.$($nic.Name)" -Check "$($nic.Name) Client for Microsoft Networks" `
                    -Result "PASS" -Current "Disabled" -Expected "Disabled on dedicated iSCSI NICs")
            }

            $serverBinding = @($nic.Bindings | Where-Object ComponentID -eq "ms_server" | Select-Object -First 1)
            if ($serverBinding -and $serverBinding.Enabled) {
                Add-Result (New-Finding -HostName $hostName -Category "Network" -CheckId "NIC.FileSharing.$($nic.Name)" -Check "$($nic.Name) File and Printer Sharing" `
                    -Result "WARNING" -Current "Enabled" -Expected "Usually disabled on dedicated iSCSI NICs" `
                    -Details "This binding is normally unnecessary on a dedicated storage interface." `
                    -Remediation "Review the design and disable File and Printer Sharing on the dedicated iSCSI interface if it is not required." `
                    -Verification "Confirm the binding is disabled after the change is approved.")
            }
            elseif ($serverBinding) {
                Add-Result (New-Finding -HostName $hostName -Category "Network" -CheckId "NIC.FileSharing.$($nic.Name)" -Check "$($nic.Name) File and Printer Sharing" `
                    -Result "PASS" -Current "Disabled" -Expected "Disabled on dedicated iSCSI NICs")
            }

            if ($DoExtended) {
                if ($nic.RSS -eq $true) {
                    Add-Result (New-Finding -HostName $hostName -Category "Extended NIC" -CheckId "NIC.RSS.$($nic.Name)" -Check "$($nic.Name) RSS" `
                        -Result "PASS" -Current ("Enabled; queues={0}; profile={1}" -f $nic.RSSQueues,$nic.RSSProfile) `
                        -Expected "Enabled for high-speed TCP storage traffic")
                }
                elseif ($null -ne $nic.RSS) {
                    Add-Result (New-Finding -HostName $hostName -Category "Extended NIC" -CheckId "NIC.RSS.$($nic.Name)" -Check "$($nic.Name) RSS" `
                        -Result "WARNING" -Current "Disabled" -Expected "Enabled for high-speed TCP storage traffic" `
                        -Remediation "Review the NIC and host performance design and enable RSS if supported and appropriate." `
                        -Verification "Confirm RSS is enabled and receive queues are available.")
                }

                Add-Result (New-Finding -HostName $hostName -Category "Extended NIC" -CheckId "NIC.Driver.$($nic.Name)" -Check "$($nic.Name) driver" `
                    -Result "INFO" -Current ("{0}; {1}" -f $nic.DriverVersion,$nic.DriverDate) -Expected "Consistent across equivalent hosts")

                if ($nic.RDMAEnabled -eq $true -and -not $nic.SMBRdmaCapable) {
                    Add-Result (New-Finding -HostName $hostName -Category "Extended NIC" -CheckId "NIC.RDMA.$($nic.Name)" -Check "$($nic.Name) RDMA state" `
                        -Result "INFO" -Current "Driver reports enabled; SMB reports not RDMA-capable" `
                        -Expected "Review only if RDMA/iSER is part of the design" `
                        -Details "No change is recommended solely from this result.")
                }

                foreach ($adv in @($nic.Advanced)) {
                    $advancedId = ("NIC.Advanced.{0}.{1}" -f $nic.Name,($adv.DisplayName -replace '\W',''))

                    if ($adv.DisplayName -match '^Jumbo Packet$') {
                        $jumboText = [string]$adv.DisplayValue
                        $jumboNumeric = 0
                        $jumboParsed = [int]::TryParse(($jumboText -replace '[^0-9]',''), [ref]$jumboNumeric)

                        if ($jumboParsed -and $jumboNumeric -ge $ExpectedStorageMtu) {
                            Add-Result (New-Finding -HostName $hostName -Category "Extended NIC" `
                                -CheckId $advancedId `
                                -Check ("{0} {1}" -f $nic.Name,$adv.DisplayName) `
                                -Result "PASS" -Current $jumboText `
                                -Expected ("NIC jumbo setting sufficient for {0}-byte IP MTU (commonly {1})" -f $ExpectedStorageMtu,($ExpectedStorageMtu + 14)))
                        }
                        elseif ($jumboParsed) {
                            Add-Result (New-Finding -HostName $hostName -Category "Extended NIC" `
                                -CheckId $advancedId `
                                -Check ("{0} {1}" -f $nic.Name,$adv.DisplayName) `
                                -Result "WARNING" -Current $jumboText `
                                -Expected ("NIC jumbo setting sufficient for {0}-byte IP MTU (commonly {1})" -f $ExpectedStorageMtu,($ExpectedStorageMtu + 14)) `
                                -Details "The NIC driver is configured for standard-size frames while the expected storage network uses jumbo frames." `
                                -Remediation "Validate the switch/VLAN/storage path before increasing the NIC driver Jumbo Packet setting." `
                                -Verification "After any approved change, confirm the driver setting and perform a do-not-fragment jumbo-frame test to a Pure target on the same storage subnet.")
                        }
                        else {
                            Add-Result (New-Finding -HostName $hostName -Category "Extended NIC" `
                                -CheckId $advancedId `
                                -Check ("{0} {1}" -f $nic.Name,$adv.DisplayName) `
                                -Result "INFO" -Current $jumboText -Expected "Review against the approved storage MTU")
                        }
                    }
                    else {
                        Add-Result (New-Finding -HostName $hostName -Category "Extended NIC" `
                            -CheckId $advancedId `
                            -Check ("{0} {1}" -f $nic.Name,$adv.DisplayName) `
                            -Result "INFO" -Current ([string]$adv.DisplayValue) -Expected "Consistent across equivalent hosts")
                    }
                }
            }
        }
    }

    if ($DoIscsiMpio) {
        if ($Inventory.MSiSCSI) {
            $svcGood = ($Inventory.MSiSCSI.Status -eq "Running" -and $Inventory.MSiSCSI.StartType -eq "Automatic")
            Add-Result (New-Finding -HostName $hostName -Category "iSCSI / MPIO" -CheckId "iSCSI.Service" -Check "Microsoft iSCSI Initiator service" `
                -Result $(if ($svcGood) {"PASS"} else {"FAIL"}) `
                -Current ("{0}/{1}" -f $Inventory.MSiSCSI.StartType,$Inventory.MSiSCSI.Status) `
                -Expected "Automatic/Running" `
                -Remediation $(if (-not $svcGood) {"Set the Microsoft iSCSI Initiator service to Automatic and ensure it is running."} else {""}) `
                -Verification "Confirm MSiSCSI reports Automatic/Running.")
        }

        $mpioInstalled = ($Inventory.MPIO -and $Inventory.MPIO.Installed)
        Add-Result (New-Finding -HostName $hostName -Category "iSCSI / MPIO" -CheckId "MPIO.Feature" -Check "Multipath-IO feature" `
            -Result $(if ($mpioInstalled) {"PASS"} else {"FAIL"}) `
            -Current $(if ($mpioInstalled) {"Installed"} else {"Not installed"}) `
            -Expected "Installed" `
            -Remediation $(if (-not $mpioInstalled) {"Install the Windows Multipath-IO feature and complete any required restart before connecting production storage."} else {""}) `
            -Verification "Confirm the Multipath-IO feature reports Installed.")

        Add-Result (New-Finding -HostName $hostName -Category "iSCSI / MPIO" -CheckId "MPIO.PureDSM" -Check "PURE FlashArray MSDSM registration" `
            -Result $(if ($Inventory.PureDSM) {"PASS"} else {"FAIL"}) `
            -Current $(if ($Inventory.PureDSM) {"Configured"} else {"Not detected"}) `
            -Expected "PURE FlashArray registered with MSDSM" `
            -Remediation $(if (-not $Inventory.PureDSM) {"Register PURE FlashArray with Microsoft DSM according to the approved Pure host configuration standard."} else {""}) `
            -Verification "Confirm PURE FlashArray appears in Get-MSDSMSupportedHW.")

        Add-Result (New-Finding -HostName $hostName -Category "iSCSI / MPIO" -CheckId "iSCSI.Portals" -Check "Configured iSCSI target portals" `
            -Result "INFO" -Current ([string]@($Inventory.Portals).Count) -Expected "Depends on build stage" `
            -Details "Audit-only observation. Zero portals can be expected before the iSCSI connection phase.")

        Add-Result (New-Finding -HostName $hostName -Category "iSCSI / MPIO" -CheckId "iSCSI.Sessions" -Check "Active iSCSI sessions" `
            -Result "INFO" -Current ([string]@($Inventory.Sessions).Count) -Expected "Depends on build stage" `
            -Details "Audit-only observation. The tool does not create sessions.")

        Add-Result (New-Finding -HostName $hostName -Category "iSCSI / MPIO" -CheckId "iSCSI.PureDisks" -Check "Pure disks visible to Windows" `
            -Result "INFO" -Current ([string]@($Inventory.PureDisks).Count) -Expected "Depends on build stage" `
            -Details "Audit-only observation. The tool does not rescan, initialize, or modify disks.")
    }

    if ($DoIscsiMpio) {
        Add-PureRuntimeConnectivityFindings -Inventory $Inventory `
            -ExpectedTargets $ExpectedPureTargets `
            -ArrayATargets $ArrayATargets `
            -ArrayBTargets $ArrayBTargets `
            -ArrayAName $ArrayAName `
            -ArrayBName $ArrayBName `
            -MinimumPathsPerArray $MinimumPathsPerArray
    }

    if ($DoActiveCluster) {
        Add-ActiveClusterHostFindings -Inventory $Inventory `
            -Topology $ActiveClusterTopology `
            -ArrayATargets $ArrayATargets `
            -ArrayBTargets $ArrayBTargets `
            -PreferredArrayMapping $PreferredArrayMapping `
            -ExpectedMpioPolicy $ExpectedMpioPolicy `
            -MinimumPathsPerArray $MinimumPathsPerArray `
            -ArrayAName $ArrayAName `
            -ArrayBName $ArrayBName
    }

    if ($DoHyperV) {
        if (-not $Inventory.HyperV -or -not $Inventory.HyperV.Installed) {
            Add-Result (New-Finding -HostName $hostName -Category "Hyper-V" -CheckId "HyperV.Role" -Check "Hyper-V role" `
                -Result "INFO" -Current "Not installed" -Expected "Installed only for Hyper-V hosts")
        }
        else {
            Add-Result (New-Finding -HostName $hostName -Category "Hyper-V" -CheckId "HyperV.Role" -Check "Hyper-V role" `
                -Result "PASS" -Current "Installed" -Expected "Installed")

            Add-Result (New-Finding -HostName $hostName -Category "Hyper-V" -CheckId "HyperV.VMMS" -Check "Hyper-V Virtual Machine Management service" `
                -Result $(if ($Inventory.HyperV.VMMS -match "Running") {"PASS"} else {"WARNING"}) `
                -Current $Inventory.HyperV.VMMS -Expected "Running on an active Hyper-V host")

            $nicDescriptions = @($Inventory.Nics | ForEach-Object { $_.Description })
            $badSwitches = @($Inventory.HyperV.Switches | Where-Object {
                $desc = [string]$_.NetAdapterInterfaceDescription
                $nicDescriptions -contains $desc
            })

            if ($badSwitches.Count -gt 0) {
                Add-Result (New-Finding -HostName $hostName -Category "Hyper-V" -CheckId "HyperV.iSCSIVSwitch" -Check "iSCSI NIC used by Hyper-V virtual switch" `
                    -Result "FAIL" -Current (($badSwitches.Name) -join ", ") -Expected "Dedicated iSCSI NICs not attached to a vSwitch" `
                    -Remediation "Remove the dedicated iSCSI adapter from the Hyper-V virtual switch design after the configuration owner reviews the impact." `
                    -Verification "Confirm no Hyper-V virtual switch is backed by a dedicated iSCSI NIC.")
            }
            else {
                Add-Result (New-Finding -HostName $hostName -Category "Hyper-V" -CheckId "HyperV.iSCSIVSwitch" -Check "iSCSI NIC used by Hyper-V virtual switch" `
                    -Result "PASS" -Current "No" -Expected "No")
            }

            $iscsiNetworks = @($Inventory.Nics | ForEach-Object { $_.Network } | Where-Object { $_ })
            $badMigration = @($Inventory.HyperV.MigrationNetworks | Where-Object {
                $subnet = [string]$_.Subnet
                $iscsiNetworks -contains $subnet
            })

            if ($badMigration.Count -gt 0) {
                Add-Result (New-Finding -HostName $hostName -Category "Hyper-V" -CheckId "HyperV.LiveMigration" -Check "iSCSI network used for Live Migration" `
                    -Result "WARNING" -Current (($badMigration.Subnet) -join ", ") -Expected "Dedicated storage networks excluded from Live Migration" `
                    -Remediation "Review Live Migration network selection and exclude dedicated iSCSI networks." `
                    -Verification "Confirm no dedicated iSCSI subnet is configured as a Live Migration network.")
            }
            else {
                Add-Result (New-Finding -HostName $hostName -Category "Hyper-V" -CheckId "HyperV.LiveMigration" -Check "iSCSI network used for Live Migration" `
                    -Result "PASS" -Current "No explicit iSCSI migration network detected" -Expected "No")
            }
        }
    }

    if ($DoCluster) {
        if (-not $Inventory.Cluster -or -not $Inventory.Cluster.Installed) {
            Add-Result (New-Finding -HostName $hostName -Category "Failover Cluster" -CheckId "Cluster.Feature" -Check "Failover Clustering feature" `
                -Result "INFO" -Current "Not installed" -Expected "Installed only for cluster nodes")
        }
        elseif (-not $Inventory.Cluster.ClusterName) {
            Add-Result (New-Finding -HostName $hostName -Category "Failover Cluster" -CheckId "Cluster.Membership" -Check "Cluster membership" `
                -Result "INFO" -Current "No active cluster detected" -Expected "Cluster membership only when required")
        }
        else {
            Add-Result (New-Finding -HostName $hostName -Category "Failover Cluster" -CheckId "Cluster.Membership" -Check "Cluster membership" `
                -Result "PASS" -Current $Inventory.Cluster.ClusterName -Expected "Cluster detected")

            Add-Result (New-Finding -HostName $hostName -Category "Failover Cluster" -CheckId "Cluster.NodeState" -Check "Cluster node state" `
                -Result $(if ($Inventory.Cluster.NodeState -eq "Up") {"PASS"} else {"WARNING"}) `
                -Current $Inventory.Cluster.NodeState -Expected "Up")

            Add-Result (New-Finding -HostName $hostName -Category "Failover Cluster" -CheckId "Cluster.Quorum" -Check "Cluster quorum" `
                -Result "INFO" -Current ("{0}; witness={1}" -f $Inventory.Cluster.QuorumType,$Inventory.Cluster.Witness) `
                -Expected "Appropriate for the cluster design")

            $nicNetworks = @($Inventory.Nics | ForEach-Object { $_.Network } | Where-Object { $_ })
            foreach ($clusterNet in @($Inventory.Cluster.Networks)) {
                $match = $false
                foreach ($n in $nicNetworks) {
                    if ($n -and $clusterNet.Address) {
                        $clusterPrefix = ""
                        if ($clusterNet.Address -and $clusterNet.AddressMask) {
                            $clusterPrefix = Get-NetworkAddressFromMask ([string]$clusterNet.Address) ([string]$clusterNet.AddressMask)
                        }
                        if ($clusterPrefix -eq $n) { $match = $true }
                    }
                }

                if ($match) {
                    $roleText = [string]$clusterNet.Role
                    $roleBad = ($roleText -match "Cluster|Client") -and ($roleText -notmatch "^None$|^0$")
                    Add-Result (New-Finding -HostName $hostName -Category "Failover Cluster" `
                        -CheckId ("Cluster.NetworkRole.{0}" -f $clusterNet.Address) `
                        -Check ("Cluster role for iSCSI network {0}" -f $clusterNet.Address) `
                        -Result $(if ($roleBad) {"WARNING"} else {"PASS"}) `
                        -Current ("Role={0}; Metric={1}; State={2}" -f $clusterNet.Role,$clusterNet.Metric,$clusterNet.State) `
                        -Expected "Dedicated iSCSI network excluded from cluster communication" `
                        -Details $(if ($roleBad) {"The dedicated storage subnet is eligible for Failover Cluster communication."} else {""}) `
                        -Remediation $(if ($roleBad) {"Change the Failover Cluster network role so the dedicated iSCSI subnet is not used for cluster communication."} else {""}) `
                        -Verification "Confirm the dedicated iSCSI cluster network role is None / Do not allow cluster network communication.")
                }
            }

            Add-Result (New-Finding -HostName $hostName -Category "Failover Cluster" -CheckId "Cluster.Disks" -Check "Cluster physical disks" `
                -Result "INFO" -Current ([string]@($Inventory.Cluster.Disks).Count) -Expected "Depends on build stage")

            Add-Result (New-Finding -HostName $hostName -Category "Failover Cluster" -CheckId "Cluster.CSV" -Check "Cluster Shared Volumes" `
                -Result "INFO" -Current ([string]@($Inventory.Cluster.CSV).Count) -Expected "Depends on build stage")
        }
    }
}

function Add-TargetFindings {
    param(
        [string]$HostName,
        [object[]]$TargetResults,
        [string]$NicPattern
    )

    foreach ($t in @($TargetResults)) {
        $status = if ($t.TCP3260) { "PASS" } else { "FAIL" }

        Add-Result (New-Finding -HostName $HostName -Category "Pure Target Connectivity" `
            -CheckId ("Pure.Target.{0}" -f $t.Target) `
            -Check ("TCP 3260 to {0}" -f $t.Target) `
            -Result $status `
            -Current ("TCP={0}; Interface={1}; Source={2}" -f $t.TCP3260,$t.RouteInterface,$t.SourceAddress) `
            -Expected "TCP 3260 reachable over the intended storage interface" `
            -Details $(if ($t.TCP3260) {"The Pure iSCSI service is reachable from this host."} else {"The host could not establish a TCP connection to the target on port 3260."}) `
            -Remediation $(if (-not $t.TCP3260) {"Review the host route, VLAN, switch path, firewall, Pure interface state, and iSCSI service reachability."} else {""}) `
            -Verification "Repeat the TCP 3260 test and confirm the target is reachable.")

        if ($t.TCP3260 -and $t.RouteInterface -and $t.RouteInterface -notlike $NicPattern) {
            Add-Result (New-Finding -HostName $HostName -Category "Pure Target Connectivity" `
                -CheckId ("Pure.Route.{0}" -f $t.Target) `
                -Check ("Route selection to {0}" -f $t.Target) `
                -Result "WARNING" `
                -Current ("Interface={0}; Source={1}" -f $t.RouteInterface,$t.SourceAddress) `
                -Expected ("Interface matching {0}" -f $NicPattern) `
                -Details "The target is reachable, but Windows selected an interface outside the configured iSCSI NIC pattern." `
                -Remediation "Review routing and interface metrics so Pure iSCSI traffic uses the intended dedicated storage interface." `
                -Verification "Confirm Find-NetRoute selects the intended iSCSI interface and source address.")
        }
    }
}

function Add-DriftFindings {
    param([string[]]$Hosts)

    if ($Hosts.Count -lt 2) { return }

    $stablePrefixes = @(
        "NIC.MTU.",
        "NIC.DefaultRoute.",
        "NIC.RSS.",
        "NIC.Driver.",
        "NIC.Advanced.",
        "iSCSI.Service",
        "MPIO.Feature",
        "MPIO.PureDSM"
    )

    $groups = $script:Results |
        Where-Object {
            $id = $_.CheckId
            @($stablePrefixes | Where-Object { $id.StartsWith($_) }).Count -gt 0
        } |
        Group-Object CheckId

    foreach ($g in $groups) {
        $rows = @($g.Group)
        if ($rows.Count -lt 2) { continue }

        $valueGroups = @($rows | Group-Object Current | Sort-Object Count -Descending)
        if ($valueGroups.Count -le 1) { continue }

        # Treat the most common value as the effective baseline. This makes
        # one-host and small-group deviations obvious in the report.
        $baselineGroup = $valueGroups[0]
        $baselineValue = [string]$baselineGroup.Name
        $baselineHosts = @($baselineGroup.Group | Select-Object -ExpandProperty Host | Sort-Object)
        $outlierRows = @($rows | Where-Object { [string]$_.Current -ne $baselineValue } | Sort-Object Host)

        $outlierText = ($outlierRows | ForEach-Object {
            "{0}={1}" -f $_.Host,$_.Current
        }) -join "; "

        $baselineText = "Baseline ({0} host(s): {1})={2}" -f `
            $baselineHosts.Count,($baselineHosts -join ", "),$baselineValue

        $currentText = if ($outlierText) {
            "{0}; {1}" -f $outlierText,$baselineText
        }
        else {
            $baselineText
        }

        $outlierHostNames = @($outlierRows | Select-Object -ExpandProperty Host)
        $detailText = if ($outlierHostNames.Count -eq 1) {
            "{0} differs from the other equivalent hosts for this setting." -f $outlierHostNames[0]
        }
        else {
            "{0} hosts differ from the majority baseline for this setting: {1}." -f `
                $outlierHostNames.Count,($outlierHostNames -join ", ")
        }

        Add-Result (New-Finding -HostName "MULTI-HOST" -Category "Configuration Drift" `
            -CheckId ("Drift.{0}" -f $g.Name) `
            -Check ("Configuration drift: {0}" -f $rows[0].Check) `
            -Result "WARNING" `
            -Current $currentText `
            -Expected "Consistent across equivalent hosts" `
            -Details $detailText `
            -Remediation "Review the differing host values and standardize the setting according to the approved host baseline." `
            -Verification "Run the multi-host audit again and confirm the setting is consistent.")
    }
}

function Add-GuidedRemediationMetadata {
    foreach ($r in $script:Results) {
        if ($r.Result -notin @("FAIL","WARNING")) { continue }

        if ($r.CheckId -like "NIC.DefaultRoute.*" -and $r.Current -ne "None") {
            $nic = $r.Check -replace "\s+persistent default route$",""
            $r.RecommendedAction = "Remove the persistent default route from the dedicated iSCSI interface after confirming that it is not intentionally required."
            $r.RemediationCommand = @"
Get-NetRoute -InterfaceAlias "$nic" -DestinationPrefix "0.0.0.0/0" -PolicyStore PersistentStore |
    Remove-NetRoute -Confirm:`$false
"@.Trim()
            $r.RollbackCommand = @"
# Record the original NextHop and RouteMetric before removal.
New-NetRoute -InterfaceAlias "$nic" -DestinationPrefix "0.0.0.0/0" -NextHop "<original-next-hop>" -RouteMetric <original-metric> -PolicyStore PersistentStore
"@.Trim()
            $r.Verification = @"
Get-NetRoute -InterfaceAlias "$nic" -DestinationPrefix "0.0.0.0/0" -PolicyStore PersistentStore -ErrorAction SilentlyContinue
"@.Trim()
            $r.Risk = "Medium. An incorrect route change can affect host connectivity if this interface is used for traffic other than dedicated iSCSI."
            $r.AutomationClass = "Automatable with confirmation"
            continue
        }

        if ($r.CheckId -like "Cluster.NetworkRole.*") {
            $subnet = $r.Check -replace "^Cluster role for iSCSI network\s+",""
            $r.RecommendedAction = "Set the Failover Cluster role for this dedicated iSCSI network to None."
            $r.RemediationCommand = @"
Get-ClusterNetwork |
    Where-Object { `$_.Address -eq "$subnet" } |
    ForEach-Object { `$_.Role = 0 }
"@.Trim()
            $r.RollbackCommand = @"
# Restore the original role only if required. Role 1 = Cluster; Role 3 = ClusterAndClient.
Get-ClusterNetwork |
    Where-Object { `$_.Address -eq "$subnet" } |
    ForEach-Object { `$_.Role = <original-role> }
"@.Trim()
            $r.Verification = @"
Get-ClusterNetwork |
    Where-Object { `$_.Address -eq "$subnet" } |
    Select-Object Name,Address,Role,Metric,State
"@.Trim()
            $r.Risk = "Medium. This changes Failover Cluster communication behavior. Confirm other cluster communication networks are healthy first."
            $r.AutomationClass = "Automatable with strong confirmation"
            continue
        }

        if ($r.CheckId -like "NIC.MSClient.*") {
            $nic = $r.Check -replace "\s+Client for Microsoft Networks$",""
            $r.RecommendedAction = "Disable Client for Microsoft Networks on this dedicated iSCSI interface if the approved design does not require it."
            $r.RemediationCommand = "Disable-NetAdapterBinding -Name `"$nic`" -ComponentID ms_msclient -Confirm:`$false"
            $r.RollbackCommand = "Enable-NetAdapterBinding -Name `"$nic`" -ComponentID ms_msclient"
            $r.Verification = @"
Get-NetAdapterBinding -Name "$nic" -ComponentID ms_msclient |
    Select-Object Name,DisplayName,Enabled
"@.Trim()
            $r.Risk = "Low to Medium. This can affect SMB/client access if the NIC is used for non-storage traffic."
            $r.AutomationClass = "Automatable with confirmation"
            continue
        }

        if ($r.CheckId -like "NIC.FileSharing.*") {
            $nic = $r.Check -replace "\s+File and Printer Sharing$",""
            $r.RecommendedAction = "Disable File and Printer Sharing for Microsoft Networks on this dedicated iSCSI interface if the approved design does not require it."
            $r.RemediationCommand = "Disable-NetAdapterBinding -Name `"$nic`" -ComponentID ms_server -Confirm:`$false"
            $r.RollbackCommand = "Enable-NetAdapterBinding -Name `"$nic`" -ComponentID ms_server"
            $r.Verification = @"
Get-NetAdapterBinding -Name "$nic" -ComponentID ms_server |
    Select-Object Name,DisplayName,Enabled
"@.Trim()
            $r.Risk = "Low to Medium. This can affect SMB/server access if the NIC is used for non-storage traffic."
            $r.AutomationClass = "Automatable with confirmation"
            continue
        }

        if ($r.CheckId -like "PureRuntime.*") {
            if ($r.Result -in @("FAIL","WARNING")) {
                if (-not $r.RecommendedAction) {
                    $r.RecommendedAction = "Review the host's Pure Storage live iSCSI sessions, source-interface binding, target portals, and MPIO state."
                }
                if (-not $r.Risk) {
                    $r.Risk = "Medium. Runtime iSCSI/path changes can interrupt access to Pure Storage volumes."
                }
                if (-not $r.AutomationClass) {
                    $r.AutomationClass = "Guided only"
                }
                if (-not $r.Verification) {
                    $r.Verification = "Re-run the Pure runtime connectivity audit and confirm the session/path finding clears."
                }
            }
            continue
        }

        if ($r.CheckId -like "ActiveCluster.*") {
            if ($r.Result -in @("FAIL","WARNING")) {
                if (-not $r.RecommendedAction) {
                    $r.RecommendedAction = "Review the host's Pure Storage iSCSI sessions, portals, MPIO configuration, and FlashArray host/volume connections against the configured ActiveCluster topology."
                }
                if (-not $r.Risk) {
                    $r.Risk = "Medium to High. ActiveCluster pathing changes can affect production storage availability."
                }
                if (-not $r.AutomationClass) {
                    $r.AutomationClass = "Guided only"
                }
                if (-not $r.Verification) {
                    $r.Verification = "Re-run the Pure ActiveCluster validation after the approved pathing change."
                }
            }
            continue
        }

        if ($r.CheckId -like "NIC.MTU.*") {
            $nic = $r.Check -replace "\s+MTU$",""
            $r.RecommendedAction = "Validate jumbo-frame support across the complete iSCSI path before changing the Windows IP MTU."
            $r.RemediationCommand = @"
# Do not change MTU until the switch/VLAN path and Pure target interfaces are confirmed for jumbo frames.
# Example after approval:
Set-NetIPInterface -InterfaceAlias "$nic" -AddressFamily IPv4 -NlMtuBytes <expected-storage-mtu>
"@.Trim()
            $r.RollbackCommand = @"
Set-NetIPInterface -InterfaceAlias "$nic" -AddressFamily IPv4 -NlMtuBytes <original-mtu>
"@.Trim()
            $r.Verification = @"
Get-NetIPInterface -InterfaceAlias "$nic" -AddressFamily IPv4 |
    Select-Object InterfaceAlias,NlMtu

# For a 9000-byte IPv4 MTU, test 8972 bytes of payload with DF set:
ping <Pure-target-IP-on-this-storage-subnet> -f -l 8972
"@.Trim()
            $r.Risk = "Medium to High. Changing only the host MTU can break iSCSI connectivity if any switch port, VLAN, intermediate path, or target interface does not support the same frame size."
            $r.AutomationClass = "Guided only"
            continue
        }

        if ($r.CheckId -like "NIC.Advanced.*.JumboPacket") {
            $nic = ($r.Check -replace "\s+Jumbo Packet$","")
            $r.RecommendedAction = "Validate end-to-end jumbo-frame support before increasing the NIC driver's Jumbo Packet setting."
            $r.RemediationCommand = @"
# Driver values vary by adapter. Inspect supported values first:
Get-NetAdapterAdvancedProperty -Name "$nic" -DisplayName "Jumbo Packet" |
    Select-Object Name,DisplayName,DisplayValue,ValidDisplayValues

# After approval, select the driver value appropriate for the expected IP MTU.
Set-NetAdapterAdvancedProperty -Name "$nic" -DisplayName "Jumbo Packet" -DisplayValue "<approved-jumbo-value>"
"@.Trim()
            $r.RollbackCommand = @"
Set-NetAdapterAdvancedProperty -Name "$nic" -DisplayName "Jumbo Packet" -DisplayValue "<original-jumbo-value>"
"@.Trim()
            $r.Verification = @"
Get-NetAdapterAdvancedProperty -Name "$nic" -DisplayName "Jumbo Packet" |
    Select-Object Name,DisplayName,DisplayValue

# For a 9000-byte IPv4 MTU, after both driver and IP MTU are configured:
ping <Pure-target-IP-on-this-storage-subnet> -f -l 8972
"@.Trim()
            $r.Risk = "Medium to High. A host-side jumbo-frame change without matching switch and storage-path configuration can interrupt iSCSI traffic."
            $r.AutomationClass = "Guided only"
            continue
        }

        if ($r.Category -eq "Configuration Drift") {
            $r.RecommendedAction = "Review the outlier host and remediate the underlying host-specific finding. Do not automatically normalize to the majority until the approved baseline is confirmed."
            $r.Risk = "Advisory only. The majority value is a comparison baseline, not proof of the approved design."
            $r.AutomationClass = "Guided only"
            continue
        }

        if (-not $r.AutomationClass) {
            $r.AutomationClass = "Guided only"
        }
    }
}

function Get-ResultCounts {
    $counts = @{
        PASS    = @($script:Results | Where-Object Result -eq "PASS").Count
        INFO    = @($script:Results | Where-Object Result -eq "INFO").Count
        WARNING = @($script:Results | Where-Object Result -eq "WARNING").Count
        FAIL    = @($script:Results | Where-Object Result -eq "FAIL").Count
    }
    $counts
}

function HtmlEncode {
    param([object]$Value)
    if ($null -eq $Value) { return "" }
    [System.Net.WebUtility]::HtmlEncode([string]$Value)
}

function Export-HtmlReport {
    param([string]$Path)

    $counts = Get-ResultCounts
    $overall = if ($counts.FAIL -gt 0) { "FAIL" } elseif ($counts.WARNING -gt 0) { "WARNING" } else { "PASS" }

    $hostText = if ($script:LastAuditHosts.Count -gt 0) { $script:LastAuditHosts -join ", " } else { "N/A" }
    $started = if ($script:AuditStarted) { $script:AuditStarted.ToString("yyyy-MM-dd HH:mm:ss") } else { "" }
    $completed = if ($script:AuditCompleted) { $script:AuditCompleted.ToString("yyyy-MM-dd HH:mm:ss") } else { "" }

    $severityOrder = @("FAIL","WARNING","INFO","PASS")
    $severityLabels = @{
        FAIL    = "Failures"
        WARNING = "Warnings"
        INFO    = "Information"
        PASS    = "Passed Checks"
    }

    $detailSections = New-Object System.Text.StringBuilder

    foreach ($severity in $severityOrder) {
        $severityRows = @($script:Results | Where-Object { $_.Result -eq $severity })
        if ($severityRows.Count -eq 0) { continue }

        $css = $severity.ToLowerInvariant()
        $openAttr = ""
        if ($severity -eq "FAIL" -and $counts.FAIL -gt 0) {
            $openAttr = " open"
        }

        [void]$detailSections.AppendLine((
            '<details class="severity-section severity-{0}"{1}>' -f $css,$openAttr
        ))
        [void]$detailSections.AppendLine((
            '<summary><span class="badge {0}">{1}</span> <span class="section-title">{2}</span> <span class="section-count">{3}</span></summary>' -f
            $css,
            (HtmlEncode $severity),
            (HtmlEncode $severityLabels[$severity]),
            $severityRows.Count
        ))
        [void]$detailSections.AppendLine('<div class="severity-body">')

        $hostGroups = @($severityRows | Group-Object Host | Sort-Object Name)
        foreach ($hostGroup in $hostGroups) {
            $hostRows = @($hostGroup.Group)

            [void]$detailSections.AppendLine('<details class="host-section">')
            [void]$detailSections.AppendLine((
                '<summary><span class="host-name">{0}</span> <span class="host-count">{1} check(s)</span></summary>' -f
                (HtmlEncode $hostGroup.Name),
                $hostRows.Count
            ))
            [void]$detailSections.AppendLine('<div class="host-body">')
            [void]$detailSections.AppendLine('<table>')
            [void]$detailSections.AppendLine('<thead><tr><th>Category</th><th>Check</th><th>Result</th><th>Current</th><th>Expected</th><th>Details</th></tr></thead>')
            [void]$detailSections.AppendLine('<tbody>')

            foreach ($r in @($hostRows | Sort-Object Category,Check)) {
                $rowCss = $r.Result.ToLowerInvariant()
                [void]$detailSections.AppendLine('<tr>')
                [void]$detailSections.AppendLine(('<td>{0}</td>' -f (HtmlEncode $r.Category)))
                [void]$detailSections.AppendLine(('<td>{0}</td>' -f (HtmlEncode $r.Check)))
                [void]$detailSections.AppendLine((
                    '<td><span class="badge {0}">{1}</span></td>' -f $rowCss,(HtmlEncode $r.Result)
                ))
                [void]$detailSections.AppendLine(('<td>{0}</td>' -f (HtmlEncode $r.Current)))
                [void]$detailSections.AppendLine(('<td>{0}</td>' -f (HtmlEncode $r.Expected)))
                [void]$detailSections.AppendLine(('<td>{0}</td>' -f (HtmlEncode $r.Details)))
                [void]$detailSections.AppendLine('</tr>')
            }

            [void]$detailSections.AppendLine('</tbody>')
            [void]$detailSections.AppendLine('</table>')
            [void]$detailSections.AppendLine('</div>')
            [void]$detailSections.AppendLine('</details>')
        }

        [void]$detailSections.AppendLine('</div>')
        [void]$detailSections.AppendLine('</details>')
    }

    $driftSummary = New-Object System.Text.StringBuilder
    $driftRows = @(
        $script:Results |
            Where-Object { $_.Category -eq "Configuration Drift" } |
            Sort-Object Check
    )

    if ($script:LastAuditHosts.Count -gt 1) {
        if ($driftRows.Count -eq 0) {
            [void]$driftSummary.AppendLine('<div class="drift-summary drift-clear">')
            [void]$driftSummary.AppendLine('<span class="badge pass">PASS</span> <b>No monitored host drift detected.</b>')
            [void]$driftSummary.AppendLine('<div class="drift-detail">The selected comparison fields are consistent across the audited hosts.</div>')
            [void]$driftSummary.AppendLine('</div>')
        }
        else {
            [void]$driftSummary.AppendLine('<div class="drift-summary drift-found">')
            [void]$driftSummary.AppendLine((
                '<span class="badge warning">WARNING</span> <b>{0} configuration drift item(s) detected.</b>' -f $driftRows.Count
            ))
            [void]$driftSummary.AppendLine('<div class="drift-list">')

            foreach ($r in $driftRows) {
                [void]$driftSummary.AppendLine('<div class="drift-item">')
                [void]$driftSummary.AppendLine(('<div class="drift-check">{0}</div>' -f (HtmlEncode $r.Check)))
                [void]$driftSummary.AppendLine(('<div><b>Difference:</b> {0}</div>' -f (HtmlEncode $r.Current)))
                if ($r.Details) {
                    [void]$driftSummary.AppendLine(('<div><b>Assessment:</b> {0}</div>' -f (HtmlEncode $r.Details)))
                }
                [void]$driftSummary.AppendLine('</div>')
            }

            [void]$driftSummary.AppendLine('</div>')
            [void]$driftSummary.AppendLine('</div>')
        }
    }

    $remRows = New-Object System.Text.StringBuilder
    $failItems = @(
        $script:Results |
            Where-Object { $_.Result -eq "FAIL" } |
            Sort-Object Host,Category,Check
    )
    $warningItems = @(
        $script:Results |
            Where-Object { $_.Result -eq "WARNING" } |
            Sort-Object Host,Category,Check
    )
    $actionable = @($failItems) + @($warningItems)

    if ($actionable.Count -eq 0) {
        [void]$remRows.AppendLine('<p>No remediation items were identified.</p>')
    }
    else {
        $remHostGroups = @($actionable | Group-Object Host | Sort-Object Name)

        foreach ($hostGroup in $remHostGroups) {
            $items = @($hostGroup.Group)

            [void]$remRows.AppendLine('<details class="rem-host">')
            [void]$remRows.AppendLine((
                '<summary><span class="host-name">{0}</span> <span class="host-count">{1} remediation item(s)</span></summary>' -f
                (HtmlEncode $hostGroup.Name),
                $items.Count
            ))
            [void]$remRows.AppendLine('<div class="rem-host-body">')

            foreach ($r in $items) {
                $itemCss = $r.Result.ToLowerInvariant()
                [void]$remRows.AppendLine(('<details class="finding finding-{0}">' -f $itemCss))
                [void]$remRows.AppendLine((
                    '<summary><span class="badge {0}">{1}</span> {2}</summary>' -f
                    $itemCss,
                    (HtmlEncode $r.Result),
                    (HtmlEncode $r.Check)
                ))
                [void]$remRows.AppendLine('<div class="finding-body">')
                [void]$remRows.AppendLine(('<p><b>Current:</b> {0}</p>' -f (HtmlEncode $r.Current)))
                [void]$remRows.AppendLine(('<p><b>Expected:</b> {0}</p>' -f (HtmlEncode $r.Expected)))

                if ($r.Details) {
                    [void]$remRows.AppendLine(('<p><b>Why it matters:</b> {0}</p>' -f (HtmlEncode $r.Details)))
                }
                if ($r.RecommendedAction) {
                    [void]$remRows.AppendLine(('<p><b>Recommended action:</b> {0}</p>' -f (HtmlEncode $r.RecommendedAction)))
                }
                elseif ($r.Remediation) {
                    [void]$remRows.AppendLine(('<p><b>Recommended action:</b> {0}</p>' -f (HtmlEncode $r.Remediation)))
                }
                if ($r.AutomationClass) {
                    [void]$remRows.AppendLine(('<p><b>Remediation class:</b> {0}</p>' -f (HtmlEncode $r.AutomationClass)))
                }
                if ($r.Risk) {
                    [void]$remRows.AppendLine(('<p><b>Risk:</b> {0}</p>' -f (HtmlEncode $r.Risk)))
                }
                if ($r.RemediationCommand) {
                    [void]$remRows.AppendLine('<p><b>Command:</b></p>')
                    [void]$remRows.AppendLine(('<pre><code>{0}</code></pre>' -f (HtmlEncode $r.RemediationCommand)))
                }
                if ($r.Verification) {
                    [void]$remRows.AppendLine('<p><b>Verification:</b></p>')
                    [void]$remRows.AppendLine(('<pre><code>{0}</code></pre>' -f (HtmlEncode $r.Verification)))
                }
                if ($r.RollbackCommand) {
                    [void]$remRows.AppendLine('<p><b>Rollback:</b></p>')
                    [void]$remRows.AppendLine(('<pre><code>{0}</code></pre>' -f (HtmlEncode $r.RollbackCommand)))
                }

                [void]$remRows.AppendLine('</div>')
                [void]$remRows.AppendLine('</details>')
            }

            [void]$remRows.AppendLine('</div>')
            [void]$remRows.AppendLine('</details>')
        }
    }

    $template = @'
<!DOCTYPE html>
<html>
<head>
<meta charset="utf-8">
<title>Pure Storage Host Readiness Report</title>
<style>
:root {
    --pass-bg: #dafbe1;
    --pass-border: #2da44e;
    --pass-text: #116329;
    --info-bg: #ddf4ff;
    --info-border: #54aeff;
    --info-text: #0969da;
    --warning-bg: #fff8c5;
    --warning-border: #d4a72c;
    --warning-text: #7d4e00;
    --fail-bg: #ffebe9;
    --fail-border: #cf222e;
    --fail-text: #a40e26;
    --border: #d0d7de;
    --muted: #57606a;
    --panel: #f6f8fa;
}
body { font-family: Segoe UI, Arial, sans-serif; margin: 28px; color: #202124; background: #fff; }
h1 { margin-bottom: 4px; }
h2 { margin-top: 30px; border-bottom: 1px solid var(--border); padding-bottom: 6px; }
.meta { color: var(--muted); margin-bottom: 20px; line-height: 1.55; }
.audit-banner { background: #eef4ff; border: 1px solid #9db7e5; padding: 12px; margin: 18px 0; font-weight: 600; }
.cards { display: grid; grid-template-columns: repeat(4, minmax(130px, 1fr)); gap: 12px; margin: 16px 0 22px 0; max-width: 760px; }
.card { border: 1px solid var(--border); border-left-width: 5px; border-radius: 7px; padding: 12px 16px; }
.card b { font-size: 24px; display:block; margin-bottom: 2px; }
.card.pass { background:var(--pass-bg); border-color:var(--pass-border); color:var(--pass-text); }
.card.info { background:var(--info-bg); border-color:var(--info-border); color:var(--info-text); }
.card.warning { background:var(--warning-bg); border-color:var(--warning-border); color:var(--warning-text); }
.card.fail { background:var(--fail-bg); border-color:var(--fail-border); color:var(--fail-text); }
.badge { display:inline-block; padding: 2px 7px; border-radius: 10px; font-weight: 700; white-space: nowrap; }
.badge.pass { background:var(--pass-bg); color:var(--pass-text); }
.badge.info { background:var(--info-bg); color:var(--info-text); }
.badge.warning { background:var(--warning-bg); color:var(--warning-text); }
.badge.fail { background:var(--fail-bg); color:var(--fail-text); }
details { border: 1px solid var(--border); border-radius: 7px; margin: 10px 0; background: #fff; }
summary { cursor: pointer; user-select: none; padding: 10px 12px; font-weight: 600; }
summary:hover { background: #f6f8fa; }
details[open] > summary { border-bottom: 1px solid var(--border); }
.severity-section { border-left-width: 5px; }
.severity-fail { border-left-color:var(--fail-border); }
.severity-warning { border-left-color:var(--warning-border); }
.severity-info { border-left-color:var(--info-border); }
.severity-pass { border-left-color:var(--pass-border); }
.section-title { margin-left: 6px; }
.section-count, .host-count { color: var(--muted); font-weight: 400; margin-left: 8px; }
.severity-body { padding: 6px 12px 12px 12px; }
.host-section { margin: 8px 0; background:#fcfcfd; }
.host-name { font-weight:700; }
.host-body { padding: 0 10px 10px 10px; overflow-x:auto; }
table { border-collapse: collapse; width: 100%; font-size: 13px; margin-top: 10px; }
th, td { border: 1px solid var(--border); padding: 7px; text-align: left; vertical-align: top; }
th { background: var(--panel); }
tr:nth-child(even) td { background:#fbfcfd; }
.rem-host { margin-bottom:12px; }
.rem-host-body { padding: 6px 12px 12px 12px; }
.finding { margin:10px 0; }
.finding-fail { border-left:4px solid var(--fail-border); }
.finding-warning { border-left:4px solid var(--warning-border); }
.finding-body { padding: 2px 14px 10px 14px; background:#fafafa; }
pre { background:#0d1117; color:#f0f6fc; border-radius:6px; padding:10px 12px; overflow-x:auto; white-space:pre-wrap; }
code { font-family: Consolas, "Courier New", monospace; font-size:12px; }
.drift-summary { border:1px solid var(--border); border-left-width:5px; border-radius:7px; padding:12px 14px; margin:12px 0 22px 0; }
.drift-clear { background:var(--pass-bg); border-left-color:var(--pass-border); }
.drift-found { background:var(--warning-bg); border-left-color:var(--warning-border); }
.drift-detail { margin-top:7px; color:var(--muted); }
.drift-list { margin-top:10px; }
.drift-item { background:#fff; border:1px solid var(--border); border-radius:6px; padding:9px 11px; margin-top:8px; }
.mpio-summary { margin:12px 0 22px 0; }
.mpio-summary table { margin-top:8px; }
.mpio-summary td, .mpio-summary th { white-space:nowrap; }
.mpio-summary td:last-child, .mpio-summary th:last-child { white-space:normal; }
.mpio-status-pass { color:var(--pass-text); font-weight:700; }
.mpio-status-info { color:var(--info-text); font-weight:700; }
.mpio-status-warning { color:var(--warning-text); font-weight:700; }
.mpio-status-fail { color:var(--fail-text); font-weight:700; }
.device-summary { margin:12px 0 22px 0; }
.device-summary table { margin-top:8px; }
.device-summary td:nth-child(3), .device-summary th:nth-child(3) { white-space:normal; }
.drift-check { font-weight:700; margin-bottom:4px; }
.small { font-size: 12px; color:var(--muted); margin-top:24px; }
@media (max-width: 800px) {
    body { margin:14px; }
    .cards { grid-template-columns: repeat(2, 1fr); }
}
</style>
</head>
<body>
<h1>Pure Storage Host Readiness Report</h1>
<div class="meta">
<b>Hosts:</b> __HOSTS__<br>
<b>Audit started:</b> __STARTED__<br>
<b>Audit completed:</b> __COMPLETED__<br>
<b>Tool version:</b> __VERSION__<br>
<b>Overall status:</b> <span class="badge __OVERALLCSS__">__OVERALL__</span>
</div>

<div class="audit-banner">AUDIT MODE - No configuration changes were performed. Remediation commands are advisory and are not executed by this tool.</div>

<div class="cards">
<div class="card fail"><b>__FAILCOUNT__</b>FAIL</div>
<div class="card warning"><b>__WARNINGCOUNT__</b>WARNING</div>
<div class="card info"><b>__INFOCOUNT__</b>INFO</div>
<div class="card pass"><b>__PASSCOUNT__</b>PASS</div>
</div>

__DRIFTSECTION__


__MPIOSUMMARY__

__PUREDEVICESUMMARY__

<h2>Detailed Results</h2>
__DETAILS__

<h2>Remediation Items</h2>
__REMEDIATION__

<p class="small">
This report is advisory. Review remediation items against the approved Pure Storage, Windows Server,
Hyper-V, Failover Cluster, and network design before making production changes.
</p>
</body>
</html>
'@

    $mpioSummary = New-Object System.Text.StringBuilder
    [void]$mpioSummary.AppendLine('<h2>MPIO Summary</h2>')
    [void]$mpioSummary.AppendLine('<div class="mpio-summary">')
    [void]$mpioSummary.AppendLine('<table>')
    [void]$mpioSummary.AppendLine('<thead><tr><th>Host</th><th>MPIO Feature</th><th>PURE MSDSM</th><th>Current Policy</th><th>Expected</th><th>Pure Disks</th><th>Active iSCSI Sessions</th><th>Max Paths / Device</th><th>Windows Max</th><th>Status</th></tr></thead>')
    [void]$mpioSummary.AppendLine('<tbody>')

    foreach ($mpioHost in $script:LastAuditHosts) {
        $hostResults = @($script:Results | Where-Object { $_.Host -eq $mpioHost })

        $feature = $hostResults | Where-Object { $_.Check -eq "Multipath-IO feature" } | Select-Object -First 1
        $msdsm = $hostResults | Where-Object { $_.Check -eq "PURE FlashArray MSDSM registration" } | Select-Object -First 1
        $policy = $hostResults | Where-Object { $_.Check -eq "Pure MPIO load-balancing policy" } | Select-Object -First 1
        $pureDisks = $hostResults | Where-Object { $_.Check -eq "Pure disks visible to Windows" } | Select-Object -First 1
        $sessions = $hostResults | Where-Object { $_.Check -eq "Active iSCSI sessions" } | Select-Object -First 1
        $pathCountFindings = @($hostResults | Where-Object { $_.CheckId -like "PureRuntime.DiskMpioPathCount.*" })

        $observedPathCounts = @(
            $pathCountFindings |
                ForEach-Object {
                    $parsed = 0
                    if ([int]::TryParse([string]$_.Current, [ref]$parsed)) { $parsed }
                } |
                Where-Object { $_ -gt 0 }
        )

        $maxPathCountText = if ($observedPathCounts.Count -gt 0) {
            [string](($observedPathCounts | Measure-Object -Maximum).Maximum)
        } else {
            "Not available"
        }

        $featureText = if ($feature) { [string]$feature.Current } else { "Not checked" }
        $msdsmText = if ($msdsm) { [string]$msdsm.Current } else { "Not checked" }
        $policyText = if ($policy) { [string]$policy.Current } else { "Not available" }
        $expectedText = if ($policy) { [string]$policy.Expected } else { "Pure Recommended (Auto)" }
        $diskText = if ($pureDisks) { [string]$pureDisks.Current } else { "Not checked" }
        $sessionText = if ($sessions) { [string]$sessions.Current } else { "Not checked" }

        $mpioRelevant = @($feature,$msdsm,$policy) + @($pathCountFindings) | Where-Object { $_ }
        $mpioSeverity = "PASS"

        if (@($mpioRelevant | Where-Object { $_.Result -eq "FAIL" }).Count -gt 0) {
            $mpioSeverity = "FAIL"
        }
        elseif (@($mpioRelevant | Where-Object { $_.Result -eq "WARNING" }).Count -gt 0) {
            $mpioSeverity = "WARNING"
        }
        elseif (-not $policy -or $diskText -eq "0") {
            $mpioSeverity = "INFO"
        }

        $statusClass = switch ($mpioSeverity) {
            "FAIL" { "mpio-status-fail" }
            "WARNING" { "mpio-status-warning" }
            "INFO" { "mpio-status-info" }
            default { "mpio-status-pass" }
        }

        [void]$mpioSummary.AppendLine(
            "<tr>" +
            "<td>$(HtmlEncode $mpioHost)</td>" +
            "<td>$(HtmlEncode $featureText)</td>" +
            "<td>$(HtmlEncode $msdsmText)</td>" +
            "<td>$(HtmlEncode $policyText)</td>" +
            "<td>$(HtmlEncode $expectedText)</td>" +
            "<td>$(HtmlEncode $diskText)</td>" +
            "<td>$(HtmlEncode $sessionText)</td>" +
            "<td>$(HtmlEncode $maxPathCountText)</td>" +
            "<td>$(HtmlEncode ([string]$script:WindowsMpioMaxPathsPerDevice))</td>" +
            "<td class='$statusClass'>$(HtmlEncode $mpioSeverity)</td>" +
            "</tr>"
        )
    }

    [void]$mpioSummary.AppendLine('</tbody></table>')
    [void]$mpioSummary.AppendLine('<div class="small" style="margin-top:8px;">The summary shows host-level MPIO readiness and the maximum observed path count for any safely correlated Pure device on each host. Windows supports a maximum of 32 MPIO paths per device. Host/global policy is not treated as proof of an existing device policy.</div>')
    [void]$mpioSummary.AppendLine('</div>')

    $pureDeviceSummary = New-Object System.Text.StringBuilder
    [void]$pureDeviceSummary.AppendLine('<h2>Pure Device MPIO / ALUA Summary</h2>')
    [void]$pureDeviceSummary.AppendLine('<div class="device-summary">')
    [void]$pureDeviceSummary.AppendLine('<table>')
    [void]$pureDeviceSummary.AppendLine('<thead><tr><th>Host</th><th>Device</th><th>Runtime State</th><th>Expected</th><th>Status</th><th>Details</th></tr></thead>')
    [void]$pureDeviceSummary.AppendLine('<tbody>')

    foreach ($deviceHost in $script:LastAuditHosts) {
        $deviceRows = @(
            $script:Results |
                Where-Object {
                    $_.Host -eq $deviceHost -and
                    $_.Category -eq "Pure Device MPIO / ALUA"
                } |
                Sort-Object Check
        )

        if ($deviceRows.Count -eq 0) {
            $diskFinding = $script:Results |
                Where-Object { $_.Host -eq $deviceHost -and $_.CheckId -eq "iSCSI.PureDisks" } |
                Select-Object -First 1

            $stateText = if ($diskFinding -and [string]$diskFinding.Current -eq "0") {
                "No Pure disks visible"
            } else {
                "No safely correlated per-device runtime data"
            }

            [void]$pureDeviceSummary.AppendLine(
                "<tr>" +
                "<td>$(HtmlEncode $deviceHost)</td>" +
                "<td>N/A</td>" +
                "<td>$(HtmlEncode $stateText)</td>" +
                "<td>Runtime device validation begins when Pure MPIO devices are visible and correlatable</td>" +
                "<td class='mpio-status-info'>INFO</td>" +
                "<td>No device-level policy or ALUA judgment is inferred.</td>" +
                "</tr>"
            )
            continue
        }

        foreach ($deviceRow in $deviceRows) {
            $deviceStatusClass = switch ([string]$deviceRow.Result) {
                "FAIL" { "mpio-status-fail" }
                "WARNING" { "mpio-status-warning" }
                "INFO" { "mpio-status-info" }
                default { "mpio-status-pass" }
            }

            [void]$pureDeviceSummary.AppendLine(
                "<tr>" +
                "<td>$(HtmlEncode $deviceHost)</td>" +
                "<td>$(HtmlEncode $deviceRow.Check)</td>" +
                "<td>$(HtmlEncode $deviceRow.Current)</td>" +
                "<td>$(HtmlEncode $deviceRow.Expected)</td>" +
                "<td class='$deviceStatusClass'>$(HtmlEncode $deviceRow.Result)</td>" +
                "<td>$(HtmlEncode $deviceRow.Details)</td>" +
                "</tr>"
            )
        }
    }

    [void]$pureDeviceSummary.AppendLine('</tbody></table>')
    [void]$pureDeviceSummary.AppendLine('<div class="small" style="margin-top:8px;">Per-device policy names come from Windows/MSDSM runtime data. ALUA state counts come from DSM_QueryLBPolicy_V2. RRWS is reported explicitly and is not silently remediated or automatically treated as equivalent to the host/global RR setting.</div>')
    [void]$pureDeviceSummary.AppendLine('</div>')

    $html = $template
    $html = $html.Replace("__HOSTS__", (HtmlEncode $hostText))
    $html = $html.Replace("__STARTED__", (HtmlEncode $started))
    $html = $html.Replace("__COMPLETED__", (HtmlEncode $completed))
    $html = $html.Replace("__VERSION__", (HtmlEncode $script:ToolVersion))
    $html = $html.Replace("__OVERALLCSS__", $overall.ToLowerInvariant())
    $html = $html.Replace("__OVERALL__", (HtmlEncode $overall))
    $html = $html.Replace("__FAILCOUNT__", [string]$counts.FAIL)
    $html = $html.Replace("__WARNINGCOUNT__", [string]$counts.WARNING)
    $html = $html.Replace("__INFOCOUNT__", [string]$counts.INFO)
    $html = $html.Replace("__PASSCOUNT__", [string]$counts.PASS)

    $driftSectionHtml = ""
    if ($script:LastAuditHosts.Count -gt 1) {
        $driftSectionHtml = "<h2>Host Drift Summary</h2>`r`n" + $driftSummary.ToString()
    }

    $html = $html.Replace("__DRIFTSECTION__", $driftSectionHtml)
    $html = $html.Replace("__MPIOSUMMARY__", $mpioSummary.ToString())
    $html = $html.Replace("__PUREDEVICESUMMARY__", $pureDeviceSummary.ToString())
    $html = $html.Replace("__DETAILS__", $detailSections.ToString())
    $html = $html.Replace("__REMEDIATION__", $remRows.ToString())

    Set-Content -Path $Path -Value $html -Encoding UTF8
}


function Show-FullUserDocumentation {
    try {
        $HelpRoot = Join-Path $env:LOCALAPPDATA "PureStorage-Host-Validation-Readiness\Help"
        if (-not (Test-Path $HelpRoot)) {
            New-Item -ItemType Directory -Path $HelpRoot -Force | Out-Null
        }

        $HelpPath = Join-Path $HelpRoot ("PureStorage-Host-Validation-Readiness-v{0}-Help.html" -f $script:ToolVersion)

        $Version = [System.Net.WebUtility]::HtmlEncode([string]$script:ToolVersion)

        $HelpHtml = @"
<!DOCTYPE html>
<html>
<head>
<meta charset="utf-8">
<title>Pure Storage Host Validation / Readiness - Help</title>
<style>
:root {
    --pure:#ff6b00;
    --ink:#202124;
    --muted:#57606a;
    --border:#d0d7de;
    --panel:#f6f8fa;
    --blue:#0969da;
    --green:#116329;
    --yellow:#7d4e00;
    --red:#a40e26;
}
* { box-sizing:border-box; }
body {
    margin:0;
    font-family:"Segoe UI", Arial, sans-serif;
    color:var(--ink);
    background:#fff;
    line-height:1.55;
}
header {
    background:#111827;
    color:white;
    padding:28px 34px;
    border-bottom:5px solid var(--pure);
}
header h1 { margin:0 0 4px 0; font-size:28px; }
header .subtitle { color:#d1d5db; }
.container {
    display:grid;
    grid-template-columns:260px minmax(0, 1fr);
    gap:28px;
    max-width:1320px;
    margin:0 auto;
    padding:28px 30px 50px 30px;
}
nav {
    position:sticky;
    top:18px;
    align-self:start;
    border:1px solid var(--border);
    border-radius:8px;
    padding:14px;
    background:#fff;
}
nav b { display:block; margin-bottom:8px; }
nav a {
    display:block;
    color:var(--blue);
    text-decoration:none;
    padding:5px 2px;
}
nav a:hover { text-decoration:underline; }
main { min-width:0; }
section {
    margin-bottom:34px;
    scroll-margin-top:20px;
}
h2 {
    margin:0 0 12px 0;
    padding-bottom:7px;
    border-bottom:1px solid var(--border);
}
h3 { margin-top:22px; }
.note, .warning, .success {
    border-left:5px solid;
    border-radius:6px;
    padding:12px 14px;
    margin:14px 0;
}
.note { background:#ddf4ff; border-color:#54aeff; }
.warning { background:#fff8c5; border-color:#d4a72c; }
.success { background:#dafbe1; border-color:#2da44e; }
table {
    border-collapse:collapse;
    width:100%;
    margin:12px 0 18px 0;
    font-size:14px;
}
th, td {
    border:1px solid var(--border);
    padding:8px 10px;
    text-align:left;
    vertical-align:top;
}
th { background:var(--panel); }
code, pre { font-family:Consolas, "Courier New", monospace; }
pre {
    background:#0d1117;
    color:#f0f6fc;
    padding:12px 14px;
    border-radius:6px;
    overflow-x:auto;
    white-space:pre-wrap;
}
kbd {
    border:1px solid #b6b6b6;
    border-bottom-width:2px;
    border-radius:4px;
    padding:1px 5px;
    background:#fafafa;
}
ul, ol { padding-left:24px; }
footer {
    color:var(--muted);
    border-top:1px solid var(--border);
    margin-top:34px;
    padding-top:14px;
    font-size:12px;
}
@media (max-width:900px) {
    .container { grid-template-columns:1fr; }
    nav { position:static; }
}
</style>
</head>
<body>
<header>
    <h1>Pure Storage Host Validation / Readiness</h1>
    <div class="subtitle">Full User Documentation &nbsp;•&nbsp; Version $Version</div>
</header>

<div class="container">
<nav>
    <b>Contents</b>
    <a href="#purpose">Purpose</a>
    <a href="#prerequisites">Prerequisites</a>
    <a href="#workflow">Recommended Workflow</a>
    <a href="#fields">Main Configuration Fields</a>
    <a href="#scopes">Audit Scopes</a>
    <a href="#activecluster">Pure ActiveCluster</a>
    <a href="#mpio">MPIO Policy</a>
    <a href="#paths">Windows MPIO Path Limit</a>
    <a href="#alua">ALUA Validation</a>
    <a href="#results">Result Severity</a>
    <a href="#report">HTML Report</a>
    <a href="#preconnection">Pre-Connection State</a>
    <a href="#postconnection">Post-Connection Validation</a>
    <a href="#remediation">Remediation Safety</a>
    <a href="#outofscope">Out of Scope</a>
    <a href="#troubleshooting">Troubleshooting</a>
</nav>

<main>
<section id="purpose">
<h2>Purpose</h2>
<p>Pure Storage Host Validation / Readiness is a read-only Windows host audit tool for Pure Storage FlashArray environments. It validates Windows, networking, iSCSI, MPIO, Hyper-V, Failover Cluster, Pure target connectivity, and optional Pure ActiveCluster host-side readiness.</p>
<div class="note"><b>Operating principle:</b> this tool answers, <i>“Is this Windows host correctly prepared and connected for Pure Storage?”</i> Configuration and remediation belong in the iSCSI Host Tool or an approved manual change workflow.</div>
<p>The validator does not configure hosts, create iSCSI sessions, initialize disks, create volumes, map LUNs, create CSVs, or modify FlashArray configuration.</p>
</section>

<section id="prerequisites">
<h2>Prerequisites</h2>
<ol>
<li>Run from Windows PowerShell 5.1 as an elevated administrator.</li>
<li>WinRM / PowerShell remoting must be available to remote target hosts.</li>
<li>The supplied Windows credential must have administrative rights on the target hosts.</li>
<li>For Pure target-connectivity tests, enter the Pure iSCSI target IP addresses.</li>
<li>For Hyper-V or Failover Cluster validation, enable the applicable audit scope.</li>
<li>For ActiveCluster validation, assign Pure targets to arrays and hosts to their local arrays in the GUI.</li>
</ol>
</section>

<section id="workflow">
<h2>Recommended Workflow</h2>
<ol>
<li>Enter the target Windows hosts.</li>
<li>Enter all intended Pure iSCSI target IP addresses.</li>
<li>Confirm the iSCSI NIC naming pattern and expected storage MTU.</li>
<li>Select the required audit scopes.</li>
<li>If ActiveCluster is used, configure topology, array names, target-to-array assignment, host-local-array mapping, MPIO policy, and minimum target paths.</li>
<li>Set the Windows credential or select <b>Use Current User</b>.</li>
<li>Run <b>Read-Only Audit</b>.</li>
<li>Review FAIL and WARNING results first.</li>
<li>Review Host Drift Summary and MPIO Summary.</li>
<li>Export the HTML report.</li>
<li>Perform approved remediation outside this validator.</li>
<li>Re-run the audit to verify the resulting state.</li>
</ol>
</section>

<section id="fields">
<h2>Main Configuration Fields</h2>
<h3>Target Hosts</h3>
<p>Enter one Windows host per line. The field starts blank intentionally so the administrative workstation is not automatically audited.</p>
<pre>host01
host02
host03</pre>

<h3>Pure iSCSI Target IPs</h3>
<p>Enter every Pure iSCSI target IP that should be reachable from the audited hosts, one per line. The validator tests TCP/3260 and records the Windows interface and source address selected for the route.</p>

<h3>iSCSI NIC Name Pattern</h3>
<p>Default: <code>iSCSI*</code>. This pattern identifies dedicated Windows storage NICs.</p>

<h3>Expected Storage MTU</h3>
<p>Default: <code>9000</code>. The validator compares the intended storage MTU to the Windows IP-interface MTU and the NIC driver Jumbo Packet setting.</p>
<div class="warning"><b>MTU/Jumbo remediation is never automatic.</b> End-to-end switch, VLAN, host, and Pure target support must be verified first.</div>
</section>

<section id="scopes">
<h2>Audit Scopes</h2>
<table>
<thead><tr><th>Scope</th><th>What It Validates</th></tr></thead>
<tbody>
<tr><td>Windows / Network</td><td>Host reachability, storage NIC discovery, IPv4 configuration, DNS registration, DNS servers, persistent default routes, interface state, and related Windows network settings.</td></tr>
<tr><td>iSCSI / MPIO</td><td>Microsoft iSCSI Initiator service, Multipath-IO installation, PURE FlashArray MSDSM registration, configured target portals, active sessions, and visible Pure disks.</td></tr>
<tr><td>Pure Target Connectivity</td><td>TCP/3260 reachability to every configured Pure target plus selected source NIC and source IP.</td></tr>
<tr><td>Hyper-V</td><td>Hyper-V role/service state, storage NIC use by vSwitches, and explicit Live Migration use.</td></tr>
<tr><td>Failover Cluster</td><td>Cluster membership, node state, storage-network cluster roles, quorum, physical disks, and CSV inventory.</td></tr>
<tr><td>Extended NIC Checks</td><td>Driver version/date, RSS, queue count/profile, flow control, checksum offload, LSO, RDMA observation, and Jumbo Packet state.</td></tr>
<tr><td>Pure ActiveCluster</td><td>Host-side topology, MPIO policy, runtime connectivity, ALUA, path counts, and locality.</td></tr>
<tr><td>Compare Hosts / Detect Drift</td><td>Configuration consistency across equivalent hosts.</td></tr>
</tbody>
</table>
</section>

<section id="activecluster">
<h2>Pure ActiveCluster</h2>
<h3>Topology</h3>
<table>
<thead><tr><th>Mode</th><th>Expected Behavior</th></tr></thead>
<tbody>
<tr><td>Uniform</td><td>Hosts are expected to have connectivity to both Pure arrays.</td></tr>
<tr><td>Non-Uniform</td><td>Hosts are evaluated using their designated local-array mapping.</td></tr>
</tbody>
</table>

<h3>Array Names</h3>
<p>Array A and Array B names are friendly report labels. They do not establish a FlashArray connection and do not modify array configuration.</p>

<h3>Target-to-Array Assignment</h3>
<p>The list is populated from the configured Pure iSCSI target IPs. Every target must be assigned to Array A or Array B before ActiveCluster validation can run.</p>

<h3>Host Local-Array Mapping</h3>
<p>The list is populated from Target Hosts. Each host is assigned the Pure array expected to be local/preferred for host-side topology validation. This does not modify the FlashArray preferred-array setting.</p>
</section>

<section id="mpio">
<h2>Pure MPIO Policy Validation</h2>
<p><b>Pure Recommended (Auto)</b> evaluates Pure Storage policy according to actual per-device path count when that runtime data is available.</p>

<table>
<thead><tr><th>Observed Paths per Pure Device</th><th>Policy Evaluation</th></tr></thead>
<tbody>
<tr><td>1-10</td><td>RR or LQD is valid. RR is identified as preferred.</td></tr>
<tr><td>11-32</td><td>LQD is expected.</td></tr>
<tr><td>More than 32</td><td>Hard FAIL for the Windows path-limit rule. Reduce presented paths.</td></tr>
<tr><td>Not yet available</td><td>Host/default policy is evaluated provisionally. Per-device policy becomes authoritative after Pure volumes are presented.</td></tr>
</tbody>
</table>

<p>The validator keeps two concepts separate:</p>
<ul>
<li><b>Host/global MSDSM policy readiness:</b> what newly discovered Pure devices are likely to inherit.</li>
<li><b>Per-device MPIO policy:</b> the actual policy of each visible Pure device. This becomes authoritative once storage is connected.</li>
</ul>

<p>A newly added path belongs to the existing MPIO device. Individual paths do not have their own load-balancing policy. If path expansion crosses the 10-path threshold, the validator re-evaluates the device policy.</p>
<div class="note"><b>RRWS:</b> Windows may report <b>Round Robin with Subset</b> for an ALUA-aware device. v1.5.0 reports RRWS explicitly. It does not silently treat the host/global RR default as proof of the device policy and does not automatically remediate RRWS without topology-specific Pure guidance.</div>
</section>

<section id="paths">
<h2>Windows MPIO Path Limit</h2>
<p>Windows supports a maximum of <b>32 MPIO paths per device</b>.</p>

<table>
<thead><tr><th>Path Count</th><th>Result</th><th>Meaning</th></tr></thead>
<tbody>
<tr><td>1-32</td><td style="color:var(--green);font-weight:700;">PASS</td><td>Within the Windows supported maximum.</td></tr>
<tr><td>&gt;32</td><td style="color:var(--red);font-weight:700;">FAIL</td><td>Exceeds the supported Windows MPIO path count.</td></tr>
<tr><td>Not correlated</td><td style="color:var(--blue);font-weight:700;">INFO</td><td>The validator cannot safely determine an authoritative per-device path count and does not guess.</td></tr>
</tbody>
</table>

<p>The MPIO Summary reports the maximum observed path count for any correlated Pure device on each host and shows the Windows maximum beside it.</p>
</section>

<section id="alua">
<h2>ALUA Validation</h2>
<p>When Pure disks are visible, the tool attempts read-only Microsoft DSM ALUA inspection through Windows WMI/CIM data.</p>
<p>Recognized states include:</p>
<ul>
<li>Active/Optimized</li>
<li>Active/Unoptimized</li>
<li>Standby</li>
<li>Unavailable</li>
<li>Not Used</li>
</ul>
<p>Uniform and Non-Uniform topology modes have different expected ALUA behavior. If the validator cannot safely correlate MSDSM/ALUA data with a Pure device, it reports INFO instead of inferring ownership.</p>
<p>The Pure Device MPIO / ALUA Summary reports the Windows/MSDSM policy name, path count, and aggregate Active/Optimized and Active/Unoptimized state counts for each safely identified Pure MPIO device.</p>
</section>

<section id="results">
<h2>Result Severity</h2>
<table>
<thead><tr><th>Severity</th><th>Meaning</th></tr></thead>
<tbody>
<tr><td style="color:var(--green);font-weight:700;">PASS</td><td>The observed state meets the validation rule.</td></tr>
<tr><td style="color:var(--blue);font-weight:700;">INFO</td><td>Informational state, build-stage observation, or a condition not yet authoritatively testable.</td></tr>
<tr><td style="color:var(--yellow);font-weight:700;">WARNING</td><td>The state differs from the recommended or expected configuration but is not a hard failure.</td></tr>
<tr><td style="color:var(--red);font-weight:700;">FAIL</td><td>The state violates a required rule or supported limit.</td></tr>
</tbody>
</table>
</section>

<section id="report">
<h2>HTML Report</h2>
<p>Use <b>Export HTML Report</b> after an audit. The exported report contains:</p>
<ul>
<li>Audit metadata and tool version</li>
<li>Overall status</li>
<li>PASS / INFO / WARNING / FAIL totals</li>
<li>Host Drift Summary</li>
<li>MPIO Summary</li>
<li>Pure Device MPIO / ALUA Summary</li>
<li>Detailed Results grouped by severity and host</li>
<li>Remediation Items with recommended action, risk, verification, and rollback guidance</li>
</ul>
<p><b>View HTML Report</b> opens the most recently exported report from the current application session.</p>
</section>

<section id="preconnection">
<h2>Expected Pre-Connection State</h2>
<div class="success">Before Pure volumes are presented, several INFO results are normal and do not represent failures.</div>
<ul>
<li>0 configured target portals</li>
<li>0 active iSCSI sessions</li>
<li>0 Pure disks</li>
<li>0 cluster physical disks</li>
<li>0 CSVs</li>
<li>ALUA validation = INFO</li>
<li>MPIO Max Paths / Device = Not available</li>
</ul>
</section>

<section id="postconnection">
<h2>Post-Storage Connection Validation</h2>
<p>After Pure volumes and iSCSI sessions exist, run the full audit again. The following checks then become authoritative:</p>
<ul>
<li>Runtime Pure iSCSI session and connection state</li>
<li>Source-NIC/source-IP path symmetry</li>
<li>Unexpected live target addresses</li>
<li>Per-Pure-device MPIO policy</li>
<li>Per-device Windows path-count limit</li>
<li>ALUA path states</li>
<li>ActiveCluster runtime topology</li>
</ul>
</section>

<section id="remediation">
<h2>Remediation Safety</h2>
<div class="warning"><b>This validator is read-only.</b> Remediation commands shown in the report are advisory and are never executed by this tool.</div>
<ul>
<li>Microsoft network bindings may later be suitable for confirmed remediation in the configuration tool.</li>
<li>Persistent default routes can be handled through an approved remediation workflow.</li>
<li>MTU/Jumbo changes remain guided-only.</li>
<li>ActiveCluster topology/pathing and ALUA corrections remain guided-only.</li>
<li>MPIO policy changes belong in the configuration tool and require explicit confirmation.</li>
</ul>
</section>

<section id="outofscope">
<h2>Out of Scope</h2>
<p>The validator does not:</p>
<ul>
<li>Create or delete Pure hosts</li>
<li>Create or modify Pure host groups</li>
<li>Create Pods or Protection Groups</li>
<li>Create volumes or assign LUNs</li>
<li>Connect volumes to hosts or host groups</li>
<li>Configure iSCSI target portals or sessions</li>
<li>Initialize or format disks</li>
<li>Create Failover Clusters or CSVs</li>
<li>Change MPIO policy</li>
<li>Change MTU or Jumbo Packet settings</li>
<li>Modify FlashArray preferred-array settings</li>
</ul>
</section>

<section id="troubleshooting">
<h2>Troubleshooting</h2>
<h3>No host results</h3>
<p>Verify host names, credentials, WinRM, firewall policy, and administrator rights.</p>

<h3>Pure target TCP test fails</h3>
<p>Verify target IP, VLAN/routing, switch configuration, source NIC selection, Pure iSCSI interface state, and TCP/3260 reachability.</p>

<h3>MPIO path count shows “Not available”</h3>
<p>This is expected before Pure disks are presented. If Pure disks are already visible, inspect Detailed Results for MSDSM/ALUA correlation information.</p>

<h3>ALUA remains INFO after storage is presented</h3>
<p>Inspect the Detailed Results. The validator intentionally refuses to infer ALUA ownership when the Windows data cannot be safely correlated.</p>

<h3>HTML audit report cannot be opened</h3>
<p>Export the report first and verify that the selected destination remains accessible.</p>
</section>

<footer>
Pure Storage Host Validation / Readiness &nbsp;•&nbsp; Version $Version<br>
Integrated documentation generated locally by the tool. No web connection is required.
</footer>
</main>
</div>
</body>
</html>
"@

        Set-Content -Path $HelpPath -Value $HelpHtml -Encoding UTF8 -Force
        Start-Process $HelpPath
    }
    catch {
        [System.Windows.MessageBox]::Show(
            "Unable to open the integrated HTML help.`n`n$($_.Exception.Message)",
            "Help Error",
            "OK",
            "Error"
        ) | Out-Null
    }
}

[xml]$Xaml = @'
<Window xmlns="http://schemas.microsoft.com/winfx/2006/xaml/presentation"
        xmlns:x="http://schemas.microsoft.com/winfx/2006/xaml"
        Title="Pure Storage Host Validation / Readiness"
        Height="900"
        Width="1500"
        MinHeight="760"
        MinWidth="1200"
        WindowStartupLocation="CenterScreen">
    <Grid Margin="10">
        <Grid.RowDefinitions>
            <RowDefinition Height="Auto"/>
            <RowDefinition Height="Auto"/>
            <RowDefinition Height="*"/>
            <RowDefinition Height="Auto"/>
        </Grid.RowDefinitions>

        <Border Grid.Row="0" BorderBrush="#7A8AA0" BorderThickness="1" Padding="10" Margin="0,0,0,8">
            <Grid>
                <Grid.ColumnDefinitions>
                    <ColumnDefinition Width="2*"/>
                    <ColumnDefinition Width="20"/>
                    <ColumnDefinition Width="2*"/>
                    <ColumnDefinition Width="20"/>
                    <ColumnDefinition Width="Auto"/>
                </Grid.ColumnDefinitions>

                <StackPanel Grid.Column="0">
                    <TextBlock Text="Target Hosts" FontWeight="Bold" Margin="0,0,0,4"/>
                    <TextBox x:Name="HostTextBox" Height="100" AcceptsReturn="True"
                             VerticalScrollBarVisibility="Auto" FontFamily="Consolas"/>
                </StackPanel>

                <StackPanel Grid.Column="2">
                    <TextBlock Text="Pure iSCSI Target IPs (all targets, optional)" FontWeight="Bold" Margin="0,0,0,4"/>
                    <TextBox x:Name="TargetTextBox" Height="100" AcceptsReturn="True"
                             VerticalScrollBarVisibility="Auto" FontFamily="Consolas"/>
                </StackPanel>

                <StackPanel Grid.Column="4" VerticalAlignment="Center">
                    <TextBlock Text="iSCSI NIC name pattern" FontWeight="Bold" Margin="0,0,0,4"/>
                    <TextBox x:Name="NicPatternTextBox" Text="iSCSI*" Width="170" Height="25"/>
                    <TextBlock Text="Expected storage MTU" FontWeight="Bold" Margin="0,10,0,4"/>
                    <TextBox x:Name="ExpectedMtuTextBox" Text="9000" Width="170" Height="25"/>
                    <Button x:Name="SetCredentialButton" Content="Set Windows Credential" Width="170" Height="30" Margin="0,10,0,0"/>
                    <Button x:Name="UseCurrentUserButton" Content="Use Current User" Width="170" Height="30" Margin="0,6,0,0"/>
                </StackPanel>
            </Grid>
        </Border>

        <Border Grid.Row="1" BorderBrush="#7A8AA0" BorderThickness="1" Padding="10" Margin="0,0,0,8">
            <Grid>
                <Grid.RowDefinitions>
                    <RowDefinition Height="Auto"/>
                    <RowDefinition Height="Auto"/>
                    <RowDefinition Height="Auto"/>
                </Grid.RowDefinitions>

                <WrapPanel Grid.Row="0">
                    <CheckBox x:Name="WindowsNetworkCheckBox" Content="Windows / Network" IsChecked="True" Margin="0,0,20,6"/>
                    <CheckBox x:Name="IscsiMpioCheckBox" Content="iSCSI / MPIO" IsChecked="True" Margin="0,0,20,6"/>
                    <CheckBox x:Name="TargetConnectivityCheckBox" Content="Pure Target Connectivity" IsChecked="True" Margin="0,0,20,6"/>
                    <CheckBox x:Name="HyperVCheckBox" Content="Hyper-V" IsChecked="False" Margin="0,0,20,6"/>
                    <CheckBox x:Name="ClusterCheckBox" Content="Failover Cluster" IsChecked="False" Margin="0,0,20,6"/>
                    <CheckBox x:Name="ExtendedCheckBox" Content="Extended NIC Checks" IsChecked="False" Margin="0,0,20,6"/>
                    <CheckBox x:Name="ActiveClusterCheckBox" Content="Pure ActiveCluster" IsChecked="False" Margin="0,0,20,6"/>
                    <CheckBox x:Name="CompareHostsCheckBox" Content="Compare Hosts / Detect Drift" IsChecked="True" Margin="0,0,20,6"/>
                </WrapPanel>

                
                <Border Grid.Row="1" BorderBrush="#D0D7DE" BorderThickness="1" Padding="8" Margin="0,6,0,0">
                    <Grid>
                        <Grid.ColumnDefinitions>
                            <ColumnDefinition Width="Auto"/>
                            <ColumnDefinition Width="16"/>
                            <ColumnDefinition Width="1.1*"/>
                            <ColumnDefinition Width="16"/>
                            <ColumnDefinition Width="1.1*"/>
                        </Grid.ColumnDefinitions>

                        <StackPanel Grid.Column="0">
                            <TextBlock Text="ActiveCluster topology" FontWeight="Bold" Margin="0,0,0,4"/>
                            <ComboBox x:Name="ActiveClusterTopologyComboBox" Width="150" Height="25" SelectedIndex="0">
                                <ComboBoxItem Content="Uniform"/>
                                <ComboBoxItem Content="Non-Uniform"/>
                            </ComboBox>

                            <TextBlock Text="Expected MPIO policy" FontWeight="Bold" Margin="0,8,0,4"/>
                            <ComboBox x:Name="ExpectedMpioPolicyComboBox" Width="150" Height="25" SelectedIndex="0">
                                <ComboBoxItem Content="Pure Recommended (Auto)"/>
                                <ComboBoxItem Content="RR"/>
                                <ComboBoxItem Content="LQD"/>
                            </ComboBox>

                            <TextBlock Text="Min target paths / array" FontWeight="Bold" Margin="0,8,0,4"/>
                            <TextBox x:Name="MinimumPathsTextBox" Text="2" Width="150" Height="25"/>
                        </StackPanel>

                        <StackPanel Grid.Column="2">
                            <Grid>
                                <Grid.ColumnDefinitions>
                                    <ColumnDefinition Width="1*"/>
                                    <ColumnDefinition Width="10"/>
                                    <ColumnDefinition Width="1*"/>
                                </Grid.ColumnDefinitions>

                                <StackPanel Grid.Column="0">
                                    <TextBlock Text="Pure Array A name" FontWeight="Bold" Margin="0,0,0,4"/>
                                    <TextBox x:Name="ArrayANameTextBox" Text="Array A" Height="25"/>
                                </StackPanel>

                                <StackPanel Grid.Column="2">
                                    <TextBlock Text="Pure Array B name" FontWeight="Bold" Margin="0,0,0,4"/>
                                    <TextBox x:Name="ArrayBNameTextBox" Text="Array B" Height="25"/>
                                </StackPanel>
                            </Grid>

                            <TextBlock Text="Pure target-to-array assignment" FontWeight="Bold" Margin="0,8,0,4"/>
                            <DataGrid x:Name="TargetArrayMappingGrid" Height="198" AutoGenerateColumns="False"
                                      CanUserAddRows="False" CanUserDeleteRows="False" IsReadOnly="False"
                                      HeadersVisibility="Column">
                                <DataGrid.Columns>
                                    <DataGridTextColumn Header="Target IP" Binding="{Binding TargetIP}" Width="*"
                                                        IsReadOnly="True"/>
                                    <DataGridTemplateColumn Header="Array" Width="145">
                                        <DataGridTemplateColumn.CellTemplate>
                                            <DataTemplate>
                                                <StackPanel Orientation="Horizontal" HorizontalAlignment="Center">
                                                    <RadioButton Content="A" Margin="4,0,10,0"
                                                                 GroupName="{Binding TargetIP, StringFormat=Target_{0}}"
                                                                 IsChecked="{Binding IsArrayA, Mode=TwoWay, UpdateSourceTrigger=PropertyChanged}"/>
                                                    <RadioButton Content="B" Margin="4,0,4,0"
                                                                 GroupName="{Binding TargetIP, StringFormat=Target_{0}}"
                                                                 IsChecked="{Binding IsArrayB, Mode=TwoWay, UpdateSourceTrigger=PropertyChanged}"/>
                                                </StackPanel>
                                            </DataTemplate>
                                        </DataGridTemplateColumn.CellTemplate>
                                    </DataGridTemplateColumn>
                                </DataGrid.Columns>
                            </DataGrid>
                            <TextBlock Text="Populated automatically from Pure iSCSI Target IPs above. Select A or B."
                                       Foreground="#57606A" FontSize="11" Margin="0,3,0,0"/>
                        </StackPanel>

                        <StackPanel Grid.Column="4">
                            <TextBlock Text="Host local-array mapping" FontWeight="Bold" Margin="0,0,0,4"/>
                            <DataGrid x:Name="HostArrayMappingGrid" Height="198" AutoGenerateColumns="False"
                                      CanUserAddRows="False" CanUserDeleteRows="False" IsReadOnly="False"
                                      HeadersVisibility="Column">
                                <DataGrid.Columns>
                                    <DataGridTextColumn Header="Host" Binding="{Binding Host}" Width="*"
                                                        IsReadOnly="True"/>
                                    <DataGridTemplateColumn Header="Local Array" Width="145">
                                        <DataGridTemplateColumn.CellTemplate>
                                            <DataTemplate>
                                                <StackPanel Orientation="Horizontal" HorizontalAlignment="Center">
                                                    <RadioButton Content="A" Margin="4,0,10,0"
                                                                 GroupName="{Binding Host, StringFormat=Host_{0}}"
                                                                 IsChecked="{Binding IsArrayA, Mode=TwoWay, UpdateSourceTrigger=PropertyChanged}"/>
                                                    <RadioButton Content="B" Margin="4,0,4,0"
                                                                 GroupName="{Binding Host, StringFormat=Host_{0}}"
                                                                 IsChecked="{Binding IsArrayB, Mode=TwoWay, UpdateSourceTrigger=PropertyChanged}"/>
                                                </StackPanel>
                                            </DataTemplate>
                                        </DataGridTemplateColumn.CellTemplate>
                                    </DataGridTemplateColumn>
                                </DataGrid.Columns>
                            </DataGrid>
                            <TextBlock Text="Populated automatically from Target Hosts above. Select the local Pure array."
                                       Foreground="#57606A" FontSize="11" Margin="0,3,0,0"/>
                        </StackPanel>
                    </Grid>
                </Border>

<StackPanel Grid.Row="2" Orientation="Horizontal" Margin="0,8,0,0">
                    <Button x:Name="RunAuditButton" Content="Run Read-Only Audit" Width="160" Height="32" Margin="0,0,8,0"/>
                    <Button x:Name="ExportHtmlButton" Content="Export HTML Report" Width="150" Height="32" Margin="0,0,8,0" IsEnabled="False"/>
                    <Button x:Name="ViewHtmlButton" Content="View HTML Report" Width="140" Height="32" Margin="0,0,8,0" IsEnabled="False"/>
                    <Button x:Name="ClearButton" Content="Clear Results" Width="120" Height="32"/>
                    <TextBlock x:Name="AuditModeText" Text="AUDIT MODE - No configuration changes are performed."
                               FontWeight="Bold" Foreground="#254B87" VerticalAlignment="Center" Margin="20,0,0,0"/>
                </StackPanel>
            </Grid>
        </Border>

        <DataGrid x:Name="ResultsGrid" Grid.Row="2" AutoGenerateColumns="False" IsReadOnly="True"
                  CanUserAddRows="False" SelectionMode="Extended" SelectionUnit="FullRow"
                  HorizontalScrollBarVisibility="Auto" VerticalScrollBarVisibility="Auto">
            <DataGrid.Columns>
                <DataGridTextColumn Header="Host" Binding="{Binding Host}" Width="120"/>
                <DataGridTextColumn Header="Category" Binding="{Binding Category}" Width="150"/>
                <DataGridTextColumn Header="Check" Binding="{Binding Check}" Width="260"/>
                <DataGridTextColumn Header="Result" Binding="{Binding Result}" Width="90"/>
                <DataGridTextColumn Header="Current" Binding="{Binding Current}" Width="300"/>
                <DataGridTextColumn Header="Expected" Binding="{Binding Expected}" Width="280"/>
                <DataGridTextColumn Header="Details" Binding="{Binding Details}" Width="*"/>
            </DataGrid.Columns>
        </DataGrid>

        <StatusBar Grid.Row="3" Margin="0,8,0,0">
            <Grid Width="{Binding ActualWidth, RelativeSource={RelativeSource AncestorType=StatusBar}}">
                <Grid.ColumnDefinitions>
                    <ColumnDefinition Width="*"/>
                    <ColumnDefinition Width="Auto"/>
                    <ColumnDefinition Width="Auto"/>
                </Grid.ColumnDefinitions>
                <TextBlock x:Name="StatusText" Grid.Column="0" Text="Ready" VerticalAlignment="Center"/>
                <TextBlock x:Name="VersionText" Grid.Column="1" FontWeight="Bold" Foreground="#57606A"
                           Margin="12,0,8,0" VerticalAlignment="Center"/>
                <Button x:Name="DocumentationButton" Grid.Column="2" Content="Help"
                        Width="60" Height="24" Margin="0,0,8,0" Padding="8,0"/>
            </Grid>
        </StatusBar>
    </Grid>
</Window>
'@

$reader = New-Object System.Xml.XmlNodeReader $Xaml
$Window = [Windows.Markup.XamlReader]::Load($reader)

$HostTextBox                 = $Window.FindName("HostTextBox")
$TargetTextBox               = $Window.FindName("TargetTextBox")
$NicPatternTextBox           = $Window.FindName("NicPatternTextBox")
$ExpectedMtuTextBox          = $Window.FindName("ExpectedMtuTextBox")
$SetCredentialButton         = $Window.FindName("SetCredentialButton")
$UseCurrentUserButton        = $Window.FindName("UseCurrentUserButton")
$WindowsNetworkCheckBox      = $Window.FindName("WindowsNetworkCheckBox")
$IscsiMpioCheckBox           = $Window.FindName("IscsiMpioCheckBox")
$TargetConnectivityCheckBox  = $Window.FindName("TargetConnectivityCheckBox")
$HyperVCheckBox              = $Window.FindName("HyperVCheckBox")
$ClusterCheckBox             = $Window.FindName("ClusterCheckBox")
$ExtendedCheckBox            = $Window.FindName("ExtendedCheckBox")
$ActiveClusterCheckBox       = $Window.FindName("ActiveClusterCheckBox")
$ActiveClusterTopologyComboBox = $Window.FindName("ActiveClusterTopologyComboBox")
$ExpectedMpioPolicyComboBox   = $Window.FindName("ExpectedMpioPolicyComboBox")
$MinimumPathsTextBox          = $Window.FindName("MinimumPathsTextBox")
$ArrayANameTextBox            = $Window.FindName("ArrayANameTextBox")
$ArrayBNameTextBox            = $Window.FindName("ArrayBNameTextBox")
$TargetArrayMappingGrid        = $Window.FindName("TargetArrayMappingGrid")
$HostArrayMappingGrid          = $Window.FindName("HostArrayMappingGrid")
$CompareHostsCheckBox        = $Window.FindName("CompareHostsCheckBox")
$RunAuditButton              = $Window.FindName("RunAuditButton")
$ExportHtmlButton            = $Window.FindName("ExportHtmlButton")
$ViewHtmlButton              = $Window.FindName("ViewHtmlButton")
$ClearButton                 = $Window.FindName("ClearButton")
$DocumentationButton         = $Window.FindName("DocumentationButton")
$ResultsGrid                 = $Window.FindName("ResultsGrid")
$StatusText                  = $Window.FindName("StatusText")
$VersionText                 = $Window.FindName("VersionText")

$Window.Title = "Pure Storage Host Validation / Readiness v$($script:ToolVersion)"
$VersionText.Text = "Version $($script:ToolVersion)"

$ResultsGrid.ItemsSource = $script:Results

$script:HostArrayMappings = New-Object System.Collections.ObjectModel.ObservableCollection[object]
$script:TargetArrayMappings = New-Object System.Collections.ObjectModel.ObservableCollection[object]
$HostArrayMappingGrid.ItemsSource = $script:HostArrayMappings
$TargetArrayMappingGrid.ItemsSource = $script:TargetArrayMappings

function Refresh-ActiveClusterMappings {
    # Preserve current choices while rebuilding from the authoritative entry fields.
    $hostChoices = @{}
    foreach ($row in @($script:HostArrayMappings)) {
        $choice = "Unassigned"
        if ([bool]$row.IsArrayA) { $choice = "ArrayA" }
        elseif ([bool]$row.IsArrayB) { $choice = "ArrayB" }
        $hostChoices[[string]$row.Host] = $choice
    }

    $targetChoices = @{}
    foreach ($row in @($script:TargetArrayMappings)) {
        $choice = "Unassigned"
        if ([bool]$row.IsArrayA) { $choice = "ArrayA" }
        elseif ([bool]$row.IsArrayB) { $choice = "ArrayB" }
        $targetChoices[[string]$row.TargetIP] = $choice
    }

    $script:HostArrayMappings.Clear()
    foreach ($h in @(Get-HostList $HostTextBox.Text)) {
        $choice = if ($hostChoices.ContainsKey($h)) { $hostChoices[$h] } else { "Unassigned" }
        $script:HostArrayMappings.Add([pscustomobject]@{
            Host     = $h
            IsArrayA = ($choice -eq "ArrayA")
            IsArrayB = ($choice -eq "ArrayB")
        })
    }

    $script:TargetArrayMappings.Clear()
    foreach ($ip in @(Get-TargetList $TargetTextBox.Text)) {
        $choice = if ($targetChoices.ContainsKey($ip)) { $targetChoices[$ip] } else { "Unassigned" }
        $script:TargetArrayMappings.Add([pscustomobject]@{
            TargetIP = $ip
            IsArrayA = ($choice -eq "ArrayA")
            IsArrayB = ($choice -eq "ArrayB")
        })
    }
}


function Set-Status {
    param([string]$Text)
    $StatusText.Text = $Text
    $Window.Dispatcher.Invoke([action]{}, "Background")
}

function Set-Busy {
    param([bool]$Busy)
    $RunAuditButton.IsEnabled = -not $Busy
    $SetCredentialButton.IsEnabled = -not $Busy
    $UseCurrentUserButton.IsEnabled = -not $Busy
    $ClearButton.IsEnabled = -not $Busy
    $ExportHtmlButton.IsEnabled = (-not $Busy -and $script:Results.Count -gt 0)
    $ViewHtmlButton.IsEnabled = (-not $Busy -and $script:LastHtmlReportPath -and (Test-Path $script:LastHtmlReportPath))
    $Window.Cursor = if ($Busy) { [System.Windows.Input.Cursors]::Wait } else { [System.Windows.Input.Cursors]::Arrow }
    $Window.Dispatcher.Invoke([action]{}, "Background")
}


$HostTextBox.Add_TextChanged([System.Windows.Controls.TextChangedEventHandler]{
    Refresh-ActiveClusterMappings
})

$TargetTextBox.Add_TextChanged([System.Windows.Controls.TextChangedEventHandler]{
    Refresh-ActiveClusterMappings
})

$SetCredentialButton.Add_Click([System.Windows.RoutedEventHandler]{
    $cred = Get-Credential -Message "Enter Windows credentials for remote host validation"
    if ($cred) {
        $script:WindowsCredential = $cred
        Set-Status ("Windows credential set for {0}." -f $cred.UserName)
    }
})

$UseCurrentUserButton.Add_Click([System.Windows.RoutedEventHandler]{
    $script:WindowsCredential = $null
    Set-Status "Using the current Windows user for remote validation."
})

$ClearButton.Add_Click([System.Windows.RoutedEventHandler]{
    $script:Results.Clear()
    $script:LastAuditHosts = @()
    $script:AuditStarted = $null
    $script:AuditCompleted = $null
    $script:LastHtmlReportPath = $null
    $ExportHtmlButton.IsEnabled = $false
    $ViewHtmlButton.IsEnabled = $false
    Set-Status "Results cleared."
})

$RunAuditButton.Add_Click([System.Windows.RoutedEventHandler]{
    try {
        $hosts = @(Get-HostList $HostTextBox.Text)
        if ($hosts.Count -eq 0) {
        [System.Windows.MessageBox]::Show("Enter at least one Windows host.","No Hosts","OK","Information") | Out-Null
        return
    }

    $invalidHosts = @($hosts | Where-Object { -not (Test-HostNameSyntax $_) })
    if ($invalidHosts.Count -gt 0) {
        [System.Windows.MessageBox]::Show(
            ("One or more target host names are invalid:`n`n{0}" -f ($invalidHosts -join "`n")),
            "Invalid Host Name",
            "OK",
            "Warning"
        ) | Out-Null
        return
    }

    $duplicateHosts = @(
        $HostTextBox.Text -split "[`r`n,; ]+" |
            ForEach-Object { $_.Trim() } |
            Where-Object { $_ } |
            Group-Object { $_.ToUpperInvariant() } |
            Where-Object { $_.Count -gt 1 } |
            ForEach-Object { $_.Group[0] }
    )
    if ($duplicateHosts.Count -gt 0) {
        [System.Windows.MessageBox]::Show(
            ("Duplicate target host names were detected:`n`n{0}" -f ($duplicateHosts -join "`n")),
            "Duplicate Hosts",
            "OK",
            "Warning"
        ) | Out-Null
        return
    }

    $nicPattern = $NicPatternTextBox.Text.Trim()
    if (-not $nicPattern) { $nicPattern = "iSCSI*" }

    $expectedStorageMtu = 0
    if (-not [int]::TryParse($ExpectedMtuTextBox.Text.Trim(), [ref]$expectedStorageMtu) -or
        $expectedStorageMtu -lt 576 -or $expectedStorageMtu -gt 9216) {
        [System.Windows.MessageBox]::Show(
            "Expected storage MTU must be a whole number between 576 and 9216.",
            "Invalid Storage MTU",
            "OK",
            "Warning"
        ) | Out-Null
        return
    }

    $doWindows = [bool]$WindowsNetworkCheckBox.IsChecked
    $doIscsi   = [bool]$IscsiMpioCheckBox.IsChecked
    $doTargets = [bool]$TargetConnectivityCheckBox.IsChecked
    $doHyperV  = [bool]$HyperVCheckBox.IsChecked
    $doCluster = [bool]$ClusterCheckBox.IsChecked
    $doExtended = [bool]$ExtendedCheckBox.IsChecked
    $doActiveCluster = [bool]$ActiveClusterCheckBox.IsChecked
    $doCompare = [bool]$CompareHostsCheckBox.IsChecked

    $activeClusterTopology = "Disabled"
    $expectedMpioPolicy = "Pure Recommended (Auto)"
    $minimumPathsPerArray = 2
    $arrayATargets = @()
    $arrayBTargets = @()
    $arrayAName = "Array A"
    $arrayBName = "Array B"
    $preferredArrayMapping = ""

    if ($doActiveCluster) {
        if ($ActiveClusterTopologyComboBox.SelectedItem) {
            $activeClusterTopology = [string]$ActiveClusterTopologyComboBox.SelectedItem.Content
        }

        if ($ExpectedMpioPolicyComboBox.SelectedItem) {
            $expectedMpioPolicy = [string]$ExpectedMpioPolicyComboBox.SelectedItem.Content
        }

        if (-not [int]::TryParse($MinimumPathsTextBox.Text.Trim(), [ref]$minimumPathsPerArray) -or
            $minimumPathsPerArray -lt 1 -or $minimumPathsPerArray -gt 64) {
            [System.Windows.MessageBox]::Show(
                "Minimum target paths per array must be a whole number between 1 and 64.",
                "Invalid ActiveCluster Path Count",
                "OK",
                "Warning"
            ) | Out-Null
            return
        }

        Refresh-ActiveClusterMappings

        $arrayAName = $ArrayANameTextBox.Text.Trim()
        $arrayBName = $ArrayBNameTextBox.Text.Trim()
        if (-not $arrayAName) { $arrayAName = "Array A" }
        if (-not $arrayBName) { $arrayBName = "Array B" }

        $unassignedTargets = @(
            @($script:TargetArrayMappings) |
                Where-Object { -not [bool]$_.IsArrayA -and -not [bool]$_.IsArrayB }
        )
        if ($unassignedTargets.Count -gt 0) {
            [System.Windows.MessageBox]::Show(
                ("Assign every Pure target IP to Array A or Array B before running ActiveCluster validation.`n`nUnassigned:`n{0}" -f (($unassignedTargets | ForEach-Object { $_.TargetIP }) -join "`n")),
                "Unassigned Pure Targets",
                "OK",
                "Warning"
            ) | Out-Null
            return
        }

        $unassignedHosts = @(
            @($script:HostArrayMappings) |
                Where-Object { -not [bool]$_.IsArrayA -and -not [bool]$_.IsArrayB }
        )
        if ($unassignedHosts.Count -gt 0) {
            [System.Windows.MessageBox]::Show(
                ("Assign every target host to its local Pure array before running ActiveCluster validation.`n`nUnassigned:`n{0}" -f (($unassignedHosts | ForEach-Object { $_.Host }) -join "`n")),
                "Unassigned Hosts",
                "OK",
                "Warning"
            ) | Out-Null
            return
        }

        $arrayATargets = @(
            @($script:TargetArrayMappings) |
                Where-Object { [bool]$_.IsArrayA } |
                ForEach-Object { [string]$_.TargetIP }
        )
        $arrayBTargets = @(
            @($script:TargetArrayMappings) |
                Where-Object { [bool]$_.IsArrayB } |
                ForEach-Object { [string]$_.TargetIP }
        )

        $preferredArrayMapping = @(
            @($script:HostArrayMappings) |
                ForEach-Object {
                    $arrayKey = if ([bool]$_.IsArrayA) { "ArrayA" } else { "ArrayB" }
                    "{0}={1}" -f $_.Host,$arrayKey
                }
        ) -join "`r`n"

        if ($arrayATargets.Count -eq 0 -or $arrayBTargets.Count -eq 0) {
            [System.Windows.MessageBox]::Show(
                "Pure ActiveCluster validation is enabled, but Array A and/or Array B target IP groups are empty. The audit will continue with limited runtime topology validation.",
                "ActiveCluster Target Groups",
                "OK",
                "Information"
            ) | Out-Null
        }
    }

    $targets = @(Get-TargetList $TargetTextBox.Text)

    if ($doTargets -and $targets.Count -eq 0) {
        $answer = [System.Windows.MessageBox]::Show(
            "Pure Target Connectivity is selected, but no target IPs were entered.`n`nContinue without target connectivity checks?",
            "No Pure Target IPs",
            "YesNo",
            "Question"
        )
        if ($answer -ne "Yes") { return }
        $doTargets = $false
    }

    $script:Results.Clear()
    $script:LastAuditHosts = @($hosts)
    $script:AuditStarted = Get-Date
    $script:AuditCompleted = $null
    $script:LastHtmlReportPath = $null
    $ViewHtmlButton.IsEnabled = $false

    Set-Busy $true

    try {
        foreach ($hostName in $hosts) {
            Set-Status "Auditing $hostName..."

            try {
                $inventory = Invoke-RemoteReadOnly -ComputerName $hostName -ScriptBlock $InventoryScript -ArgumentList @(
                    $nicPattern,$doWindows,($doIscsi -or $doActiveCluster),$doHyperV,$doCluster,$doExtended
                ) | Select-Object -First 1

                Add-InventoryFindings -Inventory $inventory -NicPattern $nicPattern `
                    -DoWindowsNetwork $doWindows -DoIscsiMpio ($doIscsi -or $doActiveCluster) `
                    -DoHyperV $doHyperV -DoCluster $doCluster -DoExtended $doExtended `
                    -ExpectedStorageMtu $expectedStorageMtu `
                    -DoActiveCluster $doActiveCluster `
                    -ActiveClusterTopology $activeClusterTopology `
                    -ArrayATargets $arrayATargets `
                    -ArrayBTargets $arrayBTargets `
                    -PreferredArrayMapping $preferredArrayMapping `
                    -ExpectedMpioPolicy $expectedMpioPolicy `
                    -MinimumPathsPerArray $minimumPathsPerArray `
                    -ArrayAName $arrayAName `
                    -ArrayBName $arrayBName `
                    -ExpectedPureTargets $targets

                if ($doTargets) {
                    Set-Status "Testing Pure target connectivity from $hostName..."
                    $targetResults = @(Invoke-RemoteReadOnly -ComputerName $hostName -ScriptBlock $TargetTestScript -ArgumentList @(,$targets))
                    Add-TargetFindings -HostName $hostName -TargetResults $targetResults -NicPattern $nicPattern
                }
            }
            catch {
                Add-Result (New-Finding -HostName $hostName -Category "Host" -CheckId "Host.Connection" -Check "Remote audit" `
                    -Result "FAIL" -Current $_.Exception.Message -Expected "Successful read-only remote query" `
                    -Details "The tool could not complete the requested audit on this host." `
                    -Remediation "Verify DNS, WinRM/PowerShell remoting, firewall access, credentials, and administrative permissions." `
                    -Verification "Run the audit again and confirm the host returns validation results.")
            }
        }

        if ($doCompare) {
            Set-Status "Comparing host configuration..."
            Add-DriftFindings -Hosts $hosts
        }

        Add-GuidedRemediationMetadata
        $script:AuditCompleted = Get-Date
        $counts = Get-ResultCounts
        Set-Status ("Audit complete. PASS={0} INFO={1} WARNING={2} FAIL={3}" -f `
            $counts.PASS,$counts.INFO,$counts.WARNING,$counts.FAIL)
    }
        finally {
            Set-Busy $false
        }
    }
    catch {
        Set-Busy $false
        Set-Status ("Audit error: {0}" -f $_.Exception.Message)
        [System.Windows.MessageBox]::Show(
            "The audit encountered an error.`n`n$($_.Exception.Message)",
            "Audit Error",
            "OK",
            "Error"
        ) | Out-Null
    }
})

$DocumentationButton.Add_Click([System.Windows.RoutedEventHandler]{
    Show-FullUserDocumentation
})

$ViewHtmlButton.Add_Click([System.Windows.RoutedEventHandler]{
    if (-not $script:LastHtmlReportPath -or -not (Test-Path $script:LastHtmlReportPath)) {
        $ViewHtmlButton.IsEnabled = $false
        [System.Windows.MessageBox]::Show(
            "No exported HTML report is currently available.`n`nExport a report first.",
            "HTML Report",
            "OK",
            "Information"
        ) | Out-Null
        return
    }

    try {
        Start-Process -FilePath $script:LastHtmlReportPath
        Set-Status ("Opened HTML report: {0}" -f $script:LastHtmlReportPath)
    }
    catch {
        [System.Windows.MessageBox]::Show(
            "Unable to open the HTML report.`n`n$($_.Exception.Message)",
            "Open Report Failed",
            "OK",
            "Error"
        ) | Out-Null
    }
})

$ExportHtmlButton.Add_Click([System.Windows.RoutedEventHandler]{
    if ($script:Results.Count -eq 0) { return }

    $dlg = New-Object Microsoft.Win32.SaveFileDialog
    $dlg.Filter = "HTML Report (*.html)|*.html"
    $defaultHost = if ($script:LastAuditHosts.Count -eq 1) { $script:LastAuditHosts[0] } else { "MultiHost" }
    $dlg.FileName = "PureStorage-HostAudit-{0}-{1}.html" -f $defaultHost,(Get-Date -Format "yyyyMMdd-HHmmss")

    if ($dlg.ShowDialog()) {
        try {
            Export-HtmlReport -Path $dlg.FileName
            $script:LastHtmlReportPath = $dlg.FileName
            $ViewHtmlButton.IsEnabled = $true
            Set-Status ("HTML report exported: {0}" -f $dlg.FileName)
            [System.Windows.MessageBox]::Show(
                "HTML report created successfully.`n`n$($dlg.FileName)",
                "Report Exported",
                "OK",
                "Information"
            ) | Out-Null
        }
        catch {
            [System.Windows.MessageBox]::Show(
                "Unable to export the HTML report.`n`n$($_.Exception.Message)",
                "Export Failed",
                "OK",
                "Error"
            ) | Out-Null
        }
    }
})

# Helpful default examples. Replace with site-specific values.
$HostTextBox.Text = ""
$TargetTextBox.Text = ""
Refresh-ActiveClusterMappings

Set-Status "Ready - read-only audit mode."
$null = $Window.ShowDialog()
