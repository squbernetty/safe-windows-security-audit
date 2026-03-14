$ErrorActionPreference = "SilentlyContinue"
Set-StrictMode -Version Latest

function New-Finding {
    param(
        [string]$Category,
        [string]$Name,
        [string]$Status,
        [ValidateSet("Critical","Important","Advisory","Informational")][string]$Severity,
        [string]$Details,
        [string]$Recommendation,
        [int]$ScoreImpact
    )

    [PSCustomObject]@{
        Category       = $Category
        Name           = $Name
        Status         = $Status
        Severity       = $Severity
        Details        = $Details
        Recommendation = $Recommendation
        ScoreImpact    = $ScoreImpact
    }
}

function Test-IsAdmin {
    try {
        $currentIdentity = [Security.Principal.WindowsIdentity]::GetCurrent()
        $principal = New-Object Security.Principal.WindowsPrincipal($currentIdentity)
        return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
    } catch {
        return $false
    }
}

function Get-SafeValue {
    param($Value, [string]$Fallback = "Unknown")
    if ($null -eq $Value -or [string]::IsNullOrWhiteSpace([string]$Value)) {
        return $Fallback
    }
    return $Value
}

function Get-SeverityColor {
    param([string]$Severity)
    switch ($Severity) {
        "Critical"      { "Red" }
        "Important"     { "Yellow" }
        "Advisory"      { "DarkYellow" }
        "Informational" { "Gray" }
        default         { "White" }
    }
}

function Write-Section {
    param([string]$Title)
    Write-Host ""
    Write-Host ("=" * 72) -ForegroundColor DarkCyan
    Write-Host $Title -ForegroundColor Cyan
    Write-Host ("=" * 72) -ForegroundColor DarkCyan
}

$OutputDirectory = Join-Path $env:USERPROFILE "Desktop\SecurityAudit"
if (-not (Test-Path -LiteralPath $OutputDirectory)) {
    New-Item -Path $OutputDirectory -ItemType Directory -Force | Out-Null
}

$timestamp = Get-Date -Format "yyyyMMdd-HHmmss"
$jsonReportPath = Join-Path $OutputDirectory "SecurityAudit-Consolidated-$timestamp.json"
$textReportPath = Join-Path $OutputDirectory "SecurityAudit-Consolidated-$timestamp.txt"

$Findings = New-Object System.Collections.Generic.List[object]
$RawData = [ordered]@{}
$AuditStart = Get-Date
$IsAdmin = Test-IsAdmin

Write-Section "SAFE CONSOLIDATED WINDOWS SECURITY AUDIT"
Write-Host "Mode             : Read-only" -ForegroundColor Green
Write-Host "Changes made     : None" -ForegroundColor Green
Write-Host "Running as admin : $IsAdmin" -ForegroundColor Green
Write-Host "Output folder    : $OutputDirectory" -ForegroundColor Green

Write-Section "1. SYSTEM BASELINE"
$computerInfo = Get-ComputerInfo
$osInfo = [PSCustomObject]@{
    ComputerName       = $env:COMPUTERNAME
    UserName           = $env:USERNAME
    WindowsProductName = Get-SafeValue $computerInfo.WindowsProductName
    WindowsVersion     = Get-SafeValue $computerInfo.WindowsVersion
    OsBuildNumber      = Get-SafeValue $computerInfo.OsBuildNumber
    OsArchitecture     = Get-SafeValue $computerInfo.OsArchitecture
    BiosMode           = Get-SafeValue $computerInfo.BiosFirmwareType
}
$RawData.System = $osInfo
$osInfo | Format-List
$Findings.Add((New-Finding "System" "OS Information" "Collected" "Informational" "Windows baseline information collected successfully." "Keep Windows updated and review unsupported versions." 0)) | Out-Null

Write-Section "2. MICROSOFT DEFENDER"
$defender = Get-MpComputerStatus
$RawData.Defender = $defender
if ($null -eq $defender) {
    Write-Host "Could not query Defender status." -ForegroundColor Yellow
    $Findings.Add((New-Finding "Defender" "Defender Status" "Unknown" "Advisory" "Could not read Microsoft Defender status." "Run as Administrator and verify whether another AV product is installed." -5)) | Out-Null
} else {
    $defenderSummary = [PSCustomObject]@{
        AMServiceEnabled           = $defender.AMServiceEnabled
        AntivirusEnabled           = $defender.AntivirusEnabled
        RealTimeProtectionEnabled  = $defender.RealTimeProtectionEnabled
        IoavProtectionEnabled      = $defender.IoavProtectionEnabled
        AntispywareEnabled         = $defender.AntispywareEnabled
        IsTamperProtected          = $defender.IsTamperProtected
        QuickScanAge               = $defender.QuickScanAge
        FullScanAge                = $defender.FullScanAge
        AntivirusSignatureAge      = $defender.AntivirusSignatureAge
    }
    $defenderSummary | Format-List

    if ($defender.AntivirusEnabled -eq $true -and $defender.RealTimeProtectionEnabled -eq $true) {
        $Findings.Add((New-Finding "Defender" "Real-time Protection" "Good" "Informational" "Microsoft Defender antivirus and real-time protection are enabled." "Keep enabled." 10)) | Out-Null
    } else {
        $Findings.Add((New-Finding "Defender" "Real-time Protection" "At Risk" "Critical" "Microsoft Defender antivirus or real-time protection appears disabled." "Review AV configuration before changing anything, especially if third-party AV is installed." -20)) | Out-Null
    }

    if ($defender.IsTamperProtected -eq $true) {
        $Findings.Add((New-Finding "Defender" "Tamper Protection" "Good" "Informational" "Tamper Protection appears enabled." "Keep enabled unless there is a specific managed endpoint requirement." 5)) | Out-Null
    } else {
        $Findings.Add((New-Finding "Defender" "Tamper Protection" "Review" "Advisory" "Tamper Protection appears disabled or unavailable." "Review manually. Do not force-enable blindly on managed or special-purpose systems." -3)) | Out-Null
    }
}

Write-Section "3. FIREWALL PROFILES"
$firewallProfiles = Get-NetFirewallProfile | Select-Object Name, Enabled, DefaultInboundAction, DefaultOutboundAction
$RawData.FirewallProfiles = $firewallProfiles
$firewallProfiles | Format-Table -AutoSize
$disabledProfiles = @($firewallProfiles | Where-Object { $_.Enabled -ne $true })
if ($disabledProfiles.Count -eq 0) {
    $Findings.Add((New-Finding "Firewall" "Firewall Profiles" "Good" "Informational" "All detected firewall profiles are enabled." "Keep enabled." 10)) | Out-Null
} else {
    $profileNames = ($disabledProfiles.Name -join ", ")
    $Findings.Add((New-Finding "Firewall" "Firewall Profiles" "Review" "Important" "One or more firewall profiles are disabled: $profileNames." "Review carefully before changing, especially if VPN, lab tools, or enterprise software depend on the current configuration." -10)) | Out-Null
}

Write-Section "4. BITLOCKER"
$bitlockerVolumes = Get-BitLockerVolume | Select-Object MountPoint, ProtectionStatus, EncryptionMethod, VolumeStatus
$RawData.BitLocker = $bitlockerVolumes
$bitlockerVolumes | Format-Table -AutoSize
$systemVolume = $bitlockerVolumes | Where-Object { $_.MountPoint -eq "C:" } | Select-Object -First 1
if ($null -eq $systemVolume) {
    $Findings.Add((New-Finding "BitLocker" "System Volume Encryption" "Unknown" "Advisory" "Could not determine BitLocker state for C:." "Verify manually." -5)) | Out-Null
} elseif ($systemVolume.ProtectionStatus -match "On|1") {
    $Findings.Add((New-Finding "BitLocker" "System Volume Encryption" "Good" "Informational" "BitLocker protection on C: appears enabled." "Ensure recovery key handling is secure." 15)) | Out-Null
} else {
    $Findings.Add((New-Finding "BitLocker" "System Volume Encryption" "At Risk" "Important" "BitLocker protection on C: appears disabled." "Review whether disk encryption is needed. Do not enable blindly without checking backup and recovery readiness." -15)) | Out-Null
}

Write-Section "5. SECURE BOOT"
try {
    $secureBootStatus = Confirm-SecureBootUEFI
} catch {
    $secureBootStatus = "Unavailable"
}
$RawData.SecureBoot = $secureBootStatus
Write-Host "Secure Boot: $secureBootStatus"
if ($secureBootStatus -eq $true) {
    $Findings.Add((New-Finding "Platform" "Secure Boot" "Good" "Informational" "Secure Boot appears enabled." "Keep enabled unless there is a specialized lab requirement." 10)) | Out-Null
} elseif ($secureBootStatus -eq $false) {
    $Findings.Add((New-Finding "Platform" "Secure Boot" "Review" "Important" "Secure Boot appears disabled." "Review carefully. Some custom boot workflows may depend on this state." -10)) | Out-Null
} else {
    $Findings.Add((New-Finding "Platform" "Secure Boot" "Unknown" "Advisory" "Secure Boot status unavailable. System may be legacy BIOS or visibility is limited." "Verify in firmware settings if needed." -2)) | Out-Null
}

Write-Section "6. TPM"
$tpm = Get-Tpm
$RawData.TPM = $tpm
if ($null -eq $tpm) {
    Write-Host "TPM information unavailable." -ForegroundColor Yellow
    $Findings.Add((New-Finding "Platform" "TPM" "Unknown" "Advisory" "Could not read TPM status." "Verify manually in Windows Security and firmware." -3)) | Out-Null
} else {
    $tpmSummary = [PSCustomObject]@{
        TpmPresent        = $tpm.TpmPresent
        TpmReady          = $tpm.TpmReady
        TpmEnabled        = $tpm.TpmEnabled
        TpmActivated      = $tpm.TpmActivated
        ManufacturerIdTxt = $tpm.ManufacturerIdTxt
    }
    $tpmSummary | Format-List

    if ($tpm.TpmPresent -eq $true -and $tpm.TpmReady -eq $true) {
        $Findings.Add((New-Finding "Platform" "TPM" "Good" "Informational" "TPM is present and ready." "Keep as-is." 10)) | Out-Null
    } else {
        $Findings.Add((New-Finding "Platform" "TPM" "Review" "Important" "TPM is missing or not ready." "Review firmware and device configuration. Do not force changes without confirming platform dependencies." -10)) | Out-Null
    }
}

Write-Section "7. REMOTE DESKTOP"
$rdpValue = $null
$rdpReg = Get-ItemProperty -Path "HKLM:\System\CurrentControlSet\Control\Terminal Server" -Name "fDenyTSConnections"
if ($null -ne $rdpReg) { $rdpValue = $rdpReg.fDenyTSConnections }
$rdpObject = [PSCustomObject]@{
    fDenyTSConnections = $rdpValue
    Meaning = if ($rdpValue -eq 0) { "RDP Enabled" } elseif ($rdpValue -eq 1) { "RDP Disabled" } else { "Unknown" }
}
$RawData.RDP = $rdpObject
$rdpObject | Format-List
if ($rdpValue -eq 1) {
    $Findings.Add((New-Finding "Remote Access" "RDP" "Good" "Informational" "Remote Desktop appears disabled." "Keep disabled unless operationally needed." 10)) | Out-Null
} elseif ($rdpValue -eq 0) {
    $Findings.Add((New-Finding "Remote Access" "RDP" "Exposed" "Important" "Remote Desktop appears enabled." "If intentionally enabled, ensure strong account security and limited exposure. Do not disable blindly if it is needed for remote operations." -10)) | Out-Null
} else {
    $Findings.Add((New-Finding "Remote Access" "RDP" "Unknown" "Advisory" "Could not determine RDP state." "Verify manually." -2)) | Out-Null
}

Write-Section "8. SMBv1"
$smb1 = Get-WindowsOptionalFeature -Online -FeatureName SMB1Protocol
$RawData.SMB1 = $smb1
$smb1 | Select-Object FeatureName, State | Format-Table -AutoSize
if ($null -eq $smb1) {
    $Findings.Add((New-Finding "Legacy Protocols" "SMBv1" "Unknown" "Advisory" "Could not read SMBv1 feature state." "Verify manually if needed." -2)) | Out-Null
} elseif ($smb1.State -eq "Disabled") {
    $Findings.Add((New-Finding "Legacy Protocols" "SMBv1" "Good" "Informational" "SMBv1 appears disabled." "Keep disabled." 10)) | Out-Null
} else {
    $Findings.Add((New-Finding "Legacy Protocols" "SMBv1" "Review" "Important" "SMBv1 appears enabled or available." "Review dependencies before changing. Some old devices or lab systems may still rely on it." -10)) | Out-Null
}

Write-Section "9. LOCAL ADMINISTRATORS"
$localAdmins = Get-LocalGroupMember -Group "Administrators" | Select-Object Name, ObjectClass, PrincipalSource
$RawData.LocalAdministrators = $localAdmins
$localAdmins | Format-Table -AutoSize
$adminCount = @($localAdmins).Count
if ($adminCount -le 2) {
    $Findings.Add((New-Finding "Accounts" "Local Administrators Group" "Reasonable" "Informational" "Administrators group member count is $adminCount." "Keep admin membership minimal." 5)) | Out-Null
} else {
    $Findings.Add((New-Finding "Accounts" "Local Administrators Group" "Review" "Important" "Administrators group contains $adminCount members." "Review whether all admin memberships are truly required. Do not remove anything without understanding app, VPN, and management dependencies." -8)) | Out-Null
}

Write-Section "10. BUILT-IN ADMINISTRATOR ACCOUNT"
$builtinAdmin = Get-LocalUser | Where-Object { $_.SID -like "*-500" } | Select-Object Name, Enabled, LastLogon
$RawData.BuiltInAdministrator = $builtinAdmin
$builtinAdmin | Format-List
if ($null -eq $builtinAdmin) {
    $Findings.Add((New-Finding "Accounts" "Built-in Administrator" "Unknown" "Advisory" "Could not read built-in Administrator account state." "Verify manually if needed." -2)) | Out-Null
} elseif ($builtinAdmin.Enabled -eq $true) {
    $Findings.Add((New-Finding "Accounts" "Built-in Administrator" "Enabled" "Important" "The built-in Administrator account appears enabled." "Review whether this is intentional. Do not disable blindly if it is used for break-glass access." -8)) | Out-Null
} else {
    $Findings.Add((New-Finding "Accounts" "Built-in Administrator" "Good" "Informational" "The built-in Administrator account appears disabled." "Keep disabled unless deliberately required." 5)) | Out-Null
}

Write-Section "11. WINDOWS UPDATE SERVICE"
$wuService = Get-Service -Name wuauserv | Select-Object Name, Status, StartType
$RawData.WindowsUpdateService = $wuService
$wuService | Format-List
if ($null -eq $wuService) {
    $Findings.Add((New-Finding "Updates" "Windows Update Service" "Unknown" "Advisory" "Could not read Windows Update service state." "Verify manually." -2)) | Out-Null
} elseif ($wuService.Status -eq "Running" -or $wuService.StartType -ne "Disabled") {
    $Findings.Add((New-Finding "Updates" "Windows Update Service" "Good" "Informational" "Windows Update service appears available." "Maintain patch cadence." 5)) | Out-Null
} else {
    $Findings.Add((New-Finding "Updates" "Windows Update Service" "Review" "Important" "Windows Update service appears disabled." "Review patching workflow before changing." -8)) | Out-Null
}

Write-Section "12. GENERAL LISTENING PORTS"
$listeningPorts = Get-NetTCPConnection -State Listen | Sort-Object LocalPort | Select-Object LocalAddress, LocalPort, OwningProcess -First 100
$RawData.ListeningPorts = $listeningPorts
$listeningPorts | Format-Table -AutoSize
$commonSensitivePorts = @(21,22,23,80,135,139,443,445,3389,5985,5986)
$exposedSensitive = @($listeningPorts | Where-Object { $commonSensitivePorts -contains $_.LocalPort })
if ($exposedSensitive.Count -eq 0) {
    $Findings.Add((New-Finding "Network Exposure" "Listening Ports" "No obvious concern" "Informational" "No common high-interest listening ports were detected in the sampled output." "Still review full service exposure if this machine hosts tools or services intentionally." 5)) | Out-Null
} else {
    $portList = ($exposedSensitive.LocalPort | Sort-Object -Unique) -join ", "
    $Findings.Add((New-Finding "Network Exposure" "Listening Ports" "Review" "Advisory" "Common high-interest listening ports detected: $portList." "Review whether each listening service is intentional. Do not close ports blindly without checking dependencies." -5)) | Out-Null
}

Write-Section "13. NETWORK PROFILES"
$networkProfiles = Get-NetConnectionProfile | Select-Object Name, InterfaceAlias, NetworkCategory, IPv4Connectivity, IPv6Connectivity
$RawData.NetworkProfiles = $networkProfiles
$networkProfiles | Format-Table -AutoSize
$publicProfiles = @($networkProfiles | Where-Object { $_.NetworkCategory -eq "Public" })
if ($publicProfiles.Count -gt 0) {
    $Findings.Add((New-Finding "Network" "Network Category" "Generally Safer" "Informational" "One or more active network profiles are set to Public." "Public is often safer for untrusted networks. Review only if this breaks intended local resource access." 3)) | Out-Null
} else {
    $Findings.Add((New-Finding "Network" "Network Category" "Review" "Advisory" "No active Public network profile detected." "Ensure trusted vs untrusted network classification matches real usage." 0)) | Out-Null
}

Write-Section "14. POWERSHELL LOGGING POLICY"
$psLoggingPaths = @(
    "HKLM:\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging",
    "HKLM:\Software\Policies\Microsoft\Windows\PowerShell\Transcription",
    "HKLM:\Software\Policies\Microsoft\Windows\PowerShell\ModuleLogging"
)
$psLoggingResults = foreach ($path in $psLoggingPaths) {
    if (Test-Path $path) {
        $props = Get-ItemProperty -Path $path
        [PSCustomObject]@{
            Path   = $path
            Exists = $true
            Values = ($props | Out-String).Trim()
        }
    } else {
        [PSCustomObject]@{
            Path   = $path
            Exists = $false
            Values = ""
        }
    }
}
$RawData.PowerShellLoggingPolicy = $psLoggingResults
$psLoggingResults | Format-Table -Wrap -AutoSize
$loggingCount = @($psLoggingResults | Where-Object { $_.Exists -eq $true }).Count
if ($loggingCount -gt 0) {
    $Findings.Add((New-Finding "Logging" "PowerShell Logging Policy" "Present" "Informational" "One or more PowerShell logging policy settings are present." "Review whether the current logging level aligns with privacy, performance, and visibility needs." 3)) | Out-Null
} else {
    $Findings.Add((New-Finding "Logging" "PowerShell Logging Policy" "Not Configured" "Advisory" "No PowerShell logging policy entries were detected." "This is not automatically bad, but visibility is lower. Review later if advanced monitoring is a goal." -1)) | Out-Null
}

Write-Section "15. RECENT FAILED LOGONS"
$failedLogons = Get-WinEvent -FilterHashtable @{
    LogName   = 'Security'
    Id        = 4625
    StartTime = (Get-Date).AddDays(-7)
} -MaxEvents 20
$failedLogonSummary = if ($null -ne $failedLogons) {
    $failedLogons | Select-Object TimeCreated, Id, ProviderName, MachineName
} else {
    @()
}
$RawData.FailedLogons = $failedLogonSummary
$failedLogonSummary | Format-Table -AutoSize
$failedCount = @($failedLogonSummary).Count
if (-not $IsAdmin) {
    $Findings.Add((New-Finding "Logging" "Failed Logons" "Limited Visibility" "Advisory" "Security log access may be limited because the script was not run as Administrator." "Run elevated if you want fuller event visibility." 0)) | Out-Null
} elseif ($failedCount -eq 0) {
    $Findings.Add((New-Finding "Logging" "Failed Logons" "No recent failures seen" "Informational" "No recent failed logons were detected in the sampled period." "Continue monitoring periodically." 3)) | Out-Null
} elseif ($failedCount -le 5) {
    $Findings.Add((New-Finding "Logging" "Failed Logons" "Low count" "Advisory" "A small number of failed logons were detected: $failedCount." "Review whether they are expected." -2)) | Out-Null
} else {
    $Findings.Add((New-Finding "Logging" "Failed Logons" "Review" "Important" "Multiple failed logons were detected in the sampled period: $failedCount." "Review event details and ensure they are explainable." -8)) | Out-Null
}

Write-Section "16. DEEP NETWORK EXPOSURE CHECK (135,139,445)"
$deepPorts = Get-NetTCPConnection -State Listen |
    Where-Object { $_.LocalPort -in 135,139,445 } |
    Select-Object LocalAddress, LocalPort, OwningProcess
$RawData.DeepPorts = $deepPorts

Write-Host "`n16.1 LISTENING PORTS"
$deepPorts | Format-Table -AutoSize

Write-Host "`n16.2 PROCESSES OWNING THOSE PORTS"
$procResults = foreach ($p in $deepPorts) {
    Get-Process -Id $p.OwningProcess -ErrorAction SilentlyContinue |
        Select-Object @{Name='LocalAddress';Expression={$p.LocalAddress}},
                      @{Name='LocalPort';Expression={$p.LocalPort}},
                      ProcessName, Id, Path
}
$RawData.DeepPortProcesses = $procResults
$procResults | Sort-Object LocalPort, Id -Unique | Format-Table -AutoSize

Write-Host "`n16.3 SERVICES ASSOCIATED WITH THOSE PROCESSES"
$allServices = Get-CimInstance Win32_Service
$serviceResults = foreach ($p in $deepPorts) {
    $allServices |
        Where-Object { $_.ProcessId -eq $p.OwningProcess } |
        Select-Object @{Name='LocalPort';Expression={$p.LocalPort}},
                      Name, DisplayName, State, StartMode, ProcessId
}
$RawData.DeepPortServices = $serviceResults
$serviceResults | Sort-Object LocalPort, ProcessId, Name -Unique | Format-Table -AutoSize

Write-Host "`n16.4 SMB SERVER CONFIGURATION"
$smbServerConfig = Get-SmbServerConfiguration |
    Select-Object EnableSMB1Protocol, EnableSMB2Protocol, EnableSecuritySignature, RequireSecuritySignature, EncryptData
$RawData.SmbServerConfiguration = $smbServerConfig
$smbServerConfig | Format-List

Write-Host "`n16.5 ACTIVE SMB SHARES"
$smbShares = Get-SmbShare |
    Select-Object Name, Path, Description, CurrentUsers, Special
$RawData.SmbShares = $smbShares
$smbShares | Format-Table -AutoSize

Write-Host "`n16.6 FILE AND PRINTER SHARING FIREWALL RULES"
$fileSharingRules = Get-NetFirewallRule -DisplayGroup "File and Printer Sharing" |
    Select-Object DisplayName, Enabled, Direction, Action, Profile
$RawData.FileSharingFirewallRules = $fileSharingRules
$fileSharingRules | Format-Table -Wrap -AutoSize

Write-Host "`n16.7 NETBIOS SETTINGS"
$netbiosSettings = Get-CimInstance Win32_NetworkAdapterConfiguration |
    Where-Object { $_.IPEnabled -eq $true } |
    Select-Object Description, IPAddress, TcpipNetbiosOptions
$RawData.NetbiosSettings = $netbiosSettings
$netbiosSettings | Format-Table -Wrap -AutoSize

Write-Host "`n16.8 RPC SERVICES"
$rpcServices = Get-Service RpcSs, DcomLaunch |
    Select-Object Name, DisplayName, Status, StartType
$RawData.RpcServices = $rpcServices
$rpcServices | Format-Table -AutoSize

Write-Host "`n16.9 NETWORK PROFILE STATE"
$networkProfileState = Get-NetConnectionProfile |
    Select-Object Name, InterfaceAlias, NetworkCategory, IPv4Connectivity, IPv6Connectivity
$RawData.NetworkProfileState = $networkProfileState
$networkProfileState | Format-Table -AutoSize

if (@($deepPorts).Count -eq 0) {
    $Findings.Add((New-Finding "Deep Network Exposure" "Ports 135/139/445" "Not listening" "Informational" "Ports 135, 139 and 445 were not detected in listening state." "No action needed." 5)) | Out-Null
} else {
    $Findings.Add((New-Finding "Deep Network Exposure" "Ports 135/139/445" "Present" "Informational" "Ports 135, 139 and/or 445 are listening. This is often normal Windows behavior and must be interpreted together with firewall and service data." "Review the deep network exposure section rather than disabling anything blindly." 0)) | Out-Null
}

$enabledInboundFileShareRules = @(
    $fileSharingRules | Where-Object {
        $_.Enabled -eq $true -and $_.Direction -eq "Inbound"
    }
)

if ($enabledInboundFileShareRules.Count -eq 0) {
    $Findings.Add((New-Finding "Deep Network Exposure" "File Sharing Firewall Rules" "Contained" "Informational" "No enabled inbound File and Printer Sharing firewall rules were detected." "This is a strong containment signal." 10)) | Out-Null
} else {
    $ruleNames = ($enabledInboundFileShareRules.DisplayName -join ", ")
    $Findings.Add((New-Finding "Deep Network Exposure" "File Sharing Firewall Rules" "Review" "Important" "Enabled inbound File and Printer Sharing firewall rules were detected: $ruleNames." "Review whether these are intentional before changing anything." -10)) | Out-Null
}

$nonSpecialShares = @($smbShares | Where-Object { $_.Special -ne $true })
if ($nonSpecialShares.Count -eq 0) {
    $Findings.Add((New-Finding "Deep Network Exposure" "SMB Shares" "Only default shares" "Informational" "Only default/special SMB shares appear present." "No action needed unless you want to reduce Windows administrative sharing later." 5)) | Out-Null
} else {
    $shareNames = ($nonSpecialShares.Name -join ", ")
    $Findings.Add((New-Finding "Deep Network Exposure" "SMB Shares" "Review" "Advisory" "Non-default SMB shares were detected: $shareNames." "Review whether those shares are needed." -5)) | Out-Null
}

if ($smbServerConfig.EnableSMB1Protocol -eq $false -and $smbServerConfig.EnableSMB2Protocol -eq $true) {
    $Findings.Add((New-Finding "Deep Network Exposure" "SMB Protocol State" "Good" "Informational" "SMB1 is disabled and SMB2 is enabled." "Keep this state." 10)) | Out-Null
} else {
    $Findings.Add((New-Finding "Deep Network Exposure" "SMB Protocol State" "Review" "Important" "Unexpected SMB protocol state detected." "Review before making changes." -10)) | Out-Null
}

Write-Section "17. RISK SUMMARY"
$baseScore = 100
$totalImpact = ($Findings | Measure-Object -Property ScoreImpact -Sum).Sum
if ($null -eq $totalImpact) { $totalImpact = 0 }
$rawScore = $baseScore + $totalImpact
if ($rawScore -gt 100) { $rawScore = 100 }
if ($rawScore -lt 0)   { $rawScore = 0 }

$criticalCount  = @($Findings | Where-Object { $_.Severity -eq "Critical" }).Count
$importantCount = @($Findings | Where-Object { $_.Severity -eq "Important" }).Count
$advisoryCount  = @($Findings | Where-Object { $_.Severity -eq "Advisory" }).Count
$infoCount      = @($Findings | Where-Object { $_.Severity -eq "Informational" }).Count

$overallRating = switch ($rawScore) {
    { $_ -ge 90 } { "Strong baseline"; break }
    { $_ -ge 75 } { "Reasonably good, review a few areas"; break }
    { $_ -ge 60 } { "Mixed posture, review recommended"; break }
    default       { "Higher risk baseline, careful review recommended" }
}

$summary = [PSCustomObject]@{
    AuditStart            = $AuditStart
    AuditEnd              = Get-Date
    ComputerName          = $env:COMPUTERNAME
    RunAsAdministrator    = $IsAdmin
    SecurityScore         = $rawScore
    OverallRating         = $overallRating
    CriticalFindings      = $criticalCount
    ImportantFindings     = $importantCount
    AdvisoryFindings      = $advisoryCount
    InformationalFindings = $infoCount
}
$RawData.Summary = $summary
$summary | Format-List

Write-Section "18. FINDINGS"
foreach ($finding in $Findings) {
    $color = Get-SeverityColor $finding.Severity
    Write-Host "[$($finding.Severity)] $($finding.Category) - $($finding.Name)" -ForegroundColor $color
    Write-Host "Status         : $($finding.Status)"
    Write-Host "Details        : $($finding.Details)"
    Write-Host "Recommendation : $($finding.Recommendation)"
    Write-Host "Score Impact   : $($finding.ScoreImpact)"
    Write-Host ("-" * 72) -ForegroundColor DarkGray
}

$exportObject = [PSCustomObject]@{
    Summary  = $summary
    Findings = $Findings
    RawData  = $RawData
}
$exportObject | ConvertTo-Json -Depth 8 | Out-File -FilePath $jsonReportPath -Encoding utf8

$textLines = New-Object System.Collections.Generic.List[string]
$textLines.Add("SAFE CONSOLIDATED WINDOWS SECURITY AUDIT REPORT") | Out-Null
$textLines.Add(("=" * 72)) | Out-Null
$textLines.Add("Generated: $(Get-Date)") | Out-Null
$textLines.Add("Computer : $env:COMPUTERNAME") | Out-Null
$textLines.Add("User     : $env:USERNAME") | Out-Null
$textLines.Add("RunAdmin : $IsAdmin") | Out-Null
$textLines.Add("") | Out-Null
$textLines.Add("SUMMARY") | Out-Null
$textLines.Add(("=" * 72)) | Out-Null
$textLines.Add("Security Score        : $($summary.SecurityScore)") | Out-Null
$textLines.Add("Overall Rating        : $($summary.OverallRating)") | Out-Null
$textLines.Add("Critical Findings     : $($summary.CriticalFindings)") | Out-Null
$textLines.Add("Important Findings    : $($summary.ImportantFindings)") | Out-Null
$textLines.Add("Advisory Findings     : $($summary.AdvisoryFindings)") | Out-Null
$textLines.Add("Informational Findings: $($summary.InformationalFindings)") | Out-Null
$textLines.Add("") | Out-Null
$textLines.Add("FINDINGS") | Out-Null
$textLines.Add(("=" * 72)) | Out-Null

foreach ($finding in $Findings) {
    $textLines.Add("[$($finding.Severity)] $($finding.Category) - $($finding.Name)") | Out-Null
    $textLines.Add("Status         : $($finding.Status)") | Out-Null
    $textLines.Add("Details        : $($finding.Details)") | Out-Null
    $textLines.Add("Recommendation : $($finding.Recommendation)") | Out-Null
    $textLines.Add("Score Impact   : $($finding.ScoreImpact)") | Out-Null
    $textLines.Add(("-" * 72)) | Out-Null
}

$textLines.Add("") | Out-Null
$textLines.Add("DEEP NETWORK EXPOSURE CHECK") | Out-Null
$textLines.Add(("=" * 72)) | Out-Null
$textLines.Add("Ports 135/139/445, related processes, services, SMB config, shares, firewall rules, NetBIOS, RPC, and network profiles were collected in RawData and JSON output.") | Out-Null

$textLines | Out-File -FilePath $textReportPath -Encoding utf8

Write-Section "19. EXPORT COMPLETE"
Write-Host "JSON report: $jsonReportPath" -ForegroundColor Green
Write-Host "TXT report : $textReportPath" -ForegroundColor Green
Write-Host "This script made no configuration changes." -ForegroundColor Green
