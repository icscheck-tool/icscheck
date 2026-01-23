<#
.SYNOPSIS
    ICScheck - Security Audit Tool for Industrial Control Systems

.DESCRIPTION
    Performs security audit of Windows-based ICS/SCADA workstations
    against IEC 62443 and NIS2 requirements.

    Primary target: Siemens WinCC V7/V8 stations

.NOTES
    Version:        0.4.0
    Author:         Lukasz Krzesinski
    Website:        https://icscheck.com
    GitHub:         https://github.com/icscheck-tool/icscheck
    License:        MIT

.EXAMPLE
    .\ICScheck.ps1

.EXAMPLE
    .\ICScheck.ps1 -OutputPath "C:\Reports"
#>

[CmdletBinding()]
param(
    [string]$OutputPath,
    [switch]$SkipHtmlReport
)

# Fix for empty $PSScriptRoot when running via -File
if (-not $OutputPath) {
    $OutputPath = if ($PSScriptRoot) { $PSScriptRoot } else { $PWD.Path }
}

#region Configuration
$script:Version = "0.4.0"
$script:ReportDate = Get-Date -Format "yyyy-MM-dd_HH-mm-ss"
$script:ComputerName = $env:COMPUTERNAME
$script:Results = @()
$script:PassCount = 0
$script:FailCount = 0
$script:WarnCount = 0

# Category descriptions for report headers
$script:CategoryDescriptions = @{
    "Access Control" = "Identification, authentication & authorization controls"
    "Use Control" = "Session management & resource usage restrictions"
    "System Integrity" = "Operating system hardening & security configuration"
    "Data Confidentiality" = "Encryption, telemetry & data protection"
    "Network Security" = "Firewall, protocols & network protection"
    "Timely Response" = "Logging, auditing & incident detection"
    "Resource Availability" = "Backup, recovery & service continuity"
    "WinCC/SCADA Security" = "SCADA-specific security configuration"
    "Audit & Logging" = "Security event logging & audit trail"
    "WinCC Specific" = "Siemens WinCC security configuration"
}

# NIS2 Article 21 tooltips
$script:NIS2Tooltips = @{
    "Art.21(a)" = "Risk analysis and security policies"
    "Art.21(b)" = "Incident handling and response"
    "Art.21(c)" = "Business continuity and crisis management"
    "Art.21(d)" = "Supply chain security"
    "Art.21(e)" = "Security in network and information systems"
    "Art.21(f)" = "Vulnerability handling and disclosure"
    "Art.21(g)" = "Cybersecurity training and hygiene"
}

# IEC 62443 Foundational Requirements tooltips
$script:FRTooltips = @{
    "FR1" = "Identification and Authentication Control"
    "FR2" = "Use Control"
    "FR3" = "System Integrity"
    "FR4" = "Data Confidentiality"
    "FR5" = "Restricted Data Flow"
    "FR6" = "Timely Response to Events"
    "FR7" = "Resource Availability"
}

# System Info (populated by Get-SystemInfo)
$script:SystemInfo = @{
    ComputerName = $env:COMPUTERNAME
    OSVersion = ""
    IPAddresses = @()
    WinCCVersion = "Not Detected"
    WinCCStationType = "Unknown"
    WinCCProject = "Not Running"
    ProjectCreated = ""
    ProjectLastEdit = ""
    TagsTotal = 0
    TagsInternal = 0
    TagsExternal = 0
    PLCCount = 0
    PLCAddresses = @()
    Protocols = @()
    ArchivedTags = 0
    # Architecture info
    Architecture = "Single Station"
    ServerName = ""
    ClientStations = @()
    # Installed drivers
    InstalledDrivers = @()
    # Communication tree (Channel -> Unit -> Connection)
    CommTree = @()
    # WinCC Users
    WinCCUsers = @()
    WinCCUserCount = 0
    ScanDate = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
}
#endregion

#region System Information Collection
function Get-SystemInfo {
    Write-Host "Collecting System Information..." -ForegroundColor Cyan

    # OS Version
    $os = Get-CimInstance Win32_OperatingSystem
    $script:SystemInfo.OSVersion = "$($os.Caption) Build $($os.BuildNumber)"

    # IP Addresses (non-loopback, non-APIPA)
    $ips = Get-NetIPAddress -AddressFamily IPv4 |
        Where-Object { $_.IPAddress -notlike "127.*" -and $_.IPAddress -notlike "169.254.*" } |
        Select-Object -ExpandProperty IPAddress
    $script:SystemInfo.IPAddresses = $ips

    # WinCC Detection
    $winccSetup = Get-ItemProperty "HKLM:\SOFTWARE\WOW6432Node\Siemens\WinCC\Setup" -ErrorAction SilentlyContinue
    $winccV8 = Get-ItemProperty "HKLM:\SOFTWARE\Siemens\WinCC\Setup" -ErrorAction SilentlyContinue
    $winccTIA = Get-ItemProperty "HKLM:\SOFTWARE\Siemens\Automation\WinCC RT Advanced" -ErrorAction SilentlyContinue
    $tiaPortal = Get-ItemProperty "HKLM:\SOFTWARE\Siemens\Automation\Openness\*" -ErrorAction SilentlyContinue

    # Check WinCC Professional (V7 or V8)
    $winccPro = $winccSetup
    if (-not $winccPro) { $winccPro = $winccV8 }

    if ($winccPro) {
        $version = $winccPro.Version
        $buildNr = $winccPro.BuildNr

        # BuildNr is more reliable for V8 detection (V08.xx = WinCC V8)
        if ($buildNr -match "^V08") {
            $script:SystemInfo.WinCCVersion = "WinCC V8 - $version (Build: $buildNr)"
        } elseif ($buildNr -match "^V07" -or $version -match "^V?7\.") {
            $script:SystemInfo.WinCCVersion = "WinCC V7 - $version"
        } elseif ($version -match "^8\.") {
            $script:SystemInfo.WinCCVersion = "WinCC V8 - $version"
        } else {
            $script:SystemInfo.WinCCVersion = "WinCC - $version"
        }

        # Detect Station Type for WinCC Professional (V7/V8)
        $winccServer = Get-Service -Name "WinCC_Server*" -ErrorAction SilentlyContinue
        $ccAgent = Get-Service -Name "CCAgent" -ErrorAction SilentlyContinue
        $sqlService = Get-Service -Name "MSSQL`$WINCC*" -ErrorAction SilentlyContinue

        if ($winccServer -or ($sqlService -and $ccAgent)) {
            $script:SystemInfo.WinCCStationType = "SERVER"
        }
        elseif ($ccAgent -and -not $winccServer) {
            $script:SystemInfo.WinCCStationType = "CLIENT"
        }
        else {
            $script:SystemInfo.WinCCStationType = "ENGINEERING"
        }
    }
    elseif ($winccTIA) {
        $script:SystemInfo.WinCCVersion = "WinCC RT Advanced (TIA Portal)"
        $script:SystemInfo.WinCCStationType = "HMI PANEL"
    }
    elseif ($tiaPortal) {
        $script:SystemInfo.WinCCVersion = "TIA Portal (Engineering)"
        $script:SystemInfo.WinCCStationType = "ENGINEERING"
    }
    else {
        # Fallback: check if WinCC SQL instance exists (even if registry key not found)
        $winccSqlService = Get-Service -Name "MSSQL`$WINCC" -ErrorAction SilentlyContinue
        if ($winccSqlService) {
            $script:SystemInfo.WinCCVersion = "WinCC (detected via SQL)"
            $script:SystemInfo.WinCCStationType = "UNKNOWN"
        }
    }

    # Detect running WinCC project from pdlrt.exe command line
    $pdlrtProcess = Get-WmiObject Win32_Process -Filter "Name='pdlrt.exe'" -ErrorAction SilentlyContinue
    if ($pdlrtProcess) {
        $cmdLine = $pdlrtProcess.CommandLine
        # Extract project path from command line (format: pdlrt.exe /Project "C:\...\ProjectName\ProjectName.mcp")
        if ($cmdLine -match '/Project\s+"?([^"]+)"?') {
            $projectPath = $Matches[1]
            # Get project name from path (folder name or .mcp file name without extension)
            $projectName = [System.IO.Path]::GetFileNameWithoutExtension($projectPath)
            if (-not $projectName) {
                $projectName = Split-Path -Leaf (Split-Path -Parent $projectPath)
            }
            $script:SystemInfo.WinCCProject = $projectName
        }
        elseif ($cmdLine -match '\\([^\\]+)\\[^\\]+\.mcp') {
            # Fallback: extract from path pattern
            $script:SystemInfo.WinCCProject = $Matches[1]
        }
        else {
            $script:SystemInfo.WinCCProject = "Running (name unknown)"
        }
    }

    # Get project details from WinCC SQL database (try even if pdlrt.exe is not running)
    if ($script:SystemInfo.WinCCVersion -eq "Not Detected") {
        Write-Host "  [SQL] Skipping SQL query - WinCC not detected" -ForegroundColor DarkYellow
    }
    if ($script:SystemInfo.WinCCVersion -ne "Not Detected") {
        try {
            $sqlInstance = ".\WINCC"
            $dbName = $null
            Write-Host "  [SQL] Connecting to $sqlInstance..." -ForegroundColor DarkGray

            # If we know the project name from pdlrt.exe, search for matching database
            if ($script:SystemInfo.WinCCProject -ne "Not Running" -and $script:SystemInfo.WinCCProject -ne "Running (name unknown)") {
                $projectName = $script:SystemInfo.WinCCProject
                $dbQuery = "SELECT name FROM sys.databases WHERE name LIKE 'CC_${projectName}_%' ORDER BY name DESC"
                $databases = Invoke-Sqlcmd -ServerInstance $sqlInstance -Query $dbQuery -ErrorAction SilentlyContinue
                if ($databases) {
                    $dbName = @($databases)[0].name
                    Write-Host "  [SQL] Found database by project name: $dbName" -ForegroundColor DarkGray
                }
            }

            # If no database found by project name, search for any CC_* database
            # Exclude: CC_ExternalLogging, and databases ending with 'R' (Runtime copies)
            if (-not $dbName) {
                $dbQuery = "SELECT name FROM sys.databases WHERE name LIKE 'CC_%' AND name NOT IN ('CC_ExternalLogging') AND RIGHT(name, 1) <> 'R' ORDER BY create_date DESC"
                $databases = Invoke-Sqlcmd -ServerInstance $sqlInstance -Query $dbQuery -ErrorAction SilentlyContinue
                if ($databases) {
                    $dbName = @($databases)[0].name
                    Write-Host "  [SQL] Found CC_* database: $dbName" -ForegroundColor DarkGray
                }
                else {
                    Write-Host "  [SQL] No CC_* databases found" -ForegroundColor DarkYellow
                }
            }

            if ($dbName) {
                # Query PDE#Project table for project info
                $projectQuery = "SELECT PROJECTNAME, CREATIONDATE, EDITDATE FROM [PDE#Project]"
                $projectInfo = Invoke-Sqlcmd -ServerInstance $sqlInstance -Database $dbName -Query $projectQuery -ErrorAction SilentlyContinue

                if ($projectInfo) {
                    Write-Host "  [SQL] Project from PDE#Project: $($projectInfo.PROJECTNAME)" -ForegroundColor DarkGray
                    $script:SystemInfo.ProjectCreated = $projectInfo.CREATIONDATE.ToString("yyyy-MM-dd")
                    $script:SystemInfo.ProjectLastEdit = $projectInfo.EDITDATE.ToString("yyyy-MM-dd HH:mm")
                    # Always update project name from SQL if we don't have it from pdlrt.exe
                    if ($script:SystemInfo.WinCCProject -eq "Not Running" -or $script:SystemInfo.WinCCProject -eq "Running (name unknown)") {
                        $script:SystemInfo.WinCCProject = $projectInfo.PROJECTNAME + " (from SQL)"
                    }
                }
                else {
                    Write-Host "  [SQL] PDE#Project table empty or not found" -ForegroundColor DarkYellow
                    # Fallback: extract project name from database name (CC_ProjectName_timestamp)
                    if ($dbName -match '^CC_(.+?)_\d{2}_\d{2}_\d{2}_\d{2}_\d{2}_\d{2}') {
                        $extractedName = $Matches[1]
                        Write-Host "  [SQL] Extracted project name from DB name: $extractedName" -ForegroundColor DarkGray
                        if ($script:SystemInfo.WinCCProject -eq "Not Running" -or $script:SystemInfo.WinCCProject -eq "Running (name unknown)") {
                            $script:SystemInfo.WinCCProject = $extractedName + " (from DB name)"
                        }
                    }
                }

                # Get tags count from MCPTVARIABLEDESC (internal vs external)
                $tagsQuery = @"
                SELECT
                    COUNT(*) AS TagCount,
                    SUM(CASE WHEN ADDRESSPARAMETER IS NULL OR ADDRESSPARAMETER = '' THEN 1 ELSE 0 END) AS InternalCount,
                    SUM(CASE WHEN ADDRESSPARAMETER IS NOT NULL AND ADDRESSPARAMETER <> '' THEN 1 ELSE 0 END) AS ExternalCount
                FROM MCPTVARIABLEDESC
"@
                $tagsResult = Invoke-Sqlcmd -ServerInstance $sqlInstance -Database $dbName -Query $tagsQuery -ErrorAction SilentlyContinue
                if ($tagsResult) {
                    $script:SystemInfo.TagsTotal = $tagsResult.TagCount
                    $script:SystemInfo.TagsInternal = $tagsResult.InternalCount
                    $script:SystemInfo.TagsExternal = $tagsResult.ExternalCount
                }

                # Get PLC connections from MCPTCONNECTION (contains IP addresses in PARAMETER column)
                $connQuery = "SELECT CONNECTIONNAME, PARAMETER FROM MCPTCONNECTION WHERE CONNECTIONNAME <> 'Internal Tag' AND PARAMETER IS NOT NULL"
                $connResult = Invoke-Sqlcmd -ServerInstance $sqlInstance -Database $dbName -Query $connQuery -ErrorAction SilentlyContinue
                if ($connResult) {
                    $connections = @($connResult)
                    $script:SystemInfo.PLCCount = $connections.Count
                    $plcAddresses = @()
                    $protocols = @()
                    foreach ($conn in $connections) {
                        $param = $conn.PARAMETER
                        $connName = $conn.CONNECTIONNAME
                        # Extract IP address from PARAMETER (format: 6!:::::S7ONLINE!::192.168.70.150:...)
                        if ($param -match '(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})') {
                            $ip = $Matches[1]
                            $plcAddresses += "$connName`: $ip"
                        }
                        elseif ($param -match '<LOCAL>') {
                            $plcAddresses += "$connName`: LOCAL"
                        }
                        # Extract protocol from PARAMETER (e.g., S7ONLINE, TCP/IP, etc.)
                        if ($param -match '!::*([A-Z0-9_/]+)!') {
                            $proto = $Matches[1]
                            if ($proto -notin $protocols) { $protocols += $proto }
                        }
                    }
                    $script:SystemInfo.PLCAddresses = $plcAddresses
                    $script:SystemInfo.Protocols = $protocols
                }

                # Get archived tags count from PDE#TAGs (ARCTYP > 0 means tag is archived)
                $archiveQuery = "SELECT COUNT(*) AS ArchiveCount FROM [PDE#TAGs] WHERE ARCTYP > 0"
                $archiveResult = Invoke-Sqlcmd -ServerInstance $sqlInstance -Database $dbName -Query $archiveQuery -ErrorAction SilentlyContinue
                if ($archiveResult) {
                    $script:SystemInfo.ArchivedTags = $archiveResult.ArchiveCount
                }

                # Get installed communication drivers from MCPTCHANNEL
                $channelQuery = "SELECT CHANNELDLLNAME FROM MCPTCHANNEL WHERE CHANNELDLLNAME NOT IN ('Interne Variable', 'Internal Variable', 'System Info')"
                $channelResult = Invoke-Sqlcmd -ServerInstance $sqlInstance -Database $dbName -Query $channelQuery -ErrorAction SilentlyContinue
                if ($channelResult) {
                    $script:SystemInfo.InstalledDrivers = @($channelResult | ForEach-Object { $_.CHANNELDLLNAME })

                    # Derive protocols and ports from driver names
                    $protocols = @()
                    foreach ($driver in $script:SystemInfo.InstalledDrivers) {
                        switch -Wildcard ($driver) {
                            "*S7-1200*" { if ("S7 (TCP 102)" -notin $protocols) { $protocols += "S7 (TCP 102)" } }
                            "*S7-1500*" { if ("S7 (TCP 102)" -notin $protocols) { $protocols += "S7 (TCP 102)" } }
                            "*S7 Protocol*" { if ("S7 (TCP 102)" -notin $protocols) { $protocols += "S7 (TCP 102)" } }
                            "*Allen Bradley*" { if ("EtherNet/IP (TCP 44818)" -notin $protocols) { $protocols += "EtherNet/IP (TCP 44818)" } }
                            "*Modbus*TCP*" { if ("Modbus TCP (TCP 502)" -notin $protocols) { $protocols += "Modbus TCP (TCP 502)" } }
                            "*Unified*" { if ("OPC UA (TCP 4840)" -notin $protocols) { $protocols += "OPC UA (TCP 4840)" } }
                            "*OPC UA*" { if ("OPC UA (TCP 4840)" -notin $protocols) { $protocols += "OPC UA (TCP 4840)" } }
                            "OPC" { if ("OPC DA (DCOM)" -notin $protocols) { $protocols += "OPC DA (DCOM)" } }
                            "*PROFINET*" { if ("PROFINET (UDP 34962-34964)" -notin $protocols) { $protocols += "PROFINET (UDP 34962-34964)" } }
                        }
                    }
                    if ($protocols.Count -gt 0) {
                        $script:SystemInfo.Protocols = $protocols
                    }
                }

                # Build Communication Tree (Channel -> Unit -> Connection)
                $treeQuery = @"
SELECT
    c.CHANNELID,
    c.CHANNELDLLNAME AS ChannelName,
    u.CHANNELUNITID,
    u.CHANNELUNITNAME AS UnitName,
    conn.CONNECTIONNAME,
    conn.PARAMETER
FROM MCPTCHANNEL c
LEFT JOIN MCPTCHANNELUNIT u ON c.CHANNELID = u.CHANNELID
LEFT JOIN MCPTCONNECTION conn ON u.CHANNELUNITID = conn.CHANNELUNITID
WHERE c.CHANNELDLLNAME NOT IN ('Interne Variable', 'Internal Variable', 'System Info')
ORDER BY c.CHANNELID, u.CHANNELUNITID, conn.CONNECTIONID
"@
                $treeResult = Invoke-Sqlcmd -ServerInstance $sqlInstance -Database $dbName -Query $treeQuery -ErrorAction SilentlyContinue
                if ($treeResult) {
                    $commTree = @()
                    $currentChannel = $null
                    $currentUnit = $null

                    foreach ($row in @($treeResult)) {
                        $channelName = $row.ChannelName
                        $unitName = $row.UnitName
                        $connName = $row.CONNECTIONNAME
                        $param = $row.PARAMETER

                        # Extract IP and Port from PARAMETER
                        $ipInfo = ""
                        if ($param) {
                            if ($param -match '(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})') {
                                $ipInfo = $Matches[1]

                                # Try to extract port from various formats
                                $port = $null
                                if ($param -match 'IP-Port=(\d+)') { $port = $Matches[1] }
                                elseif ($param -match 'Port=(\d+)') { $port = $Matches[1] }
                                elseif ($param -match '\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}:(\d+)') { $port = $Matches[1] }

                                # If no port found, use standard port based on driver
                                if (-not $port) {
                                    switch -Wildcard ($channelName) {
                                        "*S7-1200*" { $port = "102" }
                                        "*S7-1500*" { $port = "102" }
                                        "*Allen Bradley*" { $port = "44818" }
                                        "*Modbus*" { $port = "502" }
                                        "*Unified*" { $port = "4840" }
                                    }
                                }

                                if ($port) { $ipInfo += ":$port" }
                            }
                        }

                        # Build tree structure
                        if ($currentChannel -ne $channelName) {
                            if ($currentChannel) { $commTree += $currentChannelObj }
                            $currentChannel = $channelName
                            $currentChannelObj = @{
                                Name = $channelName
                                Units = @()
                            }
                            $currentUnit = $null
                        }

                        if ($unitName -and $currentUnit -ne $unitName) {
                            $currentUnit = $unitName
                            $unitObj = @{
                                Name = $unitName
                                Connections = @()
                            }
                            $currentChannelObj.Units += $unitObj
                        }

                        if ($connName -and $connName -ne 'Internal Tag') {
                            $connDisplay = if ($ipInfo) { "$connName ($ipInfo)" } else { $connName }
                            if ($currentChannelObj.Units.Count -gt 0) {
                                $currentChannelObj.Units[-1].Connections += $connDisplay
                            }
                        }
                    }
                    if ($currentChannel) { $commTree += $currentChannelObj }
                    $script:SystemInfo.CommTree = $commTree
                }

                # Get WinCC architecture info from MCPTMACHINE (Server-Client topology)
                $machineQuery = "SELECT MACHINENAME, MACHINETYPE FROM MCPTMACHINE"
                $machineResult = Invoke-Sqlcmd -ServerInstance $sqlInstance -Database $dbName -Query $machineQuery -ErrorAction SilentlyContinue
                if ($machineResult) {
                    $machines = @($machineResult)
                    if ($machines.Count -gt 1) {
                        $script:SystemInfo.Architecture = "Server-Client"
                        # MACHINETYPE: 0 = Server, 1 = Client
                        $server = $machines | Where-Object { $_.MACHINETYPE -eq 0 } | Select-Object -First 1
                        $clients = $machines | Where-Object { $_.MACHINETYPE -eq 1 }
                        if ($server) {
                            $script:SystemInfo.ServerName = $server.MACHINENAME
                        }
                        if ($clients) {
                            $script:SystemInfo.ClientStations = @($clients | ForEach-Object { $_.MACHINENAME })
                        }
                    }
                    else {
                        $script:SystemInfo.Architecture = "Single Station"
                        $script:SystemInfo.ServerName = $machines[0].MACHINENAME
                    }
                }

                # Get WinCC users from PW_USER (without passwords!)
                $userQuery = "SELECT NAME FROM PW_USER ORDER BY ID"
                $userResult = Invoke-Sqlcmd -ServerInstance $sqlInstance -Database $dbName -Query $userQuery -ErrorAction SilentlyContinue
                if ($userResult) {
                    $script:SystemInfo.WinCCUsers = @($userResult | ForEach-Object { $_.NAME })
                    $script:SystemInfo.WinCCUserCount = $script:SystemInfo.WinCCUsers.Count
                }
            }
        }
        catch {
            # SQL query failed - continue without project details
        }
    }

    # Output to console
    Write-Host "  Computer: $($script:SystemInfo.ComputerName)" -ForegroundColor White
    Write-Host "  OS: $($script:SystemInfo.OSVersion)" -ForegroundColor White
    Write-Host "  IP: $($script:SystemInfo.IPAddresses -join ', ')" -ForegroundColor White
    Write-Host "  WinCC: $($script:SystemInfo.WinCCVersion)" -ForegroundColor White
    Write-Host "  Station Type: $($script:SystemInfo.WinCCStationType)" -ForegroundColor White
    Write-Host "  Project: $($script:SystemInfo.WinCCProject)" -ForegroundColor White
    if ($script:SystemInfo.ProjectCreated) {
        Write-Host "  Project Created: $($script:SystemInfo.ProjectCreated)" -ForegroundColor White
        Write-Host "  Last Edit: $($script:SystemInfo.ProjectLastEdit)" -ForegroundColor White
    }
    if ($script:SystemInfo.TagsTotal -gt 0) {
        Write-Host "  Tags Total: $($script:SystemInfo.TagsTotal)" -ForegroundColor Yellow
        Write-Host "  PLCs Connected: $($script:SystemInfo.PLCCount)" -ForegroundColor Yellow
        if ($script:SystemInfo.Protocols.Count -gt 0) {
            Write-Host "  Protocols: $($script:SystemInfo.Protocols -join ', ')" -ForegroundColor Yellow
        }
        if ($script:SystemInfo.PLCAddresses.Count -gt 0) {
            Write-Host "  PLC Addresses:" -ForegroundColor Yellow
            foreach ($addr in $script:SystemInfo.PLCAddresses) {
                Write-Host "    - $addr" -ForegroundColor Yellow
            }
        }
    }
    # Installed drivers
    if ($script:SystemInfo.InstalledDrivers.Count -gt 0) {
        Write-Host "  Installed Drivers: $($script:SystemInfo.InstalledDrivers -join ', ')" -ForegroundColor Cyan
    }
    # Architecture info
    if ($script:SystemInfo.Architecture -eq "Server-Client") {
        Write-Host "  Architecture: $($script:SystemInfo.Architecture)" -ForegroundColor Magenta
        Write-Host "  Server: $($script:SystemInfo.ServerName)" -ForegroundColor Magenta
        if ($script:SystemInfo.ClientStations.Count -gt 0) {
            Write-Host "  Clients ($($script:SystemInfo.ClientStations.Count)):" -ForegroundColor Magenta
            foreach ($client in $script:SystemInfo.ClientStations) {
                Write-Host "    - $client" -ForegroundColor Magenta
            }
        }
    }
    # WinCC Users
    if ($script:SystemInfo.WinCCUserCount -gt 0) {
        Write-Host "  WinCC Users ($($script:SystemInfo.WinCCUserCount)): $($script:SystemInfo.WinCCUsers -join ', ')" -ForegroundColor White
    }
}
#endregion

#region Helper Functions
function Write-CheckResult {
    param(
        [string]$Category,
        [string]$CheckName,
        [string]$Status,  # PASS, FAIL, WARN, INFO
        [string]$Finding,
        [string]$Recommendation,
        [string]$IEC62443,  # FR1-FR7
        [string]$NIS2       # Article 21 reference
    )

    $result = [PSCustomObject]@{
        Category       = $Category
        CheckName      = $CheckName
        Status         = $Status
        Finding        = $Finding
        Recommendation = $Recommendation
        IEC62443       = $IEC62443
        NIS2           = $NIS2
    }

    $script:Results += $result

    switch ($Status) {
        "PASS" { $script:PassCount++; $color = "Green" }
        "FAIL" { $script:FailCount++; $color = "Red" }
        "WARN" { $script:WarnCount++; $color = "Yellow" }
        default { $color = "Cyan" }
    }

    Write-Host "[$Status] " -ForegroundColor $color -NoNewline
    Write-Host "$CheckName" -ForegroundColor White
}

function Test-IsAdmin {
    $currentUser = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal($currentUser)
    return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}
#endregion

#region Check Functions

# ============================================
# FR1 - ACCESS CONTROL (Identification & Authentication)
# ============================================

function Test-PasswordPolicy {
    Write-Host "`n[FR1] Checking Password Policy..." -ForegroundColor Cyan

    try {
        $secpol = secedit /export /cfg "$env:TEMP\secpol.cfg" 2>$null
        $content = Get-Content "$env:TEMP\secpol.cfg" -ErrorAction SilentlyContinue
        Remove-Item "$env:TEMP\secpol.cfg" -Force -ErrorAction SilentlyContinue

        # Minimum password length
        $minLength = ($content | Select-String "MinimumPasswordLength").ToString() -replace '\D+', ''
        if ([int]$minLength -ge 12) {
            Write-CheckResult -Category "Access Control" -CheckName "Password Length >= 12 characters" `
                -Status "PASS" -Finding "Minimum length: $minLength characters" `
                -Recommendation "N/A" -IEC62443 "FR1" -NIS2 "Art.21(b)"
        } else {
            Write-CheckResult -Category "Access Control" -CheckName "Password Length >= 12 characters" `
                -Status "FAIL" -Finding "Minimum length: $minLength characters (should be 12+)" `
                -Recommendation "Set MinimumPasswordLength to 12 or higher in Group Policy" `
                -IEC62443 "FR1" -NIS2 "Art.21(b)"
        }

        # Password complexity
        $complexity = ($content | Select-String "PasswordComplexity").ToString() -replace '\D+', ''
        if ([int]$complexity -eq 1) {
            Write-CheckResult -Category "Access Control" -CheckName "Password Complexity Enabled" `
                -Status "PASS" -Finding "Password complexity is enabled" `
                -Recommendation "N/A" -IEC62443 "FR1" -NIS2 "Art.21(b)"
        } else {
            Write-CheckResult -Category "Access Control" -CheckName "Password Complexity Enabled" `
                -Status "FAIL" -Finding "Password complexity is disabled" `
                -Recommendation "Enable password complexity in Group Policy" `
                -IEC62443 "FR1" -NIS2 "Art.21(b)"
        }

        # Reversible encryption (ClearTextPassword)
        $clearText = ($content | Select-String "ClearTextPassword").ToString() -replace '\D+', ''
        if ([int]$clearText -eq 0) {
            Write-CheckResult -Category "Access Control" -CheckName "Reversible Encryption Disabled" `
                -Status "PASS" -Finding "Passwords are not stored with reversible encryption" `
                -Recommendation "N/A" -IEC62443 "FR1" -NIS2 "Art.21(b)"
        } else {
            Write-CheckResult -Category "Access Control" -CheckName "Reversible Encryption Disabled" `
                -Status "FAIL" -Finding "Passwords stored with reversible encryption (CRITICAL)" `
                -Recommendation "Disable 'Store passwords using reversible encryption' in Group Policy" `
                -IEC62443 "FR1" -NIS2 "Art.21(b)"
        }
    }
    catch {
        Write-CheckResult -Category "Access Control" -CheckName "Password Policy" `
            -Status "WARN" -Finding "Could not retrieve password policy (requires admin)" `
            -Recommendation "Run as Administrator" -IEC62443 "FR1" -NIS2 "Art.21(b)"
    }
}

function Test-AccountLockout {
    Write-Host "[FR1] Checking Account Lockout Policy..." -ForegroundColor Cyan

    try {
        $lockoutThreshold = (net accounts | Select-String "Lockout threshold").ToString() -replace '\D+', ''

        if ($lockoutThreshold -eq "" -or $lockoutThreshold -eq "Never") {
            Write-CheckResult -Category "Access Control" -CheckName "Account Lockout Threshold" `
                -Status "FAIL" -Finding "Account lockout is disabled" `
                -Recommendation "Set lockout threshold to 5 attempts" `
                -IEC62443 "FR1" -NIS2 "Art.21(b)"
        }
        elseif ([int]$lockoutThreshold -le 5) {
            Write-CheckResult -Category "Access Control" -CheckName "Account Lockout Threshold" `
                -Status "PASS" -Finding "Lockout after $lockoutThreshold failed attempts" `
                -Recommendation "N/A" -IEC62443 "FR1" -NIS2 "Art.21(b)"
        }
        else {
            Write-CheckResult -Category "Access Control" -CheckName "Account Lockout Threshold" `
                -Status "WARN" -Finding "Lockout after $lockoutThreshold attempts (recommended: 5)" `
                -Recommendation "Consider reducing to 5 attempts" `
                -IEC62443 "FR1" -NIS2 "Art.21(b)"
        }
    }
    catch {
        Write-CheckResult -Category "Access Control" -CheckName "Account Lockout Threshold" `
            -Status "WARN" -Finding "Could not retrieve lockout policy" `
            -Recommendation "Check manually: net accounts" -IEC62443 "FR1" -NIS2 "Art.21(b)"
    }
}

function Test-AutoLogon {
    Write-Host "[FR1] Checking Auto-Logon Settings..." -ForegroundColor Cyan

    $autoLogon = Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" -Name "AutoAdminLogon" -ErrorAction SilentlyContinue

    if ($autoLogon.AutoAdminLogon -eq "1") {
        $defaultUser = Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" -Name "DefaultUserName" -ErrorAction SilentlyContinue
        Write-CheckResult -Category "Access Control" -CheckName "Auto-Logon Disabled" `
            -Status "FAIL" -Finding "Auto-logon enabled for user: $($defaultUser.DefaultUserName)" `
            -Recommendation "Disable auto-logon in registry or use Autologon tool from Sysinternals" `
            -IEC62443 "FR1" -NIS2 "Art.21(b)"
    }
    else {
        Write-CheckResult -Category "Access Control" -CheckName "Auto-Logon Disabled" `
            -Status "PASS" -Finding "Auto-logon is disabled" `
            -Recommendation "N/A" -IEC62443 "FR1" -NIS2 "Art.21(b)"
    }
}

function Test-GuestAccount {
    Write-Host "[FR1] Checking Guest Account..." -ForegroundColor Cyan

    try {
        $guest = Get-LocalUser -Name "Guest" -ErrorAction SilentlyContinue
        if ($guest.Enabled) {
            Write-CheckResult -Category "Access Control" -CheckName "Guest Account Disabled" `
                -Status "FAIL" -Finding "Guest account is enabled" `
                -Recommendation "Disable Guest account: net user guest /active:no" `
                -IEC62443 "FR1" -NIS2 "Art.21(b)"
        }
        else {
            Write-CheckResult -Category "Access Control" -CheckName "Guest Account Disabled" `
                -Status "PASS" -Finding "Guest account is disabled" `
                -Recommendation "N/A" -IEC62443 "FR1" -NIS2 "Art.21(b)"
        }
    }
    catch {
        Write-CheckResult -Category "Access Control" -CheckName "Guest Account Disabled" `
            -Status "INFO" -Finding "Could not check Guest account status" `
            -Recommendation "Check manually" -IEC62443 "FR1" -NIS2 "Art.21(b)"
    }
}

function Test-AdminAccountRenamed {
    Write-Host "[FR1] Checking Administrator Account..." -ForegroundColor Cyan

    try {
        $admin = Get-LocalUser | Where-Object { $_.SID -like "*-500" }
        if ($admin.Name -eq "Administrator") {
            Write-CheckResult -Category "Access Control" -CheckName "Administrator Account Renamed" `
                -Status "WARN" -Finding "Default Administrator account name unchanged" `
                -Recommendation "Rename Administrator account to non-obvious name" `
                -IEC62443 "FR1" -NIS2 "Art.21(b)"
        }
        else {
            Write-CheckResult -Category "Access Control" -CheckName "Administrator Account Renamed" `
                -Status "PASS" -Finding "Administrator account renamed to: $($admin.Name)" `
                -Recommendation "N/A" -IEC62443 "FR1" -NIS2 "Art.21(b)"
        }
    }
    catch {
        Write-CheckResult -Category "Access Control" -CheckName "Administrator Account Renamed" `
            -Status "INFO" -Finding "Could not check Administrator account" `
            -Recommendation "Check manually" -IEC62443 "FR1" -NIS2 "Art.21(b)"
    }
}

# ============================================
# FR2 - USE CONTROL
# ============================================

function Test-USBAutorun {
    Write-Host "`n[FR2] Checking USB Autorun..." -ForegroundColor Cyan

    $autorun = Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" -Name "NoDriveTypeAutoRun" -ErrorAction SilentlyContinue

    # 255 = disable autorun for all drives
    if ($autorun.NoDriveTypeAutoRun -ge 255) {
        Write-CheckResult -Category "Use Control" -CheckName "USB Autorun Disabled" `
            -Status "PASS" -Finding "Autorun disabled for all drive types" `
            -Recommendation "N/A" -IEC62443 "FR2" -NIS2 "Art.21(c)"
    }
    else {
        Write-CheckResult -Category "Use Control" -CheckName "USB Autorun Disabled" `
            -Status "FAIL" -Finding "Autorun may be enabled (value: $($autorun.NoDriveTypeAutoRun))" `
            -Recommendation "Set NoDriveTypeAutoRun to 255 in Group Policy" `
            -IEC62443 "FR2" -NIS2 "Art.21(c)"
    }
}

function Test-ScreenLock {
    Write-Host "[FR2] Checking Screen Lock Timeout..." -ForegroundColor Cyan

    try {
        $timeout = Get-ItemProperty -Path "HKCU:\Control Panel\Desktop" -Name "ScreenSaveTimeOut" -ErrorAction SilentlyContinue
        $active = Get-ItemProperty -Path "HKCU:\Control Panel\Desktop" -Name "ScreenSaveActive" -ErrorAction SilentlyContinue
        $secure = Get-ItemProperty -Path "HKCU:\Control Panel\Desktop" -Name "ScreenSaverIsSecure" -ErrorAction SilentlyContinue

        $timeoutMinutes = [int]$timeout.ScreenSaveTimeOut / 60

        if ($active.ScreenSaveActive -eq "1" -and $secure.ScreenSaverIsSecure -eq "1" -and $timeoutMinutes -le 10) {
            Write-CheckResult -Category "Use Control" -CheckName "Screen Lock <= 10 minutes" `
                -Status "PASS" -Finding "Screen lock enabled after $timeoutMinutes minutes" `
                -Recommendation "N/A" -IEC62443 "FR2" -NIS2 "Art.21(b)"
        }
        elseif ($timeoutMinutes -gt 10) {
            Write-CheckResult -Category "Use Control" -CheckName "Screen Lock <= 10 minutes" `
                -Status "WARN" -Finding "Screen lock timeout: $timeoutMinutes minutes (recommended: 10)" `
                -Recommendation "Set screen saver timeout to 600 seconds (10 min) with password" `
                -IEC62443 "FR2" -NIS2 "Art.21(b)"
        }
        else {
            Write-CheckResult -Category "Use Control" -CheckName "Screen Lock <= 10 minutes" `
                -Status "FAIL" -Finding "Screen lock not properly configured" `
                -Recommendation "Enable password-protected screen saver with 10 min timeout" `
                -IEC62443 "FR2" -NIS2 "Art.21(b)"
        }
    }
    catch {
        Write-CheckResult -Category "Use Control" -CheckName "Screen Lock <= 10 minutes" `
            -Status "WARN" -Finding "Could not determine screen lock settings" `
            -Recommendation "Check screen saver settings manually" -IEC62443 "FR2" -NIS2 "Art.21(b)"
    }
}

# ============================================
# FR3 - SYSTEM INTEGRITY
# ============================================

function Test-Antivirus {
    Write-Host "`n[FR3] Checking Antivirus Status..." -ForegroundColor Cyan

    try {
        $av = Get-CimInstance -Namespace "root\SecurityCenter2" -ClassName AntiVirusProduct -ErrorAction SilentlyContinue

        if ($av) {
            $avNames = ($av | Select-Object -ExpandProperty displayName) -join ", "
            Write-CheckResult -Category "System Integrity" -CheckName "Antivirus Installed" `
                -Status "PASS" -Finding "Antivirus detected: $avNames" `
                -Recommendation "N/A" -IEC62443 "FR3" -NIS2 "Art.21(e)"

            # Check Windows Defender status
            $defenderStatus = Get-MpComputerStatus -ErrorAction SilentlyContinue
            if ($defenderStatus) {
                if ($defenderStatus.AntivirusEnabled -and $defenderStatus.RealTimeProtectionEnabled) {
                    Write-CheckResult -Category "System Integrity" -CheckName "Windows Defender Active" `
                        -Status "PASS" -Finding "Real-time protection enabled, signatures: $($defenderStatus.AntivirusSignatureLastUpdated)" `
                        -Recommendation "N/A" -IEC62443 "FR3" -NIS2 "Art.21(e)"
                }
                else {
                    Write-CheckResult -Category "System Integrity" -CheckName "Windows Defender Active" `
                        -Status "WARN" -Finding "Windows Defender not fully active" `
                        -Recommendation "Enable real-time protection" -IEC62443 "FR3" -NIS2 "Art.21(e)"
                }
            }
        }
        else {
            Write-CheckResult -Category "System Integrity" -CheckName "Antivirus Installed" `
                -Status "FAIL" -Finding "No antivirus detected" `
                -Recommendation "Install antivirus software approved for ICS environments" `
                -IEC62443 "FR3" -NIS2 "Art.21(e)"
        }
    }
    catch {
        Write-CheckResult -Category "System Integrity" -CheckName "Antivirus Installed" `
            -Status "WARN" -Finding "Could not check antivirus status" `
            -Recommendation "Verify antivirus manually" -IEC62443 "FR3" -NIS2 "Art.21(e)"
    }
}

function Test-WindowsUpdate {
    Write-Host "[FR3] Checking Windows Update Status..." -ForegroundColor Cyan

    try {
        $updateSession = New-Object -ComObject Microsoft.Update.Session
        $updateSearcher = $updateSession.CreateUpdateSearcher()
        $lastSearch = $updateSearcher.GetTotalHistoryCount()

        if ($lastSearch -gt 0) {
            $lastUpdate = $updateSearcher.QueryHistory(0, 1) | Select-Object -First 1
            $daysSinceUpdate = (Get-Date) - $lastUpdate.Date

            if ($daysSinceUpdate.Days -le 90) {
                Write-CheckResult -Category "System Integrity" -CheckName "Windows Update < 90 days" `
                    -Status "PASS" -Finding "Last update: $($lastUpdate.Date.ToString('yyyy-MM-dd')) ($($daysSinceUpdate.Days) days ago)" `
                    -Recommendation "N/A" -IEC62443 "FR3" -NIS2 "Art.21(e)"
            }
            else {
                Write-CheckResult -Category "System Integrity" -CheckName "Windows Update < 90 days" `
                    -Status "FAIL" -Finding "Last update: $($lastUpdate.Date.ToString('yyyy-MM-dd')) ($($daysSinceUpdate.Days) days ago)" `
                    -Recommendation "Apply security updates within 90-day window" `
                    -IEC62443 "FR3" -NIS2 "Art.21(e)"
            }
        }
    }
    catch {
        Write-CheckResult -Category "System Integrity" -CheckName "Windows Update < 90 days" `
            -Status "WARN" -Finding "Could not check Windows Update history" `
            -Recommendation "Check Windows Update manually" -IEC62443 "FR3" -NIS2 "Art.21(e)"
    }
}

function Test-PowerShellExecutionPolicy {
    Write-Host "[FR3] Checking PowerShell Execution Policy..." -ForegroundColor Cyan

    $policy = Get-ExecutionPolicy

    if ($policy -eq "Restricted" -or $policy -eq "AllSigned") {
        Write-CheckResult -Category "System Integrity" -CheckName "PowerShell Execution Policy" `
            -Status "PASS" -Finding "Execution policy: $policy" `
            -Recommendation "N/A" -IEC62443 "FR3" -NIS2 "Art.21(c)"
    }
    elseif ($policy -eq "RemoteSigned") {
        Write-CheckResult -Category "System Integrity" -CheckName "PowerShell Execution Policy" `
            -Status "WARN" -Finding "Execution policy: $policy (allows local unsigned scripts)" `
            -Recommendation "Consider AllSigned for production ICS systems" `
            -IEC62443 "FR3" -NIS2 "Art.21(c)"
    }
    else {
        Write-CheckResult -Category "System Integrity" -CheckName "PowerShell Execution Policy" `
            -Status "FAIL" -Finding "Execution policy: $policy (too permissive)" `
            -Recommendation "Set execution policy to AllSigned or RemoteSigned" `
            -IEC62443 "FR3" -NIS2 "Art.21(c)"
    }
}

function Test-UnnecessaryServices {
    Write-Host "[FR3] Checking Unnecessary Services..." -ForegroundColor Cyan

    # Services that should not be running on ICS/SCADA systems
    $unnecessaryServices = @(
        @{Name="DiagTrack"; Display="Connected User Experiences and Telemetry"},
        @{Name="dmwappushservice"; Display="Device Management WAP Push"},
        @{Name="WSearch"; Display="Windows Search"},
        @{Name="WMPNetworkSvc"; Display="Windows Media Player Network Sharing"},
        @{Name="RemoteRegistry"; Display="Remote Registry"},
        @{Name="lfsvc"; Display="Geolocation Service"},
        @{Name="MapsBroker"; Display="Downloaded Maps Manager"},
        @{Name="XblAuthManager"; Display="Xbox Live Auth Manager"},
        @{Name="XblGameSave"; Display="Xbox Live Game Save"},
        @{Name="XboxNetApiSvc"; Display="Xbox Live Networking Service"}
    )

    $runningUnnecessary = @()

    foreach ($svc in $unnecessaryServices) {
        $service = Get-Service -Name $svc.Name -ErrorAction SilentlyContinue
        if ($service -and $service.Status -eq "Running") {
            $runningUnnecessary += $svc.Display
        }
    }

    if ($runningUnnecessary.Count -eq 0) {
        Write-CheckResult -Category "System Integrity" -CheckName "No Unnecessary Services Running" `
            -Status "PASS" -Finding "No unnecessary services detected in running state" `
            -Recommendation "N/A" -IEC62443 "FR3" -NIS2 "Art.21(c)"
    }
    elseif ($runningUnnecessary.Count -le 3) {
        Write-CheckResult -Category "System Integrity" -CheckName "No Unnecessary Services Running" `
            -Status "WARN" -Finding "Unnecessary services running: $($runningUnnecessary -join ', ')" `
            -Recommendation "Disable unnecessary services to reduce attack surface" `
            -IEC62443 "FR3" -NIS2 "Art.21(c)"
    }
    else {
        Write-CheckResult -Category "System Integrity" -CheckName "No Unnecessary Services Running" `
            -Status "FAIL" -Finding "Multiple unnecessary services: $($runningUnnecessary -join ', ')" `
            -Recommendation "Disable telemetry, media, gaming and remote services on ICS systems" `
            -IEC62443 "FR3" -NIS2 "Art.21(c)"
    }
}

# ============================================
# FR4 - DATA CONFIDENTIALITY
# ============================================

function Test-BitLocker {
    Write-Host "`n[FR4] Checking BitLocker Status..." -ForegroundColor Cyan

    try {
        $bitlocker = Get-BitLockerVolume -MountPoint "C:" -ErrorAction SilentlyContinue

        if ($bitlocker.ProtectionStatus -eq "On") {
            Write-CheckResult -Category "Data Confidentiality" -CheckName "BitLocker Enabled (C:)" `
                -Status "PASS" -Finding "BitLocker protection: ON, Encryption: $($bitlocker.EncryptionPercentage)%" `
                -Recommendation "N/A" -IEC62443 "FR4" -NIS2 "Art.21(d)"
        }
        else {
            Write-CheckResult -Category "Data Confidentiality" -CheckName "BitLocker Enabled (C:)" `
                -Status "WARN" -Finding "BitLocker not enabled on system drive" `
                -Recommendation "Enable BitLocker for data-at-rest protection" `
                -IEC62443 "FR4" -NIS2 "Art.21(d)"
        }
    }
    catch {
        Write-CheckResult -Category "Data Confidentiality" -CheckName "BitLocker Enabled (C:)" `
            -Status "INFO" -Finding "BitLocker status could not be determined (may not be available)" `
            -Recommendation "Verify encryption status manually" -IEC62443 "FR4" -NIS2 "Art.21(d)"
    }
}

function Test-NetworkShares {
    Write-Host "[FR4] Checking Network Shares..." -ForegroundColor Cyan

    try {
        $shares = Get-SmbShare | Where-Object { $_.Name -notlike "*$" -and $_.Name -ne "Users" }

        if ($shares.Count -eq 0) {
            Write-CheckResult -Category "Data Confidentiality" -CheckName "No Unnecessary Network Shares" `
                -Status "PASS" -Finding "No non-administrative shares found" `
                -Recommendation "N/A" -IEC62443 "FR4" -NIS2 "Art.21(d)"
        }
        else {
            $shareList = ($shares | Select-Object -ExpandProperty Name) -join ", "
            Write-CheckResult -Category "Data Confidentiality" -CheckName "No Unnecessary Network Shares" `
                -Status "WARN" -Finding "Found shares: $shareList" `
                -Recommendation "Review and remove unnecessary network shares" `
                -IEC62443 "FR4" -NIS2 "Art.21(d)"
        }
    }
    catch {
        Write-CheckResult -Category "Data Confidentiality" -CheckName "No Unnecessary Network Shares" `
            -Status "INFO" -Finding "Could not enumerate shares" `
            -Recommendation "Check shares manually: Get-SmbShare" -IEC62443 "FR4" -NIS2 "Art.21(d)"
    }
}

function Test-SharesWithEveryone {
    Write-Host "[FR4] Checking Shares with Everyone Permissions..." -ForegroundColor Cyan

    try {
        $sharesWithEveryone = @()

        # Get all non-admin shares
        $shares = Get-SmbShare | Where-Object { $_.Name -notlike "*$" }

        foreach ($share in $shares) {
            $acl = Get-SmbShareAccess -Name $share.Name -ErrorAction SilentlyContinue
            # Check for Everyone (SID: S-1-1-0) or BUILTIN\Users with Full or Change access
            $everyoneAccess = $acl | Where-Object {
                ($_.AccountName -eq "Everyone" -or $_.AccountName -like "*\Everyone" -or
                 $_.AccountName -eq "BUILTIN\Users") -and
                ($_.AccessRight -eq "Full" -or $_.AccessRight -eq "Change")
            }
            if ($everyoneAccess) {
                $sharesWithEveryone += $share.Name
            }
        }

        if ($sharesWithEveryone.Count -eq 0) {
            Write-CheckResult -Category "Data Confidentiality" -CheckName "No Shares with Everyone Access" `
                -Status "PASS" -Finding "No shares grant full/change access to Everyone" `
                -Recommendation "N/A" -IEC62443 "FR4" -NIS2 "Art.21(d)"
        }
        else {
            Write-CheckResult -Category "Data Confidentiality" -CheckName "No Shares with Everyone Access" `
                -Status "FAIL" -Finding "Shares with Everyone access: $($sharesWithEveryone -join ', ')" `
                -Recommendation "Remove Everyone permissions, use specific security groups" `
                -IEC62443 "FR4" -NIS2 "Art.21(d)"
        }
    }
    catch {
        Write-CheckResult -Category "Data Confidentiality" -CheckName "No Shares with Everyone Access" `
            -Status "INFO" -Finding "Could not check share permissions" `
            -Recommendation "Check manually: Get-SmbShareAccess" -IEC62443 "FR4" -NIS2 "Art.21(d)"
    }
}

# ============================================
# FR5 - NETWORK SECURITY
# ============================================

function Test-Firewall {
    Write-Host "`n[FR5] Checking Windows Firewall..." -ForegroundColor Cyan

    try {
        $profiles = Get-NetFirewallProfile
        $allEnabled = $true

        foreach ($profile in $profiles) {
            if (-not $profile.Enabled) {
                $allEnabled = $false
                Write-CheckResult -Category "Network Security" -CheckName "Firewall Enabled ($($profile.Name))" `
                    -Status "FAIL" -Finding "Windows Firewall is DISABLED for $($profile.Name) profile" `
                    -Recommendation "Enable Windows Firewall for all profiles" `
                    -IEC62443 "FR5" -NIS2 "Art.21(c)"
            }
        }

        if ($allEnabled) {
            Write-CheckResult -Category "Network Security" -CheckName "Windows Firewall Enabled" `
                -Status "PASS" -Finding "Firewall enabled for all profiles (Domain, Private, Public)" `
                -Recommendation "N/A" -IEC62443 "FR5" -NIS2 "Art.21(c)"
        }
    }
    catch {
        Write-CheckResult -Category "Network Security" -CheckName "Windows Firewall Enabled" `
            -Status "WARN" -Finding "Could not check firewall status" `
            -Recommendation "Verify firewall settings manually" -IEC62443 "FR5" -NIS2 "Art.21(c)"
    }
}

function Test-RDP {
    Write-Host "[FR5] Checking RDP Configuration..." -ForegroundColor Cyan

    $rdpEnabled = Get-ItemProperty -Path "HKLM:\System\CurrentControlSet\Control\Terminal Server" -Name "fDenyTSConnections" -ErrorAction SilentlyContinue
    $nla = Get-ItemProperty -Path "HKLM:\System\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp" -Name "UserAuthentication" -ErrorAction SilentlyContinue

    if ($rdpEnabled.fDenyTSConnections -eq 1) {
        Write-CheckResult -Category "Network Security" -CheckName "RDP Disabled or NLA Required" `
            -Status "PASS" -Finding "RDP is disabled" `
            -Recommendation "N/A" -IEC62443 "FR5" -NIS2 "Art.21(c)"
    }
    elseif ($nla.UserAuthentication -eq 1) {
        Write-CheckResult -Category "Network Security" -CheckName "RDP Disabled or NLA Required" `
            -Status "WARN" -Finding "RDP enabled with NLA (Network Level Authentication)" `
            -Recommendation "Consider disabling RDP if not required, or use VPN" `
            -IEC62443 "FR5" -NIS2 "Art.21(c)"
    }
    else {
        Write-CheckResult -Category "Network Security" -CheckName "RDP Disabled or NLA Required" `
            -Status "FAIL" -Finding "RDP enabled WITHOUT NLA - high risk!" `
            -Recommendation "Enable NLA or disable RDP entirely" `
            -IEC62443 "FR5" -NIS2 "Art.21(c)"
    }
}

function Test-OpenPorts {
    Write-Host "[FR5] Checking Open Ports (LISTENING)..." -ForegroundColor Cyan

    try {
        $listeningPorts = Get-NetTCPConnection -State Listen | Select-Object LocalPort -Unique | Sort-Object LocalPort

        # Known risky ports
        $riskyPorts = @{
            21 = "FTP"
            23 = "Telnet"
            135 = "RPC"
            139 = "NetBIOS"
            445 = "SMB"
            1433 = "SQL Server"
            1434 = "SQL Browser"
            3389 = "RDP"
            5900 = "VNC"
        }

        $foundRisky = @()
        foreach ($port in $listeningPorts) {
            if ($riskyPorts.ContainsKey($port.LocalPort)) {
                $foundRisky += "$($port.LocalPort) ($($riskyPorts[$port.LocalPort]))"
            }
        }

        if ($foundRisky.Count -eq 0) {
            Write-CheckResult -Category "Network Security" -CheckName "No Risky Ports Open" `
                -Status "PASS" -Finding "No common risky ports detected in LISTENING state" `
                -Recommendation "N/A" -IEC62443 "FR5" -NIS2 "Art.21(c)"
        }
        else {
            Write-CheckResult -Category "Network Security" -CheckName "No Risky Ports Open" `
                -Status "WARN" -Finding "Risky ports listening: $($foundRisky -join ', ')" `
                -Recommendation "Review necessity of each open port, close if not required" `
                -IEC62443 "FR5" -NIS2 "Art.21(c)"
        }

        # WinCC specific ports
        $winccPorts = @(1433, 1434, 2308, 5412, 8889, 28092)
        $foundWinCC = @()
        foreach ($port in $listeningPorts) {
            if ($winccPorts -contains $port.LocalPort) {
                $foundWinCC += $port.LocalPort
            }
        }

        if ($foundWinCC.Count -gt 0) {
            Write-CheckResult -Category "Network Security" -CheckName "WinCC Ports Detected" `
                -Status "INFO" -Finding "WinCC-related ports listening: $($foundWinCC -join ', ')" `
                -Recommendation "Ensure WinCC ports are properly firewalled from untrusted networks" `
                -IEC62443 "FR5" -NIS2 "Art.21(c)"
        }
    }
    catch {
        Write-CheckResult -Category "Network Security" -CheckName "Open Ports Check" `
            -Status "WARN" -Finding "Could not enumerate open ports" `
            -Recommendation "Check manually: netstat -an" -IEC62443 "FR5" -NIS2 "Art.21(c)"
    }
}

# ============================================
# FR6 - TIMELY RESPONSE (Audit & Logging)
# ============================================

function Test-EventLog {
    Write-Host "`n[FR6] Checking Event Log Configuration..." -ForegroundColor Cyan

    try {
        $securityLog = Get-WinEvent -ListLog Security -ErrorAction SilentlyContinue

        if ($securityLog.IsEnabled) {
            $sizeMB = [math]::Round($securityLog.MaximumSizeInBytes / 1MB, 0)
            $retentionDays = if ($securityLog.LogMode -eq "Circular") { "Circular (overwrite)" } else { $securityLog.LogMode }

            if ($sizeMB -ge 100) {
                Write-CheckResult -Category "Audit & Logging" -CheckName "Security Event Log Enabled" `
                    -Status "PASS" -Finding "Security log enabled, size: ${sizeMB}MB, mode: $retentionDays" `
                    -Recommendation "N/A" -IEC62443 "FR6" -NIS2 "Art.21(g)"
            }
            else {
                Write-CheckResult -Category "Audit & Logging" -CheckName "Security Event Log Enabled" `
                    -Status "WARN" -Finding "Security log enabled but small (${sizeMB}MB)" `
                    -Recommendation "Increase Security log size to at least 100MB" `
                    -IEC62443 "FR6" -NIS2 "Art.21(g)"
            }
        }
        else {
            Write-CheckResult -Category "Audit & Logging" -CheckName "Security Event Log Enabled" `
                -Status "FAIL" -Finding "Security event log is DISABLED" `
                -Recommendation "Enable Security event log immediately" `
                -IEC62443 "FR6" -NIS2 "Art.21(g)"
        }
    }
    catch {
        Write-CheckResult -Category "Audit & Logging" -CheckName "Security Event Log Enabled" `
            -Status "WARN" -Finding "Could not check event log configuration" `
            -Recommendation "Verify event log settings manually" -IEC62443 "FR6" -NIS2 "Art.21(g)"
    }
}

function Test-AuditPolicy {
    Write-Host "[FR6] Checking Audit Policy..." -ForegroundColor Cyan

    try {
        $auditpol = auditpol /get /category:* 2>$null

        # Check for key audit categories
        $logonEvents = $auditpol | Select-String "Logon" | Select-String "Success and Failure"
        $objectAccess = $auditpol | Select-String "Object Access"

        if ($logonEvents) {
            Write-CheckResult -Category "Audit & Logging" -CheckName "Logon Auditing Enabled" `
                -Status "PASS" -Finding "Logon events are being audited" `
                -Recommendation "N/A" -IEC62443 "FR6" -NIS2 "Art.21(g)"
        }
        else {
            Write-CheckResult -Category "Audit & Logging" -CheckName "Logon Auditing Enabled" `
                -Status "WARN" -Finding "Logon auditing may not be fully configured" `
                -Recommendation "Enable auditing for Logon/Logoff events (Success and Failure)" `
                -IEC62443 "FR6" -NIS2 "Art.21(g)"
        }
    }
    catch {
        Write-CheckResult -Category "Audit & Logging" -CheckName "Audit Policy" `
            -Status "WARN" -Finding "Could not retrieve audit policy (requires admin)" `
            -Recommendation "Run as Administrator to check audit policy" -IEC62443 "FR6" -NIS2 "Art.21(g)"
    }
}

# ============================================
# FR7 - RESOURCE AVAILABILITY
# ============================================

function Test-SystemRestore {
    Write-Host "`n[FR7] Checking System Restore..." -ForegroundColor Cyan

    try {
        $restorePoints = Get-ComputerRestorePoint -ErrorAction SilentlyContinue

        if ($restorePoints) {
            $latest = $restorePoints | Sort-Object CreationTime -Descending | Select-Object -First 1
            $daysSince = ((Get-Date) - $latest.ConvertToDateTime($latest.CreationTime)).Days

            if ($daysSince -le 7) {
                Write-CheckResult -Category "Resource Availability" -CheckName "System Restore Point < 7 days" `
                    -Status "PASS" -Finding "Latest restore point: $daysSince days ago" `
                    -Recommendation "N/A" -IEC62443 "FR7" -NIS2 "Art.21(f)"
            }
            else {
                Write-CheckResult -Category "Resource Availability" -CheckName "System Restore Point < 7 days" `
                    -Status "WARN" -Finding "Latest restore point: $daysSince days ago" `
                    -Recommendation "Create regular restore points (weekly minimum)" `
                    -IEC62443 "FR7" -NIS2 "Art.21(f)"
            }
        }
        else {
            Write-CheckResult -Category "Resource Availability" -CheckName "System Restore Point < 7 days" `
                -Status "FAIL" -Finding "No restore points found" `
                -Recommendation "Enable System Restore and create restore points regularly" `
                -IEC62443 "FR7" -NIS2 "Art.21(f)"
        }
    }
    catch {
        Write-CheckResult -Category "Resource Availability" -CheckName "System Restore" `
            -Status "WARN" -Finding "Could not check System Restore status" `
            -Recommendation "Verify System Restore settings manually" -IEC62443 "FR7" -NIS2 "Art.21(f)"
    }
}

# ============================================
# WINCC SPECIFIC CHECKS
# ============================================

function Test-WinCCInstallation {
    Write-Host "`n[WinCC] Checking WinCC Installation..." -ForegroundColor Magenta

    # Check for WinCC V7
    $winccSetup = Get-ItemProperty "HKLM:\SOFTWARE\WOW6432Node\Siemens\WinCC\Setup" -ErrorAction SilentlyContinue
    $winccV8Key = Get-ItemProperty "HKLM:\SOFTWARE\Siemens\WinCC\Setup" -ErrorAction SilentlyContinue
    $winccPro = $winccSetup
    if (-not $winccPro) { $winccPro = $winccV8Key }

    # Check for WinCC RT Advanced / TIA Portal
    $winccTIA = Get-ItemProperty "HKLM:\SOFTWARE\Siemens\Automation\WinCC RT Advanced" -ErrorAction SilentlyContinue

    # Check for WinCC services
    $winccServices = Get-Service | Where-Object { $_.Name -like "*WinCC*" -or $_.Name -like "*CCAgent*" }

    if ($winccPro) {
        $version = $winccPro.Version
        $buildNr = $winccPro.BuildNr

        # BuildNr is more reliable for V8 detection (V08.xx = WinCC V8)
        if ($buildNr -match "^V08") {
            $versionLabel = "WinCC V8 detected: $version (Build: $buildNr)"
        } elseif ($buildNr -match "^V07" -or $version -match "^V?7\.") {
            $versionLabel = "WinCC V7 detected: $version"
        } elseif ($version -match "^8\.") {
            $versionLabel = "WinCC V8 detected: $version"
        } else {
            $versionLabel = "WinCC detected: $version"
        }
        Write-CheckResult -Category "WinCC Specific" -CheckName "WinCC Installation Detected" `
            -Status "INFO" -Finding $versionLabel `
            -Recommendation "Ensure WinCC is patched to latest version" `
            -IEC62443 "FR3" -NIS2 "Art.21(e)"
    }
    elseif ($winccTIA) {
        Write-CheckResult -Category "WinCC Specific" -CheckName "WinCC Installation Detected" `
            -Status "INFO" -Finding "WinCC (TIA Portal) detected" `
            -Recommendation "Ensure WinCC is patched to latest version" `
            -IEC62443 "FR3" -NIS2 "Art.21(e)"
    }
    elseif ($winccServices) {
        Write-CheckResult -Category "WinCC Specific" -CheckName "WinCC Installation Detected" `
            -Status "INFO" -Finding "WinCC services found: $($winccServices.Name -join ', ')" `
            -Recommendation "Verify WinCC version and patch status" `
            -IEC62443 "FR3" -NIS2 "Art.21(e)"
    }
    else {
        Write-CheckResult -Category "WinCC Specific" -CheckName "WinCC Installation Detected" `
            -Status "INFO" -Finding "No WinCC installation detected - general Windows ICS checks performed" `
            -Recommendation "N/A" -IEC62443 "FR3" -NIS2 "Art.21(e)"
    }
}

function Test-SQLServerForWinCC {
    Write-Host "[WinCC] Checking SQL Server Configuration..." -ForegroundColor Magenta

    try {
        $sqlService = Get-Service -Name "MSSQL*" -ErrorAction SilentlyContinue

        if ($sqlService) {
            $sqlInstance = $sqlService.Name -replace "MSSQL\$", ""

            # Check if SQL is listening only on localhost
            $sqlPorts = Get-NetTCPConnection -State Listen | Where-Object { $_.LocalPort -eq 1433 }

            if ($sqlPorts) {
                $localOnly = $sqlPorts | Where-Object { $_.LocalAddress -eq "127.0.0.1" -or $_.LocalAddress -eq "::1" }

                if ($localOnly.Count -eq $sqlPorts.Count) {
                    Write-CheckResult -Category "WinCC Specific" -CheckName "SQL Server Local Only" `
                        -Status "PASS" -Finding "SQL Server ($sqlInstance) listening on localhost only" `
                        -Recommendation "N/A" -IEC62443 "FR5" -NIS2 "Art.21(c)"
                }
                else {
                    Write-CheckResult -Category "WinCC Specific" -CheckName "SQL Server Local Only" `
                        -Status "WARN" -Finding "SQL Server listening on network interfaces" `
                        -Recommendation "Configure SQL Server to listen only on localhost if remote access not required" `
                        -IEC62443 "FR5" -NIS2 "Art.21(c)"
                }
            }
        }
    }
    catch {
        Write-CheckResult -Category "WinCC Specific" -CheckName "SQL Server Configuration" `
            -Status "INFO" -Finding "Could not check SQL Server configuration" `
            -Recommendation "Verify SQL Server security settings manually" `
            -IEC62443 "FR5" -NIS2 "Art.21(c)"
    }
}

function Test-WinCCDefaultUsers {
    Write-Host "[WinCC] Checking WinCC Default User Accounts..." -ForegroundColor Magenta

    if ($script:SystemInfo.WinCCUserCount -gt 0) {
        # Check for default user accounts that should be renamed or removed
        $defaultUsers = @('Administrator', 'Admin', 'Operator', 'Guest', 'User')
        $foundDefaults = @()

        foreach ($user in $script:SystemInfo.WinCCUsers) {
            if ($user -in $defaultUsers) {
                $foundDefaults += $user
            }
        }

        if ($foundDefaults.Count -eq 0) {
            Write-CheckResult -Category "WinCC Specific" -CheckName "No Default WinCC User Accounts" `
                -Status "PASS" -Finding "No default user accounts found in WinCC ($($script:SystemInfo.WinCCUserCount) users configured)" `
                -Recommendation "N/A" -IEC62443 "FR1" -NIS2 "Art.21(b)"
        }
        else {
            Write-CheckResult -Category "WinCC Specific" -CheckName "No Default WinCC User Accounts" `
                -Status "WARN" -Finding "Default accounts found: $($foundDefaults -join ', ')" `
                -Recommendation "Rename or disable default accounts, use unique usernames" `
                -IEC62443 "FR1" -NIS2 "Art.21(b)"
        }
    }
    else {
        Write-CheckResult -Category "WinCC Specific" -CheckName "No Default WinCC User Accounts" `
            -Status "INFO" -Finding "Could not retrieve WinCC user list" `
            -Recommendation "Verify WinCC user accounts manually" -IEC62443 "FR1" -NIS2 "Art.21(b)"
    }
}

function Test-WinCCRuntimeUser {
    Write-Host "[WinCC] Checking WinCC Runtime User Privileges..." -ForegroundColor Magenta

    try {
        # Check if WinCC Runtime (pdlrt.exe) is running and get its owner
        $runtimeProcess = Get-WmiObject -Query "SELECT * FROM Win32_Process WHERE Name='pdlrt.exe'" -ErrorAction SilentlyContinue

        if ($runtimeProcess) {
            $owner = $runtimeProcess.GetOwner()
            $userName = "$($owner.Domain)\$($owner.User)"

            # Check if user is in Administrators group
            $adminGroup = Get-WmiObject -Query "SELECT * FROM Win32_GroupUser WHERE GroupComponent='Win32_Group.Domain=""$env:COMPUTERNAME"",Name=""Administrators""'" -ErrorAction SilentlyContinue
            $isAdmin = $adminGroup | Where-Object { $_.PartComponent -match $owner.User }

            if ($isAdmin) {
                Write-CheckResult -Category "WinCC Specific" -CheckName "WinCC Runtime Non-Admin User" `
                    -Status "FAIL" -Finding "WinCC Runtime running as administrator: $userName" `
                    -Recommendation "Configure WinCC to run with a dedicated non-admin service account" `
                    -IEC62443 "FR1" -NIS2 "Art.21(b)"
            }
            else {
                Write-CheckResult -Category "WinCC Specific" -CheckName "WinCC Runtime Non-Admin User" `
                    -Status "PASS" -Finding "WinCC Runtime running as non-admin user: $userName" `
                    -Recommendation "N/A" -IEC62443 "FR1" -NIS2 "Art.21(b)"
            }
        }
        else {
            Write-CheckResult -Category "WinCC Specific" -CheckName "WinCC Runtime Non-Admin User" `
                -Status "INFO" -Finding "WinCC Runtime (pdlrt.exe) not currently running" `
                -Recommendation "Verify runtime user when WinCC is active" -IEC62443 "FR1" -NIS2 "Art.21(b)"
        }
    }
    catch {
        Write-CheckResult -Category "WinCC Specific" -CheckName "WinCC Runtime Non-Admin User" `
            -Status "INFO" -Finding "Could not determine WinCC Runtime user" `
            -Recommendation "Check manually when WinCC Runtime is active" -IEC62443 "FR1" -NIS2 "Art.21(b)"
    }
}

function Test-SiemensEncryptedCommunication {
    Write-Host "[WinCC] Checking Siemens Encrypted Communication..." -ForegroundColor Magenta

    try {
        # Check Siemens Discovery Security Level registry key
        $securityReg = Get-ItemProperty "HKLM:\SOFTWARE\Wow6432Node\SIEMENS\SCS\Discovery\Security" -ErrorAction SilentlyContinue

        if ($securityReg) {
            $level = $securityReg.Level
            if ($level -ge 1) {
                Write-CheckResult -Category "WinCC Specific" -CheckName "Siemens Encrypted Communication" `
                    -Status "PASS" -Finding "Encrypted communication enabled (Security Level: $level)" `
                    -Recommendation "N/A" -IEC62443 "FR5" -NIS2 "Art.21(c)"
            }
            else {
                Write-CheckResult -Category "WinCC Specific" -CheckName "Siemens Encrypted Communication" `
                    -Status "FAIL" -Finding "Encrypted communication disabled (Security Level: 0)" `
                    -Recommendation "Enable encrypted communication in Siemens Security Controller" `
                    -IEC62443 "FR5" -NIS2 "Art.21(c)"
            }
        }
        else {
            Write-CheckResult -Category "WinCC Specific" -CheckName "Siemens Encrypted Communication" `
                -Status "INFO" -Finding "Siemens Security configuration not found" `
                -Recommendation "Configure Siemens Security Controller if available" `
                -IEC62443 "FR5" -NIS2 "Art.21(c)"
        }
    }
    catch {
        Write-CheckResult -Category "WinCC Specific" -CheckName "Siemens Encrypted Communication" `
            -Status "INFO" -Finding "Could not check Siemens security settings" `
            -Recommendation "Verify Siemens security configuration manually" -IEC62443 "FR5" -NIS2 "Art.21(c)"
    }
}

function Test-WindowsTelemetry {
    Write-Host "[FR4] Checking Windows Telemetry Settings..." -ForegroundColor Cyan

    try {
        # Check telemetry level in registry
        $telemetry = Get-ItemProperty "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection" -Name "AllowTelemetry" -ErrorAction SilentlyContinue

        if ($telemetry) {
            $level = $telemetry.AllowTelemetry
            $levelNames = @{0="Security (Off)"; 1="Basic"; 2="Enhanced"; 3="Full"}
            $levelName = if ($levelNames.ContainsKey($level)) { $levelNames[$level] } else { "Unknown ($level)" }

            if ($level -eq 0) {
                Write-CheckResult -Category "Data Confidentiality" -CheckName "Windows Telemetry Disabled" `
                    -Status "PASS" -Finding "Telemetry level: $levelName" `
                    -Recommendation "N/A" -IEC62443 "FR4" -NIS2 "Art.21(d)"
            }
            elseif ($level -eq 1) {
                Write-CheckResult -Category "Data Confidentiality" -CheckName "Windows Telemetry Disabled" `
                    -Status "WARN" -Finding "Telemetry level: $levelName (consider Security level for ICS)" `
                    -Recommendation "Set AllowTelemetry to 0 (Security) in Group Policy" `
                    -IEC62443 "FR4" -NIS2 "Art.21(d)"
            }
            else {
                Write-CheckResult -Category "Data Confidentiality" -CheckName "Windows Telemetry Disabled" `
                    -Status "FAIL" -Finding "Telemetry level: $levelName (too permissive for ICS)" `
                    -Recommendation "Disable telemetry: Set AllowTelemetry to 0 in Group Policy" `
                    -IEC62443 "FR4" -NIS2 "Art.21(d)"
            }
        }
        else {
            # Check if DiagTrack service is disabled as alternative
            $diagTrack = Get-Service -Name "DiagTrack" -ErrorAction SilentlyContinue
            if ($diagTrack -and $diagTrack.StartType -eq "Disabled") {
                Write-CheckResult -Category "Data Confidentiality" -CheckName "Windows Telemetry Disabled" `
                    -Status "PASS" -Finding "DiagTrack service is disabled" `
                    -Recommendation "N/A" -IEC62443 "FR4" -NIS2 "Art.21(d)"
            }
            else {
                Write-CheckResult -Category "Data Confidentiality" -CheckName "Windows Telemetry Disabled" `
                    -Status "WARN" -Finding "Telemetry policy not configured via Group Policy" `
                    -Recommendation "Configure telemetry settings in Group Policy for ICS systems" `
                    -IEC62443 "FR4" -NIS2 "Art.21(d)"
            }
        }
    }
    catch {
        Write-CheckResult -Category "Data Confidentiality" -CheckName "Windows Telemetry Disabled" `
            -Status "INFO" -Finding "Could not check telemetry settings" `
            -Recommendation "Verify telemetry configuration manually" -IEC62443 "FR4" -NIS2 "Art.21(d)"
    }
}

#endregion

#region Report Generation

function New-HtmlReport {
    Write-Host "`nGenerating HTML Report..." -ForegroundColor Cyan

    $totalChecks = $script:PassCount + $script:FailCount + $script:WarnCount
    $complianceScore = if ($totalChecks -gt 0) { [math]::Round(($script:PassCount / $totalChecks) * 100, 1) } else { 0 }

    # Prepare IP addresses string
    $ipString = if ($script:SystemInfo.IPAddresses.Count -gt 0) { $script:SystemInfo.IPAddresses -join ", " } else { "N/A" }

    # Build Communication Architecture Tree HTML
    $commTreeHtml = ""
    if ($script:SystemInfo.CommTree -and $script:SystemInfo.CommTree.Count -gt 0) {
        $treeContent = ""

        foreach ($channel in $script:SystemInfo.CommTree) {
            # Channel (Driver)
            $treeContent += "<div class='tree-channel'>"
            $treeContent += "<div class='tree-node channel'>&#x1F4E1; $($channel.Name)</div>"
            $treeContent += "<div class='tree-children'>"

            foreach ($unit in $channel.Units) {
                # Unit
                $treeContent += "<div class='tree-unit'>"
                $treeContent += "<div class='tree-node unit'>&#x1F4E6; $($unit.Name)</div>"
                $treeContent += "<div class='tree-children'>"

                foreach ($conn in $unit.Connections) {
                    # Connection
                    $treeContent += "<div class='tree-node connection'>&#x1F517; $conn</div>"
                }

                $treeContent += "</div></div>"  # Close unit children and unit
            }

            $treeContent += "</div></div>"  # Close channel children and channel
        }

        # Build commTreeHtml using string concatenation to avoid here-string issues with CSS variables
        $commTreeHtml = '<div class="system-info" style="margin-bottom: 24px;">'
        $commTreeHtml += '<div style="grid-column: span 4;">'
        $commTreeHtml += '<span class="system-info-label" style="font-size: 14px; margin-bottom: 12px; display: block;">&#x1F310; Communication Architecture</span>'
        $commTreeHtml += '<div class="comm-tree">'
        $commTreeHtml += $treeContent
        $commTreeHtml += '</div></div></div>'
    }

    $html = @"
<!DOCTYPE html>
<html lang="en" data-theme="dark">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>ICScheck Security Report - $script:ComputerName</title>
    <style>
        :root {
            --bg-primary: #0D1117;
            --bg-secondary: #161B22;
            --bg-tertiary: #21262D;
            --text-primary: #E6EDF3;
            --text-secondary: #8B949E;
            --border: #30363D;
            --green: #238636;
            --red: #F85149;
            --yellow: #D29922;
            --blue: #58A6FF;
        }
        [data-theme="light"] {
            --bg-primary: #FFFFFF;
            --bg-secondary: #F6F8FA;
            --bg-tertiary: #EAEEF2;
            --text-primary: #1F2328;
            --text-secondary: #656D76;
            --border: #D0D7DE;
            --green: #1A7F37;
            --red: #CF222E;
            --yellow: #9A6700;
            --blue: #0969DA;
        }
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body {
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            background: var(--bg-primary);
            color: var(--text-primary);
            line-height: 1.6;
            padding: 40px;
            transition: background 0.3s, color 0.3s;
        }
        .container { max-width: 1200px; margin: 0 auto; }
        .header {
            text-align: center;
            margin-bottom: 24px;
            padding-bottom: 20px;
            border-bottom: 1px solid var(--border);
            position: relative;
        }
        .header h1 { font-size: 32px; color: var(--green); margin-bottom: 10px; }
        .header p { color: var(--text-secondary); }
        .theme-toggle {
            position: absolute;
            top: 0;
            right: 0;
            background: var(--bg-secondary);
            border: 1px solid var(--border);
            border-radius: 8px;
            padding: 8px 16px;
            cursor: pointer;
            color: var(--text-primary);
            font-size: 14px;
            display: flex;
            align-items: center;
            gap: 8px;
            transition: background 0.3s;
        }
        .theme-toggle:hover { background: var(--bg-tertiary); }
        .theme-toggle svg { width: 18px; height: 18px; }
        .system-info {
            background: var(--bg-secondary);
            border: 1px solid var(--border);
            border-radius: 12px;
            padding: 24px;
            margin-bottom: 24px;
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 16px;
        }
        .system-info-item {
            display: flex;
            flex-direction: column;
        }
        .system-info-label {
            font-size: 12px;
            color: var(--text-secondary);
            text-transform: uppercase;
            letter-spacing: 0.5px;
            margin-bottom: 4px;
        }
        .system-info-value {
            font-size: 16px;
            font-weight: 600;
            color: var(--text-primary);
        }
        .system-info-value.wincc { color: var(--blue); }
        .system-info-value.station-server { color: var(--green); }
        .system-info-value.station-client { color: var(--yellow); }
        .system-info-value.station-engineering { color: var(--blue); }
        .system-info-value.project { color: var(--purple, #a855f7); font-weight: 600; }
        .summary {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(150px, 1fr));
            gap: 16px;
            margin-bottom: 24px;
        }
        .summary-card {
            background: var(--bg-secondary);
            border: 1px solid var(--border);
            border-radius: 8px;
            padding: 20px;
            text-align: center;
            transition: background 0.3s;
        }
        .summary-card.score { border-color: var(--green); }
        .summary-card h2 { font-size: 32px; margin-bottom: 4px; }
        .summary-card p { color: var(--text-secondary); font-size: 13px; }
        .pass { color: var(--green); }
        .fail { color: var(--red); }
        .warn { color: var(--yellow); }
        .info { color: var(--blue); }
        .filter-tabs {
            display: flex;
            gap: 8px;
            margin-bottom: 16px;
            flex-wrap: wrap;
        }
        .filter-tab {
            background: var(--bg-secondary);
            border: 1px solid var(--border);
            border-radius: 20px;
            padding: 8px 20px;
            cursor: pointer;
            font-size: 14px;
            color: var(--text-secondary);
            transition: all 0.2s;
        }
        .filter-tab:hover { background: var(--bg-tertiary); color: var(--text-primary); }
        .filter-tab.active { background: var(--green); border-color: var(--green); color: white; }
        .filter-tab.active-fail { background: var(--red); border-color: var(--red); color: white; }
        .filter-tab.active-warn { background: var(--yellow); border-color: var(--yellow); color: white; }
        .filter-tab .count {
            display: inline-block;
            background: rgba(255,255,255,0.2);
            padding: 2px 8px;
            border-radius: 10px;
            margin-left: 6px;
            font-size: 12px;
        }
        table {
            width: 100%;
            border-collapse: collapse;
            margin-bottom: 40px;
            background: var(--bg-secondary);
            border-radius: 8px;
            overflow: hidden;
        }
        th {
            background: var(--bg-tertiary);
            padding: 16px;
            text-align: left;
            font-weight: 600;
            border-bottom: 1px solid var(--border);
        }
        td {
            padding: 16px;
            border-bottom: 1px solid var(--border);
            vertical-align: top;
        }
        tr:last-child td { border-bottom: none; }
        tr:hover { background: var(--bg-tertiary); }
        tr.hidden { display: none; }
        .status {
            display: inline-block;
            padding: 4px 12px;
            border-radius: 20px;
            font-size: 12px;
            font-weight: 600;
        }
        .status.pass { background: rgba(35, 134, 54, 0.2); color: var(--green); }
        .status.fail { background: rgba(248, 81, 73, 0.2); color: var(--red); }
        .status.warn { background: rgba(210, 153, 34, 0.2); color: var(--yellow); }
        .status.info { background: rgba(88, 166, 255, 0.2); color: var(--blue); }
        [data-theme="light"] .status.pass { background: rgba(26, 127, 55, 0.15); }
        [data-theme="light"] .status.fail { background: rgba(207, 34, 46, 0.15); }
        [data-theme="light"] .status.warn { background: rgba(154, 103, 0, 0.15); }
        [data-theme="light"] .status.info { background: rgba(9, 105, 218, 0.15); }
        .category-header {
            background: var(--bg-tertiary) !important;
            padding: 16px 24px;
            font-size: 18px;
            font-weight: 600;
        }
        .footer {
            text-align: center;
            margin-top: 40px;
            padding-top: 20px;
            border-top: 1px solid var(--border);
            color: var(--text-secondary);
            font-size: 14px;
        }
        .footer a { color: var(--green); text-decoration: none; }
        .recommendation { font-size: 13px; color: var(--text-secondary); margin-top: 8px; }
        .compliance-tag {
            display: inline-block;
            padding: 2px 8px;
            background: var(--bg-tertiary);
            border-radius: 4px;
            font-size: 11px;
            margin-right: 4px;
            position: relative;
            cursor: help;
        }
        .compliance-tag:hover::after {
            content: attr(data-tooltip);
            position: absolute;
            bottom: 100%;
            left: 50%;
            transform: translateX(-50%);
            background: var(--bg-primary);
            color: var(--text-primary);
            padding: 6px 10px;
            border-radius: 6px;
            font-size: 11px;
            white-space: nowrap;
            z-index: 100;
            border: 1px solid var(--border);
            box-shadow: 0 4px 12px rgba(0,0,0,0.3);
            margin-bottom: 4px;
        }
        .compliance-tag:hover::before {
            content: '';
            position: absolute;
            bottom: 100%;
            left: 50%;
            transform: translateX(-50%);
            border: 5px solid transparent;
            border-top-color: var(--border);
            margin-bottom: -6px;
            z-index: 101;
        }
        .category-desc {
            font-weight: 400;
            color: var(--text-secondary);
            font-size: 13px;
            margin-left: 8px;
        }
        .comm-tree {
            background: var(--bg-tertiary);
            border-radius: 8px;
            padding: 16px;
            font-family: 'Consolas', 'Monaco', monospace;
            font-size: 13px;
        }
        .comm-tree .tree-channel { margin-bottom: 8px; }
        .comm-tree .tree-node { padding: 4px 8px; border-radius: 4px; margin: 2px 0; display: block; }
        .comm-tree .tree-node.channel { background: var(--bg-secondary); color: var(--blue); font-weight: bold; }
        .comm-tree .tree-node.unit { background: var(--bg-secondary); color: var(--yellow); margin-left: 20px; }
        .comm-tree .tree-node.connection { color: var(--green); margin-left: 40px; }
        .comm-tree .tree-children { margin-left: 12px; border-left: 2px solid var(--border); padding-left: 8px; }
        @media (max-width: 768px) {
            body { padding: 16px; }
            .theme-toggle { position: static; margin-bottom: 16px; justify-content: center; }
            .system-info { grid-template-columns: 1fr 1fr; }
        }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <button class="theme-toggle" onclick="toggleTheme()">
                <svg class="sun-icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                    <circle cx="12" cy="12" r="5"></circle>
                    <line x1="12" y1="1" x2="12" y2="3"></line>
                    <line x1="12" y1="21" x2="12" y2="23"></line>
                    <line x1="4.22" y1="4.22" x2="5.64" y2="5.64"></line>
                    <line x1="18.36" y1="18.36" x2="19.78" y2="19.78"></line>
                    <line x1="1" y1="12" x2="3" y2="12"></line>
                    <line x1="21" y1="12" x2="23" y2="12"></line>
                    <line x1="4.22" y1="19.78" x2="5.64" y2="18.36"></line>
                    <line x1="18.36" y1="5.64" x2="19.78" y2="4.22"></line>
                </svg>
                <span class="theme-text">Light Mode</span>
            </button>
            <h1>ICScheck Security Report</h1>
            <p>Generated: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss') | Version: $script:Version</p>
        </div>

        <div class="system-info">
            <div class="system-info-item">
                <span class="system-info-label">Computer Name</span>
                <span class="system-info-value">$($script:SystemInfo.ComputerName)</span>
            </div>
            <div class="system-info-item">
                <span class="system-info-label">Operating System</span>
                <span class="system-info-value">$($script:SystemInfo.OSVersion)</span>
            </div>
            <div class="system-info-item">
                <span class="system-info-label">IP Address(es)</span>
                <span class="system-info-value">$ipString</span>
            </div>
            <div class="system-info-item">
                <span class="system-info-label">SCADA Software</span>
                <span class="system-info-value wincc">$($script:SystemInfo.WinCCVersion)</span>
            </div>
            <div class="system-info-item">
                <span class="system-info-label">Station Type</span>
                <span class="system-info-value station-$($script:SystemInfo.WinCCStationType.ToLower())">$($script:SystemInfo.WinCCStationType)</span>
            </div>
            <div class="system-info-item">
                <span class="system-info-label">WinCC Project</span>
                <span class="system-info-value project">$($script:SystemInfo.WinCCProject)</span>
            </div>
            $(if ($script:SystemInfo.ProjectCreated) { @"
            <div class="system-info-item">
                <span class="system-info-label">Project Created</span>
                <span class="system-info-value">$($script:SystemInfo.ProjectCreated)</span>
            </div>
            <div class="system-info-item">
                <span class="system-info-label">Last Edit</span>
                <span class="system-info-value">$($script:SystemInfo.ProjectLastEdit)</span>
            </div>
"@ })
            <div class="system-info-item">
                <span class="system-info-label">Scan Date</span>
                <span class="system-info-value">$($script:SystemInfo.ScanDate)</span>
            </div>
        </div>

        $(if ($script:SystemInfo.TagsTotal -gt 0) { @"
        <div class="system-info" style="margin-bottom: 24px;">
            <div class="system-info-item">
                <span class="system-info-label">Total Tags</span>
                <span class="system-info-value" style="color: var(--yellow);">$($script:SystemInfo.TagsTotal)</span>
            </div>
            <div class="system-info-item">
                <span class="system-info-label">PLCs Connected</span>
                <span class="system-info-value" style="color: var(--yellow);">$($script:SystemInfo.PLCCount)</span>
            </div>
            <div class="system-info-item">
                <span class="system-info-label">Archived Tags</span>
                <span class="system-info-value" style="color: var(--yellow);">$($script:SystemInfo.ArchivedTags)</span>
            </div>
        </div>
"@ })

        $(if ($script:SystemInfo.Architecture -eq "Server-Client") { @"
        <div class="system-info" style="margin-bottom: 24px;">
            <div class="system-info-item">
                <span class="system-info-label">Architecture</span>
                <span class="system-info-value" style="color: var(--blue);">$($script:SystemInfo.Architecture)</span>
            </div>
            <div class="system-info-item">
                <span class="system-info-label">Server</span>
                <span class="system-info-value" style="color: var(--green);">$($script:SystemInfo.ServerName)</span>
            </div>
            <div class="system-info-item">
                <span class="system-info-label">Client Count</span>
                <span class="system-info-value" style="color: var(--yellow);">$($script:SystemInfo.ClientStations.Count)</span>
            </div>
            <div class="system-info-item" style="grid-column: span 2;">
                <span class="system-info-label">Client Stations</span>
                <span class="system-info-value" style="color: var(--yellow); font-size: 14px;">$($script:SystemInfo.ClientStations -join '<br>')</span>
            </div>
        </div>
"@ })

        $(if ($script:SystemInfo.WinCCUserCount -gt 0) { @"
        <div class="system-info" style="margin-bottom: 24px;">
            <div class="system-info-item">
                <span class="system-info-label">WinCC User Count</span>
                <span class="system-info-value" style="color: var(--blue);">$($script:SystemInfo.WinCCUserCount)</span>
            </div>
            <div class="system-info-item" style="grid-column: span 3;">
                <span class="system-info-label">WinCC Users</span>
                <span class="system-info-value" style="font-size: 14px;">$($script:SystemInfo.WinCCUsers -join ', ')</span>
            </div>
        </div>
"@ })

        $commTreeHtml

        <div class="summary">
            <div class="summary-card score">
                <h2>$complianceScore%</h2>
                <p>Compliance Score</p>
            </div>
            <div class="summary-card">
                <h2 class="pass">$script:PassCount</h2>
                <p>Passed</p>
            </div>
            <div class="summary-card">
                <h2 class="fail">$script:FailCount</h2>
                <p>Failed</p>
            </div>
            <div class="summary-card">
                <h2 class="warn">$script:WarnCount</h2>
                <p>Warnings</p>
            </div>
        </div>

        <div class="filter-tabs">
            <button class="filter-tab active" data-filter="all" onclick="filterResults('all', this)">
                All<span class="count">$totalChecks</span>
            </button>
            <button class="filter-tab" data-filter="pass" onclick="filterResults('pass', this)">
                Passed<span class="count">$script:PassCount</span>
            </button>
            <button class="filter-tab" data-filter="fail" onclick="filterResults('fail', this)">
                Failed<span class="count">$script:FailCount</span>
            </button>
            <button class="filter-tab" data-filter="warn" onclick="filterResults('warn', this)">
                Warnings<span class="count">$script:WarnCount</span>
            </button>
        </div>

        <table>
            <thead>
                <tr>
                    <th style="width: 100px;">Status</th>
                    <th style="width: 200px;">Check</th>
                    <th>Finding</th>
                    <th style="width: 120px;">Compliance</th>
                </tr>
            </thead>
            <tbody>
"@

    $currentCategory = ""
    foreach ($result in $script:Results) {
        if ($result.Category -ne $currentCategory) {
            $currentCategory = $result.Category
            $categoryDesc = $script:CategoryDescriptions[$currentCategory]
            $descSpan = if ($categoryDesc) { "<span class='category-desc'>- $categoryDesc</span>" } else { "" }
            $html += "<tr class='category-row'><td colspan='4' class='category-header'>$currentCategory$descSpan</td></tr>"
        }

        $statusClass = $result.Status.ToLower()
        $frTooltip = $script:FRTooltips[$result.IEC62443]
        $nis2Tooltip = $script:NIS2Tooltips[$result.NIS2]
        $html += @"
                <tr data-status="$statusClass">
                    <td><span class="status $statusClass">$($result.Status)</span></td>
                    <td><strong>$($result.CheckName)</strong></td>
                    <td>
                        $($result.Finding)
                        $(if ($result.Recommendation -ne "N/A") { "<div class='recommendation'><strong>Recommendation:</strong> $($result.Recommendation)</div>" })
                    </td>
                    <td>
                        <span class="compliance-tag" data-tooltip="IEC 62443: $frTooltip">$($result.IEC62443)</span>
                        <span class="compliance-tag" data-tooltip="$nis2Tooltip">NIS2 $($result.NIS2)</span>
                    </td>
                </tr>
"@
    }

    $html += @"
            </tbody>
        </table>

        <div class="footer">
            <p>Generated by <a href="https://icscheck.com">ICScheck</a> v$script:Version |
            <a href="https://github.com/icscheck-tool/icscheck">GitHub</a> |
            MIT License</p>
        </div>
    </div>

    <script>
        // Theme toggle
        function toggleTheme() {
            const html = document.documentElement;
            const currentTheme = html.getAttribute('data-theme');
            const newTheme = currentTheme === 'dark' ? 'light' : 'dark';
            html.setAttribute('data-theme', newTheme);

            const themeText = document.querySelector('.theme-text');
            themeText.textContent = newTheme === 'dark' ? 'Light Mode' : 'Dark Mode';

            localStorage.setItem('icscheck-theme', newTheme);
        }

        // Load saved theme
        const savedTheme = localStorage.getItem('icscheck-theme');
        if (savedTheme) {
            document.documentElement.setAttribute('data-theme', savedTheme);
            document.querySelector('.theme-text').textContent = savedTheme === 'dark' ? 'Light Mode' : 'Dark Mode';
        }

        // Filter results
        function filterResults(filter, btn) {
            // Update active button
            document.querySelectorAll('.filter-tab').forEach(tab => {
                tab.classList.remove('active', 'active-fail', 'active-warn');
            });

            if (filter === 'fail') btn.classList.add('active-fail');
            else if (filter === 'warn') btn.classList.add('active-warn');
            else btn.classList.add('active');

            // Filter rows
            const rows = document.querySelectorAll('tbody tr');
            rows.forEach(row => {
                if (row.classList.contains('category-row')) {
                    // Category rows: show if any child matches
                    row.classList.remove('hidden');
                    return;
                }

                const status = row.getAttribute('data-status');
                if (filter === 'all' || status === filter) {
                    row.classList.remove('hidden');
                } else {
                    row.classList.add('hidden');
                }
            });

            // Hide empty categories
            const categoryRows = document.querySelectorAll('.category-row');
            categoryRows.forEach(catRow => {
                let hasVisibleChild = false;
                let nextRow = catRow.nextElementSibling;

                while (nextRow && !nextRow.classList.contains('category-row')) {
                    if (!nextRow.classList.contains('hidden')) {
                        hasVisibleChild = true;
                        break;
                    }
                    nextRow = nextRow.nextElementSibling;
                }

                if (hasVisibleChild || filter === 'all') {
                    catRow.classList.remove('hidden');
                } else {
                    catRow.classList.add('hidden');
                }
            });
        }
    </script>
</body>
</html>
"@

    $reportPath = Join-Path $OutputPath "ICScheck_Report_$script:ComputerName`_$script:ReportDate.html"
    $html | Out-File -FilePath $reportPath -Encoding UTF8

    return $reportPath
}

#endregion

#region Main Execution

Clear-Host
Write-Host @"

  _____ _____  _____      _               _
 |_   _/ ____|/ ____|    | |             | |
   | || |    | (___   ___| |__   ___  ___| | __
   | || |     \___ \ / __| '_ \ / _ \/ __| |/ /
  _| || |____ ____) | (__| | | |  __/ (__|   <
 |_____\_____|_____/ \___|_| |_|\___|\___|_|\_\

        Security Audit for ICS/SCADA
        Version: $script:Version
        https://icscheck.com

"@ -ForegroundColor Green

# Check admin rights
if (-not (Test-IsAdmin)) {
    Write-Host "WARNING: Running without Administrator privileges. Some checks may be limited." -ForegroundColor Yellow
    Write-Host "For full audit, run PowerShell as Administrator.`n" -ForegroundColor Yellow
}

Write-Host "Starting security audit of: $script:ComputerName" -ForegroundColor White
Write-Host "=" * 60

# Collect system information first
Get-SystemInfo
Write-Host ""

# Run all checks
Test-PasswordPolicy
Test-AccountLockout
Test-AutoLogon
Test-GuestAccount
Test-AdminAccountRenamed

Test-USBAutorun
Test-ScreenLock

Test-Antivirus
Test-WindowsUpdate
Test-PowerShellExecutionPolicy
Test-UnnecessaryServices

Test-BitLocker
Test-NetworkShares
Test-SharesWithEveryone
Test-WindowsTelemetry

Test-Firewall
Test-RDP
Test-OpenPorts

Test-EventLog
Test-AuditPolicy

Test-SystemRestore

Test-WinCCInstallation
Test-SQLServerForWinCC
Test-WinCCRuntimeUser
Test-WinCCDefaultUsers
Test-SiemensEncryptedCommunication

# Generate report
Write-Host "`n" + "=" * 60
Write-Host "AUDIT COMPLETE" -ForegroundColor Green
Write-Host "=" * 60

$totalChecks = $script:PassCount + $script:FailCount + $script:WarnCount
$complianceScore = if ($totalChecks -gt 0) { [math]::Round(($script:PassCount / $totalChecks) * 100, 1) } else { 0 }

Write-Host "`nSummary:" -ForegroundColor White
Write-Host "  Compliance Score: " -NoNewline; Write-Host "$complianceScore%" -ForegroundColor $(if ($complianceScore -ge 80) { "Green" } elseif ($complianceScore -ge 60) { "Yellow" } else { "Red" })
Write-Host "  Passed: " -NoNewline; Write-Host $script:PassCount -ForegroundColor Green
Write-Host "  Failed: " -NoNewline; Write-Host $script:FailCount -ForegroundColor Red
Write-Host "  Warnings: " -NoNewline; Write-Host $script:WarnCount -ForegroundColor Yellow

if (-not $SkipHtmlReport) {
    $reportPath = New-HtmlReport
    Write-Host "`nHTML Report saved to:" -ForegroundColor Cyan
    Write-Host "  $reportPath" -ForegroundColor White

    # Open report in browser
    Start-Process $reportPath
}

Write-Host "`nFor more information visit: https://icscheck.com" -ForegroundColor Gray

#endregion
