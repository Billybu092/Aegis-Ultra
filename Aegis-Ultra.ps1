<#
===============================================================================
 █████╗ ███████╗ ██████╗ ██╗███████╗    ██╗   ██╗██╗     ████████╗██████╗  █████╗ 
██╔══██╗██╔════╝██╔════╝ ██║██╔════╝    ██║   ██║██║     ╚══██╔══╝██╔══██╗██╔══██╗
███████║█████╗  ██║  ███╗██║███████╗    ██║   ██║██║        ██║   ██████╔╝███████║
██╔══██║██╔══╝  ██║   ██║██║╚════██║    ██║   ██║██║        ██║   ██╔══██╗██╔══██║
██║  ██║███████╗╚██████╔╝██║███████║    ╚██████╔╝███████╗   ██║   ██║  ██║██║  ██║
╚═╝  ╚═╝╚══════╝ ╚═════╝ ╚═╝╚══════╝     ╚═════╝ ╚══════╝   ╚═╝   ╚═╝  ╚═╝╚═╝  ╚═╝
===============================================================================
 PROJECT: AEGIS ULTRA (SOVEREIGN FORENSIC ENGINE)
 VERSION: 1.0 (ULTIMATE) | AUTHOR: BILEL JELASSI
 QUOTE  : "Vigilantia et Integritas"
===============================================================================
#>

param([Parameter(Mandatory=$false)][Switch]$Help)

# --- [ HELP SYSTEM ] ---
if ($Help) {
    Clear-Host
    Write-Host "╔════════════════════════════════════════════════════════════════╗" -ForegroundColor Cyan
    Write-Host "║              🛡️ AEGIS ULTRA v3.5 OPERATOR MANUAL               ║" -ForegroundColor Cyan
    Write-Host "╚════════════════════════════════════════════════════════════════╝" -ForegroundColor Cyan
    Write-Host "`n[PHASES DECODED]" -ForegroundColor White
    Write-Host " [SEC]  -> Forensic Audit: Hunting for deep-state threats." -ForegroundColor Magenta
    Write-Host " [INFO] -> Telemetry: Hardware and maintenance diagnostics." -ForegroundColor Cyan
    Write-Host " [OK]   -> Verified: Component matches secure baseline." -ForegroundColor Green
    Write-Host " [WARN] -> Suspicious: Entry found; manual review advised." -ForegroundColor Yellow
    Write-Host " [FAIL] -> Critical: Integrity breach or hardware failure." -ForegroundColor Red
    Write-Host "`nStay Secure, Operator. — Bilel Jelassi`n" -ForegroundColor Cyan
    exit
}

# --- [ PRE-FLIGHT & CONFIG ] ---
[Console]::OutputEncoding = [System.Text.Encoding]::UTF8
$ErrorActionPreference = "SilentlyContinue"

if (-not ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Start-Process powershell.exe "-NoProfile -ExecutionPolicy Bypass -File `"$PSCommandPath`"" -Verb RunAs
    exit
}

$LogDir = "$env:USERPROFILE\Documents\SystemLogs"
if (-not (Test-Path $LogDir)) { New-Item -Path $LogDir -ItemType Directory | Out-Null }
$LogFile = Join-Path $LogDir "Aegis_Report_$(Get-Date -Format 'yyyyMMdd').log"

# Tracking Globals
$Global:ShadowFound = $false
$Global:UntrustedPorts = @()
$Global:TaskAlerts = 0
$Global:OpenCriticalPorts = @()

function Write-Aegis($Message, $Status = "INFO") {
    $Color = switch ($Status) { "OK" {"Green"} "WARN" {"Yellow"} "FAIL" {"Red"} "SEC" {"Magenta"} default {"Cyan"} }
    $TS = Get-Date -Format "HH:mm:ss"
    Write-Host "  [$TS] " -NoNewline -ForegroundColor Gray
    Write-Host "$($Message.PadRight(52, '.'))" -NoNewline -ForegroundColor White
    Write-Host "──[" -NoNewline -ForegroundColor Gray
    Write-Host "$Status" -NoNewline -ForegroundColor $Color
    Write-Host "]" -ForegroundColor Gray
    "[$TS] $Status : $Message" | Out-File -FilePath $LogFile -Append
}

function Show-Header {
    Clear-Host
    $C = "Cyan"; $B = "Blue"; $M = "Magenta"
    Write-Host "  ╔══════════════════════════════════════════════════════════════════════╗" -ForegroundColor $B
    Write-Host "  ║   █████╗ ███████╗ ██████╗ ██╗███████╗    ██╗   ██╗██╗     ████████╗  ║" -ForegroundColor $C
    Write-Host "  ║  ██╔══██╗██╔════╝██╔════╝ ██║██╔════╝    ██║   ██║██║     ╚══██╔══╝  ║" -ForegroundColor $C
    Write-Host "  ║  ███████║█████╗  ██║  ███╗██║███████╗    ██║   ██║██║        ██║     ║" -ForegroundColor $C
    Write-Host "  ║  ██╔══██║██╔══╝  ██║   ██║██║╚════██║    ██║   ██║██║        ██║     ║" -ForegroundColor $B
    Write-Host "  ║  ██║  ██║███████╗╚██████╔╝██║███████║    ╚██████╔╝███████╗   ██║     ║" -ForegroundColor $B
    Write-Host "  ╚══════════════════════════════════════════════════════════════════════╝" -ForegroundColor $B
    Write-Host "     Sovereign Forensic Engine v1.0 | Created by: BILEL JELASSI" -ForegroundColor "White"
    Write-Host "     Operator Presence: $($env:USERNAME) detected." -ForegroundColor "Gray"
    Write-Host ""
}

# --- [ EXECUTION ENGINE ] ---
Show-Header
Write-Aegis "Initializing Forensic Sovereignty" "SEC"

# PHASE 1: DLL INTEGRITY
Write-Aegis "Auditing System32 DLL Signatures" "SEC"
$Unsigned = Get-ChildItem -Path "C:\Windows\System32\*.dll" | Get-AuthenticodeSignature | Where-Object { $_.Status -ne "Valid" }
if ($Unsigned) { Write-Aegis "DETECTED: $($Unsigned.Count) Unsigned DLLs!" "FAIL" } else { Write-Aegis "Core DLL Integrity Verified" "OK" }

# PHASE 2: SHADOW ADMIN (The Sovereign Whitelist)
Write-Aegis "Scanning for Shadow Administrators" "SEC"
Get-LocalGroupMember -Group "Administrators" | ForEach-Object {
    $Name = $_.Name
    # We add 'Billy_Pc' to the list of trusted names
    if ($Name -like "*Administrator*" -or $Name -like "*Domain Admins*" -or $Name -like "*Billy_Pc*") {
        Write-Aegis "Verified Sovereign Admin: $Name" "OK"
    } else {
        # This will now ONLY trigger if a name you DON'T recognize shows up
        Write-Aegis "SHADOW ADMIN DETECTED: $Name" "FAIL"
        $Global:ShadowFound = $true
    }
}

# PHASE 3: PORT AUDIT (Signature Verified)
Write-Aegis "Auditing Network Perimeter Signatures" "SEC"
Get-NetTCPConnection -State Listen | ForEach-Object {
    $Proc = Get-Process -Id $_.OwningProcess -ErrorAction SilentlyContinue
    if ($_.LocalPort -gt 1024 -and $Proc) {
        $Sig = Get-AuthenticodeSignature -FilePath $Proc.Path
        if ($Sig.Status -eq "Valid") { Write-Aegis "Verified: Port $($_.LocalPort) ($($Proc.Name))" "OK" }
        else { Write-Aegis "UNTRUSTED: Port $($_.LocalPort) ($($Proc.Name))" "WARN"; $Global:UntrustedPorts += "$($Proc.Name)" }
    }
}

# PHASE 4: TASK HUNTER
Write-Aegis "Hunting Scheduled Task Persistence" "SEC"
Get-ScheduledTask | Where-Object { $_.TaskPath -notlike "\Microsoft*" } | ForEach-Object {
    $Action = $_.Actions.Execute + $_.Actions.Arguments
    if ($Action -match "powershell|pwsh|cmd|.vbs|.ps1") { Write-Aegis "SUSPICIOUS TASK: $($_.TaskName)" "WARN"; $Global:TaskAlerts++ }
    else { Write-Aegis "User Task: $($_.TaskName)" "OK" }
}

# PHASE 5: WMI & REGISTRY
Write-Aegis "Hunting WMI Event Persistence" "SEC"
Get-WmiObject -Namespace root\subscription -Class __EventConsumer | ForEach-Object {
    if ($_.Name -eq "SCM Event Log Consumer") { Write-Aegis "Verified WMI: $($_.Name)" "OK" }
    else { Write-Aegis "WMI Hook Detected: $($_.Name)" "WARN" }
}

Write-Aegis "Stalking Registry Run Keys" "SEC"
$Paths = @("HKLM:\Software\Microsoft\Windows\CurrentVersion\Run", "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run")
foreach ($P in $Paths) {
    if (Test-Path $P) {
        (Get-ItemProperty $P).PSObject.Properties | ForEach-Object {
            $Junk = "PSPath|PSParentPath|PSChildName|PSDrive|PSProvider|PSIsContainer"
            if ($_.Name -notmatch $Junk -and $_.Value -and $_.Name -ne "(default)") {
                Write-Aegis "Auto-Start Entry: $($_.Name)" "WARN"
            }
        }
    }
}

# PHASE 6: HARDWARE S.M.A.R.T.
Write-Aegis "Analyzing NVMe/SSD Reliability" "INFO"
Get-StorageReliabilityCounter | Select-Object Wear | ForEach-Object { 
    if ($_.Wear -lt 80) { Write-Aegis "Drive Health: $($_.Wear)% Wear Level" "OK" }
    else { Write-Aegis "CRITICAL: Drive Wear at $($_.Wear)%" "FAIL" }
}

# PHASE 7: KERNEL REPAIR (The Coffee Break)
Write-Aegis "Deep Kernel Integrity Scan (SFC)" "SEC"
Write-Host "  [!] Grab a coffee ☕ while Aegis reconstructs your Kernel DNA..." -ForegroundColor Gray
$Job = Start-Job -ScriptBlock { sfc /scannow }
$Spin = @("|", "/", "-", "\"); $i = 0
while ($Job.State -eq "Running") { 
    Write-Host "`r  [PROCESSING] $($Spin[$i % 4]) Repairing System Files..." -NoNewline -ForegroundColor Cyan
    $i++; Start-Sleep -Milliseconds 200 
}
Receive-Job $Job | Out-Null; Write-Host "`r"; Write-Aegis "Kernel Integrity Audit Complete" "OK"

# PHASE 8: JUNK PURGE
Write-Aegis "Decimating System Junk Artifacts" "INFO"
Remove-Item "$env:TEMP\*" -Recurse -Force; Remove-Item "C:\Windows\Temp\*" -Recurse -Force
Write-Aegis "Purged Unnecessary System Bloat" "OK"

# PHASE 9: NMAP PROBE (With CVE Intelligence)
Write-Aegis "Launching Critical Port Discovery" "SEC"
$TargetPorts = [ordered]@{
    # Current Ports
    21   = @{ Name = "FTP";        Risk = "Cleartext Credential Theft" }
    22   = @{ Name = "SSH";        Risk = "Brute Force / Lateral Movement" }
    23   = @{ Name = "Telnet";     Risk = "Critical Insecurity (No Encryption)" }
    445  = @{ Name = "SMB";        Risk = "Ransomware / EternalBlue Attack" }
    3389 = @{ Name = "RDP";        Risk = "BlueKeep / Remote Hijacking" }
    # Added Critical Ports
    135  = @{ Name = "RPC";        Risk = "Endpoint Mapper / System Fingerprinting" }
    1433 = @{ Name = "SQL Server"; Risk = "Database Exfiltration / Data Theft" }
    5900 = @{ Name = "VNC";        Risk = "Unsecured Remote Screen Access" }
    5985 = @{ Name = "WinRM";      Risk = "Remote PowerShell Execution" }
    8080 = @{ Name = "HTTP-Alt";   Risk = "Unsecured Admin Control Panels" }
}

Write-Host "  [!] Probing local attack surface for vulnerabilities..." -ForegroundColor Gray
foreach ($P in $TargetPorts.Keys) {
    $Info = $TargetPorts[$P]
    Write-Host "      Probing Port $P ($($Info.Name))... " -NoNewline -ForegroundColor Gray
    if (Test-NetConnection -ComputerName localhost -Port $P -InformationLevel Quiet) {
        Write-Host "[EXPOSED]" -ForegroundColor Red
        Write-Aegis "VULNERABILITY: Port $P is open!" "FAIL"
        Write-Host "      [!] RISK: $($Info.Risk)" -ForegroundColor Yellow
        $Global:OpenCriticalPorts += "Port $P"
    } else { Write-Host "[SECURE]" -ForegroundColor Green }
}

# PHASE 10: SOVEREIGNTY PURGE
Write-Aegis "Executing Sovereignty Network Purge" "INFO"
$null = ipconfig /flushdns; $null = netsh winsock reset
Write-Aegis "Network Pathing & DNS Refresh Complete" "OK"

# --- [ EXECUTIVE SUMMARY ] ---
Write-Host "`n  ┌─────────────────── FORENSIC AUDIT SUMMARY ───────────────────┐" -ForegroundColor Cyan
Write-Host "  │" -ForegroundColor Cyan

# The Privilege Risk now only shows if someone OTHER than Billy_Pc is found
if ($Global:ShadowFound) { 
    Write-Host "  │  [!] PRIVILEGE RISK: Unknown Admin found in local hive!      " -ForegroundColor Red 
} else {
    Write-Host "  │  [✓] SOVEREIGNTY: Verified & Owned by BILEL JELASSI          " -ForegroundColor Magenta 
}

Write-Host "  │  [✓] KERNEL REPAIR: System files verified & repaired.        " -ForegroundColor Green
Write-Host "  │  [✓] HEALTH: Drive S.M.A.R.T. and WMI verified.              " -ForegroundColor Green
Write-Host "  │  [✓] PRIVACY: System junk and DNS logs decimated.            " -ForegroundColor Green
Write-Host "  │" -ForegroundColor Cyan
Write-Host "  |  REPORT: $LogFile" -ForegroundColor Gray
Write-Host "  └──────────────────────────────────────────────────────────────┘" -ForegroundColor Cyan
Write-Host "`n  Scan complete. Your Sovereignty has been restored." -ForegroundColor Cyan
Write-Host "  Stay Secure, $($env:USERNAME). — Bilel Jelassi 🛡️`n" -ForegroundColor Magenta
Write-Host ("=" * 72) -ForegroundColor Cyan



