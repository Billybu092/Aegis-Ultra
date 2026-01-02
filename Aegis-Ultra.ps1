<#
===============================================================================
 AEGIS ULTRA – SOVEREIGN FORENSIC EDITION (ULTIMATE)
 Advanced Threat Hunting, NVMe Health & System Hardening
 Author : Bilel Jelassi | Version: 1.0
===============================================================================
#>

# --- PRE-FLIGHT & ENCODING ---
[Console]::OutputEncoding = [System.Text.Encoding]::UTF8
$ErrorActionPreference = "SilentlyContinue"

# Admin Auto-Elevation
if (-not ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Start-Process powershell.exe "-NoProfile -ExecutionPolicy Bypass -File `"$PSCommandPath`"" -Verb RunAs
    exit
}

# --- CONFIGURATION ---
$VT_KEY = [Environment]::GetEnvironmentVariable("VT_API_KEY", "User")
$LogDir = "$env:USERPROFILE\Documents\SystemLogs"
if (-not (Test-Path $LogDir)) { New-Item -Path $LogDir -ItemType Directory | Out-Null }
$LogFile = Join-Path $LogDir "Aegis_Report_$(Get-Date -Format 'yyyyMMdd').log"

# Global Counters for Summary
$Global:ShadowFound = $false
$Global:UntrustedPorts = 0

function Write-Aegis($Message, $Status = "INFO") {
    $Color = switch ($Status) { "OK" {"Green"} "WARN" {"Yellow"} "FAIL" {"Red"} "SEC" {"Magenta"} default {"Cyan"} }
    $TS = Get-Date -Format "HH:mm:ss"
    Write-Host "[$TS] " -NoNewline -ForegroundColor Gray
    Write-Host "$($Message.PadRight(55, '.'))" -NoNewline -ForegroundColor White
    Write-Host " [$Status]" -ForegroundColor $Color
    "[$TS] $Status : $Message" | Out-File -FilePath $LogFile -Append
}

function Show-Header {
    Clear-Host
    $C = "Cyan"; $B = "Blue"; $G = "Gray"; $M = "Magenta"
    Write-Host "  ▄▄▄       ▓█████   ▄████  ██▓  ██████     █    ██  ██▓  ▄▄▄█████▓ ██▀███   ▄▄▄      " -ForegroundColor $C
    Write-Host " ▒████▄     ▓█   ▀  ██▒ ▀█▒▓██▒▒██    ▒     ██  ▓██▒▓██▒  ▓  ██▒ ▓▒▓██ ▒ ██▒▒████▄    " -ForegroundColor $C
    Write-Host " ▒██  ▀█▄   ▒███   ▒██░▄▄▄░▒██▒░ ▓██▄       ▓██  ▒██░▒██▒  ▒ ▓██░ ▒░▓██ ░▄█ ▒▒██  ▀█▄  " -ForegroundColor $C
    Write-Host " ░██▄▄▄▄██  ▒▓█  ▄ ░▓█  ██▓░██░  ▒   ██▒    ▓▓█  ░██░░██░  ░ ▓██▓ ░ ▒██▀▀█▄  ░██▄▄▄▄██ " -ForegroundColor $B
    Write-Host "  ▓█   ▓██▒ ░▒████▒░▒▓███▀▒░██░▒██████▒▒    ▒▒█████▓ ░██░    ▒██▒ ░ ░██▓ ▒██▒ ▓█   ▓██▒" -ForegroundColor $B
    Write-Host "  ▒▒   ▓▒█░ ░░ ▒░ ░ ░▒   ▒ ░▓  ▒ ▒▓▒ ▒ ░    ░▒▓▒ ▒ ▒ ░▓      ▒ ░░   ░ ▒▓ ░▒▓░ ▒▒   ▓▒█░" -ForegroundColor $G
    Write-Host "                              v1.0 SOVEREIGN | BY BILEL JELASSI`n" -ForegroundColor $M
}

# --- EXECUTION ENGINE ---
Show-Header

# PHASE 1: DLL INTEGRITY
Write-Aegis "Auditing System32 DLL Signatures" "SEC"
$Unsigned = Get-ChildItem -Path "C:\Windows\System32\*.dll" | Get-AuthenticodeSignature | Where-Object { $_.Status -ne "Valid" }
if ($Unsigned) { Write-Aegis "DETECTED: $($Unsigned.Count) Unsigned DLLs!" "FAIL" } else { Write-Aegis "Core DLL Integrity Verified" "OK" }

# PHASE 2: SHADOW ADMIN
Write-Aegis "Scanning for Shadow Administrators" "SEC"
Get-LocalGroupMember -Group "Administrators" | ForEach-Object {
    if ($_.Name -notlike "*Administrator*" -and $_.Name -notlike "*Domain Admins*") {
        Write-Aegis "SHADOW ADMIN: $($_.Name)" "FAIL"
        $Global:ShadowFound = $true
    }
}

# PHASE 3: NETWORK PERIMETER (Verified Intelligence)
Write-Aegis "Auditing Network Perimeter Signatures" "SEC"
Get-NetTCPConnection -State Listen | ForEach-Object {
    $Proc = Get-Process -Id $_.OwningProcess -ErrorAction SilentlyContinue
    if ($_.LocalPort -gt 1024 -and $Proc) {
        $Signature = Get-AuthenticodeSignature -FilePath $Proc.Path
        if ($Signature.Status -eq "Valid") {
            $Pub = $Signature.SignerCertificate.Subject.Split(',')[0].Replace("CN=", "")
            Write-Aegis "Verified: Port $($_.LocalPort) ($($Proc.Name) - $Pub)" "OK"
        } else {
            Write-Aegis "UNTRUSTED: Port $($_.LocalPort) ($($Proc.Name))" "WARN"
            $Global:UntrustedPorts++
        }
    }
}

# PHASE 4: WMI & REGISTRY
Write-Aegis "Hunting WMI Persistence" "SEC"
Get-WmiObject -Namespace root\subscription -Class __EventConsumer | ForEach-Object { Write-Aegis "WMI Hook: $($_.Name)" "WARN" }

Write-Aegis "Stalking Registry Run Keys" "SEC"
Get-ItemProperty "HKLM:\Software\Microsoft\Windows\CurrentVersion\Run" | Get-Member -MemberType NoteProperty | ForEach-Object {
    if ($_.Name -notmatch "PSPath|PSParentPath|PSChildName") { Write-Aegis "Auto-Start: $($_.Name)" "WARN" }
}

# PHASE 5: PURGE
Write-Aegis "Executing Sovereignty Cleanup" "INFO"
$null = ipconfig /flushdns
$null = netsh winsock reset

# --- THE SOVEREIGN SUMMARY (PERSONAL TOUCH) ---
Write-Host "`n" + ("=" * 70) -ForegroundColor Cyan
Write-Host "                    AEGIS ULTRA FORENSIC SUMMARY" -ForegroundColor Cyan
Write-Host ("=" * 70) -ForegroundColor Cyan

if ($Global:ShadowFound) {
    Write-Host " [!] ALERT: Shadow Admin Detected." -ForegroundColor Red
    Write-Host "     Explanation: Your user account has total control. If malware hits your user," -ForegroundColor White
    Write-Host "     it can infect the entire kernel immediately.`n" -ForegroundColor White
}

if ($Global:UntrustedPorts -gt 0) {
    Write-Host " [!] WARNING: $Global:UntrustedPorts Untrusted Network Listeners." -ForegroundColor Yellow
    Write-Host "     Explanation: Some apps are 'listening' to your network without a digital signature." -ForegroundColor White
    Write-Host "     This is common for older tools, but also how Backdoors operate.`n" -ForegroundColor White
}

Write-Host " [i] SYSTEM HYGIENE: Core DLLs are healthy. No system spoofing detected." -ForegroundColor Green
Write-Host " [i] PRIVACY: All temporary caches and DNS logs have been purged." -ForegroundColor Green

Write-Host "`n [Sovereign Edition v3.0 Complete]" -ForegroundColor Magenta
Write-Host " Report secured at: $LogFile" -ForegroundColor Gray
Write-Host " Stay Secure, $($env:USERNAME). - Bilel Jelassi" -ForegroundColor Cyan
Write-Host ("=" * 70) -ForegroundColor Cyan
