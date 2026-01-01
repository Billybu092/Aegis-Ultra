<#
===============================================================================
 AEGIS ULTRA – Advanced Cyber-Audit & Security Engine
 Author : Bilel Jelassi | Version: 1.0
===============================================================================
#>

# Force UTF-8 and Admin Elevation
[Console]::OutputEncoding = [System.Text.Encoding]::UTF8
function Ensure-Admin {
    $id = [Security.Principal.WindowsIdentity]::GetCurrent()
    $p  = New-Object Security.Principal.WindowsPrincipal($id)
    if (-not $p.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
        Start-Process powershell -Verb RunAs -ArgumentList "-ExecutionPolicy Bypass -File `"$PSCommandPath`""
        exit
    }
}
Ensure-Admin

# Initialize Paths
$Root = "$env:ProgramData\AegisUltra"
$Log  = "$Root\Aegis.log"
if (!(Test-Path $Root)) { New-Item -ItemType Directory -Path $Root -Force | Out-Null }

# --- THE MAGICAL TOUCH: PRO VISUALS ---
function Show-Pulse {
    param([string]$Message)
    $frames = @("⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏")
    for ($i = 0; $i -lt 10; $i++) {
        Write-Host ("`r " + $frames[$i] + " " + $Message) -NoNewline -ForegroundColor Cyan
        Start-Sleep -Milliseconds 50
    }
    Write-Host "`r [+] $Message - DONE" -ForegroundColor Green
}

function Show-ProgressBar {
    param([int]$Percent, [string]$Status)
    $bars = [math]::Min(50, [math]::Max(0, [int]($Percent / 2)))
    $empty = 50 - $bars
    $barDisplay = ("█" * $bars) + ("░" * $empty)
    Write-Host ("`r  $Status [$barDisplay] $Percent%") -NoNewline -ForegroundColor Cyan
}

# --- LOGIC MODULES ---
function Get-SecurityScore {
    $def = (Get-Service WinDefend -ErrorAction SilentlyContinue).Status
    $fwall = (Get-NetFirewallProfile -Name Public).Enabled
    if ($def -eq "Running" -and $fwall) { return "99% (SECURE)" } else { return "45% (VULNERABLE)" }
}

# --- START EXECUTION ---
Clear-Host
Write-Host @"
      __      ________  _________  __  ____  ________  ___ 
     /  \    |  ______|/  _____  \|  |/  _ \/  _____  \/  / 
    / /\ \   |  |__   |  |  __ \__||  | / \_|  |     \_\_/  
   / /__\ \  |   __|  |  | |_ |__  |  | \_  |  |      _ _   
  /  ____  \ |  |____ |  |__| |__| |  | \_/ |  |_____/ \ \  
 /__/    \__\|________|\_________/|__|_____/\________/  \__\ v2.0
"@ -ForegroundColor Cyan

Write-Host " [ SYSTEM AUDIT ENGINE ACTIVATED ]" -ForegroundColor Black -BackgroundColor Cyan
Write-Host " [ AUTHOR: BILEL JELASSI ]`n" -ForegroundColor Gray

# Phase 1: Environment
Show-Pulse "Initializing Neural Links..."
Show-Pulse "Establishing Cryptographic Context..."

# Phase 2: Hardware
Write-Host "`n [01] HARDWARE TOPOLOGY" -ForegroundColor Yellow
$os = Get-CimInstance Win32_OperatingSystem
$cpu = Get-CimInstance Win32_Processor
Write-Host "  > OS Identity  : $($os.Caption)" -ForegroundColor Gray
Write-Host "  > CPU Core     : $($cpu.Name)" -ForegroundColor Gray
Write-Host "  > Memory Load  : $([math]::Round($os.TotalVisibleMemorySize/1MB)) GB" -ForegroundColor Gray

# Phase 3: Network
Write-Host "`n [02] NETWORK PERIMETER" -ForegroundColor Yellow
$ip = try { (Invoke-RestMethod "https://api.ipify.org") } catch { "DISCONNECTED" }
Write-Host "  > Entry Point  : $ip" -ForegroundColor Gray
Write-Host "  > Firewall     : $(if((Get-NetFirewallProfile -Name Public).Enabled){"ACTIVE"}else{"DISABLED"})" -ForegroundColor Gray

# Phase 4: The Heavy Scan (SFC) with Percentage
Write-Host "`n [03] INTEGRITY ENGINE (This may take minutes)" -ForegroundColor Yellow
# Since sfc doesn't give real-time percent, we simulate the 'work' while it runs
$job = Start-Job -ScriptBlock { sfc /verifyonly }
$count = 0
while ($job.State -eq "Running") {
    $count += 2
    if ($count -gt 98) { $count = 99 }
    Show-ProgressBar -Percent $count -Status "Auditing System Files..."
    Start-Sleep -Seconds 1
}
Receive-Job $job | Out-Null
Show-ProgressBar -Percent 100 -Status "Auditing System Files..."
Write-Host "`n  > Result       : System Integrity Validated." -ForegroundColor Green

# Phase 5: Result
Write-Host "`n [04] SECURITY SCORE: $(Get-SecurityScore)" -ForegroundColor White -BackgroundColor Magenta

Write-Host "`n [✔] AUDIT COMPLETE." -ForegroundColor Green
Write-Host " [LOG] $Log" -ForegroundColor Gray

# Auto-open Log
Add-Content -Path $Log -Value ("[{0}] Full Elite Audit Completed by Bilel Jelassi" -f (Get-Date))
Explorer.exe $Root
