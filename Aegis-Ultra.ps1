<#
===============================================================================
 AEGIS ULTRA – Windows Audit, Hygiene & Security Engine
 Author : Bilel Jelassi | Version: 1.0
===============================================================================
#>

function Ensure-Admin {
    $id = [Security.Principal.WindowsIdentity]::GetCurrent()
    $p  = New-Object Security.Principal.WindowsPrincipal($id)
    if (-not $p.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
        Write-Host "[!] Elevation required. Authenticating..." -ForegroundColor Cyan
        Start-Process powershell -Verb RunAs -ArgumentList "-ExecutionPolicy Bypass -File `"$PSCommandPath`""
        exit
    }
}
Ensure-Admin

$Root = "$env:ProgramData\AegisUltra"
$Log  = "$Root\Aegis.log"
# Force creation of directory if it doesn't exist
if (!(Test-Path $Root)) { New-Item -ItemType Directory -Path $Root -Force | Out-Null }

function Log {
    param($Msg)
    $Timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    Add-Content -Path $Log -Value ("[{0}] {1}" -f $Timestamp, $Msg)
}

# --- Advanced Modules ---
function Get-ExternalIP {
    try { (Invoke-RestMethod -Uri "https://api.ipify.org" -ErrorAction Stop) } catch { return "Offline" }
}

Clear-Host
Write-Host "🛡️ AEGIS ULTRA ENGINE" -ForegroundColor Cyan
Write-Host "Developed by Bilel Jelassi`n" -ForegroundColor Gray

# System Section
Write-Host "[>] Scanning Hardware..." -ForegroundColor Yellow
$os = Get-CimInstance Win32_OperatingSystem
[PSCustomObject]@{
    OS        = $os.Caption
    RAM_GB    = [math]::Round($os.TotalVisibleMemorySize / 1MB, 2)
    Public_IP = Get-ExternalIP
} | Format-Table

# Security Section
Write-Host "[>] Checking Defensive Perimeter..." -ForegroundColor Yellow
$DefStatus = (Get-Service WinDefend -ErrorAction SilentlyContinue).Status
[PSCustomObject]@{
    Defender  = if($DefStatus -eq "Running") {"✅ Protected"} else {"❌ Action Required"}
    Firewall  = if((Get-NetFirewallProfile -Name Public).Enabled) {"✅ On"} else {"❌ Off"}
} | Format-List

# Finalize
Write-Host "[>] Running Integrity Verification..." -ForegroundColor Yellow
Write-Progress -Activity "Aegis Ultra" -Status "Verifying System Files..."
sfc /verifyonly | Out-Null

Log "Sophisticated Audit Completed Successfully."
Write-Host "`n[✔] Audit complete. Log generated at: $Log" -ForegroundColor Green

# The 'Magical Touch': Automatically open the log location for the user
Explorer.exe $Root
