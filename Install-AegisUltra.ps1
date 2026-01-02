<#
 AEGIS ULTRA – Master Installer (Syntax Fix Version)
#>

if (-not ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Start-Process powershell -Verb RunAs -ArgumentList "-ExecutionPolicy Bypass -File `"$PSCommandPath`""
    exit
}

$Target = "$env:ProgramFiles\AegisUltra"
$MainFile = "$Target\Aegis-Ultra.ps1"

if (!(Test-Path $Target)) { New-Item -ItemType Directory -Path $Target -Force | Out-Null }

if (Test-Path ".\Aegis-Ultra.ps1") {
    # 1. Copy the file
    Copy-Item ".\Aegis-Ultra.ps1" $MainFile -Force
    
    # 2. Read content and fix the specific broken lines
    $Content = Get-Content $MainFile
    
    # Fix the Ampersands (which cause "Reserved Character" errors)
    $Content = $Content -replace 'Verified & Owned', 'Verified and Owned'
    $Content = $Content -replace 'verified & repaire', 'verified and repaired'
    
    # Fix Line 213 (The terminator error caused by non-standard whitespace)
    $Content = $Content -replace 'Write-Host .*REPORT: \$LogFile.*', 'Write-Host "  |  REPORT: $LogFile" -ForegroundColor Gray'

    # 3. Save back with clean encoding
    $Content | Set-Content $MainFile -Encoding UTF8

    Write-Host "[✔] Installation Successful. Code patched for compatibility." -ForegroundColor Green
    & "$MainFile"
} else {
    Write-Host "[!] Error: Aegis-Ultra.ps1 not found in current folder." -ForegroundColor Red
}
