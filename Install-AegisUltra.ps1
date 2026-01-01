<#
 AEGIS ULTRA – Installer & Automation
 Author: Bilel Jelassi
#>

function Ensure-Admin {
    $id = [Security.Principal.WindowsIdentity]::GetCurrent()
    $p  = New-Object Security.Principal.WindowsPrincipal($id)
    if (-not $p.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
        Start-Process powershell -Verb RunAs -ArgumentList "-ExecutionPolicy Bypass -File `"$PSCommandPath`""
        exit
    }
}
Ensure-Admin

$Target = "$env:ProgramFiles\AegisUltra"
if (!(Test-Path $Target)) {
    New-Item -ItemType Directory -Path $Target | Out-Null
}

# Ensure the file exists before copying
if (Test-Path ".\Aegis-Ultra.ps1") {
    Copy-Item ".\Aegis-Ultra.ps1" "$Target\Aegis-Ultra.ps1" -Force
    Write-Host "[✔] Aegis Ultra successfully installed to $Target" -ForegroundColor Green
    
    # Launch for initial audit
    powershell -ExecutionPolicy Bypass -File "$Target\Aegis-Ultra.ps1"
} else {
    Write-Host "[!] Error: Aegis-Ultra.ps1 not found in current directory." -ForegroundColor Red
}

