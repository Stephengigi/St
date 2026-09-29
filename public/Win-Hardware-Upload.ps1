<#
.SYNOPSIS
LiSheng's Box Windows hardware collect and upload script
Run as administrator, collect hardware info and POST to web backend
#>
# ========== Modify site URL, local: http://127.0.0.1:3000, production use render domain ==========
$baseUrl = "http://127.0.0.1:3000"
#$baseUrl = "https://st-ws3r.onrender.com"

# Check admin privilege
$isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]"Administrator")
if(-not $isAdmin){
    Write-Host "❌ This script must run in Administrator PowerShell!" -ForegroundColor Red
    pause
    exit
}

Write-Host "`n===== Start collecting local hardware information =====" -ForegroundColor Cyan

# Collect BIOS serial number, device model
$bios = Get-CimInstance Win32_BIOS
$csInfo = Get-CimInstance Win32_ComputerSystem
$osInfo = Get-CimInstance Win32_OperatingSystem
$cpuInfo = Get-CimInstance Win32_Processor
$memoryTotalGB = [Math]::Round($csInfo.TotalPhysicalMemory / 1GB,2)

# Network adapter info(filter physical nic, exclude virtual adapters)
$nicList = @()
$nics = Get-CimInstance Win32_NetworkAdapterConfiguration | Where-Object {$_.MACAddress -and $_.IPAddress -and $_.Description -notmatch "VPN|Virtual|VMware|Hyper-V"}
foreach($nic in $nics){
    $nicList += [PSCustomObject]@{
        description = $nic.Description
        macAddress  = $nic.MACAddress
        ipAddress   = $nic.IPAddress
    }
}

# Build JSON payload
$payload = [PSCustomObject]@{
    computerName = $env:COMPUTERNAME
    model        = $csInfo.Model
    biosSN       = $bios.SerialNumber
    osCaption    = $osInfo.Caption
    osVersion    = $osInfo.Version
    cpuName      = $cpuInfo.Name.Trim()
    totalMemoryGB= $memoryTotalGB
    nicList      = $nicList
}

$jsonData = $payload | ConvertTo-Json -Depth 10
Write-Host "`n✅ Collection finished, preparing to upload:`n" -ForegroundColor Green
Write-Host $jsonData

# POST submit to backend api
try{
    $response = Invoke-RestMethod -Uri "$baseUrl/api/hardware/upload" -Method Post -Body $jsonData -ContentType "application/json"
    if($response.success){
        Write-Host "`n✅ Upload success!" -ForegroundColor Green
    }else{
        Write-Host "`n❌ Upload failed: $($response.msg)" -ForegroundColor Red
    }
}
catch{
    Write-Host "`n❌ Network request exception: $($_.Exception.Message)" -ForegroundColor Red
}

Write-Host "`nPress Enter to exit..." -ForegroundColor Gray
pause
