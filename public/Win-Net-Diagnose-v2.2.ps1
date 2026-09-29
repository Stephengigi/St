<#
.SYNOPSIS
Windows本地网络+系统综合诊断脚本 v2.2
运行要求：右键 -> 使用PowerShell运行(管理员)
执行时长：约50?60秒，仅检测，不会自动修改/删除文件！
功能：网络诊断 + 磁盘空间 + 蓝屏日志 + 基础安全风险筛查
#>
[Console]::OutputEncoding = [System.Text.Encoding]::UTF8
$ErrorActionPreference = "SilentlyContinue"

Write-Host "=============================================" -ForegroundColor Cyan
Write-Host "    Windows 网络+系统综合诊断工具 v2.2      " -ForegroundColor Cyan
Write-Host " ?本脚本仅检测，不会自动删除/修改任何文件！必须管理员权限运行" -ForegroundColor Yellow
Write-Host "=============================================`n" -ForegroundColor Cyan

$global:hasError = $false
$reportLines = @()

function Write-Report([string]$msg, [ValidateSet("OK","WARN","ERROR")]$level="OK"){
    switch($level){
        "OK" {Write-Host "? $msg`n" -ForegroundColor Green }
        "WARN" {Write-Host "??  $msg`n" -ForegroundColor Yellow; $global:hasError=$true }
        "ERROR" {Write-Host "? $msg`n" -ForegroundColor Red; $global:hasError=$true }
    }
    $reportLines += "[$level] $msg"
}

# 自定义函数：调用系统原生ping.exe，和CMD ping完全一致
function Test-PingNative{
    param(
        [string]$target,
        [int]$count = 1
    )
    $result = ping -n $count -w 1000 $target
    if($LASTEXITCODE -eq 0){
        return $true
    }else{
        return $false
    }
}

#1.权限校验
Write-Host "【1/15】校验脚本运行权限" -ForegroundColor White
$isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")
if(-not $isAdmin){
    Write-Report "未以管理员身份运行！部分检测项失效。关闭脚本，右键脚本选择【使用PowerShell运行(管理员)】" ERROR
}else{
    Write-Report "?已确认管理员权限" OK
}

#2.网卡检测
Write-Host "【2/15】网卡适配器状态检测" -ForegroundColor White
$adapters = Get-NetAdapter | Where-Object {$_.Status -ne 'Disabled'}
if($null -eq $adapters -or $adapters.Count -eq 0){
    Write-Report "没有找到启用的网卡适配器，请检查网卡驱动、设备管理器" ERROR
}else{
    foreach($nic in $adapters){
        $link = $nic.Status
        $name = $nic.Name
        if($link -ne 'Up'){
            Write-Report "网卡【$name】状态异常：$link；建议：检查网线/Wi-Fi开关，设备管理器查看网卡驱动是否异常" WARN
        }else{
            Write-Report "网卡【$name】状态正常(已连接)" OK
        }
    }
}

#3.IP DHCP
Write-Host "【3/15】IP地址 & DHCP 检测" -ForegroundColor White
$ipConfigs = Get-NetIPConfiguration -AddressFamily IPv4 | Where-Object {$_.InterfaceAlias -in $adapters.Name}
foreach($ipc in $ipConfigs){
    $ifName = $ipc.InterfaceAlias
    $dhcpEnabled = $ipc.DhcpEnabled
    $ipAddr = $ipc.IPAddress.IPAddress
    if([string]::IsNullOrEmpty($ipAddr)){
        Write-Report "网卡【$ifName】没有获取IPv4地址！" ERROR
        if($dhcpEnabled){
            Write-Report "网卡【$ifName】开启DHCP，但未拿到IP；排查：路由器DHCP服务、重启网卡 ipconfig /renew" WARN
        }else{
            Write-Report "网卡【$ifName】静态IP未配置，请核对静态IP参数" WARN
        }
    }else{
        $dhcpText = if($dhcpEnabled){"开启"}else{"关闭"}
        Write-Report "网卡【$ifName】IP:$ipAddr DHCP:$dhcpText" OK
    }
}

#4.DNS检测
Write-Host "【4/15】DNS服务器连通性检测" -ForegroundColor White
$dnsServers = Get-DnsClientServerAddress -AddressFamily IPv4 | Where-Object {$_.InterfaceAlias -in $adapters.Name}
$testDomains = @("baidu.com","microsoft.com")
foreach($dnsItem in $dnsServers){
    foreach($dns in $dnsItem.ServerAddresses){
        if([string]::IsNullOrWhiteSpace($dns)){continue}
        $dnsOk = $false
        foreach($d in $testDomains){
            try{
                $null = Resolve-DnsName -Name $d -Server $dns -ErrorAction Stop
                $dnsOk = $true
                break
            }catch{}
        }
        if($dnsOk){
            Write-Report "DNS服务器 $dns 解析正常" OK
        }else{
            Write-Report "DNS服务器 $dns 解析失败；修复建议：切换公共DNS：114.114.114.114 / 223.5.5.5" ERROR
        }
    }
}

#5.DNS缓存
Write-Host "【5/15】本地DNS缓存检查" -ForegroundColor White
try{
    $cache = Get-DnsClientCache
    Write-Report "本地DNS缓存读取成功；解析异常可执行 ipconfig /flushdns 清空DNS缓存" OK
}catch{
    Write-Report "读取DNS缓存异常，建议执行 ipconfig /flushdns" WARN
}

#6.网关ping（调用原生ping.exe，和CMD一模一样）
Write-Host "【6/15】默认网关连通ping测试" -ForegroundColor White
$routes = Get-NetRoute -AddressFamily IPv4 | Where-Object {$_.DestinationPrefix -eq '0.0.0.0/0'}
$gateways = $routes.NextHop | Select-Object -Unique
if($null -eq $gateways -or $gateways.Count -eq 0){
    Write-Report "系统没有配置默认网关，无法访问外网，请检查网卡配置" ERROR
}else{
    foreach($gw in $gateways){
        if($gw -eq "0.0.0.0"){continue}
        $pingGw = Test-PingNative -target $gw -count 1
        if($pingGw){
            Write-Report "默认网关 $gw ping 连通正常" OK
        }else{
            Write-Report "默认网关 $gw ping无应答（路由器屏蔽ICMP，不代表网络不能上网）" WARN
        }
    }
}

#7.外网连通（原生ping.exe，和CMD ping一致）
Write-Host "【7/15】外网互联网连通性测试" -ForegroundColor White
$internetTargets = @("223.5.5.5")
$internetOk = $false
foreach($t in $internetTargets){
    $res = Test-PingNative -target $t -count 1
    if($res){
        $internetOk=$true
        break
    }
}
if($internetOk){
    Write-Report "互联网基础IP连通正常" OK
}else{
    Write-Report "外网IP ping无应答（目标屏蔽ICMP，不代表网页无法访问）" WARN
}

#8.HOSTS检查
Write-Host "【8/15】系统Hosts文件检查" -ForegroundColor White
$hostsPath = "$env:SystemRoot\System32\drivers\etc\hosts"
$hostsContent = Get-Content $hostsPath -Encoding Default -ErrorAction SilentlyContinue
$badLines = $hostsContent | Where-Object { $_ -match "^\s*\d" -and $_ -notmatch "^#" -and ($_ -match "baidu.com|microsoft.com|qq.com")}
if($badLines.Count -gt 0){
    Write-Report "?? hosts文件发现非注释绑定域名记录，可能存在劫持！路径：$hostsPath" WARN
    Write-Host "异常行：`n$($badLines -join "`n")`n" -ForegroundColor Yellow
}else{
    Write-Report "hosts文件未发现可疑域名劫持记录" OK
}

#9.防火墙
Write-Host "【9/15】Windows Defender防火墙状态" -ForegroundColor White
$fwProf = Get-NetFirewallProfile
foreach($p in $fwProf){
    $pName = $p.Name
    $enable = $p.Enabled
    if($enable){
        Write-Report "防火墙配置文件[$pName]：已启用（系统默认安全状态）" OK
    }else{
        Write-Report "防火墙配置文件[$pName]：已关闭；安全风险，建议开启Windows Defender防火墙" WARN
    }
}

#10.网络服务
Write-Host "【10/15】关键网络系统服务检测" -ForegroundColor White
$svcList = @("Dhcp","Dnscache","NlaSvc","WinHttpAutoProxySvc")
foreach($svcName in $svcList){
    $svc = Get-Service -Name $svcName -ErrorAction SilentlyContinue
    if($null -eq $svc){ continue }
    if($svc.Status -eq 'Running'){
        Write-Report "服务 $svcName 正在运行" OK
    }else{
        Write-Report "关键网络服务 $svcName 未运行；尝试执行：Start-Service $svcName 或重启电脑" ERROR
    }
}

#11.代理检测
Write-Host "【11/15】系统代理/VPN检测" -ForegroundColor White
$proxyReg = Get-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings"
if($proxyReg.ProxyEnable -eq 1){
    Write-Report "?? Windows系统代理已开启！很多网页打不开、解析异常由此导致；建议关闭代理/VPN再测试网络" WARN
}else{
    Write-Report "系统代理未开启" OK
}

#12.磁盘空间
Write-Host "【12/15】磁盘分区空闲空间检测" -ForegroundColor White
$drives = Get-Volume | Where-Object {$_.DriveLetter -ne $null}
foreach($disk in $drives){
    $drvLetter = $disk.DriveLetter
    $sizeTotal = $disk.SizeRemaining + $disk.Size
    $sizeFreeGB = [math]::Round($disk.SizeRemaining / 1GB,2)
    $totalGB = [math]::Round($sizeTotal /1GB,2)
    if($drvLetter -eq "C"){
        if($sizeFreeGB -lt 15){
            Write-Report "C盘剩余空间仅 $sizeFreeGB GB (总$totalGB GB)！空间不足会导致系统卡顿、蓝屏、更新失败。建议清理回收站、下载文件夹、临时文件，释放至少15GB以上空间" ERROR
        }elseif($sizeFreeGB -lt 30){
            Write-Report "C盘剩余空间 $sizeFreeGB GB，偏低，建议清理文件，预留更多空间防止系统异常" WARN
        }else{
            Write-Report "C盘剩余空间充足：$sizeFreeGB GB" OK
        }
    }else{
        if($sizeFreeGB -lt 5){
            Write-Report "分区 $($drvLetter): 剩余 $sizeFreeGB GB，空间紧张，建议清理" WARN
        }else{
            Write-Report "分区 $($drvLetter): 剩余 $sizeFreeGB GB" OK
        }
    }
}

#13.蓝屏日志
Write-Host "【13/15】系统蓝屏(BSOD)日志 近30天检测" -ForegroundColor White
$startTime = (Get-Date).AddDays(-30)
$bsodEvents = Get-WinEvent -FilterHashtable @{LogName='System'; Id=1001; StartTime=$startTime} -ErrorAction SilentlyContinue
if($bsodEvents -and $bsodEvents.Count -gt 0){
    Write-Report "检测到最近30天存在【$($bsodEvents.Count)】次系统蓝屏崩溃！" ERROR
    foreach($e in $bsodEvents){
        Write-Host "? 蓝屏时间：$($e.TimeCreated) 描述：$($e.Message)`n" -ForegroundColor Red
    }
    Write-Host "修复参考：更新显卡/芯片组驱动、检查内存，C盘空间不足也会引发蓝屏；可查看事件管理器详细信息`n"
}else{
    Write-Report "近30天未检索到系统蓝屏崩溃记录" OK
}

#14.安全筛查
Write-Host "【14/15】基础安全风险筛查（Windows Defender+可疑文件）" -ForegroundColor White
$avStatus = Get-MpComputerStatus
if($avStatus.AntivirusEnabled -eq $true){
    Write-Report "Windows Defender防病毒已启用，实时保护开启" OK
}else{
    Write-Report "Windows Defender实时保护关闭！电脑缺少基础防护，容易中毒木马，建议开启" ERROR
}
$tempPath = $env:TEMP
$suspiciousExe = Get-ChildItem "$tempPath\*.exe" -ErrorAction SilentlyContinue
if($suspiciousExe -and $suspiciousExe.Count -gt 0){
    Write-Report "?? 用户临时目录发现 $($suspiciousExe.Count) 个可执行exe文件，存在恶意程序风险，建议全盘杀毒扫描" WARN
    Write-Host "可疑文件列表：`n$($suspiciousExe.FullName -join "`n")`n" -ForegroundColor Yellow
}else{
    Write-Report "用户临时目录未发现exe可疑文件" OK
}
$startupItems = Get-CimInstance Win32_StartupCommand
$unusualStartup = $startupItems | Where-Object {$_.Command -match "temp|%temp%|appdata\\local\\temp"}
if($unusualStartup){
    Write-Report "?? 发现从临时目录启动的开机程序，大概率是恶意木马，建议禁用并全盘扫描杀毒" WARN
    Write-Host "异常启动项：$($unusualStartup.Command)`n"
}else{
    Write-Report "开机启动项无临时目录可疑程序" OK
}
Write-Host "?? 重要提醒：本脚本仅简易筛查，无法完全查杀病毒木马，发现风险请使用Windows Defender全盘扫描`n"

#15.汇总
Write-Host "`n====================检测完成====================" -ForegroundColor Cyan
if($global:hasError){
    Write-Host "?? 本次检测发现【存在警告/异常】，部分警告不代表网络不可用，请仔细阅读提示。`n" -ForegroundColor Yellow
}else{
    Write-Host "? 全部网络+系统检测项未发现异常，本机系统与网络基础环境正常。`n" -ForegroundColor Green
}

Write-Host "脚本结束，按回车键关闭窗口……" -ForegroundColor White
$null = Read-Host
