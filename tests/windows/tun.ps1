# TUN on Windows: the built-in wintun.dll, routes, pinning of the core's
# own sockets to the uplink, DNS hijacking, process rules, clean removal.
#
# Only 1.1.1.1/32 and 1.0.0.1/32 are routed into the TUN, so the runner's
# own connection is never touched. Those routes are enough to prove the
# loop protection: the core reaches 1.1.1.1 directly although the routing
# table sends 1.1.1.1 into the TUN. Needs administrator rights.
param([string]$Exe = "target\release\sybau.exe")
$ErrorActionPreference = "Stop"

function Fail($msg) {
    if (Test-Path $log) { Get-Content $log -Tail 40 | Write-Host }
    Write-Error "FAIL: $msg"
    exit 1
}
function Ok($msg) { Write-Host "  ok    $msg" }

$Exe = (Resolve-Path $Exe).Path
$work = Join-Path $env:TEMP "sybau-tun"
New-Item -ItemType Directory -Force $work | Out-Null
$log = Join-Path $work "core.log"
$dll = Join-Path (Split-Path -Parent $Exe) "wintun.dll"
# The copy built into sybau.exe must be used.
Remove-Item $dll -ErrorAction SilentlyContinue

$config = Join-Path $work "tun.json"
@'
{"log": {"level": "debug"},
 "control": {"path": "\\\\.\\pipe\\sybau-tun-test"},
 "inbounds": [{"type": "tun", "tag": "tun", "route_address": ["1.1.1.1/32", "1.0.0.1/32"]}],
 "outbounds": [{"type": "direct", "tag": "direct"}],
 "dns": {"servers": [{"tag": "cloudflare", "address": "udp://1.0.0.1"}],
         "hosts": {"hijack.test": ["192.0.2.7"]}},
 "route": {"rules": [{"process_name": ["curl.exe"], "action": "reject"}]}}
'@ | Set-Content -Encoding ascii $config

$core = Start-Process $Exe -ArgumentList "run", "-c", $config, "--profile", "tun" -PassThru -WindowStyle Hidden `
    -RedirectStandardError $log
try {
    $up = $false
    for ($i = 0; $i -lt 50; $i++) {
        Start-Sleep -Milliseconds 200
        if ($core.HasExited) { Fail "core exited early" }
        if ((Test-Path $log) -and (Select-String -Path $log -Pattern "TUN .* up" -Quiet)) { $up = $true; break }
    }
    if (-not $up) { Fail "TUN did not come up" }

    if (-not (Test-Path $dll)) { Fail "the built-in wintun.dll was not written next to sybau.exe" }
    Ok "built-in wintun.dll used"
    $adapter = Get-NetAdapter -Name "SYBAU" -ErrorAction SilentlyContinue
    if (-not $adapter) { Fail "adapter SYBAU not found" }
    Ok "adapter SYBAU: $($adapter.InterfaceDescription)"
    $route = Get-NetRoute -DestinationPrefix "1.1.1.1/32" -ErrorAction SilentlyContinue | Where-Object InterfaceAlias -eq "SYBAU"
    if (-not $route) { Fail "no route 1.1.1.1/32 via SYBAU" }
    Ok "route 1.1.1.1/32 via the TUN"

    $trace = (Invoke-WebRequest -UseBasicParsing -TimeoutSec 15 "http://1.1.1.1/cdn-cgi/trace").Content
    if ($trace -notmatch "ip=") { Fail "no answer from 1.1.1.1: $trace" }
    if (-not (Select-String -Path $log -Pattern "-> 1\.1\.1\.1:80 .*via direct" -Quiet)) { Fail "the request did not go through the TUN" }
    Ok "TCP through the TUN; the core's own connection bypassed it (no loop)"

    $hijack = Resolve-DnsName hijack.test -Server 1.1.1.1 -DnsOnly -Type A -ErrorAction SilentlyContinue
    if ($hijack.IPAddress -ne "192.0.2.7") { Fail "UDP DNS to 1.1.1.1 was not hijacked: $($hijack | Out-String)" }
    Ok "DNS over UDP hijacked"
    $real = Resolve-DnsName one.one.one.one -Server 1.1.1.1 -DnsOnly -Type A -TcpOnly -ErrorAction SilentlyContinue
    if (-not ($real.IPAddress -contains "1.1.1.1")) { Fail "DNS over TCP via the DNS module failed: $($real | Out-String)" }
    Ok "DNS over TCP hijacked, answered by the DNS module through the uplink"

    $viaCurl = & curl.exe -s -m 10 http://1.1.1.1/cdn-cgi/trace
    if ($viaCurl -match "ip=") { Fail "curl.exe was not rejected by the process rule" }
    if (-not (Select-String -Path $log -Pattern "rejected \(rule 0" -Quiet)) { Fail "no rejection in the log" }
    Ok "process rule matched curl.exe on a TUN connection"

    $system = Resolve-DnsName hijack.test -Type A -ErrorAction SilentlyContinue
    Write-Host "        (system resolver for hijack.test: $(@($system.IPAddress) -join ', '))"

    & $Exe ctl core.stop --endpoint "\\.\pipe\sybau-tun-test" | Out-Null
    if (-not $core.WaitForExit(10000)) { Fail "core did not exit after core.stop" }
    Start-Sleep -Seconds 1
    if (Get-NetAdapter -Name "SYBAU" -ErrorAction SilentlyContinue) { Fail "adapter SYBAU left behind" }
    if (Get-NetRoute -DestinationPrefix "1.1.1.1/32" -ErrorAction SilentlyContinue | Where-Object InterfaceAlias -eq "SYBAU") { Fail "route left behind" }
    Ok "clean exit removed the adapter and routes"
}
finally {
    if (-not $core.HasExited) { $core.Kill() }
}

# --- Kill switch (WFP) and the DNS block of strict_route -----------------
# Blocking phases are kept short and always end with tun-cleanup, so the
# runner's own network comes back even if a check fails.
function Can-Connect($ip, $port) {
    $c = [System.Net.Sockets.TcpClient]::new()
    try { return $c.ConnectAsync($ip, $port).Wait(3000) -and $c.Connected }
    catch { return $false }
    finally { $c.Dispose() }
}
function Start-Core($json, $name) {
    $path = Join-Path $work "$name.json"
    $json | Set-Content -Encoding ascii $path
    $script:log = Join-Path $work "$name.log"
    $p = Start-Process $Exe -ArgumentList "run", "-c", $path, "--profile", "tun" -PassThru -WindowStyle Hidden `
        -RedirectStandardError $script:log
    for ($i = 0; $i -lt 50; $i++) {
        Start-Sleep -Milliseconds 200
        if ($p.HasExited) { Fail "core exited early" }
        if ((Test-Path $script:log) -and (Select-String -Path $script:log -Pattern "TUN .* up" -Quiet)) { return $p }
    }
    Fail "TUN did not come up"
}

if (-not (Can-Connect "8.8.8.8" 53)) { Fail "baseline: 8.8.8.8:53 is not reachable" }
try {
    $core = Start-Core @'
{"inbounds": [{"type": "tun", "tag": "tun", "route_address": ["1.1.1.1/32", "1.0.0.1/32"], "kill_switch": true}],
 "outbounds": [{"type": "direct", "tag": "direct"}],
 "dns": {"servers": [{"tag": "google", "address": "udp://8.8.4.4"}]}}
'@ "killswitch"
    if (Can-Connect "8.8.8.8" 53) { Fail "kill switch: 8.8.8.8:53 reachable outside the TUN" }
    Ok "kill switch blocks traffic outside the TUN"
    $trace = (Invoke-WebRequest -UseBasicParsing -TimeoutSec 15 "http://1.1.1.1/cdn-cgi/trace").Content
    if ($trace -notmatch "ip=") { Fail "kill switch: traffic through the TUN is blocked too" }
    Ok "traffic through the TUN still flows"
    $real = Resolve-DnsName one.one.one.one -Server 1.0.0.1 -DnsOnly -Type A -ErrorAction SilentlyContinue
    if (-not ($real.IPAddress -contains "1.1.1.1")) { Fail "kill switch: the core's own DNS upstream (8.8.4.4) is blocked" }
    Ok "the core's own sockets are allowed"
    Stop-Process -Id $core.Id -Force
    Start-Sleep -Seconds 2
    if (Can-Connect "8.8.8.8" 53) { Fail "kill switch did not survive the crash" }
    Ok "kill switch stays after the core was killed"
    & $Exe tun-cleanup | Out-Null
    if (-not (Can-Connect "8.8.8.8" 53)) { Fail "tun-cleanup did not lift the kill switch" }
    Ok "tun-cleanup lifts it"

    $core = Start-Core @'
{"inbounds": [{"type": "tun", "tag": "tun", "route_address": ["1.1.1.1/32", "1.0.0.1/32"], "strict_route": true}],
 "outbounds": [{"type": "direct", "tag": "direct"}],
 "dns": {"servers": [{"tag": "google", "address": "udp://8.8.4.4"}]}}
'@ "strict"
    $leak = Resolve-DnsName example.com -Server 8.8.8.8 -DnsOnly -Type A -QuickTimeout -ErrorAction SilentlyContinue
    if ($leak) { Fail "strict_route: DNS to 8.8.8.8 outside the TUN was not blocked" }
    Ok "strict_route blocks DNS outside the TUN"
    if (-not (Can-Connect "8.8.8.8" 443)) { Fail "strict_route blocked more than DNS" }
    Ok "other traffic outside the TUN is untouched"
    Stop-Process -Id $core.Id -Force
    Start-Sleep -Seconds 2
    $after = Resolve-DnsName example.com -Server 8.8.8.8 -DnsOnly -Type A -ErrorAction SilentlyContinue
    if (-not $after) { Fail "the DNS block outlived the core" }
    Ok "the DNS block goes away with the core"
}
finally {
    if ($core -and -not $core.HasExited) { $core.Kill() }
    & $Exe tun-cleanup | Out-Null
}
Write-Host "Windows TUN test passed"
