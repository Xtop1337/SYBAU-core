# Checks the Windows-specific behaviour of sybau.exe:
# file metadata, single instance, named-pipe control channel, proxying.
param([string]$Exe = "target\release\sybau.exe")
$ErrorActionPreference = "Stop"

function Fail($msg) { Write-Error "FAIL: $msg"; exit 1 }

$info = (Get-Item $Exe).VersionInfo
if ($info.ProductName -ne "SYBAU-CORE") { Fail "ProductName is '$($info.ProductName)'" }
if ($info.FileDescription -ne "SYBAU-CORE") { Fail "FileDescription is '$($info.FileDescription)'" }
if (-not $info.FileVersion) { Fail "FileVersion is empty" }
Write-Host "metadata OK: $($info.ProductName) $($info.FileVersion)"

$work = Join-Path $env:TEMP "sybau-smoke"
New-Item -ItemType Directory -Force $work | Out-Null
$config = Join-Path $work "config.json"
'{"inbounds":[{"type":"mixed","port":20821}],"outbounds":[{"type":"direct","tag":"direct"}]}' | Set-Content -Encoding ascii $config
"hello from origin" | Set-Content -Encoding ascii (Join-Path $work "index.txt")

$origin = Start-Process python -ArgumentList "-m","http.server","20822","--bind","127.0.0.1","--directory",$work -PassThru -WindowStyle Hidden
$core = Start-Process $Exe -ArgumentList "run","-c",$config -PassThru -WindowStyle Hidden `
    -RedirectStandardError (Join-Path $work "core.log")
try {
    Start-Sleep -Seconds 2
    if ($core.HasExited) { Fail "core exited early: $(Get-Content (Join-Path $work 'core.log') -Raw)" }
    if ((Get-Process -Id $core.Id).ProcessName -ne "sybau") { Fail "process name is not sybau" }

    # Second launch must exit with code 3 and leave the first one alone.
    $second = Start-Process $Exe -ArgumentList "run","-c",$config -PassThru -Wait -WindowStyle Hidden
    if ($second.ExitCode -ne 3) { Fail "second instance exit code $($second.ExitCode), expected 3" }
    if ($core.HasExited) { Fail "first instance died after second launch" }
    Write-Host "single instance OK"

    $status = & $Exe ctl core.status | ConvertFrom-Json
    if (-not $status.running) { Fail "core.status says not running" }
    if ($status.pid -ne $core.Id) { Fail "core.status pid mismatch" }
    Write-Host "named pipe control OK"

    $viaSocks = curl.exe -sS -m 10 --noproxy "" -x socks5h://127.0.0.1:20821 http://127.0.0.1:20822/index.txt
    if ($viaSocks -notmatch "hello from origin") { Fail "SOCKS5 proxying: '$viaSocks'" }
    $viaHttp = curl.exe -sS -m 10 --noproxy "" -x http://127.0.0.1:20821 http://127.0.0.1:20822/index.txt
    if ($viaHttp -notmatch "hello from origin") { Fail "HTTP proxying: '$viaHttp'" }
    $stats = & $Exe ctl stats.get | ConvertFrom-Json
    if ($stats.down -le 0) { Fail "no traffic counted" }
    Write-Host "proxying OK"

    & $Exe ctl core.stop | Out-Null
    if (-not $core.WaitForExit(5000)) { Fail "core did not exit after core.stop" }
    Write-Host "graceful stop OK"
}
finally {
    if (-not $core.HasExited) { $core.Kill() }
    if (-not $origin.HasExited) { $origin.Kill() }
}
# --- System proxy: set while running, restored on stop and after a crash ---
$key = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings"
Set-ItemProperty $key -Name ProxyEnable -Value 0
Set-ItemProperty $key -Name ProxyServer -Value "before.example:1"
$spConfig = Join-Path $work "sysproxy.json"
'{"inbounds":[{"type":"mixed","port":20831}],"system_proxy":{"enabled":true}}' | Set-Content -Encoding ascii $spConfig

function Expect-Proxy($enable, $server, $what) {
    $p = Get-ItemProperty $key
    if ($p.ProxyEnable -ne $enable -or $p.ProxyServer -ne $server) {
        Fail "$what: ProxyEnable=$($p.ProxyEnable) ProxyServer=$($p.ProxyServer), expected $enable / $server"
    }
}

$core = Start-Process $Exe -ArgumentList "run","-c",$spConfig,"--profile","sp" -PassThru -WindowStyle Hidden `
    -RedirectStandardError (Join-Path $work "sp.log")
Start-Sleep -Seconds 2
Expect-Proxy 1 "127.0.0.1:20831" "while running"
& $Exe ctl core.stop --profile sp | Out-Null
if (-not $core.WaitForExit(5000)) { Fail "core did not exit" }
Expect-Proxy 0 "before.example:1" "after a clean stop"
Write-Host "system proxy restored on stop OK"

$core = Start-Process $Exe -ArgumentList "run","-c",$spConfig,"--profile","sp" -PassThru -WindowStyle Hidden `
    -RedirectStandardError (Join-Path $work "sp2.log")
Start-Sleep -Seconds 2
Expect-Proxy 1 "127.0.0.1:20831" "while running again"
Stop-Process -Id $core.Id -Force
Start-Sleep -Seconds 3
Expect-Proxy 0 "before.example:1" "after the core was killed (guard)"
Write-Host "system proxy restored after a crash OK"

Write-Host "Windows smoke test passed"
