# Downloads the official Wintun build, checks its SHA-256 and extracts the
# DLL for one architecture. In GitHub Actions it also sets SYBAU_WINTUN_DLL
# so that the build embeds it.
param([ValidateSet("amd64", "arm64", "x86", "arm")][string]$Arch = "amd64")
$ErrorActionPreference = "Stop"

$version = "0.14.1"
# Published SHA-256 of wintun-0.14.1.zip.
$sha256 = "07c256185d6ee3652e09fa55c0b673e2624b565e02c4b9091c79ca7d2f24ef51"

$dir = Join-Path ([System.IO.Path]::GetTempPath()) "wintun-$version"
$zip = Join-Path $dir "wintun-$version.zip"
New-Item -ItemType Directory -Force $dir | Out-Null
if (-not (Test-Path $zip)) {
    Invoke-WebRequest "https://www.wintun.net/builds/wintun-$version.zip" -OutFile $zip
}
$got = (Get-FileHash $zip -Algorithm SHA256).Hash.ToLower()
if ($got -ne $sha256) {
    Remove-Item $zip
    throw "wintun-$version.zip: SHA-256 is $got, expected $sha256"
}
Expand-Archive $zip -DestinationPath $dir -Force
$dll = Join-Path $dir "wintun\bin\$Arch\wintun.dll"
if (-not (Test-Path $dll)) { throw "no $dll in the archive" }
Write-Host "wintun.dll ($Arch): $dll"
if ($env:GITHUB_ENV) {
    "SYBAU_WINTUN_DLL=$dll" | Out-File -FilePath $env:GITHUB_ENV -Append -Encoding utf8
    "SYBAU_WINTUN_LICENSE=$(Join-Path $dir 'wintun\LICENSE.txt')" | Out-File -FilePath $env:GITHUB_ENV -Append -Encoding utf8
}
