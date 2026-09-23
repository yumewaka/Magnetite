<#
.SYNOPSIS
    Build Magnetite into a self-contained, runnable distribution folder.

.DESCRIPTION
    Drives `cargo leptos build --release` (the single binary + the WASM/CSS site
    bundle), then assembles a `dist/magnetite` directory containing everything
    needed to run the platform on another machine:

        magnetite-server(.exe)   the single server binary
        site/                    compiled front-end assets (pkg/, favicon, ...)
        magnetite.toml           configuration (edit before production use)
        run.ps1 / run.sh         launchers that point the binary at ./site
        README.txt               quick-start

    The embedded database is created at ./data next to magnetite.toml on first
    run, so the folder is fully portable and stateful.

.PARAMETER OutDir
    Output directory (default: dist/magnetite).

.PARAMETER Zip
    Also produce dist/magnetite.zip.

.PARAMETER SkipBuild
    Reuse an existing target/release build (assemble only).

.EXAMPLE
    pwsh ./scripts/package.ps1 -Zip
#>
[CmdletBinding()]
param(
    [string]$OutDir = "dist/magnetite",
    [switch]$Zip,
    [switch]$SkipBuild
)

$ErrorActionPreference = "Stop"
$RepoRoot = Split-Path -Parent $PSScriptRoot
Set-Location $RepoRoot

function Require-Tool($name, $install) {
    if (-not (Get-Command $name -ErrorAction SilentlyContinue)) {
        throw "'$name' not found. Install it with: $install"
    }
}

Write-Host "==> Checking prerequisites" -ForegroundColor Cyan
Require-Tool "cargo" "https://rustup.rs"
Require-Tool "cargo-leptos" "cargo install cargo-leptos"
$targets = rustc --print target-list 2>$null
if (-not (rustup target list --installed | Select-String -SimpleMatch "wasm32-unknown-unknown")) {
    Write-Host "    Adding wasm32-unknown-unknown target" -ForegroundColor Yellow
    rustup target add wasm32-unknown-unknown
}

if (-not $SkipBuild) {
    Write-Host "==> cargo leptos build --release (this takes a while)" -ForegroundColor Cyan
    cargo leptos build --release
    if ($LASTEXITCODE -ne 0) { throw "cargo leptos build failed" }
}

# Locate build outputs.
$exe = if ($IsWindows -or $env:OS -eq "Windows_NT") { "magnetite-server.exe" } else { "magnetite-server" }
$binPath = Join-Path "target/release" $exe
$sitePath = "target/site"
if (-not (Test-Path $binPath)) { throw "Server binary not found at $binPath (did the build succeed?)" }
if (-not (Test-Path $sitePath)) { throw "Site bundle not found at $sitePath" }

Write-Host "==> Assembling $OutDir" -ForegroundColor Cyan
if (Test-Path $OutDir) { Remove-Item -Recurse -Force $OutDir }
New-Item -ItemType Directory -Force -Path $OutDir | Out-Null

Copy-Item $binPath (Join-Path $OutDir $exe)
Copy-Item -Recurse $sitePath (Join-Path $OutDir "site")
Copy-Item "magnetite.toml" (Join-Path $OutDir "magnetite.toml")

# Launchers: set LEPTOS_SITE_ROOT to the bundled site dir, then run the binary
# with the local config. The embedded DB lands in ./data automatically.
@'
#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")"
export LEPTOS_SITE_ROOT="./site"
exec ./magnetite-server magnetite.toml
'@ | Set-Content -Encoding utf8 -NoNewline (Join-Path $OutDir "run.sh")

@'
$ErrorActionPreference = "Stop"
Set-Location $PSScriptRoot
$env:LEPTOS_SITE_ROOT = "./site"
& ./magnetite-server.exe magnetite.toml
'@ | Set-Content -Encoding utf8 (Join-Path $OutDir "run.ps1")

@'
Magnetite - integrated infrastructure platform
==============================================

Run:
    Windows:  ./run.ps1
    Linux:    ./run.sh      (chmod +x run.sh magnetite-server first)

Then open the address in [server] of magnetite.toml (default
http://127.0.0.1:4000). The first launch creates ./data (the embedded
database) and prompts you to set up the first admin account.

Configuration (magnetite.toml):
  * [server] host/port      - set host = "0.0.0.0" to serve on the LAN.
  * [domains.<d>.server]     - uncomment to run the embedded DNS/DHCP/LDAP/
                               Mail/Proxy servers. Privileged ports (53, 67,
                               25, 389, 443) need elevated privileges.
  * [sso]                    - optional OIDC single sign-on; remove to use
                               local accounts only.

Keep magnetite-server, site/ and magnetite.toml together. ./data holds all
state - back it up to preserve accounts, zones, mailboxes, etc.
'@ | Set-Content -Encoding utf8 (Join-Path $OutDir "README.txt")

if (-not ($IsWindows -or $env:OS -eq "Windows_NT")) {
    chmod +x (Join-Path $OutDir $exe) (Join-Path $OutDir "run.sh")
}

Write-Host "==> Done: $OutDir" -ForegroundColor Green
Get-ChildItem $OutDir | Format-Table Name, Length -AutoSize

if ($Zip) {
    $zipPath = "$OutDir.zip"
    if (Test-Path $zipPath) { Remove-Item -Force $zipPath }
    Write-Host "==> Zipping -> $zipPath" -ForegroundColor Cyan
    Compress-Archive -Path $OutDir -DestinationPath $zipPath
    Write-Host "==> Wrote $zipPath" -ForegroundColor Green
}
