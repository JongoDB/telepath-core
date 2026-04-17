# install.ps1 — install telepath on Windows from a local release bundle.
#
# Usage (PowerShell):
#   1. Extract the release archive (e.g. telepath-0.1.0.tar.gz).
#   2. cd into that directory.
#   3. .\install.ps1
#
# Expected artifact in the current directory:
#   telepath-<version>-windows-amd64.zip
#
# Installs telepath.exe to $env:LOCALAPPDATA\telepath\bin and prints the
# PowerShell line to add that directory to your user PATH.

$ErrorActionPreference = 'Stop'

$arch = 'amd64'
# PowerShell's $env:PROCESSOR_ARCHITECTURE is AMD64, ARM64, x86; map to Go names.
switch ($env:PROCESSOR_ARCHITECTURE) {
    'AMD64' { $arch = 'amd64' }
    'ARM64' { Write-Error "telepath v0.1 doesn't ship windows/arm64 yet. Build from source."; exit 1 }
    default { Write-Error "Unsupported arch: $env:PROCESSOR_ARCHITECTURE"; exit 1 }
}

$artifact = Get-ChildItem -Filter "telepath-*-windows-$arch.zip" | Select-Object -First 1
if (-not $artifact) {
    Write-Error "No telepath zip for windows/$arch found in $(Get-Location)."
    exit 1
}

$installDir = Join-Path $env:LOCALAPPDATA 'telepath\bin'
New-Item -ItemType Directory -Force -Path $installDir | Out-Null

Write-Host "Installing $($artifact.Name) -> $installDir\telepath.exe"
Expand-Archive -Path $artifact.FullName -DestinationPath $installDir -Force

$bin = Join-Path $installDir 'telepath.exe'
if (-not (Test-Path $bin)) {
    Write-Error "Install verification failed: $bin not found."
    exit 1
}

Write-Host "Installed: $(& $bin --version)"
Write-Host ""
Write-Host "To add telepath to your user PATH, paste this into a PowerShell window:"
Write-Host ""
Write-Host "  [Environment]::SetEnvironmentVariable('PATH', '$installDir;' + [Environment]::GetEnvironmentVariable('PATH', 'User'), 'User')"
Write-Host ""
Write-Host "Then close and reopen PowerShell, and verify:"
Write-Host "  telepath --version"
Write-Host ""
Write-Host "Next steps:"
Write-Host "  1. telepath config init        # set up operator identity + Claude Code auth"
Write-Host "  2. telepath daemon run          # start the daemon (keep this window open)"
Write-Host "  3. telepath engagement new ... # create your first engagement (other window)"
