# pack.ps1 -- pack the built aletheia_canary with UPX and Lethe (when available).
[CmdletBinding()]
param()
$ErrorActionPreference = "Stop"
$root = $PSScriptRoot
$exe  = Join-Path $root "canary\target\release\aletheia_canary.exe"
if (-not (Test-Path $exe)) {
    Write-Host "canary not built yet -- running cargo build --release first" -Fore Cyan
    Push-Location (Join-Path $root "canary")
    cargo build --release
    Pop-Location
}
if (-not (Test-Path $exe)) { throw "cargo build succeeded but $exe not found" }

# UPX -----------------------------------------------------------------------
$upx = (Get-Command upx -ErrorAction SilentlyContinue).Source
if ($upx) {
    $upxOut = Join-Path (Split-Path $exe) "aletheia_canary_upx.exe"
    Copy-Item $exe $upxOut -Force
    & $upx --best $upxOut
    Write-Host "[upx] $upxOut" -Fore Green
} else {
    Write-Host "[upx] skipped -- upx not on PATH" -Fore DarkGray
}

# Lethe ---------------------------------------------------------------------
if ($env:LETHE_BIN -and (Test-Path $env:LETHE_BIN)) {
    $letheOut = Join-Path (Split-Path $exe) "aletheia_canary_lethe.exe"
    # Lethe CLI: `lethe.py <in> -o <out>` per the Lethe repo docs.
    Write-Host "[lethe] running $env:LETHE_BIN" -Fore Cyan
    & $env:LETHE_BIN $exe -o $letheOut
    if (Test-Path $letheOut) {
        Write-Host "[lethe] $letheOut" -Fore Green
    }
} else {
    Write-Host "[lethe] skipped -- set `$env:LETHE_BIN` to your lethe launcher to enable" -Fore DarkGray
}

Write-Host ""
Write-Host "Point Aletheia at these to test detection:"
Write-Host "  raw:   $exe"
if ($upx)          { Write-Host "  upx:   " (Join-Path (Split-Path $exe) 'aletheia_canary_upx.exe') }
if ($env:LETHE_BIN){ Write-Host "  lethe: " (Join-Path (Split-Path $exe) 'aletheia_canary_lethe.exe') }
