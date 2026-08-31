<#
    Aletheia HV -- direct WDK build script.

    Bypasses MSBuild / .vcxproj so the compile-error iteration loop is fast:
    cl.exe compiles each .c to .obj, ml64.exe assembles asm_x64.asm, link.exe
    produces aletheia_hv.sys. Signature is a separate step (signtool sign
    /a /v ...) so a failed build never wastes a signature.

    USAGE (inside a VM with the Windows Driver Kit installed):
      # from the repo's hv\ folder, in an elevated PowerShell:
      .\build.ps1                     # compile + link (no sign)
      .\build.ps1 -Sign               # compile + link + test-sign
      .\build.ps1 -Clean              # rm build\
      .\build.ps1 -Verbose            # dump every cl.exe / link.exe line

    REQUIRES: WDK 10 (or newer) installed under the standard location:
              C:\Program Files (x86)\Windows Kits\10
              -- specifically the km ("kernel-mode") libs + the ntddk.h/wdm.h
              headers + ml64.exe.
    First-run: the script auto-detects the newest KM lib + Include version.
#>
[CmdletBinding()]
param(
    [switch]$Sign,
    [switch]$Clean,
    [string]$OutName = "aletheia_hv"
)

$ErrorActionPreference = "Stop"
$hvRoot   = Split-Path -Parent $PSCommandPath
$buildDir = Join-Path $hvRoot "build"
$srcDir   = Join-Path $hvRoot "src"
$incDir   = Join-Path $hvRoot "include"

if ($Clean) { Remove-Item -Recurse -Force $buildDir -ErrorAction SilentlyContinue; Write-Host "clean." -Fore Cyan; return }
New-Item -ItemType Directory -Force -Path $buildDir | Out-Null

# ---- Locate the WDK ----------------------------------------------------------
$wdkRoot = "C:\Program Files (x86)\Windows Kits\10"
if (-not (Test-Path $wdkRoot)) { throw "WDK not found at $wdkRoot. Install the Windows Driver Kit." }

# Newest installed KM lib version (e.g. 10.0.22621.0).
$libVers = Get-ChildItem "$wdkRoot\Lib" -Directory | Where-Object { $_.Name -match '^\d+\.\d+\.\d+\.\d+$' } |
           Sort-Object Name -Descending
if (-not $libVers) { throw "No versioned $wdkRoot\Lib\* found." }
$libVer = $libVers[0].Name

$kmLib  = Join-Path $wdkRoot "Lib\$libVer\km\x64"
$incKm  = Join-Path $wdkRoot "Include\$libVer\km"
$incSh  = Join-Path $wdkRoot "Include\$libVer\shared"
$incUcrt= Join-Path $wdkRoot "Include\$libVer\ucrt"

foreach ($p in @($kmLib, $incKm, $incSh, $incUcrt)) {
    if (-not (Test-Path $p)) { throw "Missing WDK path: $p" }
}
Write-Host "[wdk] using version $libVer" -Fore Cyan

# ---- Locate MSVC (cl.exe / ml64.exe / link.exe) ------------------------------
# Prefer the Visual Studio Developer PowerShell environment if the user is
# already in one; else find the newest installed VC.
if ($env:VCINSTALLDIR) {
    $vcBin = Join-Path $env:VCINSTALLDIR "Tools\MSVC"
} else {
    $vsRoot = "C:\Program Files\Microsoft Visual Studio"
    if (-not (Test-Path $vsRoot)) { $vsRoot = "C:\Program Files (x86)\Microsoft Visual Studio" }
    $vcRoots = Get-ChildItem $vsRoot -Directory -ErrorAction SilentlyContinue | ForEach-Object {
        Get-ChildItem $_.FullName -Directory | ForEach-Object {
            $p = Join-Path $_.FullName "VC\Tools\MSVC"
            if (Test-Path $p) { $p }
        }
    }
    $vcBin = ($vcRoots | Select-Object -First 1)
}
if (-not $vcBin) { throw "Visual Studio C++ Build Tools not found; install a VS 2022 (or newer) with C++ + MSVC v143 x64." }

$msvcVers = Get-ChildItem $vcBin -Directory | Sort-Object Name -Descending
$msvcVer = $msvcVers[0].Name
$msvcBin = Join-Path (Join-Path $vcBin $msvcVer) "bin\Hostx64\x64"
$msvcLib = Join-Path (Join-Path $vcBin $msvcVer) "lib\x64"
$msvcInc = Join-Path (Join-Path $vcBin $msvcVer) "include"
$cl = Join-Path $msvcBin "cl.exe"
$ml = Join-Path $msvcBin "ml64.exe"
$link = Join-Path $msvcBin "link.exe"
foreach ($t in @($cl,$ml,$link)) {
    if (-not (Test-Path $t)) { throw "Missing MSVC tool: $t" }
}
Write-Host "[msvc] using $msvcVer" -Fore Cyan

# ---- Compile flags -----------------------------------------------------------
$env:INCLUDE = "$msvcInc;$incKm;$incSh;$incUcrt"
$env:LIB     = "$msvcLib;$kmLib"

# Kernel-mode flags per the WDK conventions.
$clFlags = @(
    "/nologo", "/c",
    "/W3", "/WX-", "/GS-", "/Gy", "/Zi",
    "/D_AMD64_", "/DAMD64", "/D_WIN64", "/DKERNEL_MODE=1",
    "/DPOOL_NX_OPTIN=1", "/DNDEBUG", "/kernel"
)
if ($VerbosePreference -eq "Continue") { $clFlags = @($clFlags | Where-Object { $_ -ne "/nologo" }) }

# ---- 1. Compile each .c ------------------------------------------------------
$cSources = @("vmx.c","vmcs.c","ept.c","svm.c","vmcb.c","npt.c","vmexit.c","vmi.c","driver.c") |
            ForEach-Object { Join-Path $srcDir $_ } | Where-Object { Test-Path $_ }
if (-not $cSources) { throw "No .c sources found under $srcDir." }

$objs = @()
foreach ($c in $cSources) {
    $obj = Join-Path $buildDir ([IO.Path]::GetFileNameWithoutExtension($c) + ".obj")
    Write-Host "[cc] $(Split-Path -Leaf $c)" -Fore DarkGray
    & $cl @clFlags "/I$incDir" "/Fo$obj" $c
    if ($LASTEXITCODE -ne 0) { throw "cl.exe failed on $c (exit $LASTEXITCODE)" }
    $objs += $obj
}

# ---- 2. Assemble asm_x64.asm -------------------------------------------------
$asm = Join-Path $srcDir "asm_x64.asm"
$asmObj = Join-Path $buildDir "asm_x64.obj"
Write-Host "[ml] asm_x64.asm" -Fore DarkGray
& $ml /nologo /c /Fo$asmObj $asm
if ($LASTEXITCODE -ne 0) { throw "ml64.exe failed on asm_x64.asm (exit $LASTEXITCODE)" }
$objs += $asmObj

# ---- 3. Link the .sys --------------------------------------------------------
$sys = Join-Path $buildDir "$OutName.sys"
$linkFlags = @(
    "/nologo", "/DRIVER",
    "/SUBSYSTEM:NATIVE,6.01",
    "/MACHINE:X64", "/DEBUG", "/OPT:REF", "/OPT:ICF",
    "/ENTRY:DriverEntry",
    "/NODEFAULTLIB", "/INCREMENTAL:NO", "/RELEASE",
    "/OUT:$sys",
    "ntoskrnl.lib", "hal.lib", "wdmsec.lib"
)
Write-Host "[link] $OutName.sys" -Fore DarkGray
& $link @linkFlags $objs
if ($LASTEXITCODE -ne 0) { throw "link.exe failed (exit $LASTEXITCODE)" }
Write-Host "[ok] built $sys" -Fore Green

# ---- 4. (optional) Test-sign -------------------------------------------------
if ($Sign) {
    $signtool = Get-ChildItem "$wdkRoot\bin\$libVer\x64\signtool.exe" -ErrorAction SilentlyContinue |
                Select-Object -First 1
    if (-not $signtool) { throw "signtool.exe not found under $wdkRoot\bin\$libVer\x64" }
    $certName = "AletheiaHVTest"
    $cert = Get-ChildItem Cert:\CurrentUser\My | Where-Object { $_.Subject -eq "CN=$certName" }
    if (-not $cert) {
        Write-Host "[sign] no test cert; creating CN=$certName" -Fore Cyan
        New-SelfSignedCertificate -Subject "CN=$certName" -Type CodeSigningCert `
            -CertStoreLocation Cert:\CurrentUser\My -KeyUsage DigitalSignature `
            -KeyAlgorithm RSA -KeyLength 2048 -HashAlgorithm SHA256 | Out-Null
        $cert = Get-ChildItem Cert:\CurrentUser\My | Where-Object { $_.Subject -eq "CN=$certName" } | Select-Object -First 1
    }
    & $signtool.FullName sign /fd SHA256 /sha1 $cert.Thumbprint /t http://timestamp.digicert.com $sys
    if ($LASTEXITCODE -ne 0) { throw "signtool sign failed (exit $LASTEXITCODE)" }
    Write-Host "[sign] test-signed OK" -Fore Green
}

Write-Host ""
Write-Host "Output: $sys" -Fore Green
