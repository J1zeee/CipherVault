# Builds native/win-x64/argon2.dll from the vendored P-H-C reference sources
# (tag 20190702, commit 62358ba2123abd17fccf2a108a301d4b52c01a7c) and prints its
# SHA-256. Needs Visual Studio with the C++ desktop workload.
#
# opt.c needs only SSE2, which every x64 CPU has; /arch:AVX2 is deliberately not
# used so the DLL still runs on older processors. /MT links the CRT statically, so
# the DLL has no vcruntime140.dll dependency. /Brepro makes the build deterministic:
# the same toolset produces the same bytes, so the hash in the README can be checked.

$ErrorActionPreference = 'Stop'

$root = $PSScriptRoot
$outDir = Join-Path $root '..\win-x64' | Resolve-Path -ErrorAction SilentlyContinue
if (-not $outDir) {
    $outDir = New-Item -ItemType Directory -Force (Join-Path $root '..\win-x64')
}
$outDir = "$outDir"

$vswhere = Join-Path ${env:ProgramFiles(x86)} 'Microsoft Visual Studio\Installer\vswhere.exe'
$vsPath = & $vswhere -latest -products * -requires Microsoft.VisualStudio.Component.VC.Tools.x86.x64 -property installationPath
if (-not $vsPath) {
    throw 'Visual Studio with the C++ x64 toolset was not found'
}
$vcvars = Join-Path $vsPath 'VC\Auxiliary\Build\vcvars64.bat'

$objDir = Join-Path ([IO.Path]::GetTempPath()) "argon2-build-$PID"
New-Item -ItemType Directory -Force $objDir | Out-Null

$sources = @(
    'src\argon2.c', 'src\core.c', 'src\encoding.c', 'src\opt.c', 'src\thread.c',
    'src\blake2\blake2b.c'
) | ForEach-Object { '"' + (Join-Path $root $_) + '"' }

$cl = "cl /nologo /c /O2 /MT /GS /guard:cf /Brepro /W3 /D_CRT_SECURE_NO_WARNINGS /I`"$root\include`" /I`"$root\src`" /Fo`"$objDir\\`" $($sources -join ' ')"
$link = "link /nologo /DLL /DYNAMICBASE /HIGHENTROPYVA /NXCOMPAT /GUARD:CF /Brepro /OUT:`"$outDir\argon2.dll`" `"$objDir\*.obj`""

try {
    # vcvars64 looks vswhere up on PATH; without it the script prints a harmless error.
    $env:PATH = "$(Split-Path $vswhere);$env:PATH"
    cmd /c "`"$vcvars`" >nul && $cl && $link"
    if ($LASTEXITCODE -ne 0) {
        throw "Build failed with exit code $LASTEXITCODE"
    }
}
finally {
    Remove-Item -Recurse -Force $objDir
    Remove-Item -Force -ErrorAction SilentlyContinue "$outDir\argon2.exp", "$outDir\argon2.lib"
}

(Get-FileHash -Algorithm SHA256 "$outDir\argon2.dll").Hash
