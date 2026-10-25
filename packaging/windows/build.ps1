# Build the Windows zip (x86_64 by default; -Target overrides it).
#
#   powershell -ExecutionPolicy Bypass -File packaging\windows\build.ps1
#   powershell -ExecutionPolicy Bypass -File packaging\windows\build.ps1 -Msi
#
# The C runtime is linked statically, so okagent.exe needs no Visual C++
# redistributable. hidapi's Win32 backend talks to hid.dll and setupapi.dll,
# which every Windows has.
#
# -Msi also builds an installer from okagent.wxs with the WiX 5 CLI
# (`dotnet tool install --global wix --version 5.0.2`), adding its util
# extension when missing.
#
# Output: dist\okagent-<version>-<target>.zip (and .msi) and an appended
#         SHA256SUMS.

param(
    [string] $Target = 'x86_64-pc-windows-msvc',
    [switch] $Msi
)

$wixVersion = '5.0.2'

$ErrorActionPreference = 'Stop'

$root = (Resolve-Path "$PSScriptRoot\..\..").Path
Set-Location $root

$metadata = cargo metadata --no-deps --format-version 1 | ConvertFrom-Json
if ($LASTEXITCODE -ne 0) { throw "cargo metadata failed ($LASTEXITCODE)" }
$version = ($metadata.packages | Where-Object name -eq 'okagent').version
$name = "okagent-$version-$Target"
$dist = Join-Path $root 'dist'
$stage = Join-Path ([IO.Path]::GetTempPath()) "okagent-stage-$PID"
$prefix = Join-Path $stage $name

if (-not (rustup target list --installed | Select-String -SimpleMatch -Pattern $Target -Quiet)) {
    Write-Host "installing rustup target $Target"
    rustup target add $Target
    if ($LASTEXITCODE -ne 0) { throw "rustup target add failed ($LASTEXITCODE)" }
}

# Per target, so build scripts (built for the host) are left alone.
$flagsVar = 'CARGO_TARGET_' + ($Target.ToUpper() -replace '-', '_') + '_RUSTFLAGS'
Set-Item "env:$flagsVar" "$((Get-Item "env:$flagsVar" -ErrorAction SilentlyContinue).Value) -C target-feature=+crt-static".Trim()

Write-Host "building okagent $version for $Target"
cargo build --release --locked -p okagent --target $Target
if ($LASTEXITCODE -ne 0) { throw "cargo build failed ($LASTEXITCODE)" }

try {
    New-Item -ItemType Directory -Force $prefix | Out-Null
    $exe = Join-Path $prefix 'okagent.exe'
    Copy-Item "target\$Target\release\okagent.exe" $exe
    Copy-Item README.md, LICENSE, packaging\windows\install.ps1 $prefix

    # Running it also checks that the static build starts. An ARM64 build
    # cannot run on an x64 host, so it gets the host build's script, which is
    # the same for every target.
    $hostExe = $exe
    if ((rustc -vV | Select-String '^host: (.*)').Matches[0].Groups[1].Value -ne $Target) {
        cargo build --release --locked -p okagent
        if ($LASTEXITCODE -ne 0) { throw "cargo build (host) failed ($LASTEXITCODE)" }
        $hostExe = 'target\release\okagent.exe'
    }
    $completion = & $hostExe completions powershell
    if ($LASTEXITCODE -ne 0) { throw "okagent completions failed ($LASTEXITCODE)" }
    [IO.File]::WriteAllLines((Join-Path $prefix 'okagent-completion.ps1'), [string[]] $completion)

    New-Item -ItemType Directory -Force $dist | Out-Null
    $zip = Join-Path $dist "$name.zip"
    Remove-Item $zip -ErrorAction SilentlyContinue
    Compress-Archive -Path $prefix -DestinationPath $zip

    $outputs = @($zip)

    if ($Msi) {
        $arch = @{ 'x86_64' = 'x64'; 'aarch64' = 'arm64'; 'i686' = 'x86' }[$Target.Split('-')[0]]
        if (-not $arch) { throw "no MSI architecture for $Target" }
        $util = "WixToolset.Util.wixext/$wixVersion"
        if (-not (wix extension list -g | Select-String -SimpleMatch $util -Quiet)) {
            wix extension add -g $util
            if ($LASTEXITCODE -ne 0) { throw "wix extension add failed ($LASTEXITCODE)" }
        }
        $msiPath = Join-Path $dist "$name.msi"
        # An MSI version is numbers only, so a -rc1 suffix is dropped.
        wix build packaging\windows\okagent.wxs -arch $arch -ext $util `
            -d "Version=$($version -replace '-.*$', '')" -d "Stage=$prefix" `
            -o $msiPath
        if ($LASTEXITCODE -ne 0) { throw "wix build failed ($LASTEXITCODE)" }
        Remove-Item (Join-Path $dist "$name.wixpdb") -ErrorAction SilentlyContinue
        $outputs += $msiPath
    }

    # The same format as sha256sum, which writes the rest of the file.
    foreach ($file in $outputs) {
        $hash = (Get-FileHash -Algorithm SHA256 $file).Hash.ToLower()
        [IO.File]::AppendAllText((Join-Path $dist 'SHA256SUMS'), "$hash  $(Split-Path -Leaf $file)`n")
        Write-Host "wrote $file"
    }
} finally {
    Remove-Item -Recurse -Force $stage -ErrorAction SilentlyContinue
}
