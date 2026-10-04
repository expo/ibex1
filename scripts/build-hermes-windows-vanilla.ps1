param(
  [ValidateSet("x64")]
  [string]$Arch = "x64",
  [string]$Ref = "",
  [switch]$Clean
)

$ErrorActionPreference = "Stop"
Set-StrictMode -Version Latest
# @ref LLP 0068#windows-host-and-engine — export the vanilla pin without
# resetting, cleaning, or patching the legacy source checkout.
$repoRoot = Split-Path -Parent $PSScriptRoot
$versionText = Get-Content -LiteralPath (Join-Path $PSScriptRoot "hermes-version.sh") -Raw
if (-not $Ref) {
  $pin = [regex]::Match($versionText, 'IBEX_HERMES_VANILLA_SOURCE_COMMIT="\$\{IBEX_HERMES_VANILLA_SOURCE_COMMIT:-([0-9a-f]{40})\}"')
  if (-not $pin.Success) { throw "Cannot read vanilla Hermes source pin" }
  $Ref = $pin.Groups[1].Value
}
if ($Ref -notmatch '^[0-9a-f]{40}$') { throw "Vanilla Hermes requires an exact 40-hex commit" }
if (-not (Get-Command cl -ErrorAction SilentlyContinue)) {
  throw "Run this builder from an x64 Visual Studio developer shell"
}
$cacheRoot = [IO.Path]::GetFullPath((Join-Path $env:LOCALAPPDATA "Exact\hermes2-windows-vanilla"))
$cacheDir = [IO.Path]::GetFullPath((Join-Path $cacheRoot "$Ref-$Arch"))
if (-not $cacheDir.StartsWith($cacheRoot + [IO.Path]::DirectorySeparatorChar, [StringComparison]::OrdinalIgnoreCase)) {
  throw "Build cache escaped its root"
}
New-Item -ItemType Directory -Force -Path $cacheRoot | Out-Null
# Kernel-owned single-builder lock; termination releases it without stale-PID recovery.
$lock = [IO.File]::Open((Join-Path $cacheRoot 'source-build.lock'), 'OpenOrCreate', 'ReadWrite', 'None')
try {
  if ($Clean) {
    if (Test-Path -LiteralPath $cacheDir) { Remove-Item -LiteralPath $cacheDir -Recurse -Force }
    return
  }
  $sourceDir = Join-Path $cacheDir "source"
  $buildDir = Join-Path $cacheDir "build"
  $sourceMarker = Join-Path $cacheDir "source-commit.txt"
  if (-not (Test-Path -LiteralPath $sourceMarker)) {
    if (Test-Path -LiteralPath $sourceDir) {
      throw "Incomplete source export at $sourceDir; use -Clean before retrying"
    }
    New-Item -ItemType Directory -Force -Path $sourceDir | Out-Null
    $legacySource = Join-Path $env:LOCALAPPDATA "Exact\hermes-windows\hermes-src"
    $archive = Join-Path $cacheDir "source.tar"
    if (Test-Path -LiteralPath (Join-Path $legacySource ".git")) {
      git -C $legacySource fetch origin $Ref
      if ($LASTEXITCODE -ne 0) { throw "Could not fetch vanilla Hermes commit" }
      git -C $legacySource archive --format=tar "--output=$archive" $Ref
      if ($LASTEXITCODE -ne 0) { throw "Could not export vanilla Hermes commit" }
      tar -xf $archive -C $sourceDir
    } else {
      Invoke-WebRequest "https://codeload.github.com/facebook/hermes/tar.gz/$Ref" -OutFile $archive
      tar -xf $archive -C $sourceDir --strip-components=1
    }
    if ($LASTEXITCODE -ne 0) { throw "Could not extract vanilla Hermes source" }
    Remove-Item -LiteralPath $archive
    [IO.File]::WriteAllText($sourceMarker, $Ref)
  }
  if ([IO.File]::ReadAllText($sourceMarker) -ne $Ref) { throw "Source export pin mismatch" }
  cmake -S $sourceDir -B $buildDir -G Ninja `
    -DCMAKE_BUILD_TYPE=Release -DHERMES_ENABLE_DEBUGGER=ON `
    -DHERMES_ENABLE_INTL=OFF -DHERMES_ENABLE_WIN10_ICU_FALLBACK=ON `
    -DHERMES_BUILD_APPLE_FRAMEWORK=OFF -DHERMES_BUILD_SHARED_JSI=OFF `
    -DHERMES_ENABLE_TEST_SUITE=OFF -DHERMES_MSVC_MP=OFF
  if ($LASTEXITCODE -ne 0) { throw "Vanilla Hermes CMake configuration failed" }
  cmake --build $buildDir --target hermesvm_a jsi boost_context hermesc hermes --parallel 8
  if ($LASTEXITCODE -ne 0) { throw "Vanilla Hermes build failed" }

  $toolsDir = Join-Path $repoRoot "tools\hermes-vanilla"
  $installDir = Join-Path $toolsDir "windows-$Arch"
  $headers = Join-Path $installDir "hermes-headers"
  $libs = Join-Path $installDir "windows-static"
  New-Item -ItemType Directory -Force -Path $headers, $libs, (Join-Path $headers 'jsi'), (Join-Path $headers 'hermes') | Out-Null
  Copy-Item -Path (Join-Path $sourceDir 'API\jsi\jsi\*') -Destination (Join-Path $headers 'jsi') -Recurse -Force
  Copy-Item -Path (Join-Path $sourceDir 'API\hermes\*') -Destination (Join-Path $headers 'hermes') -Recurse -Force
  Copy-Item -LiteralPath (Join-Path $sourceDir 'public\hermes\Public') -Destination (Join-Path $headers 'hermes') -Recurse -Force
  foreach ($name in @('hermesvm_a.lib', 'jsi.lib', 'boost_context.lib')) {
    $found = @(Get-ChildItem -LiteralPath $buildDir -Recurse -File -Filter $name)
    if ($found.Count -ne 1) { throw "Expected exactly one $name, found $($found.Count)" }
    Copy-Item -LiteralPath $found[0].FullName -Destination (Join-Path $libs $name) -Force
  }
  foreach ($name in @('hermesc', 'hermes')) {
    Copy-Item -LiteralPath (Join-Path $buildDir "bin\$name.exe") -Destination (Join-Path $toolsDir "$name-windows-$Arch.exe") -Force
  }
  Write-Host "Installed vanilla Windows Hermes at $installDir ($Ref)"
} finally {
  $lock.Dispose()
}
