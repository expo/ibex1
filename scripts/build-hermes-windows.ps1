param(
  [ValidateSet("x64", "arm64")]
  [string]$Arch = "x64",
  [string]$Ref = "",
  [switch]$Debug,
  [switch]$Clean,
  [switch]$Vanilla,
  [switch]$PrintIdentity,
  [switch]$PrintCMakeGenerator
)

$ErrorActionPreference = "Stop"
Set-StrictMode -Version Latest

$scriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$builderScriptPath = $MyInvocation.MyCommand.Path
$repoRoot = Resolve-Path (Join-Path $scriptDir "..")
$versionScript = Join-Path $scriptDir "hermes-version.sh"
$versionText = Get-Content -LiteralPath $versionScript -Raw

# @ref LLP 0068#windows-host-and-engine — the vanilla cache and static
# install cannot alias the legacy patched Windows engine.
if ($Vanilla) {
  if ($Debug -or $PrintIdentity -or $PrintCMakeGenerator) {
    throw "The vanilla profile supports -Arch, -Ref, and -Clean only"
  }
  & (Join-Path $scriptDir "build-hermes-windows-vanilla.ps1") -Arch $Arch -Ref $Ref -Clean:$Clean
  return
}
$sourceVersionMatch = [regex]::Match(
  $versionText,
  'IBEX_HERMES_VERSION="\$\{IBEX_HERMES_VERSION:-([^}]+)\}"'
)
$sourceCommitMatch = [regex]::Match(
  $versionText,
  'IBEX_HERMES_SOURCE_COMMIT="\$\{IBEX_HERMES_SOURCE_COMMIT:-([0-9a-f]{40})\}"'
)
if (-not $sourceVersionMatch.Success -or -not $sourceCommitMatch.Success) {
  throw "Could not resolve the reviewed Hermes source identity from scripts/hermes-version.sh"
}
$reviewedSourceVersion = $sourceVersionMatch.Groups[1].Value
$reviewedSourceRef = "$reviewedSourceVersion-stable"
$reviewedSourceCommit = $sourceCommitMatch.Groups[1].Value
if (-not $Ref) {
  $Ref = $reviewedSourceCommit
}

function ConvertTo-LowerHex {
  param([byte[]]$Bytes)
  # @ref LLP 0001#4-what-ci-must-handle-per-cell — the reviewed Windows
  # artifact path must run in the platform's default PowerShell 5 host.
  return [System.BitConverter]::ToString($Bytes).Replace("-", "").ToLowerInvariant()
}

function Write-Utf8NoBomFile {
  param(
    [string]$Path,
    [string]$Content
  )
  $encoding = New-Object System.Text.UTF8Encoding($false)
  [System.IO.File]::WriteAllText(
    $Path,
    $Content + [System.Environment]::NewLine,
    $encoding
  )
}

function Get-PatchStackDigestHex {
  $lines = @()
  $patches = Get-ChildItem -LiteralPath (Join-Path $repoRoot "patches\hermes") -Filter "*.patch" |
    Sort-Object Name
  foreach ($patch in $patches) {
    $hash = (Get-FileHash -Algorithm SHA256 -LiteralPath $patch.FullName).Hash.ToLowerInvariant()
    $lines += "$hash  patches/hermes/$($patch.Name)"
  }
  $payload = if ($lines.Count -eq 0) { "" } else { ($lines -join "`n") + "`n" }
  $sha = [System.Security.Cryptography.SHA256]::Create()
  try {
    $digest = $sha.ComputeHash([System.Text.Encoding]::UTF8.GetBytes($payload))
  }
  finally {
    $sha.Dispose()
  }
  return (ConvertTo-LowerHex -Bytes $digest)
}

function Get-FileSuffixDigestHex {
  param(
    [string]$Path,
    [string]$Marker
  )
  $bytes = [System.IO.File]::ReadAllBytes($Path)
  $markerBytes = [System.Text.Encoding]::UTF8.GetBytes($Marker)
  $start = -1
  for ($index = 0; $index -le $bytes.Length - $markerBytes.Length; $index++) {
    $matches = $true
    for ($offset = 0; $offset -lt $markerBytes.Length; $offset++) {
      if ($bytes[$index + $offset] -ne $markerBytes[$offset]) {
        $matches = $false
        break
      }
    }
    if ($matches) {
      $start = $index
      break
    }
  }
  if ($start -lt 0) {
    throw "Could not find reviewed authority marker '$Marker' in $Path"
  }
  $suffix = [byte[]]::new($bytes.Length - $start)
  [System.Array]::Copy($bytes, $start, $suffix, 0, $suffix.Length)
  $sha = [System.Security.Cryptography.SHA256]::Create()
  try {
    $digest = $sha.ComputeHash($suffix)
  }
  finally {
    $sha.Dispose()
  }
  return (ConvertTo-LowerHex -Bytes $digest)
}

function Find-OneFile {
  param(
    [string]$Root,
    [string]$Name,
    [string]$Purpose
  )
  $matches = @(Get-ChildItem -LiteralPath $Root -Recurse -File -Filter $Name)
  if ($matches.Count -eq 0) {
    throw "Could not find $Purpose ($Name) under $Root"
  }
  $release = @($matches | Where-Object { $_.FullName -match '[\\/]Release[\\/]' })
  return $(if ($release.Count -gt 0) { $release[0] } else { $matches[0] })
}

function Convert-ToBashPath {
  param([string]$Path)
  $full = [System.IO.Path]::GetFullPath($Path)
  if ($full -match '^([A-Za-z]):\\(.*)$') {
    return "/$($matches[1].ToLowerInvariant())/$($matches[2].Replace('\', '/'))"
  }
  return $full.Replace('\', '/')
}

function Get-VisualStudioCMakeGenerator {
  # The hosted Windows image can move between reviewed Visual Studio major
  # versions while this source build falls back from a missing release asset.
  # Select only the exact CMake generator matching the already-activated MSVC
  # developer environment; never silently fall back to an ambient generator.
  # @ref LLP 0001#4-what-ci-must-handle-per-cell — Windows source builds
  # must remain reproducible on the supported hosted MSVC image rather than
  # naming a retired installation.
  $version = $env:VisualStudioVersion
  if (-not $version -or $version -notmatch '^(17|18)\.\d+(?:\.\d+){0,2}$') {
    throw "Supported Visual Studio developer environment is required (observed VisualStudioVersion '$version')"
  }
  switch ($matches[1]) {
    "17" { return "Visual Studio 17 2022" }
    "18" { return "Visual Studio 18 2026" }
    default { throw "Unsupported Visual Studio major version $($matches[1])" }
  }
}

# FileShare.None gives all cooperating Windows builder/installer processes one
# kernel-owned lock. The stable file is never unlinked: process termination
# closes the handle, so recovery does not depend on PID/stale-owner heuristics.
# @ref LLP 0013#upstream-tracking-and-re-derivation — one builder owns the
# mutable checkout/build/publication boundary from pristine reset to receipt.
function Enter-HermesSourceBuildLock {
  param([string]$Entrypoint)

  $lockPath = if ($env:IBEX_HERMES_WINDOWS_BUILD_LOCK_FILE) {
    $env:IBEX_HERMES_WINDOWS_BUILD_LOCK_FILE
  } else {
    Join-Path $cacheRoot "source-build.lock"
  }
  $lockDirectory = Split-Path -Parent $lockPath
  if ($lockDirectory) {
    New-Item -ItemType Directory -Force -Path $lockDirectory | Out-Null
  }

  $timeoutSeconds = 14400
  if ($env:IBEX_HERMES_WINDOWS_BUILD_LOCK_TIMEOUT_SECONDS) {
    $parsedTimeout = 0
    if (-not [int]::TryParse(
        $env:IBEX_HERMES_WINDOWS_BUILD_LOCK_TIMEOUT_SECONDS,
        [ref]$parsedTimeout
      ) -or $parsedTimeout -lt 1) {
      throw "IBEX_HERMES_WINDOWS_BUILD_LOCK_TIMEOUT_SECONDS must be a positive integer"
    }
    $timeoutSeconds = $parsedTimeout
  }

  $wait = [System.Diagnostics.Stopwatch]::StartNew()
  $announcedWait = $false
  while ($true) {
    try {
      $stream = [System.IO.File]::Open(
        $lockPath,
        [System.IO.FileMode]::OpenOrCreate,
        [System.IO.FileAccess]::ReadWrite,
        [System.IO.FileShare]::None
      )
      try {
        $owner = "pid=$PID`nentrypoint=$Entrypoint`n"
        $ownerBytes = [System.Text.Encoding]::UTF8.GetBytes($owner)
        $stream.SetLength(0)
        $stream.Write($ownerBytes, 0, $ownerBytes.Length)
        $stream.Flush($true)
      }
      catch {
        $stream.Dispose()
        throw
      }
      Write-Host "[lock] Acquired Windows Hermes source-build lock for $Entrypoint."
      return $stream
    }
    catch [System.IO.IOException] {
      if ($wait.Elapsed.TotalSeconds -ge $timeoutSeconds) {
        throw "Timed out after $timeoutSeconds seconds waiting for Windows Hermes source-build lock $lockPath"
      }
      if (-not $announcedWait) {
        Write-Host "[lock] Waiting for the Windows Hermes source-build lock at $lockPath..."
        $announcedWait = $true
      }
      Start-Sleep -Milliseconds 250
    }
  }
}

function Exit-HermesSourceBuildLock {
  param([System.IO.FileStream]$Lock)

  if ($null -ne $Lock) {
    $Lock.Dispose()
    Write-Host "[lock] Released Windows Hermes source-build lock."
  }
}

$patchStackDigestHex = Get-PatchStackDigestHex
$patchDigest = $patchStackDigestHex.Substring(0, 12)
$commitKey = if ($Ref -match '^[0-9a-f]{40}$') { $Ref.Substring(0, 12) } else { $Ref }
$identity = "$commitKey-$patchDigest"
if ($PrintIdentity) {
  Write-Output $identity
  exit 0
}
if ($PrintCMakeGenerator) {
  Write-Output (Get-VisualStudioCMakeGenerator)
  exit 0
}
$cmakeGenerator = Get-VisualStudioCMakeGenerator
$profile = if ($Debug) { "debug" } else { "release" }
$cacheRoot = Join-Path $env:LOCALAPPDATA "Exact\hermes-windows"
$cacheDir = Join-Path $cacheRoot "$commitKey-$profile-p$patchDigest-$Arch"
$sourceDir = Join-Path $cacheRoot "hermes-src"
$buildDir = Join-Path $cacheDir "build"
$installDir = Join-Path $cacheDir "install"
$targetRoot = Join-Path $repoRoot "tools\hermes\windows-$Arch"

if (-not (Get-Command git -ErrorAction SilentlyContinue)) { throw "git is required" }
if (-not (Get-Command cmake -ErrorAction SilentlyContinue)) { throw "cmake is required" }
if (-not (Get-Command bash -ErrorAction SilentlyContinue)) { throw "Git Bash is required" }

New-Item -ItemType Directory -Force -Path $cacheRoot | Out-Null
$buildLock = Enter-HermesSourceBuildLock "build-hermes-windows-$Arch"
try {
  if ($Clean) {
    Remove-Item -LiteralPath $cacheDir -Recurse -Force -ErrorAction SilentlyContinue
    Write-Host "Cleaned Windows Hermes cache: $cacheDir"
    return
  }

  if (-not (Test-Path (Join-Path $sourceDir ".git"))) {
    git clone https://github.com/facebook/hermes.git $sourceDir
    if ($LASTEXITCODE -ne 0) { throw "Failed to clone Hermes" }
  }

  git -C $sourceDir fetch origin --tags
  if ($LASTEXITCODE -ne 0) { throw "Failed to fetch Hermes" }
  if ($Ref -match '^[0-9a-f]{40}$') {
    git -C $sourceDir cat-file -e "$Ref^{commit}" 2>$null
    if ($LASTEXITCODE -ne 0) {
      git -C $sourceDir fetch origin $Ref
      if ($LASTEXITCODE -ne 0) { throw "Failed to fetch pinned Hermes commit $Ref" }
    }
  }
  git -C $sourceDir checkout --force $Ref
  if ($LASTEXITCODE -ne 0) { throw "Failed to check out Hermes $Ref" }
  $checkedOutCommit = (git -C $sourceDir rev-parse HEAD).Trim()
  if ($LASTEXITCODE -ne 0 -or $checkedOutCommit -notmatch '^[0-9a-f]{40}$') {
    throw "Failed to resolve the checked-out Hermes commit"
  }
  git -C $sourceDir reset --hard $checkedOutCommit
  if ($LASTEXITCODE -ne 0) { throw "Failed to hard-reset the Hermes checkout" }
  git -C $sourceDir clean -fdxq
  if ($LASTEXITCODE -ne 0) { throw "Failed to clean ignored/untracked Hermes checkout state" }

  $applyScriptUnix = Convert-ToBashPath (Join-Path $scriptDir "apply-hermes-patches.sh")
  $sourceDirUnix = Convert-ToBashPath $sourceDir
& bash $applyScriptUnix $sourceDirUnix
  if ($LASTEXITCODE -ne 0) { throw "Failed to apply the checked Hermes patch stack" }

  Remove-Item -LiteralPath $buildDir, $installDir -Recurse -Force -ErrorAction SilentlyContinue
  New-Item -ItemType Directory -Force -Path $buildDir, $installDir | Out-Null
  $cmakeArch = if ($Arch -eq "arm64") { "ARM64" } else { "x64" }
  $debuggerFlag = if ($Debug) { "ON" } else { "OFF" }
  cmake -S $sourceDir -B $buildDir -G $cmakeGenerator -A $cmakeArch `
    "-DHERMES_ENABLE_DEBUGGER:BOOL=$debuggerFlag" `
    -DHERMES_ENABLE_INTL=OFF `
    -DHERMES_ENABLE_WIN10_ICU_FALLBACK=ON `
    -DHERMES_BUILD_APPLE_FRAMEWORK=OFF `
    -DHERMES_BUILD_SHARED_JSI=OFF
  if ($LASTEXITCODE -ne 0) { throw "Hermes CMake configuration failed" }
  $cmakeCache = Join-Path $buildDir "CMakeCache.txt"
  $expectedDebuggerCache = "HERMES_ENABLE_DEBUGGER:BOOL=$debuggerFlag"
  $debuggerCacheEntries = @(
    Get-Content -LiteralPath $cmakeCache | Where-Object {
      $_ -match '^HERMES_ENABLE_DEBUGGER:'
    }
  )
  if ($debuggerCacheEntries.Count -ne 1 -or
      $debuggerCacheEntries[0] -ne $expectedDebuggerCache) {
    throw "Hermes CMake debugger profile drifted (expected $expectedDebuggerCache, got $($debuggerCacheEntries -join ', '))"
  }
  cmake --build $buildDir --config Release --target hermesvm hermes hermesc -- /m
  if ($LASTEXITCODE -ne 0) { throw "Hermes Windows build failed" }

  $hermesDll = Find-OneFile $buildDir "hermesvm.dll" "Hermes runtime DLL"
  $hermesLib = Find-OneFile $buildDir "hermesvm.lib" "Hermes import library"
  $hermesExe = Find-OneFile $buildDir "hermes.exe" "Hermes CLI"
  $hermescExe = Find-OneFile $buildDir "hermesc.exe" "Hermes compiler"
  if (-not $Debug) {
    if (-not (Get-Command dumpbin -ErrorAction SilentlyContinue)) {
      throw "dumpbin is required to attest the no-debugger Windows Hermes profile"
    }
    $hermesExports = dumpbin /exports $hermesDll.FullName | Out-String
    if ($hermesExports -match 'CDPAgent|CDPDebugAPI') {
      throw "No-debugger Windows Hermes build still exports the CDP debugger implementation"
    }
  }

  $includeDir = Join-Path $installDir "include"
  $libDir = Join-Path $installDir "lib"
  $binDir = Join-Path $installDir "bin"
  New-Item -ItemType Directory -Force -Path $includeDir, $libDir, $binDir | Out-Null
  New-Item -ItemType Directory -Force -Path (Join-Path $includeDir "jsi"), (Join-Path $includeDir "hermes") | Out-Null
  Copy-Item -Path (Join-Path $sourceDir "API\jsi\jsi\*") -Destination (Join-Path $includeDir "jsi") -Recurse -Force
  Copy-Item -Path (Join-Path $sourceDir "API\hermes\*") -Destination (Join-Path $includeDir "hermes") -Recurse -Force
  Copy-Item -Path (Join-Path $sourceDir "public\hermes\Public") -Destination (Join-Path $includeDir "hermes") -Recurse -Force
  Copy-Item -LiteralPath $hermesDll.FullName -Destination (Join-Path $binDir "hermesvm.dll") -Force
  Copy-Item -LiteralPath $hermesDll.FullName -Destination (Join-Path $libDir "hermesvm.dll") -Force
  Copy-Item -LiteralPath $hermesLib.FullName -Destination (Join-Path $libDir "hermesvm.lib") -Force
  # Keep build.rs's historical Windows default while preserving the upstream
  # hermesvm import-library name for explicit consumers.
  Copy-Item -LiteralPath $hermesLib.FullName -Destination (Join-Path $libDir "hermes.lib") -Force
  Copy-Item -LiteralPath $hermesExe.FullName -Destination (Join-Path $binDir "hermes.exe") -Force
  Copy-Item -LiteralPath $hermescExe.FullName -Destination (Join-Path $binDir "hermesc.exe") -Force

  $actualCommit = (git -C $sourceDir rev-parse HEAD).Trim()
  $sourceBuildAuthorityDigest = (
    Get-FileHash -Algorithm SHA256 -LiteralPath $builderScriptPath
  ).Hash.ToLowerInvariant()
  $manifest = [ordered]@{
    schema = "ibex/hermes-build/1"
    sourceCommit = $actualCommit
    patchDigest = $patchDigest
    sourceBuildAuthorityDigest = $sourceBuildAuthorityDigest
    architecture = $Arch
    configuration = "Release"
    debugger = [bool]$Debug
    binarySha256 = (Get-FileHash -Algorithm SHA256 -LiteralPath (Join-Path $binDir "hermesvm.dll")).Hash.ToLowerInvariant()
  }
  Write-Utf8NoBomFile `
    -Path (Join-Path $installDir "artifact.json") `
    -Content ($manifest | ConvertTo-Json)

  # Only the exact reviewed no-debugger source build may carry an authenticated
  # profile receipt. Custom refs and debugger-enabled builds remain usable local
  # artifacts, but cannot present themselves as the reviewed Windows profile.
  # @ref LLP 0013#artifact-provenance-and-remaining-trust-boundaries — bind the
  # Windows runtime and import library to the complete reviewed fork authority.
  if ($actualCommit -eq $reviewedSourceCommit -and -not $Debug) {
    $patchApplicationAuthorityDigest = (
      Get-FileHash -Algorithm SHA256 -LiteralPath (Join-Path $scriptDir "apply-hermes-patches.sh")
    ).Hash.ToLowerInvariant()
    $patchIdentityAuthorityDigest = Get-FileSuffixDigestHex `
      -Path $versionScript `
      -Marker "ibex_sha256() {`n"
    $sourceInstallerAuthorityDigest = (
      Get-FileHash -Algorithm SHA256 -LiteralPath (Join-Path $scriptDir "install-windows-hermes.ps1")
    ).Hash.ToLowerInvariant()
    $targetArchitecture = if ($Arch -eq "arm64") { "aarch64" } else { "x86_64" }
    $runtimeDigest = $manifest.binarySha256
    $linkDigest = (
      Get-FileHash -Algorithm SHA256 -LiteralPath (Join-Path $libDir "hermes.lib")
    ).Hash.ToLowerInvariant()
    $reviewedProfileIdentity = [ordered]@{
      artifact = "facebook/hermes"
      patchApplicationAuthorityDigest = "sha256-$patchApplicationAuthorityDigest"
      patchIdentityAuthorityDigest = "sha256-$patchIdentityAuthorityDigest"
      patchStackDigest = "sha256-$patchStackDigestHex"
      sourceBuildAuthorityDigest = "sha256-$sourceBuildAuthorityDigest"
      sourceCommit = $reviewedSourceCommit
      sourceInstallerAuthorityDigest = "sha256-$sourceInstallerAuthorityDigest"
      sourceRef = $reviewedSourceRef
      sourceVersion = $reviewedSourceVersion
    }
    $receipt = [ordered]@{
      schema = "ibex/hermes-profile-provenance-receipt/2"
      profileId = "windows-source-patched"
      targetVariant = "windows"
      artifact = [ordered]@{
        binaryDigest = "sha256-$runtimeDigest"
        fileName = "hermesvm.dll"
        targetArchitecture = $targetArchitecture
      }
      linkArtifact = [ordered]@{
        binaryDigest = "sha256-$linkDigest"
        fileName = "hermes.lib"
        targetArchitecture = $targetArchitecture
      }
      origin = [ordered]@{
        configuration = "Release"
        debugger = $false
        kind = "source-patched-build"
        reviewedProfileIdentity = $reviewedProfileIdentity
      }
    }
    Write-Utf8NoBomFile `
      -Path (Join-Path $binDir "hermes-profile-provenance.json") `
      -Content ($receipt | ConvertTo-Json -Depth 8)
  }

  Remove-Item -LiteralPath $targetRoot -Recurse -Force -ErrorAction SilentlyContinue
  New-Item -ItemType Directory -Force -Path $targetRoot | Out-Null
  Copy-Item -Path (Join-Path $installDir "*") -Destination $targetRoot -Recurse -Force

  Write-Host "Installed patched Windows Hermes at $targetRoot"
  Write-Host "  commit:   $actualCommit"
  Write-Host "  patches:  $patchDigest"
  Write-Host "  debugger: $([bool]$Debug)"
}
finally {
  Exit-HermesSourceBuildLock $buildLock
}
