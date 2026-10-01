#!/bin/bash
#
# build-hermes.sh
# Builds Hermes from source for iOS, tvOS, and macOS using their native build scripts
#
# Usage:
#   ./scripts/build-hermes.sh                      # Build pinned stable Hermes release
#   ./scripts/build-hermes.sh --latest             # Build latest static_h head
#   ./scripts/build-hermes.sh 260318099.0.0-stable # Build specific branch
#   ./scripts/build-hermes.sh v0.13.0              # Build specific tag
#   ./scripts/build-hermes.sh <commit>             # Build specific commit
#   ./scripts/build-hermes.sh --release            # Build without debugger
#   ./scripts/build-hermes.sh --debug              # Force debugger on
#   ./scripts/build-hermes.sh --clean              # Clean cache and rebuild
#   ./scripts/build-hermes.sh --vanilla            # Unpatched pin → ios/Frameworks-vanilla
#   ./scripts/build-hermes.sh --vanilla --release  # Unpatched, no debugger → ios/Frameworks-vanilla-nodebug
#   ./scripts/build-hermes.sh --normalize-static-archive <path>
#                                                   # Normalize one Apple archive in place
#
# The built xcframework is cached at:
#   ~/.cache/exact/hermes/<version>/
#
# After building, it's automatically copied to:
#   ios/Frameworks/
#

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"
source "$SCRIPT_DIR/hermes-version.sh"

# Configuration
# Default to the pinned Hermes commit (scripts/hermes-version.sh) — the stable
# branch name moves under cold clones (ENG-23092). Use --latest only when you
# explicitly want the moving static_h development head.
DEFAULT_HERMES_REF="$IBEX_HERMES_BUILD_REF"
HERMES_VERSION_FROM_ENV="${HERMES_VERSION:-}"
HERMES_VERSION="${HERMES_VERSION:-$DEFAULT_HERMES_REF}"
HERMES_CLI_REF=false
CACHE_DIR="$HOME/.cache/exact/hermes"
FRAMEWORKS_DIR="$PROJECT_ROOT/ios/Frameworks"
HERMES_DEBUGGER="${HERMES_ENABLE_DEBUGGER:-true}"
CLEAN_CACHE=false
# The vanilla profile builds pristine upstream Hermes with the carried patch
# series NOT applied, installs it beside (never over) the reviewed artifacts,
# and emits no source-profile receipt. It exists so Ibex 2 can be developed and
# gated against an unpatched engine.
# @ref LLP 0060#6-verification — the vanilla gate this build mode serves
HERMES_VANILLA="${IBEX_HERMES_VANILLA:-false}"
HOST_ARCH_RAW="$(uname -m)"
case "$HOST_ARCH_RAW" in
    x86_64|amd64) HOST_ARCH="x64" ;;
    arm64|aarch64) HOST_ARCH="arm64" ;;
    *) HOST_ARCH="$HOST_ARCH_RAW" ;;
esac
HERMES_TOOLS_DIR="$PROJECT_ROOT/tools/hermes"
HERMESC_DEST="$HERMES_TOOLS_DIR/hermesc-macos-$HOST_ARCH"
MACOS_FRAMEWORK_DEST="$FRAMEWORKS_DIR/hermesvm.framework"
MACOS_STATIC_DIR="$FRAMEWORKS_DIR/macos-static"
PROFILE_RECEIPT_DEST="$FRAMEWORKS_DIR/hermes-profile-provenance.json"

# Apple's archive tools preserve member mtimes and numeric owner ids unless
# deterministic mode is requested. Two otherwise byte-identical Hermes builds
# therefore produced different fat .a files. Normalize each architecture with
# libtool -D, then recreate the universal archive in canonical architecture
# order. The object bytes and member order stay source-derived; only archive
# metadata and the derived symbol table are rebuilt.
# @ref LLP 0047#implementation-checkpoint--2026-08-03 — matching physical
# builders must converge before their release-kit identities are compared.
normalize_macos_static_archive() {
    local archive="$1"
    local archive_dir temp_dir arch
    local -a normalized_slices

    if [[ ! -f "$archive" || -L "$archive" ]]; then
        echo "[✗] Static archive is absent or redirected: $archive" >&2
        return 1
    fi
    archive_dir="$(cd "$(dirname "$archive")" && pwd)"
    archive="$archive_dir/$(basename "$archive")"
    temp_dir="$(mktemp -d "$archive_dir/.ibex-static-archive.XXXXXX")"

    if ! (
        set -e
        normalized_slices=()
        for arch in $(lipo -archs "$archive" | tr ' ' '\n' | LC_ALL=C sort); do
            [[ -n "$arch" ]] || continue
            lipo "$archive" -thin "$arch" \
                -output "$temp_dir/$arch.input.a"
            libtool -static -D -no_warning_for_no_symbols \
                -o "$temp_dir/$arch.normalized.a" \
                "$temp_dir/$arch.input.a"
            normalized_slices+=("$temp_dir/$arch.normalized.a")
        done
        [[ ${#normalized_slices[@]} -gt 0 ]]
        lipo -create "${normalized_slices[@]}" \
            -output "$temp_dir/normalized.a"
        chmod 0644 "$temp_dir/normalized.a"
        mv "$temp_dir/normalized.a" "$archive"
    ); then
        rm -rf "$temp_dir"
        echo "[✗] Could not normalize static archive: $archive" >&2
        return 1
    fi
    rm -rf "$temp_dir"
}

# A narrow utility mode lets the deterministic transform be tested against
# synthetic archives without cloning or building Hermes.
if [[ "${1:-}" == "--normalize-static-archive" ]]; then
    if [[ $# -ne 2 ]]; then
        echo "usage: $0 --normalize-static-archive <path>" >&2
        exit 2
    fi
    normalize_macos_static_archive "$2"
    exit 0
fi

while [[ $# -gt 0 ]]; do
    case "$1" in
        --latest)
            HERMES_VERSION="static_h"
            HERMES_CLI_REF=true
            shift
            ;;
        --clean)
            CLEAN_CACHE=true
            shift
            ;;
        --release|--no-debugger)
            HERMES_DEBUGGER=false
            shift
            ;;
        --debug)
            HERMES_DEBUGGER=true
            shift
            ;;
        --vanilla)
            HERMES_VANILLA=true
            shift
            ;;
        *)
            HERMES_VERSION="$1"
            HERMES_CLI_REF=true
            shift
            ;;
    esac
done
DEBUG_SUFFIX=""
if [[ "$HERMES_DEBUGGER" == "1" || "$HERMES_DEBUGGER" == "true" || "$HERMES_DEBUGGER" == "TRUE" || "$HERMES_DEBUGGER" == "yes" || "$HERMES_DEBUGGER" == "YES" ]]; then
    DEBUG_SUFFIX="-debug"
fi

# Redirect every install destination for the vanilla profile. The reviewed
# artifacts under ios/Frameworks/ and tools/hermes/ are never touched, so the
# two engines coexist and build.rs's existing lookup cannot pick the unpatched
# one up by accident. A vanilla build is opt-in at every layer: this flag, a
# separate cache key space, a separate install root, and no source-patched
# receipt. Debugger and release installs also stay apart so a --release rebuild
# cannot clobber the default ibex2 link.
# @ref LLP 0058.000#d1-vanilla-means-zero-ibex-source-patches
case "$HERMES_VANILLA" in
    1|true|TRUE|yes|YES|on|ON)
        HERMES_VANILLA=true
        if [ "$HERMES_CLI_REF" != true ] && [ -z "$HERMES_VERSION_FROM_ENV" ]; then
            HERMES_VERSION="$IBEX_HERMES_VANILLA_SOURCE_COMMIT"
        fi
        if [ -n "$DEBUG_SUFFIX" ]; then
            FRAMEWORKS_DIR="$PROJECT_ROOT/ios/Frameworks-vanilla"
        else
            FRAMEWORKS_DIR="$PROJECT_ROOT/ios/Frameworks-vanilla-nodebug"
        fi
        HERMES_TOOLS_DIR="$PROJECT_ROOT/tools/hermes-vanilla"
        HERMESC_DEST="$HERMES_TOOLS_DIR/hermesc-macos-$HOST_ARCH"
        MACOS_FRAMEWORK_DEST="$FRAMEWORKS_DIR/hermesvm.framework"
        MACOS_STATIC_DIR="$FRAMEWORKS_DIR/macos-static"
        PROFILE_RECEIPT_DEST="$FRAMEWORKS_DIR/hermes-profile-provenance.json"
        ;;
    *)
        HERMES_VANILLA=false
        ;;
esac

# Both platform builders reuse mutable source/build caches. Hold the shared
# kernel-backed lock until the final cache/receipt install has completed. EXIT
# also runs after the explicit signal traps; on SIGKILL, the kernel releases
# after the final inherited descriptor closes.
ibex_acquire_hermes_source_build_lock "$(basename "$0")"
trap 'ibex_release_hermes_source_build_lock' EXIT
trap 'exit 129' HUP
trap 'exit 130' INT
trap 'exit 143' TERM

is_truthy() {
    case "$1" in
        1|true|TRUE|yes|YES|on|ON) return 0 ;;
        *) return 1 ;;
    esac
}

verify_debugger_symbols() {
    local framework_dir="$1"
    local binary="$framework_dir/Versions/1/hermesvm"
    local symbols
    if ! is_truthy "$HERMES_DEBUGGER"; then
        return
    fi
    if [ ! -f "$binary" ]; then
        echo "[✗] Expected Hermes macOS binary at $binary"
        exit 1
    fi
    symbols="$(nm -gU "$binary" 2>/dev/null)" || {
        echo "[✗] Could not inspect Hermes macOS framework symbols"
        exit 1
    }
    if [[ "$symbols" != *AsyncDebuggerAPI* ]]; then
        echo "[✗] Hermes macOS framework was built without debugger symbols"
        echo "    Missing AsyncDebuggerAPI in $binary"
        exit 1
    fi
    echo "[✓] Verified Hermes debugger symbols in $(basename "$framework_dir")"
}

write_profile_receipt() {
    # A vanilla build is not the reviewed source-patched profile and must never
    # present itself as one. Emit nothing, and clear any receipt left behind by
    # an earlier occupant of this destination.
    if [ "$HERMES_VANILLA" = true ]; then
        rm -f "$PROFILE_RECEIPT_DEST"
        echo "[provenance] vanilla profile: no source-patched receipt emitted."
        return 0
    fi
    ibex_write_source_patched_profile_receipt \
        "$MACOS_FRAMEWORK_DEST/Versions/1/hermesvm" \
        "$PROFILE_RECEIPT_DEST" \
        "$HERMES_VERSION" \
        "$(basename "$VERSION_CACHE")"
}

# Minimum OS versions for each Apple slice
export IOS_DEPLOYMENT_TARGET="15.0"
# Not exported: clang reads TVOS_DEPLOYMENT_TARGET from the environment and
# rejects it beside the exported XROS_DEPLOYMENT_TARGET.
TVOS_MIN_VERSION="15.0"
export MAC_DEPLOYMENT_TARGET="12.0"
export XROS_DEPLOYMENT_TARGET="1.0"

# Handle --clean flag
if [ "$CLEAN_CACHE" = true ]; then
    echo "Cleaning Hermes cache..."
    rm -rf "$CACHE_DIR"
    echo "Done. Run again without --clean to rebuild."
    exit 0
fi

# Resolve version to a cache key
resolve_version() {
    local version="$1"
    local ref="$version"
    if [[ "$version" == "static_h" || "$version" == "main" ]]; then
        ref="static_h"
    fi
    # A full commit SHA is already an exact key; skip the remote lookup.
    if [[ "$version" =~ ^[0-9a-f]{40}$ ]]; then
        echo "${version:0:12}"
        return
    fi
    local remote_sha
    remote_sha="$(git ls-remote https://github.com/facebook/hermes.git \
        "refs/heads/$ref" "refs/tags/$ref" "refs/tags/v$ref" 2>/dev/null \
        | awk 'NR == 1 { print substr($1, 1, 12); exit }')"
    if [[ -n "$remote_sha" ]]; then
        echo "$remote_sha"
    else
        echo "$version"
    fi
}

# The carried patch stack is part of the build identity: the framework the
# cache-hit path installs was built from upstream@SHA *plus* patches/hermes/*.
# Keying only on the upstream SHA let an edited/added patch silently install a
# stale-patched framework ("already built"), greenlighting old enforcement
# semantics in the authenticated CapSec callback/conformance suites. Digest content + filenames so an edit,
# add, remove, or reorder all miss the cache. (ENG-23131; mirrors the
# hashFiles('patches/hermes/**') key compartment-conformance.yml already uses.)
# The digest derivation is shared with download-hermes.sh and the
# hermes-artifacts publish workflow via scripts/hermes-version.sh (ENG-23147).
VERSION_KEY=$(resolve_version "$HERMES_VERSION")
PATCH_DIGEST=$(ibex_hermes_patch_digest)
APPLE_BUILD_AUTHORITY_DIGEST="$(ibex_hermes_apple_build_authority_digest_hex)"
LINUX_BUILD_AUTHORITY_DIGEST="$(ibex_hermes_linux_build_authority_digest_hex)"
PATCH_APPLICATION_AUTHORITY_DIGEST="$(ibex_hermes_patch_application_authority_digest)"
PATCH_IDENTITY_AUTHORITY_DIGEST="$(ibex_hermes_patch_identity_authority_digest)"
if [ "$HERMES_VANILLA" = true ]; then
    VERSION_CACHE="$CACHE_DIR/$(ibex_hermes_apple_vanilla_cache_key "$VERSION_KEY" "$DEBUG_SUFFIX")"
else
    VERSION_CACHE="$CACHE_DIR/$(ibex_hermes_apple_source_cache_key "$VERSION_KEY" "$DEBUG_SUFFIX")"
fi

echo "=== Hermes Build Script ==="
if [ "$HERMES_VANILLA" = true ]; then
    echo "Profile: VANILLA (upstream, patch series NOT applied)"
    echo "Install root: $FRAMEWORKS_DIR"
else
    echo "Profile: source-patched (reviewed)"
fi
echo "Version: $HERMES_VERSION"
echo "Cache key: $VERSION_KEY (patch stack: $PATCH_DIGEST)"
echo "Apple build authority: ${APPLE_BUILD_AUTHORITY_DIGEST:0:12}"
echo "Linux build authority: ${LINUX_BUILD_AUTHORITY_DIGEST:0:12}"
echo "Patch application authority: $PATCH_APPLICATION_AUTHORITY_DIGEST"
echo "Patch identity authority: $PATCH_IDENTITY_AUTHORITY_DIGEST"
echo "Debugger suffix: $DEBUG_SUFFIX"
echo "Cache dir: $VERSION_CACHE"
echo "iOS Deployment Target: $IOS_DEPLOYMENT_TARGET"
echo "tvOS Deployment Target: $TVOS_MIN_VERSION"
echo "Hermes Debugger: $HERMES_DEBUGGER"
echo ""

# A reviewed cache hit must carry a receipt for this exact cache identity. An
# incomplete/crashed publication or a bundle built by an older patch verifier
# is a miss, never a source-profile install.
if [ -d "$VERSION_CACHE/hermesvm.xcframework" ] \
    && [ "$HERMES_VANILLA" != true ] \
    && [[ "$HERMES_VERSION" == "$IBEX_HERMES_SOURCE_COMMIT" ]] \
    && ! ibex_hermes_profile_receipt_has_cache_key \
        "$VERSION_CACHE/hermes-profile-provenance.json" \
        "$(basename "$VERSION_CACHE")"; then
    echo "[provenance] Discarding Hermes cache entry with a missing or stale source-profile receipt: $VERSION_CACHE" >&2
    rm -rf "$VERSION_CACHE"
fi

# Check if already built
if [ -d "$VERSION_CACHE/hermesvm.xcframework" ] && [ -d "$VERSION_CACHE/macos-static" ]; then
    echo "[✓] Hermes $VERSION_KEY already built"
    echo ""

    # Copy to project
    echo "Installing to project..."
    mkdir -p "$FRAMEWORKS_DIR"
    rm -rf "$FRAMEWORKS_DIR/hermes.xcframework"
    cp -R "$VERSION_CACHE/hermesvm.xcframework" "$FRAMEWORKS_DIR/hermes.xcframework"
    if [ -d "$VERSION_CACHE/hermesvm.framework" ]; then
        rm -rf "$MACOS_FRAMEWORK_DEST"
        cp -R "$VERSION_CACHE/hermesvm.framework" "$MACOS_FRAMEWORK_DEST"
        verify_debugger_symbols "$MACOS_FRAMEWORK_DEST"
        if [ -f "$VERSION_CACHE/hermes-profile-provenance.json" ]; then
            cp "$VERSION_CACHE/hermes-profile-provenance.json" "$PROFILE_RECEIPT_DEST"
        else
            rm -f "$PROFILE_RECEIPT_DEST"
            echo "[provenance] cached Hermes has no source-build receipt; profile remains unverified." >&2
        fi
    else
        rm -f "$PROFILE_RECEIPT_DEST"
    fi
    if [ -d "$VERSION_CACHE/macos-static" ]; then
        rm -rf "$MACOS_STATIC_DIR"
        cp -R "$VERSION_CACHE/macos-static" "$MACOS_STATIC_DIR"
        echo "[✓] static macOS Hermes bundle installed"
    fi

    # Copy headers
    if [ -d "$VERSION_CACHE/include" ]; then
        rm -rf "$FRAMEWORKS_DIR/hermes-headers"
        mkdir -p "$FRAMEWORKS_DIR/hermes-headers"
        cp -R "$VERSION_CACHE/include/"* "$FRAMEWORKS_DIR/hermes-headers/"
    fi

    # Copy hermesc / hermes binaries
    if [ -f "$VERSION_CACHE/bin/hermesc" ]; then
        mkdir -p "$HERMES_TOOLS_DIR"
        cp "$VERSION_CACHE/bin/hermesc" "$HERMESC_DEST"
        echo "[✓] hermesc installed"
    fi
    if [ -f "$VERSION_CACHE/bin/hermes" ]; then
        mkdir -p "$HERMES_TOOLS_DIR"
        cp "$VERSION_CACHE/bin/hermes" "$HERMES_TOOLS_DIR/hermes"
        echo "[✓] hermes installed"
    fi

    echo "[✓] Installed to $FRAMEWORKS_DIR"
    if [ "$HERMES_VANILLA" = true ]; then
        echo "Write a HermesInputReceipt with:"
        echo "  node \"$SCRIPT_DIR/hermes-input-receipt.mjs\" \"$FRAMEWORKS_DIR\""
    fi
    exit 0
fi
if [ -d "$VERSION_CACHE/hermesvm.xcframework" ]; then
    echo "[!] Cached Hermes bundle predates the static-stub archive set; rebuilding it"
    rm -rf "$VERSION_CACHE"
fi

# Check dependencies
echo "Checking dependencies..."

if ! command -v cmake &> /dev/null; then
    echo "[✗] cmake not found. Install with: brew install cmake"
    exit 1
fi
echo "[✓] cmake: $(cmake --version | head -1)"

if ! command -v ninja &> /dev/null; then
    echo "[!] ninja not found (optional, will use make). Install with: brew install ninja"
fi

if ! xcode-select -p &> /dev/null; then
    echo "[✗] Xcode command line tools not found"
    exit 1
fi
echo "[✓] Xcode: $(xcode-select -p)"

echo ""

# Clone or update Hermes
HERMES_SRC="$CACHE_DIR/hermes-src"

if [ ! -d "$HERMES_SRC/.git" ]; then
    echo "Cloning Hermes repository..."
    rm -rf "$HERMES_SRC"
    git clone https://github.com/facebook/hermes.git "$HERMES_SRC"
fi

cd "$HERMES_SRC"

# An interrupted prior build may leave tracked, staged, ignored, or untracked
# state that can affect checkout itself. This is a build-owned cache: erase the
# complete source worktree before selecting the requested revision.
git reset --hard HEAD
git clean -ffdx

echo "Checking out $HERMES_VERSION..."
git fetch origin --tags
if [[ "$HERMES_VERSION" =~ ^[0-9a-f]{40}$ ]]; then
    # A full object ID is an object identity, never a branch name. Resolve it
    # before any origin/<name> lookup so an upstream ref named with 40 hex
    # characters cannot substitute another commit for the reviewed pin.
    if ! git rev-parse --verify --quiet "${HERMES_VERSION}^{commit}" >/dev/null; then
        git fetch origin "$HERMES_VERSION"
    fi
    git rev-parse --verify --quiet "${HERMES_VERSION}^{commit}" >/dev/null \
        || { echo "[✗] Requested Hermes commit is unavailable: $HERMES_VERSION" >&2; exit 1; }
    git checkout --detach "${HERMES_VERSION}^{commit}"
elif [[ "$HERMES_VERSION" == "static_h" || "$HERMES_VERSION" == "main" ]]; then
    git checkout --detach origin/static_h
elif git rev-parse --verify --quiet "origin/$HERMES_VERSION" >/dev/null; then
    git checkout --detach "origin/$HERMES_VERSION"
else
    git checkout --detach "$HERMES_VERSION"
fi

CHECKED_OUT_COMMIT="$(git rev-parse HEAD^{commit})"
if [[ "$HERMES_VERSION" =~ ^[0-9a-f]{40}$ && "$CHECKED_OUT_COMMIT" != "$HERMES_VERSION" ]]; then
    echo "[✗] Checked-out Hermes commit $CHECKED_OUT_COMMIT differs from requested object $HERMES_VERSION" >&2
    exit 1
fi
git reset --hard "$CHECKED_OUT_COMMIT"
git clean -ffdx
if [[ -n "$(git status --porcelain=v1 --untracked-files=all)" ]]; then
    echo "[✗] Hermes source checkout is not pristine after reset/clean" >&2
    exit 1
fi

ACTUAL_COMMIT=$(printf '%s' "$CHECKED_OUT_COMMIT" | cut -c1-12)
echo "Building commit: $ACTUAL_COMMIT"
echo ""

# @ref LLP 0013#upstream-tracking — the complete checkout is now pristine,
# including its real index and all ignored build outputs, before replaying the
# carried Hermes patch stack.
if [ "$HERMES_VANILLA" = true ]; then
    echo "[vanilla] Skipping the carried patch series; building pristine upstream Hermes."
else
    "$SCRIPT_DIR/apply-hermes-patches.sh" "$HERMES_SRC"
fi

echo "=== Building Hermes for Apple platforms ==="
echo ""

NUM_CORES=$(sysctl -n hw.ncpu)

# Build host hermesc first (force macOS SDK to avoid visionOS defaults)
echo "Building host hermesc..."
# Note: HAVE_CXX_ATOMICS*_WITHOUT_LIB=ON works around a CMake detection issue on macOS
#
# HERMES_ENABLE_TEST_SUITE=false: the host hermesc build only needs the
# compiler; disabling the test suite skips add_subdirectory(unittests). Old
# Hermes unittests mix plain and keyword target_link_libraries signatures,
# which CMake 4.x hard-errors on ("all uses ... must be either all-keyword or
# all-plain" — HermesADTTests/HermesOptimizerTests via cmake/modules/Lit.cmake),
# breaking a cold-clone Hermes bootstrap on a machine with Homebrew CMake 4.x
# and no prebuilt artifacts. The three device/simulator/macos configures below
# already pass this flag; the host configure was the only one missing it.
# (ENG-23077, ported from the exact-side ENG-22565 fix.)
cmake -S . -B build_host_hermesc -DCMAKE_BUILD_TYPE=Release \
    -DCMAKE_OSX_SYSROOT:STRING="macosx" \
    -DCMAKE_OSX_ARCHITECTURES:STRING="arm64" \
    -DCMAKE_OSX_DEPLOYMENT_TARGET:STRING="$MAC_DEPLOYMENT_TARGET" \
    -DHERMES_ENABLE_TEST_SUITE:BOOLEAN=false \
    -DHAVE_CXX_ATOMICS_WITHOUT_LIB=ON \
    -DHAVE_CXX_ATOMICS64_WITHOUT_LIB=ON
cmake --build ./build_host_hermesc --target hermesc -j "${NUM_CORES}"
cmake --build ./build_host_hermesc --target hermes -j "${NUM_CORES}"

# Build one iOS-family slice (device or simulator) into destroot/Library/Frameworks/<platform>.
build_apple_mobile_slice() {
    local platform="$1"
    local archs="$2"
    local deployment_target="$3"
    echo ""
    echo "Building for $platform ($archs)..."
    cmake -S . -B "build_$platform" \
        -DHERMES_APPLE_TARGET_PLATFORM:STRING="$platform" \
        -DCMAKE_OSX_ARCHITECTURES:STRING="$archs" \
        -DCMAKE_OSX_DEPLOYMENT_TARGET:STRING="$deployment_target" \
        -DHERMES_ENABLE_DEBUGGER:BOOLEAN="$HERMES_DEBUGGER" \
        -DHERMES_ENABLE_INTL:BOOLEAN=true \
        -DHERMES_ENABLE_LIBFUZZER:BOOLEAN=false \
        -DHERMES_ENABLE_FUZZILLI:BOOLEAN=false \
        -DHERMES_ENABLE_TEST_SUITE:BOOLEAN=false \
        -DHERMES_ENABLE_BITCODE:BOOLEAN=false \
        -DHERMES_BUILD_APPLE_FRAMEWORK:BOOLEAN=true \
        -DHERMES_BUILD_SHARED_JSI:BOOLEAN=false \
        -DIMPORT_HOST_COMPILERS:PATH="$PWD/build_host_hermesc/ImportHostCompilers.cmake" \
        -DCMAKE_BUILD_TYPE=MinSizeRel

    # Build bytecode include first (required dependency)
    cmake --build "./build_$platform" --target ExtensionsBytecodeInclude -j 1
    cmake --build "./build_$platform" --target hermesvm -j "${NUM_CORES}"

    mkdir -p "destroot/Library/Frameworks/$platform"
    cp -R "./build_$platform/lib/hermesvm.framework" "destroot/Library/Frameworks/$platform/"
}

build_apple_mobile_slice iphoneos "arm64" "$IOS_DEPLOYMENT_TARGET"
build_apple_mobile_slice iphonesimulator "x86_64;arm64" "$IOS_DEPLOYMENT_TARGET"
build_apple_mobile_slice appletvos "arm64" "$TVOS_MIN_VERSION"
build_apple_mobile_slice appletvsimulator "x86_64;arm64" "$TVOS_MIN_VERSION"

# Build for macOS
echo ""
echo "Building for macOS (arm64, x86_64)..."
# Note: We add flags to suppress visionOS availability errors in newer SDKs
cmake -S . -B build_macosx \
    -DHERMES_APPLE_TARGET_PLATFORM:STRING="macosx" \
    -DCMAKE_OSX_ARCHITECTURES:STRING="x86_64;arm64" \
    -DCMAKE_OSX_DEPLOYMENT_TARGET:STRING="$MAC_DEPLOYMENT_TARGET" \
    -DHERMES_ENABLE_DEBUGGER:BOOLEAN="$HERMES_DEBUGGER" \
    -DHERMES_ENABLE_INTL:BOOLEAN=true \
    -DHERMES_ENABLE_LIBFUZZER:BOOLEAN=false \
    -DHERMES_ENABLE_FUZZILLI:BOOLEAN=false \
    -DHERMES_ENABLE_TEST_SUITE:BOOLEAN=false \
    -DHERMES_ENABLE_BITCODE:BOOLEAN=false \
    -DHERMES_BUILD_APPLE_FRAMEWORK:BOOLEAN=true \
    -DHERMES_BUILD_SHARED_JSI:BOOLEAN=false \
    -DIMPORT_HOST_COMPILERS:PATH="$PWD/build_host_hermesc/ImportHostCompilers.cmake" \
    -DCMAKE_BUILD_TYPE=MinSizeRel \
    -DCMAKE_C_FLAGS="-Wno-unguarded-availability -Wno-unguarded-availability-new -Wno-availability" \
    -DCMAKE_CXX_FLAGS="-Wno-unguarded-availability -Wno-unguarded-availability-new -Wno-availability"

# Build bytecode include first (required dependency)
cmake --build ./build_macosx --target ExtensionsBytecodeInclude -j 1
cmake --build ./build_macosx --target hermesvm -j "${NUM_CORES}"
cmake --build ./build_macosx --target hermesvmlean_a -j "${NUM_CORES}"

mkdir -p destroot/Library/Frameworks/macosx
cp -R ./build_macosx/lib/hermesvm.framework destroot/Library/Frameworks/macosx/

# Copy headers
mkdir -p destroot/include/hermes/Public
cp public/hermes/Public/*.h destroot/include/hermes/Public/
mkdir -p destroot/include/hermes
cp API/hermes/*.h destroot/include/hermes/
mkdir -p destroot/include/hermes/cdp
cp API/hermes/cdp/*.h destroot/include/hermes/cdp/
mkdir -p destroot/include/jsi
cp API/jsi/jsi/*.h destroot/include/jsi/

# Create xcframework from the iOS, tvOS, and macOS slices
echo ""
echo "Creating xcframework..."
mkdir -p destroot/Library/Frameworks/universal
xcodebuild -create-xcframework \
    -framework "destroot/Library/Frameworks/iphoneos/hermesvm.framework" \
    -framework "destroot/Library/Frameworks/iphonesimulator/hermesvm.framework" \
    -framework "destroot/Library/Frameworks/appletvos/hermesvm.framework" \
    -framework "destroot/Library/Frameworks/appletvsimulator/hermesvm.framework" \
    -framework "destroot/Library/Frameworks/macosx/hermesvm.framework" \
    -output "destroot/Library/Frameworks/universal/hermesvm.xcframework"

# Copy results to cache
echo ""
echo "Caching build results..."
mkdir -p "$VERSION_CACHE"
cp -R "$HERMES_SRC/destroot/Library/Frameworks/universal/hermesvm.xcframework" "$VERSION_CACHE/"
cp -R "$HERMES_SRC/build_macosx/lib/hermesvm.framework" "$VERSION_CACHE/"
mkdir -p "$VERSION_CACHE/macos-static"
cp "$HERMES_SRC/build_macosx/lib/libhermesvm_a.a" "$VERSION_CACHE/macos-static/"
cp "$HERMES_SRC/build_macosx/lib/libhermesvmlean_a.a" "$VERSION_CACHE/macos-static/"
cp "$HERMES_SRC/build_macosx/jsi/libjsi.a" "$VERSION_CACHE/macos-static/"
cp "$HERMES_SRC/build_macosx/external/boost/boost_1_86_0/libs/context/libboost_context.a" "$VERSION_CACHE/macos-static/"
for static_archive in "$VERSION_CACHE/macos-static/"*.a; do
    normalize_macos_static_archive "$static_archive"
done
cp -R "$HERMES_SRC/destroot/include" "$VERSION_CACHE/"
mkdir -p "$VERSION_CACHE/bin"
cp "$HERMES_SRC/destroot/bin/hermesc" "$VERSION_CACHE/bin/" 2>/dev/null || true
cp "$HERMES_SRC/build_host_hermesc/bin/hermesc" "$VERSION_CACHE/bin/" 2>/dev/null || true
cp "$HERMES_SRC/build_host_hermesc/bin/hermes" "$VERSION_CACHE/bin/" 2>/dev/null || true

# Install to project
echo ""
echo "=== Installing to project ==="
mkdir -p "$FRAMEWORKS_DIR"
rm -rf "$FRAMEWORKS_DIR/hermes.xcframework"
cp -R "$VERSION_CACHE/hermesvm.xcframework" "$FRAMEWORKS_DIR/hermes.xcframework"
rm -rf "$MACOS_FRAMEWORK_DEST"
cp -R "$VERSION_CACHE/hermesvm.framework" "$MACOS_FRAMEWORK_DEST"
verify_debugger_symbols "$MACOS_FRAMEWORK_DEST"
write_profile_receipt
if [ -f "$PROFILE_RECEIPT_DEST" ]; then
    cp "$PROFILE_RECEIPT_DEST" "$VERSION_CACHE/hermes-profile-provenance.json"
else
    rm -f "$VERSION_CACHE/hermes-profile-provenance.json"
fi
rm -rf "$MACOS_STATIC_DIR"
cp -R "$VERSION_CACHE/macos-static" "$MACOS_STATIC_DIR"

rm -rf "$FRAMEWORKS_DIR/hermes-headers"
mkdir -p "$FRAMEWORKS_DIR/hermes-headers"
cp -R "$VERSION_CACHE/include/"* "$FRAMEWORKS_DIR/hermes-headers/"

# hermesc is the ahead-of-time compiler the whole build pipeline depends on, so
# a missing one is a failed build, not a warning. The previous `2>/dev/null ||
# true` here reported "Build Complete" and printed the CLI path while the copy
# had silently failed — which is exactly what the fail-loud rule forbids. It
# was latent only because tools/hermes/ already exists in a real checkout.
# @ref scripts/README.md — the fail-loud rule this restores
mkdir -p "$HERMES_TOOLS_DIR"
if [ ! -f "$VERSION_CACHE/bin/hermesc" ]; then
    echo "[✗] hermesc is missing from the build cache: $VERSION_CACHE/bin/hermesc" >&2
    exit 1
fi
cp "$VERSION_CACHE/bin/hermesc" "$HERMESC_DEST"
# The full hermes CLI is optional; its absence is not a build failure.
if [ -f "$VERSION_CACHE/bin/hermes" ]; then
    cp "$VERSION_CACHE/bin/hermes" "$HERMES_TOOLS_DIR/hermes"
fi

echo ""
echo "=== Build Complete ==="
echo ""
echo "Installed:"
echo "  Framework: $FRAMEWORKS_DIR/hermes.xcframework"
echo "  macOS FW:  $MACOS_FRAMEWORK_DEST"
echo "  macOS lib: $MACOS_STATIC_DIR"
echo "  Headers:   $FRAMEWORKS_DIR/hermes-headers/"
echo "  CLI:       $HERMESC_DEST"
echo ""
echo "Cached at: $VERSION_CACHE"
echo ""
echo "Note: The framework is named 'hermesvm' internally but installed as 'hermes'"
echo "      for compatibility with the existing project structure."
if [ "$HERMES_VANILLA" = true ]; then
    echo ""
    echo "Write a HermesInputReceipt with:"
    echo "  node \"$SCRIPT_DIR/hermes-input-receipt.mjs\" \"$FRAMEWORKS_DIR\""
fi
echo ""
