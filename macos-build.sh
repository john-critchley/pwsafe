#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BUILD_ROOT="${BUILD_ROOT:-$ROOT_DIR/build/macos}"
PROGRESS_FILE="${PROGRESS_FILE:-$BUILD_ROOT/.progress}"
WX_VERSION="${WX_VERSION:-3.2.8}"
WX_SRC_DIR="${WX_SRC_DIR:-$BUILD_ROOT/wxWidgets-$WX_VERSION}"
WX_BUILD_NAME="${WX_BUILD_NAME:-}"
WX_BUILD_DIR="${WX_BUILD_DIR:-}"
DERIVED_DATA="${DERIVED_DATA:-$BUILD_ROOT/xcderived}"
XCODE_PROJECT="$ROOT_DIR/Xcode/pwsafe-xcode6.xcodeproj"
XCODE_SCHEME="${XCODE_SCHEME:-All}"
XCODE_CONFIG="${XCODE_CONFIG:-Release}"
ARCH_MODE="${ARCH_MODE:-universal}"
MACOS_MIN="${MACOS_MIN:-10.14}"
MAKE_JOBS="${MAKE_JOBS:-}"
BUILD_DMG=0
RUN_AFTER_BUILD=0
RUN_TESTS=1
INSTALL_BREW_DEPS=1
BUILD_WX=1
BUILD_YUBI=1
FORCE_STEPS=0
SOURCE_ONLY=0
XCODE_APP="${XCODE_APP:-}"

LIBYUBIKEY_COMMIT="${LIBYUBIKEY_COMMIT:-e4334554857b0367085cbf845bf87dd92433e020}"
YKPERS_COMMIT="${YKPERS_COMMIT:-db0c0d641d47ee52e43af94dcee603d76186b6d3}"

usage() {
  cat <<'EOF'
Usage: ./macos-build.sh [options]

Build Password Safe on macOS using the same basic path as the macOS CI build:
Homebrew dependencies, static Yubikey libraries, wxWidgets, generated Xcode
xcconfig, xcodebuild, and tests. Release DMG packaging is opt-in because it
uses create-dmg, which automates Finder with AppleScript.

Progress markers are written to build/macos/.progress by default. Delete that
file, edit it, pass --force, or set PROGRESS_FILE to control resumed builds.

Options:
  --config Release|Debug|Debug-no-yubi
      Xcode configuration to build. Default: Release.

  --arch universal|native|arm64|x86_64
      wxWidgets architecture mode. Default: universal.
      Use native for a faster local build on the current Mac.

  --wx-version VERSION
      wxWidgets version tag to build, without the leading "v". Default: 3.2.8.

  --xcode-app PATH
      Select a specific Xcode app before building, e.g. /Applications/Xcode.app.

  --derived-data PATH
      Xcode derived data directory. Default: build/macos/xcderived.

  --skip-brew
      Do not install Homebrew packages.

  --skip-yubi
      Do not build libyubikey/ykpers. Implied by --config Debug-no-yubi.

  --skip-wx
      Reuse the existing wxWidgets build.

  --source-only
      Skip external dependencies and rebuild only repo source outputs
      (Xcode config, pwsafe, tests, and --dmg if requested).

  --no-tests
      Build only; do not run coretest or pwsafe-cli-test.

  --dmg
      Create the release DMG. This uses create-dmg and may prompt for Finder
      automation permission on macOS.

  --no-dmg
      Do not create the release DMG.

  --run
      Launch pwsafe after a successful build.

  --force
      Ignore the progress file and rerun requested steps.

  -h, --help
      Show this help.

Environment overrides:
  BUILD_ROOT, WX_SRC_DIR, WX_BUILD_NAME, WX_BUILD_DIR, DERIVED_DATA, MAKE_JOBS,
  XCODE_SCHEME, XCODE_CONFIG, ARCH_MODE, MACOS_MIN, XCODE_APP,
  LIBYUBIKEY_COMMIT, YKPERS_COMMIT, PROGRESS_FILE
EOF
}

log() {
  printf '\n==> %s\n' "$*"
}

die() {
  printf 'error: %s\n' "$*" >&2
  exit 1
}

have() {
  command -v "$1" >/dev/null 2>&1
}

progress_done() {
  [[ -f "$PROGRESS_FILE" ]] && grep -Fxq "$1" "$PROGRESS_FILE"
}

mark_progress() {
  mkdir -p "$(dirname "$PROGRESS_FILE")"
  if ! progress_done "$1"; then
    printf '%s\n' "$1" >> "$PROGRESS_FILE"
    log "Recorded progress: $1"
  fi
}

run_step() {
  local key="$1"
  local label="$2"
  shift 2

  if [[ "$FORCE_STEPS" -eq 0 ]] && progress_done "$key"; then
    log "Skipping $label; already recorded in $PROGRESS_FILE"
    return 0
  fi

  log "$label"
  "$@"
  mark_progress "$key"
}

run_source_step() {
  local key="$1"
  local label="$2"
  shift 2

  if [[ "$SOURCE_ONLY" -eq 1 ]]; then
    log "$label"
    "$@"
    mark_progress "$key"
    return 0
  fi

  run_step "$key" "$label" "$@"
}

while (($#)); do
  case "$1" in
    --config)
      XCODE_CONFIG="${2:-}"
      shift 2
      ;;
    --arch)
      ARCH_MODE="${2:-}"
      shift 2
      ;;
    --wx-version)
      WX_VERSION="${2:-}"
      WX_SRC_DIR="$BUILD_ROOT/wxWidgets-$WX_VERSION"
      shift 2
      ;;
    --xcode-app)
      XCODE_APP="${2:-}"
      shift 2
      ;;
    --derived-data)
      DERIVED_DATA="${2:-}"
      shift 2
      ;;
    --skip-brew)
      INSTALL_BREW_DEPS=0
      shift
      ;;
    --skip-yubi)
      BUILD_YUBI=0
      shift
      ;;
    --skip-wx)
      BUILD_WX=0
      shift
      ;;
    --source-only)
      SOURCE_ONLY=1
      INSTALL_BREW_DEPS=0
      BUILD_YUBI=0
      BUILD_WX=0
      shift
      ;;
    --no-tests)
      RUN_TESTS=0
      shift
      ;;
    --dmg)
      BUILD_DMG=1
      shift
      ;;
    --no-dmg)
      BUILD_DMG=0
      shift
      ;;
    --run)
      RUN_AFTER_BUILD=1
      shift
      ;;
    --force)
      FORCE_STEPS=1
      shift
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      die "unknown option: $1"
      ;;
  esac
done

case "$XCODE_CONFIG" in
  Release|Debug|Debug-no-yubi) ;;
  *) die "--config must be Release, Debug, or Debug-no-yubi" ;;
esac

case "$ARCH_MODE" in
  universal|native|arm64|x86_64) ;;
  *) die "--arch must be universal, native, arm64, or x86_64" ;;
esac

if [[ "$XCODE_CONFIG" == "Debug-no-yubi" ]]; then
  BUILD_YUBI=0
fi

if [[ "$XCODE_CONFIG" != "Release" ]]; then
  BUILD_DMG=0
fi

if [[ -z "$WX_BUILD_NAME" ]]; then
  if [[ "$XCODE_CONFIG" == "Release" ]]; then
    WX_BUILD_NAME="static-release"
  else
    WX_BUILD_NAME="static-debug"
  fi
fi

if [[ -z "$WX_BUILD_DIR" ]]; then
  WX_BUILD_DIR="$WX_SRC_DIR/$WX_BUILD_NAME"
fi

if [[ "$(uname -s)" != "Darwin" ]]; then
  die "this script must be run on macOS"
fi

if [[ -z "$MAKE_JOBS" ]]; then
  MAKE_JOBS="$(sysctl -n hw.ncpu)"
fi

log "Checking required tools"
have git || die "git is required"
have make || die "make is required"
have perl || die "perl is required"
have xcodebuild || die "Xcode command line tools are required; run: xcode-select --install"

if [[ -n "$XCODE_APP" ]]; then
  [[ -d "$XCODE_APP" ]] || die "Xcode app does not exist: $XCODE_APP"
  log "Selecting Xcode at $XCODE_APP"
  sudo xcode-select -s "$XCODE_APP"
fi

if [[ "$INSTALL_BREW_DEPS" -eq 1 ]]; then
  have brew || die "Homebrew is required for dependency installation; install it or pass --skip-brew"
  run_step "brew:deps:googletest:autoconf:automake:libtool" \
    "Installing Homebrew dependencies" \
    brew install googletest autoconf automake libtool
  if [[ "$BUILD_DMG" -eq 1 ]]; then
    run_step "brew:deps:create-dmg" \
      "Installing DMG packaging dependency" \
      brew install create-dmg
  fi
fi

mkdir -p "$BUILD_ROOT"

build_autotools_project() {
  local name="$1"
  local repo="$2"
  local commit="$3"
  local dir="$BUILD_ROOT/$name"
  local key="yubi:$name:$commit:macosmin=$MACOS_MIN"

  if [[ "$FORCE_STEPS" -eq 0 ]] && progress_done "$key"; then
    log "Skipping $name; already recorded in $PROGRESS_FILE"
    return 0
  fi

  if [[ ! -d "$dir/.git" ]]; then
    log "Cloning $name"
    git clone --no-checkout "$repo" "$dir"
  fi

  log "Building $name at $commit"
  git -C "$dir" fetch --quiet origin
  git -C "$dir" checkout --quiet "$commit"
  (
    cd "$dir"
    autoreconf --force --install
    ./configure --disable-shared --disable-documentation CFLAGS="-O2 -arch arm64 -arch x86_64 -mmacosx-version-min=$MACOS_MIN"
    make -j "$MAKE_JOBS" check
    sudo make install
  )
  mark_progress "$key"
}

if [[ "$BUILD_YUBI" -eq 1 ]]; then
  build_autotools_project "yubico-c" "https://github.com/Yubico/yubico-c.git" "$LIBYUBIKEY_COMMIT"
  build_autotools_project "yubikey-personalization" "https://github.com/Yubico/yubikey-personalization.git" "$YKPERS_COMMIT"
else
  log "Skipping Yubikey libraries"
fi

build_wx_widgets() {
  if [[ ! -d "$WX_SRC_DIR/.git" ]]; then
    log "Cloning wxWidgets v$WX_VERSION"
    git clone --branch "v$WX_VERSION" --single-branch https://github.com/wxWidgets/wxWidgets.git "$WX_SRC_DIR"
  fi

  log "Updating wxWidgets submodules"
  git -C "$WX_SRC_DIR" submodule update --init

  log "Configuring wxWidgets"
  rm -rf "$WX_BUILD_DIR"
  mkdir -p "$WX_BUILD_DIR"

  (
    cd "$WX_BUILD_DIR"
    set --
    if [[ "$XCODE_CONFIG" != "Release" ]]; then
      set -- "$@" -d
    fi
    case "$ARCH_MODE" in
      universal) ;;
      native) set -- "$@" -a "$(uname -m)" ;;
      arm64|x86_64) set -- "$@" -a "$ARCH_MODE" ;;
    esac
    "$ROOT_DIR/Misc/osx-build-wx" "$@"
    make -j "$MAKE_JOBS"
    (cd "$WX_SRC_DIR/locale" && make allmo)
  )
}

if [[ "$BUILD_WX" -eq 1 ]]; then
  WX_STEP_KEY="wx:$WX_VERSION:$WX_BUILD_NAME:$ARCH_MODE:$XCODE_CONFIG:macosmin=$MACOS_MIN"
  WX_CONFIG="$WX_BUILD_DIR/wx-config"
  if [[ "$FORCE_STEPS" -eq 0 ]] && ! progress_done "$WX_STEP_KEY" && [[ -x "$WX_CONFIG" ]]; then
    log "Found existing wxWidgets build at $WX_BUILD_DIR"
    mark_progress "$WX_STEP_KEY"
  fi
  run_step "$WX_STEP_KEY" \
    "Building wxWidgets v$WX_VERSION ($WX_BUILD_NAME, $ARCH_MODE)" \
    build_wx_widgets
else
  log "Skipping wxWidgets build"
fi

WX_CONFIG="$WX_BUILD_DIR/wx-config"
[[ -x "$WX_CONFIG" ]] || die "wx-config not found or not executable: $WX_CONFIG"

generate_xcode_config() {
  if [[ "$XCODE_CONFIG" == "Release" ]]; then
    "$ROOT_DIR/Xcode/generate-configs" -r "$WX_CONFIG" > "$ROOT_DIR/Xcode/pwsafe-release.xcconfig"
  else
    "$ROOT_DIR/Xcode/generate-configs" -d "$WX_CONFIG" > "$ROOT_DIR/Xcode/pwsafe-debug.xcconfig"
  fi
}

run_source_step "xcode_config:$XCODE_CONFIG:$WX_CONFIG" \
  "Generating Xcode wxWidgets config" \
  generate_xcode_config

build_pwsafe() {
  xcodebuild \
    -derivedDataPath "$DERIVED_DATA" \
    -project "$XCODE_PROJECT" \
    -scheme "$XCODE_SCHEME" \
    -configuration "$XCODE_CONFIG"
}

run_source_step "xcodebuild:$XCODE_SCHEME:$XCODE_CONFIG:$DERIVED_DATA" \
  "Building Password Safe with xcodebuild" \
  build_pwsafe

PRODUCT_DIR="$DERIVED_DATA/Build/Products/$XCODE_CONFIG"

build_webdav_plugin() {
  local plugin_src="$ROOT_DIR/src/os/plugins/webdav/transport-webdav.cpp"
  local app_macos="$PRODUCT_DIR/pwsafe.app/Contents/MacOS"
  local out="$app_macos/pwsafe-https.so"

  local curl_cflags curl_libs
  curl_cflags="$(curl-config --cflags)"
  curl_libs="$(curl-config --libs)"

  clang++ -bundle -undefined dynamic_lookup \
    -std=c++17 \
    -I "$ROOT_DIR/src/os" \
    $curl_cflags \
    -o "$out" \
    "$plugin_src" \
    $curl_libs

  ln -sf pwsafe-https.so "$app_macos/pwsafe-http.so"
  log "Built WebDAV plugin: $out"
}

run_source_step "webdav-plugin:$XCODE_CONFIG:$PRODUCT_DIR" \
  "Building WebDAV transport plugin" \
  build_webdav_plugin

if [[ "$RUN_TESTS" -eq 1 ]]; then
  run_tests() {
    (cd "$ROOT_DIR/src/test" && "$PRODUCT_DIR/coretest")
    "$PRODUCT_DIR/pwsafe-cli-test"
  }
  run_source_step "tests:$XCODE_SCHEME:$XCODE_CONFIG:$DERIVED_DATA" \
    "Running tests" \
    run_tests
fi

if [[ "$BUILD_DMG" -eq 1 ]]; then
  create_dmg() {
    make -C "$ROOT_DIR/install/macosx" RELDIR="$PRODUCT_DIR"
  }
  run_source_step "dmg:$XCODE_CONFIG:$PRODUCT_DIR" \
    "Creating DMG" \
    create_dmg
fi

log "Build complete"
printf 'Products: %s\n' "$PRODUCT_DIR"
if [[ "$BUILD_DMG" -eq 1 ]]; then
  printf 'DMG output is written under: %s/install/macosx\n' "$ROOT_DIR"
fi

if [[ "$RUN_AFTER_BUILD" -eq 1 ]]; then
  log "Launching pwsafe"
  open "$PRODUCT_DIR/pwsafe.app"
fi
