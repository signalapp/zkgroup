#!/bin/bash

#
# Copyright 2020-2021 Signal Messenger, LLC.
# SPDX-License-Identifier: AGPL-3.0-only
#

set -euo pipefail

SCRIPT_DIR=$(dirname "$0")
cd "${SCRIPT_DIR}"/../..
. bin/build_helpers.sh

export CARGO_PROFILE_RELEASE_DEBUG=1 # enable line tables
export CARGO_PROFILE_RELEASE_LTO=fat # use fat LTO to reduce binary size

usage() {
  cat >&2 <<END
Usage: $(basename "$0") [-d|-r] [-v] [--generate-ffi|--verify-ffi] [--build-std]

Options:
  -d -- debug build (default)
  -r -- release build
  -v -- verbose build

  --generate-ffi -- regenerate ffi headers
  --verify-ffi   -- verify that ffi headers are up to date
  --build-std    -- build the standard library from source

Use CARGO_BUILD_TARGET for cross-compilation (such as for iOS).
END
}

check_cbindgen() {
  if ! command -v cbindgen > /dev/null; then
    echo 'error: cbindgen not found in PATH' >&2
    if command -v cargo > /dev/null; then
      echo 'note: get it by running' >&2
      printf "\n\t%s\n\n" "cargo install cbindgen --vers '^0.16'" >&2
    fi
    exit 1
  fi
}


RELEASE_BUILD=
VERBOSE=
SHOULD_CBINDGEN=
CBINDGEN_VERIFY=
BUILD_STD=

while [ "${1:-}" != "" ]; do
  case $1 in
    -d | --debug )
      RELEASE_BUILD=
      ;;
    -r | --release )
      RELEASE_BUILD=1
      ;;
    -v | --verbose )
      VERBOSE=1
      ;;
    --generate-ffi )
      SHOULD_CBINDGEN=1
      ;;
    --verify-ffi )
      SHOULD_CBINDGEN=1
      CBINDGEN_VERIFY=1
      ;;
    --build-std)
      BUILD_STD=1
      ;;
    -h | --help )
      usage
      exit
      ;;
    * )
      usage
      exit 2
  esac
  shift
done

check_rust

if [[ -n "${DEVELOPER_SDK_DIR:-}" ]]; then
  # Assume we're in Xcode, which means we're probably cross-compiling.
  # In this case, we need to add an extra library search path for build scripts and proc-macros,
  # which run on the host instead of the target.
  # (macOS Big Sur does not have linkable libraries in /usr/lib/.)
  export LIBRARY_PATH="${DEVELOPER_SDK_DIR}/MacOSX.sdk/usr/lib:${LIBRARY_PATH:-}"
fi

echo_then_run cargo ${BUILD_STD:+-Zbuild-std} build -p zkgroup ${RELEASE_BUILD:+--release} ${VERBOSE:+--verbose} ${CARGO_BUILD_TARGET:+--target $CARGO_BUILD_TARGET}

FFI_HEADER_PATH=ffi/swift/Sources/libzkgroup/zkgroup.h

if [[ -n "${SHOULD_CBINDGEN}" ]]; then
  check_cbindgen
  if [[ -n "${CBINDGEN_VERIFY}" ]]; then
    echo diff -u "${FFI_HEADER_PATH}" "<(cbindgen -q ${RELEASE_BUILD:+--profile release} --lang c rust)"
    if ! diff -u "${FFI_HEADER_PATH}"  <(cbindgen -q ${RELEASE_BUILD:+--profile release} --lang c rust); then
      echo
      echo 'error: signal_ffi.h not up to date; run' "$0" '--generate-ffi' >&2
      exit 1
    fi
  else
    echo cbindgen ${RELEASE_BUILD:+--profile release} --lang c -o "${FFI_HEADER_PATH}" rust
    # Use sed to ignore irrelevant cbindgen warnings.
    # ...and then disable the shellcheck warning about literal backticks in single-quotes
    # shellcheck disable=SC2016
    cbindgen ${RELEASE_BUILD:+--profile release} --lang c -o "${FFI_HEADER_PATH}" rust 2>&1 |
      sed '/WARN: Missing `\[defines\]` entry for `feature = "ffi"` in cbindgen config\./ d' >&2
  fi
fi
