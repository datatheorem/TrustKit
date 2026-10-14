#!/usr/bin/env bash

. "$(dirname "$0")/lib.sh"

PLATFORM="${1:?usage: $0 <ios|macos|tvos> [xcodebuild arguments...]}"
shift
configure_platform "$PLATFORM"

RESULT_BUNDLE="${OUTPUT_DIR}/${PLATFORM}-tests.xcresult"
rm -rf "$RESULT_BUNDLE"

xcodebuild_pretty test \
    -project "${ROOT_DIR}/TrustKit.xcodeproj" \
    -scheme "$SCHEME" \
    -destination "$DESTINATION" \
    -resultBundlePath "$RESULT_BUNDLE" \
    "$@"
