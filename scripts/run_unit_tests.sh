#!/usr/bin/env bash

. "$(dirname "$0")/lib.sh"

PLATFORM="${1:?usage: $0 <ios-simulator|macos|tvos-simulator> [xcodebuild arguments...]}"
shift
configure_platform "$PLATFORM"

RESULT_BUNDLE="output/${PLATFORM}-tests.xcresult"
rm -rf "$RESULT_BUNDLE"

xcodebuild_pretty test \
    -project TrustKit.xcodeproj \
    -scheme "$SCHEME" \
    -destination "platform=${PLATFORM_NAME}${SIMULATOR:+,name=${SIMULATOR}}" \
    -resultBundlePath "$RESULT_BUNDLE" \
    "$@"
