#!/usr/bin/env bash

. "$(dirname "$0")/lib.sh"

PLATFORM="${1:?usage: $0 <ios-simulator|macos|tvos-simulator> [xcodebuild arguments...]}"
shift
configure_platform "$PLATFORM"

RESULT_BUNDLE="output/${PLATFORM}-tests.xcresult"
rm -rf "$RESULT_BUNDLE"

DESTINATION="platform=${PLATFORM_NAME}"
if [[ -n "$SIMULATOR" ]]; then
    DESTINATION+=",name=${SIMULATOR},OS=$(xcrun --sdk "$SIMULATOR_SDK" --show-sdk-version)"
fi

xcodebuild_pretty test \
    -project TrustKit.xcodeproj \
    -scheme "$SCHEME" \
    -destination "$DESTINATION" \
    -resultBundlePath "$RESULT_BUNDLE" \
    "$@"
