#!/usr/bin/env bash

. "$(dirname "$0")/lib.sh"

PLATFORM="${1:?usage: $0 <ios|ios-static|macos|tvos|watchos> [xcodebuild arguments...]}"
shift
configure_platform "$PLATFORM"

xcodebuild_pretty build \
    -project "${ROOT_DIR}/TrustKit.xcodeproj" \
    -scheme "$SCHEME" \
    -destination "$DESTINATION" \
    CODE_SIGNING_ALLOWED=NO \
    "$@"
