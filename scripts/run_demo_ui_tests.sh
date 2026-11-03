#!/usr/bin/env bash

. "$(dirname "$0")/lib.sh"

DEMO_SCHEME="${1:?usage: $0 <TrustKitDemo-ObjC|TrustKitDemo-Swift> [xcodebuild arguments...]}"
shift
configure_platform ios-simulator

RESULT_BUNDLE="output/${DEMO_SCHEME}-ui-tests.xcresult"
rm -rf "$RESULT_BUNDLE"

xcodebuild_pretty test \
    -project TrustKitDemo/TrustKitDemo.xcodeproj \
    -scheme "$DEMO_SCHEME" \
    -destination "platform=${PLATFORM_NAME},name=${SIMULATOR},OS=$(xcrun --sdk "$SIMULATOR_SDK" --show-sdk-version)" \
    -resultBundlePath "$RESULT_BUNDLE" \
    -collect-test-diagnostics never \
    "$@"
