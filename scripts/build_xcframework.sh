#!/usr/bin/env bash

. "$(dirname "$0")/lib.sh"

ARCHIVES_DIR="output/archives"
XCFRAMEWORK="output/TrustKit.xcframework"
ZIP="output/TrustKit-static.zip"
rm -rf "$ARCHIVES_DIR" "$XCFRAMEWORK" "$ZIP"

FRAMEWORKS=()
for PLATFORM in ios ios-simulator macos tvos tvos-simulator watchos watchos-simulator visionos visionos-simulator; do
    configure_platform "$PLATFORM"
    xcodebuild_pretty archive \
        -project TrustKit.xcodeproj \
        -scheme "$SCHEME" \
        -destination "generic/platform=${PLATFORM_NAME}" \
        -archivePath "${ARCHIVES_DIR}/${PLATFORM}.xcarchive" \
        SKIP_INSTALL=NO \
        MACH_O_TYPE=staticlib \
        CODE_SIGNING_ALLOWED=NO \
        "$@"
    FRAMEWORKS+=(-framework "${ARCHIVES_DIR}/${PLATFORM}.xcarchive/Products/Library/Frameworks/TrustKit.framework")
done

xcodebuild -create-xcframework "${FRAMEWORKS[@]}" -output "$XCFRAMEWORK"
ditto -c -k --keepParent "$XCFRAMEWORK" "$ZIP"
