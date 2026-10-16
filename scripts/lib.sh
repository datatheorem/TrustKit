#!/usr/bin/env bash

set -o errexit
set -o nounset
set -o pipefail

cd "$(dirname "$0")/.."

xcodebuild_pretty() {
    if ! command -v xcbeautify >/dev/null 2>&1; then
        xcodebuild "$@"
    elif [[ -n "${GITHUB_ACTIONS:-}" ]]; then
        NSUnbufferedIO=YES xcodebuild "$@" 2>&1 | xcbeautify --preserve-unbeautified --renderer github-actions
    else
        NSUnbufferedIO=YES xcodebuild "$@" 2>&1 | xcbeautify --preserve-unbeautified
    fi
}

configure_platform() {
    SIMULATOR=""
    DESTINATION_SUFFIX=""
    case "$1" in
        ios)                SCHEME="TrustKit";          PLATFORM_NAME="iOS" ;;
        ios-simulator)      SCHEME="TrustKit";          PLATFORM_NAME="iOS Simulator";      SIMULATOR="iPhone 17";                    SIMULATOR_SDK="iphonesimulator" ;;
        macos)              SCHEME="TrustKit OS X";     PLATFORM_NAME="macOS" ;;
        maccatalyst)        SCHEME="TrustKit";          PLATFORM_NAME="macOS";              DESTINATION_SUFFIX=",variant=Mac Catalyst" ;;
        tvos)               SCHEME="TrustKit tvOS";     PLATFORM_NAME="tvOS" ;;
        tvos-simulator)     SCHEME="TrustKit tvOS";     PLATFORM_NAME="tvOS Simulator";     SIMULATOR="Apple TV 4K (3rd generation)"; SIMULATOR_SDK="appletvsimulator" ;;
        watchos)            SCHEME="TrustKit watchOS";  PLATFORM_NAME="watchOS" ;;
        watchos-simulator)  SCHEME="TrustKit watchOS";  PLATFORM_NAME="watchOS Simulator";  SIMULATOR="Apple Watch Series 12 (46mm)"; SIMULATOR_SDK="watchsimulator" ;;
        visionos)           SCHEME="TrustKit visionOS"; PLATFORM_NAME="visionOS" ;;
        visionos-simulator) SCHEME="TrustKit visionOS"; PLATFORM_NAME="visionOS Simulator"; SIMULATOR="Apple Vision Pro";             SIMULATOR_SDK="xrsimulator" ;;
        *)
            echo "Unknown platform '$1'; expected ios, ios-simulator, macos, maccatalyst, tvos, tvos-simulator, watchos, watchos-simulator, visionos or visionos-simulator" >&2
            exit 1
            ;;
    esac
}

simulator_available() {
    xcrun simctl list devices available | awk -v section="-- $1 --" -v device="    $2 (" '
        $0 == section { in_section = 1; next }
        /^-- / { in_section = 0 }
        in_section && index($0, device) == 1 { found = 1 }
        END { exit !found }'
}

require_simulator_runtime() {
    local runtime="${PLATFORM_NAME% Simulator}"
    local image_dir
    SIMULATOR_OS="$(xcrun --sdk "$SIMULATOR_SDK" --show-sdk-version)"
    if simulator_available "${runtime} ${SIMULATOR_OS}" "$SIMULATOR"; then
        return
    fi

    echo "${SIMULATOR} (${runtime} ${SIMULATOR_OS}) is not available; adding the ${runtime} ${SIMULATOR_OS} simulator runtime" >&2
    xcrun simctl runtime list >&2
    image_dir="$(mktemp -d)"
    xcodebuild -downloadPlatform "$runtime" -buildVersion "$SIMULATOR_OS" -architectureVariant arm64 -exportPath "$image_dir"
    find "$image_dir" -name '*.dmg' -exec xcrun simctl runtime add {} \;
    rm -rf "$image_dir"

    if ! simulator_available "${runtime} ${SIMULATOR_OS}" "$SIMULATOR"; then
        xcrun simctl runtime list >&2
        xcrun simctl list devices >&2
        echo "${SIMULATOR} (${runtime} ${SIMULATOR_OS}) is still not available" >&2
        exit 1
    fi
}
