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
    case "$1" in
        ios)                SCHEME="TrustKit";          PLATFORM_NAME="iOS" ;;
        ios-simulator)      SCHEME="TrustKit";          PLATFORM_NAME="iOS Simulator";      SIMULATOR="iPhone 17";                    SIMULATOR_SDK="iphonesimulator" ;;
        macos)              SCHEME="TrustKit OS X";     PLATFORM_NAME="macOS" ;;
        tvos)               SCHEME="TrustKit tvOS";     PLATFORM_NAME="tvOS" ;;
        tvos-simulator)     SCHEME="TrustKit tvOS";     PLATFORM_NAME="tvOS Simulator";     SIMULATOR="Apple TV 4K (3rd generation)"; SIMULATOR_SDK="appletvsimulator" ;;
        watchos)            SCHEME="TrustKit watchOS";  PLATFORM_NAME="watchOS" ;;
        watchos-simulator)  SCHEME="TrustKit watchOS";  PLATFORM_NAME="watchOS Simulator";  SIMULATOR="Apple Watch Series 12 (46mm)"; SIMULATOR_SDK="watchsimulator" ;;
        visionos)           SCHEME="TrustKit visionOS"; PLATFORM_NAME="visionOS" ;;
        visionos-simulator) SCHEME="TrustKit visionOS"; PLATFORM_NAME="visionOS Simulator"; SIMULATOR="Apple Vision Pro";             SIMULATOR_SDK="xrsimulator" ;;
        *)
            echo "Unknown platform '$1'; expected ios, ios-simulator, macos, tvos, tvos-simulator, watchos, watchos-simulator, visionos or visionos-simulator" >&2
            exit 1
            ;;
    esac
}

require_simulator_runtime() {
    local runtime="${PLATFORM_NAME% Simulator}"
    local runtimes
    SIMULATOR_OS="$(xcrun --sdk "$SIMULATOR_SDK" --show-sdk-version)"
    runtimes="$(xcrun simctl list runtimes available)"
    if ! grep -q "^${runtime} ${SIMULATOR_OS} (" <<< "$runtimes"; then
        echo "${runtime} ${SIMULATOR_OS} simulator runtime is not available; downloading it" >&2
        xcrun simctl runtime list >&2
        xcodebuild -downloadPlatform "$runtime" -buildVersion "$SIMULATOR_OS" -architectureVariant arm64
    fi
}
