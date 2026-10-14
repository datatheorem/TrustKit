#!/usr/bin/env bash

set -o errexit
set -o nounset
set -o pipefail

cd "$(dirname "$0")/.."

xcodebuild_pretty() {
    if ! command -v xcbeautify >/dev/null 2>&1; then
        xcodebuild "$@"
    elif [[ -n "${GITHUB_ACTIONS:-}" ]]; then
        NSUnbufferedIO=YES xcodebuild "$@" 2>&1 | xcbeautify --renderer github-actions
    else
        NSUnbufferedIO=YES xcodebuild "$@" 2>&1 | xcbeautify
    fi
}

configure_platform() {
    SIMULATOR=""
    case "$1" in
        ios)               SCHEME="TrustKit";         PLATFORM_NAME="iOS" ;;
        ios-simulator)     SCHEME="TrustKit";         PLATFORM_NAME="iOS Simulator";     SIMULATOR="iPhone 17" ;;
        macos)             SCHEME="TrustKit OS X";    PLATFORM_NAME="macOS" ;;
        tvos)              SCHEME="TrustKit tvOS";    PLATFORM_NAME="tvOS" ;;
        tvos-simulator)    SCHEME="TrustKit tvOS";    PLATFORM_NAME="tvOS Simulator";    SIMULATOR="Apple TV 4K (3rd generation)" ;;
        watchos)           SCHEME="TrustKit watchOS"; PLATFORM_NAME="watchOS" ;;
        watchos-simulator) SCHEME="TrustKit watchOS"; PLATFORM_NAME="watchOS Simulator" ;;
        *)
            echo "Unknown platform '$1'; expected ios, ios-simulator, macos, tvos, tvos-simulator, watchos or watchos-simulator" >&2
            exit 1
            ;;
    esac
}
