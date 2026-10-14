#!/usr/bin/env bash

set -o errexit
set -o nounset
set -o pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
OUTPUT_DIR="${ROOT_DIR}/output"

xcodebuild_pretty() {
    if ! command -v xcbeautify >/dev/null 2>&1; then
        xcodebuild "$@"
    elif [[ -n "${GITHUB_ACTIONS:-}" ]]; then
        NSUnbufferedIO=YES xcodebuild "$@" 2>&1 | xcbeautify --renderer github-actions
    else
        NSUnbufferedIO=YES xcodebuild "$@" 2>&1 | xcbeautify
    fi
}

simulator_id() {
    local runtime_platform="$1" name_prefix="$2" sdk="$3"
    xcrun simctl list devices available --json | python3 -I -c '
import json, sys

platform, name_prefix, sdk = sys.argv[1], sys.argv[2], sys.argv[3]
sdk_version = tuple(int(part) for part in sdk.split("."))
runtime_prefix = "com.apple.CoreSimulator.SimRuntime.%s-" % platform

best = None
for runtime, devices in json.load(sys.stdin)["devices"].items():
    if not runtime.startswith(runtime_prefix):
        continue
    version = tuple(int(part) for part in runtime[len(runtime_prefix):].split("-"))
    if version > sdk_version:
        continue
    for device in devices:
        if device["name"].startswith(name_prefix) and (best is None or version > best[0]):
            best = (version, device["udid"])

if best is None:
    sys.exit("No available %s simulator named %s* for SDK %s" % (platform, name_prefix, sdk))
print(best[1])
' "$runtime_platform" "$name_prefix" "$(xcrun --sdk "$sdk" --show-sdk-version)"
}

configure_platform() {
    case "$1" in
        ios)
            SCHEME="TrustKit"
            DESTINATION="platform=iOS Simulator,id=$(simulator_id iOS iPhone iphonesimulator)"
            ;;
        ios-static)
            SCHEME="TrustKit_Static"
            DESTINATION="generic/platform=iOS"
            ;;
        macos)
            SCHEME="TrustKit OS X"
            DESTINATION="platform=macOS"
            ;;
        tvos)
            SCHEME="TrustKit tvOS"
            DESTINATION="platform=tvOS Simulator,id=$(simulator_id tvOS "Apple TV" appletvsimulator)"
            ;;
        watchos)
            SCHEME="TrustKit watchOS"
            DESTINATION="generic/platform=watchOS"
            ;;
        *)
            echo "Unknown platform '$1'; expected ios, ios-static, macos, tvos or watchos" >&2
            exit 1
            ;;
    esac
}
