#!/usr/bin/env bash

. "$(dirname "$0")/lib.sh"

PLATFORM="${1:?usage: $0 <ios-simulator|tvos-simulator|watchos-simulator|visionos-simulator>}"
configure_platform "$PLATFORM"

RUNTIME="${PLATFORM_NAME% Simulator}"
OS_VERSION="$(xcrun --sdk "$SIMULATOR_SDK" --show-sdk-version)"
EXPORT_DIR="$(mktemp -d)"
trap 'rm -rf "$EXPORT_DIR"' EXIT

sudo --preserve-env=DEVELOPER_DIR xcodebuild -runFirstLaunch
xcrun simctl list > /dev/null

xcodebuild -downloadPlatform "$RUNTIME" -buildVersion "$OS_VERSION" -architectureVariant arm64 -exportPath "$EXPORT_DIR" || true
IMAGE="$(find "$EXPORT_DIR" -name '*.dmg' -print -quit)"
if [[ -z "$IMAGE" ]]; then
    echo "No ${RUNTIME} ${OS_VERSION} runtime image found in the export" >&2
    exit 1
fi
xcrun simctl runtime add "$IMAGE"
xcrun simctl list devices available "$RUNTIME $OS_VERSION"
