#!/usr/bin/env bash

. "$(dirname "$0")/lib.sh"

PLATFORM="${1:?usage: $0 <ios-simulator|tvos-simulator|watchos-simulator|visionos-simulator>}"
configure_platform "$PLATFORM"

RUNTIME="${PLATFORM_NAME% Simulator}"
OS_VERSION="$(xcrun --sdk "$SIMULATOR_SDK" --show-sdk-version)"

simulator_available() {
    xcrun simctl list devices available | awk -v section="-- ${RUNTIME} ${OS_VERSION} --" -v device="    ${SIMULATOR} (" '
        $0 == section { in_section = 1; next }
        /^-- / { in_section = 0 }
        in_section && index($0, device) == 1 { found = 1 }
        END { exit !found }'
}

runtime_images() {
    xcrun simctl runtime list -j | jq -r --arg platform "com.apple.platform.${SIMULATOR_SDK}" --arg version "$OS_VERSION" \
        "to_entries[] | select(.value.platformIdentifier == \$platform and .value.version == \$version) | $1"
}

sudo --preserve-env=DEVELOPER_DIR xcodebuild -runFirstLaunch
xcrun simctl list > /dev/null

if simulator_available; then
    exit 0
fi

echo "${SIMULATOR} (${RUNTIME} ${OS_VERSION}) is not available; reinstalling the ${RUNTIME} ${OS_VERSION} runtime" >&2
runtime_images '"\(.key) \(.value.kind), \(.value.state), signature \(.value.signatureState)"' >&2

EXPORT_DIR="$(mktemp -d)"
trap 'rm -rf "$EXPORT_DIR"' EXIT
xcodebuild -downloadPlatform "$RUNTIME" -buildVersion "$OS_VERSION" -architectureVariant arm64 -exportPath "$EXPORT_DIR" || true
IMAGE="$(find "$EXPORT_DIR" -name '*.dmg' -print -quit)"
if [[ -z "$IMAGE" ]]; then
    echo "No ${RUNTIME} ${OS_VERSION} runtime image found in the export" >&2
    exit 1
fi

for IMAGE_ID in $(runtime_images .key); do
    xcrun simctl runtime delete "$IMAGE_ID"
done
xcrun simctl runtime add "$IMAGE"

if ! simulator_available; then
    xcrun simctl runtime list >&2
    xcrun simctl list devices "${RUNTIME} ${OS_VERSION}" >&2
    echo "${SIMULATOR} (${RUNTIME} ${OS_VERSION}) is still not available" >&2
    exit 1
fi
