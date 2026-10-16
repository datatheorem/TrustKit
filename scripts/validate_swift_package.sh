#!/usr/bin/env bash

. "$(dirname "$0")/lib.sh"

swift build

CONSUMER_DIR="$(mktemp -d)"
trap 'rm -rf "$CONSUMER_DIR"' EXIT

mkdir -p "${CONSUMER_DIR}/Sources/TrustKitConsumer" "${CONSUMER_DIR}/Sources/TrustKitObjCConsumer/include"
cat > "${CONSUMER_DIR}/Package.swift" <<EOF
// swift-tools-version:5.9
import PackageDescription

let package = Package(
    name: "TrustKitConsumer",
    products: [.library(name: "TrustKitConsumer", targets: ["TrustKitConsumer", "TrustKitObjCConsumer"])],
    dependencies: [.package(name: "TrustKit", path: "${PWD}")],
    targets: [
        .target(name: "TrustKitConsumer", dependencies: ["TrustKit"]),
        .target(name: "TrustKitObjCConsumer", dependencies: ["TrustKit"]),
    ]
)
EOF
cat > "${CONSUMER_DIR}/Sources/TrustKitConsumer/Consumer.swift" <<'EOF'
import TrustKit

public func makePinningValidator(configuration: [String: Any]) -> TSKPinningValidator {
    TrustKit(configuration: configuration).pinningValidator
}
EOF
cat > "${CONSUMER_DIR}/Sources/TrustKitObjCConsumer/Consumer.m" <<'EOF'
#import <TrustKit/TrustKit.h>

TSKPinningValidator *TSKMakePinningValidator(NSDictionary<TSKGlobalConfigurationKey, id> *configuration) {
    return [[TrustKit alloc] initWithConfiguration:configuration].pinningValidator;
}
EOF

cd "$CONSUMER_DIR"
for PLATFORM in iOS macOS tvOS watchOS; do
    xcodebuild_pretty build \
        -scheme TrustKitConsumer \
        -destination "generic/platform=${PLATFORM}" \
        -derivedDataPath "${CONSUMER_DIR}/DerivedData" \
        CODE_SIGNING_ALLOWED=NO \
        "$@"
done
