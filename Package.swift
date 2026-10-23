// swift-tools-version:6.0
import PackageDescription

let package = Package(
    name: "TrustKit",
    platforms: [
        .iOS(.v15),
        .macOS(.v12),
        .macCatalyst(.v15),
        .tvOS(.v15),
        .watchOS(.v9),
        .visionOS(.v1)
    ],
    products: [
        .library(
            name: "TrustKit",
            targets: ["TrustKit"]
        ),
    ],
    dependencies: [
    ],
    targets: [
        .target(
            name: "TrustKit",
            dependencies: ["TrustKitSwift"],
            path: "TrustKit",   
            exclude: ["Swift"],
            resources: [.process("PrivacyInfo.xcprivacy")],
            publicHeadersPath: "public",
            cSettings: [.define("NS_BLOCK_ASSERTIONS", to: "1", .when(configuration: .release))]
        ),
        .target(
            name: "TrustKitSwift",
            path: "TrustKit/Swift"
        ),
    ]
)
