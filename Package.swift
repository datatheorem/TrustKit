// swift-tools-version:5.1
import PackageDescription

let package = Package(
    name: "TrustKit",
    platforms: [
        .iOS(.v12),
        .macOS(.v10_13),
        .tvOS(.v12),
        .watchOS(.v4)
    ],
    products: [
        .library(
            name: "TrustKit",
            targets: ["TrustKit"]
        ),
        .library(
            name: "TrustKitDynamic",
            type: .dynamic,
            targets: ["TrustKit"]
        ),
        .library(
            name: "TrustKitStatic",
            type: .static,
            targets: ["TrustKit"]
        ),
    ],
    dependencies: [
    ],
    targets: [
        .target(
            name: "TrustKit",
            dependencies: [],
            path: "TrustKit",            
            publicHeadersPath: "public",
            cSettings: [.define("NS_BLOCK_ASSERTIONS", to: "1", .when(configuration: .release))]
        ),
    ]
)
