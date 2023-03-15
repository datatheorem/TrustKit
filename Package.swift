// swift-tools-version:5.3
import PackageDescription

let package = Package(
    name: "TrustKit",
    platforms: [
        .iOS(.v14),
        .macOS(.v11),
        .tvOS(.v14),
        .watchOS(.v7)
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
