// swift-tools-version:5.7
import PackageDescription

let package = Package(
    name: "TrustKit",
    platforms: [
        .iOS(.v15),
        .macOS(.v12),
        .tvOS(.v15),
        .watchOS(.v9)
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
            path: "TrustKit",   
            resources: [.process("PrivacyInfo.xcprivacy")],
            publicHeadersPath: "public",
            cSettings: [.define("NS_BLOCK_ASSERTIONS", to: "1", .when(configuration: .release))]
        ),
    ]
)
