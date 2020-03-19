// swift-tools-version:5.1
import PackageDescription

let package = Package(
    name: "TrustKit",
    platforms: [
        .iOS(.v10),
        .macOS(.v10_12),
        .tvOS(.v10),
        .watchOS(.v3)
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
            dependencies: [],
            path: "TrustKit",            
            publicHeadersPath: "public"
        ),
    ]
)
