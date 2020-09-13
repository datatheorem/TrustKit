// swift-tools-version:5.1
import PackageDescription

let package = Package(
    name: "TrustKit",
    platforms: [
        .iOS(.v11),
        .macOS(.v10_13),
        .tvOS(.v11),
        .watchOS(.v4)
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
