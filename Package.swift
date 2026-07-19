// swift-tools-version:5.9
import PackageDescription

/// Shared iOS foundation for TGI apps (ECP, ERP, Fides, Vitae, E2P IDE).
let package = Package(
    name: "TGIKit",
    platforms: [
        .iOS(.v17),
        .macOS(.v13),
    ],
    products: [
        .library(name: "TGIKit", targets: ["TGIKit"]),
    ],
    targets: [
        .target(
            name: "TGIKit",
            path: "Sources/TGIKit"
        ),
        .executableTarget(
            name: "TGIKitSmoke",
            dependencies: ["TGIKit"],
            path: "Sources/TGIKitSmoke"
        ),
    ]
)
