// swift-tools-version:5.9
import PackageDescription

/// Shared iOS foundation for TGI apps (ECP, ERP, Fides, Vitae, E2P IDE).
/// Auth token helpers + Keychain — one place for session survival rules.
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
        .testTarget(
            name: "TGIKitTests",
            dependencies: ["TGIKit"],
            path: "Tests/TGIKitTests"
        ),
    ]
)
