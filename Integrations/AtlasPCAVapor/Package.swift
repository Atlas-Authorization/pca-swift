// swift-tools-version:6.0
import PackageDescription

// The Vapor integration of Atlas PCA: an `AsyncMiddleware` over the framework-free `PcaGuard` of the core package. It is a separate
// package so the core stays dependency-free; it depends on the core by path.
let package = Package(
    name: "AtlasPCAVapor",
    platforms: [.macOS(.v12)],
    products: [
        .library(name: "AtlasPCAVapor", targets: ["AtlasPCAVapor"]),
    ],
    dependencies: [
        .package(name: "AtlasPCA", path: "../.."),
        .package(url: "https://github.com/vapor/vapor.git", from: "4.99.0"),
    ],
    targets: [
        .target(
            name: "AtlasPCAVapor",
            dependencies: [
                .product(name: "Vapor", package: "vapor"),
                .product(name: "AtlasPCAVerify", package: "AtlasPCA"),
            ],
            path: "Sources/AtlasPCAVapor"),
        .testTarget(
            name: "AtlasPCAVaporTests",
            dependencies: [
                "AtlasPCAVapor",
                .product(name: "XCTVapor", package: "vapor"),
                .product(name: "AtlasPCAVerify", package: "AtlasPCA"),
            ],
            path: "Tests/AtlasPCAVaporTests"),
    ],
    swiftLanguageModes: [.v5] // tools 6.0 is required for a package nested in its path dependency; the code stays Swift 5 mode
)
