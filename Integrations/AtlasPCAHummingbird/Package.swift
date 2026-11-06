// swift-tools-version:6.0
import PackageDescription

// The Hummingbird 2 integration of Atlas PCA: a `RouterMiddleware` over the framework-free `PcaGuard` of the core package. It is a
// separate package so the core stays dependency-free; it depends on the core by path.
let package = Package(
    name: "AtlasPCAHummingbird",
    platforms: [.macOS(.v14), .iOS(.v17)],
    products: [
        .library(name: "AtlasPCAHummingbird", targets: ["AtlasPCAHummingbird"]),
    ],
    dependencies: [
        .package(name: "AtlasPCA", path: "../.."),
        .package(url: "https://github.com/hummingbird-project/hummingbird.git", from: "2.5.0"),
    ],
    targets: [
        .target(
            name: "AtlasPCAHummingbird",
            dependencies: [
                .product(name: "Hummingbird", package: "hummingbird"),
                .product(name: "AtlasPCAVerify", package: "AtlasPCA"),
            ],
            path: "Sources/AtlasPCAHummingbird"),
        .testTarget(
            name: "AtlasPCAHummingbirdTests",
            dependencies: [
                "AtlasPCAHummingbird",
                .product(name: "HummingbirdTesting", package: "hummingbird"),
                .product(name: "AtlasPCAVerify", package: "AtlasPCA"),
            ],
            path: "Tests/AtlasPCAHummingbirdTests"),
    ],
    swiftLanguageModes: [.v5] // tools 6.0 is required for a package nested in its path dependency; the code stays Swift 5 mode
)
