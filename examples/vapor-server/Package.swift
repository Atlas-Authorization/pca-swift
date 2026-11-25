// swift-tools-version:6.0
import PackageDescription

// A minimal Vapor resource server guarded by Atlas PCA. It builds against the library next to it by path; to use it on its own, replace
// the two path dependencies with the published package URL.
let package = Package(
    name: "VaporServer",
    platforms: [.macOS(.v13)],
    dependencies: [
        .package(name: "AtlasPCA", path: "../.."),
        .package(name: "AtlasPCAVapor", path: "../../Integrations/AtlasPCAVapor"),
        .package(url: "https://github.com/vapor/vapor.git", from: "4.99.0"),
        // swift-log 1.17 uses an attribute newer than the Swift 6.2 toolchain: stay on the 1.6 line
        .package(url: "https://github.com/apple/swift-log.git", .upToNextMinor(from: "1.6.0")),
    ],
    targets: [
        .target(
            name: "App",
            dependencies: [
                .product(name: "Vapor", package: "vapor"),
                .product(name: "AtlasPCAVerify", package: "AtlasPCA"),
                .product(name: "AtlasPCAVapor", package: "AtlasPCAVapor"),
            ],
            path: "Sources/App"),
        .executableTarget(name: "Run", dependencies: ["App", .product(name: "Vapor", package: "vapor")], path: "Sources/Run"),
        .testTarget(
            name: "AppTests",
            dependencies: [
                "App",
                .product(name: "XCTVapor", package: "vapor"),
                .product(name: "AtlasPCAVerify", package: "AtlasPCA"),
            ],
            path: "Tests/AppTests"),
    ],
    swiftLanguageModes: [.v5] // tools 6.0 is required for a package nested in its path dependency; the code stays Swift 5 mode
)
