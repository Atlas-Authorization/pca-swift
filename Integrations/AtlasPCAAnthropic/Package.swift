// swift-tools-version:6.0
import PackageDescription

// The Anthropic integration of Atlas PCA, typed against jamesrochabrun/SwiftAnthropic: turns a Claude `tool_use` block into a PCActn (the core's
// `bridgeToolCall`), runs your handler with the proof attached and hands back the `tool_result` for the next model turn. A separate package so the core stays dependency-free; it
// depends on the core by path.
let package = Package(
    name: "AtlasPCAAnthropic",
    platforms: [.macOS(.v13)],
    products: [
        .library(name: "AtlasPCAAnthropic", targets: ["AtlasPCAAnthropic"]),
    ],
    dependencies: [
        .package(name: "AtlasPCA", path: "../.."),
        .package(url: "https://github.com/jamesrochabrun/SwiftAnthropic.git", from: "2.2.2"),
        // swift-log 1.17 uses an attribute newer than the Swift 6.2 toolchain: stay on the 1.6 line
        .package(url: "https://github.com/apple/swift-log.git", .upToNextMinor(from: "1.6.0")),
    ],
    targets: [
        .target(
            name: "AtlasPCAAnthropic",
            dependencies: [
                .product(name: "SwiftAnthropic", package: "SwiftAnthropic"),
                .product(name: "AtlasPCAVerify", package: "AtlasPCA"),
            ],
            path: "Sources/AtlasPCAAnthropic"),
        .testTarget(
            name: "AtlasPCAAnthropicTests",
            dependencies: [
                "AtlasPCAAnthropic",
                .product(name: "SwiftAnthropic", package: "SwiftAnthropic"),
                .product(name: "AtlasPCAVerify", package: "AtlasPCA"),
            ],
            path: "Tests/AtlasPCAAnthropicTests"),
    ],
    swiftLanguageModes: [.v5] // tools 6.0 is required for a package nested in its path dependency; the code stays Swift 5 mode
)
