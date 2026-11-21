// swift-tools-version:6.0
import PackageDescription

// The OpenAI integration of Atlas PCA, typed against MacPaw/OpenAI: turns a chat completion `tool_call` into a PCActn (the core's `bridgeToolCall`), runs your
// handler with the proof attached and hands back the `tool` message for the next model turn. A separate package so the core stays dependency-free; it
// depends on the core by path.
let package = Package(
    name: "AtlasPCAOpenAI",
    platforms: [.macOS(.v13)],
    products: [
        .library(name: "AtlasPCAOpenAI", targets: ["AtlasPCAOpenAI"]),
    ],
    dependencies: [
        .package(name: "AtlasPCA", path: "../.."),
        .package(url: "https://github.com/MacPaw/OpenAI.git", from: "0.6.1"),
    ],
    targets: [
        .target(
            name: "AtlasPCAOpenAI",
            dependencies: [
                .product(name: "OpenAI", package: "OpenAI"),
                .product(name: "AtlasPCAVerify", package: "AtlasPCA"),
            ],
            path: "Sources/AtlasPCAOpenAI"),
        .testTarget(
            name: "AtlasPCAOpenAITests",
            dependencies: [
                "AtlasPCAOpenAI",
                .product(name: "OpenAI", package: "OpenAI"),
                .product(name: "AtlasPCAVerify", package: "AtlasPCA"),
            ],
            path: "Tests/AtlasPCAOpenAITests"),
    ],
    swiftLanguageModes: [.v5] // tools 6.0 is required for a package nested in its path dependency; the code stays Swift 5 mode
)
