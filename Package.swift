// swift-tools-version:5.9
import PackageDescription

// Two products ship from this package:
//
//  * AtlasPCAStepUp — the principal-device step-up module for PCA (Provable Capability
//    Authorization). A human uses it on their iPhone to approve (or deny) a high-risk
//    (t=3) agent action.
//
//  * AtlasPCAVerify — the NATIVE Swift verifier for the CORE PCActn checks (wire format v2):
//    strict canonical JSON, strict RFC 8032 Ed25519, capability-chain attenuation, Merkle
//    plan inclusion, threshold multi-signatures. Byte-matches `@atlasauth/pca` and the other
//    language verifiers (sdks/{rust,go,dotnet,...}-pca); see packages/pca/conformance.
//
// Zero third-party dependencies: Ed25519 is CryptoKit's Curve25519.Signing (equation) layered
// with a pure-Swift strict RFC 8032 check (S < L, small-/mixed-order rejection); SHA-256/512 are
// CryptoKit; the key store uses the Keychain. `swift build` needs no network.
let package = Package(
    name: "AtlasPCA",
    platforms: [.iOS(.v15), .macOS(.v12)],
    products: [
        .library(name: "AtlasPCAStepUp", targets: ["AtlasPCAStepUp"]),
        .library(name: "AtlasPCAVerify", targets: ["AtlasPCAVerify"]),
    ],
    targets: [
        .target(name: "AtlasPCAStepUp", path: "Sources/AtlasPCAStepUp"),
        .testTarget(name: "AtlasPCAStepUpTests", dependencies: ["AtlasPCAStepUp"], path: "Tests/AtlasPCAStepUpTests"),
        .target(name: "AtlasPCAVerify", path: "Sources/AtlasPCAVerify"),
        .testTarget(name: "AtlasPCAVerifyTests", dependencies: ["AtlasPCAVerify"], path: "Tests/AtlasPCAVerifyTests"),
    ]
)
