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
//  * AtlasPCASQLite — durable stores on the system SQLite3 (no package dependency): the replay store with an atomic single-statement
//    claim, the operation-record store, and an atomic key/value store for the plan registry. Opt-in, a separate product.
//
// The Vapor and Hummingbird integrations are separate packages (Integrations/AtlasPCAVapor, Integrations/AtlasPCAHummingbird) that depend on this one
// by path, so this package stays dependency-free.
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
        .library(name: "AtlasPCASQLite", targets: ["AtlasPCASQLite"]),
    ],
    targets: [
        .target(name: "AtlasPCAStepUp", path: "Sources/AtlasPCAStepUp"),
        .testTarget(name: "AtlasPCAStepUpTests", dependencies: ["AtlasPCAStepUp"], path: "Tests/AtlasPCAStepUpTests"),
        .target(name: "AtlasPCAVerify", path: "Sources/AtlasPCAVerify"),
        .testTarget(name: "AtlasPCAVerifyTests", dependencies: ["AtlasPCAVerify"], path: "Tests/AtlasPCAVerifyTests"),
        .systemLibrary(name: "CSQLite3", path: "Sources/CSQLite3", pkgConfig: "sqlite3", providers: [.apt(["libsqlite3-dev"]), .brew(["sqlite"])]),
        .target(name: "AtlasPCASQLite", dependencies: ["AtlasPCAVerify", .target(name: "CSQLite3", condition: .when(platforms: [.linux]))], path: "Sources/AtlasPCASQLite"),
        .testTarget(name: "AtlasPCASQLiteTests", dependencies: ["AtlasPCASQLite", "AtlasPCAVerify"], path: "Tests/AtlasPCASQLiteTests"),
    ]
)
