// swift-tools-version:6.2
import PackageDescription
import Foundation

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
//    It is also the agent side: PCAAgent.fromPrincipal mints a grant and signs one PCActn per action, and PCAIssue /
//    PCASigners sign the other artifacts (Ed25519, ML-DSA and their hybrids; SLH-DSA, FN-DSA and LESS are refused here unless an opt-in backend registers (SLH-DSA: AtlasPCAOpenSSL on libcrypto 3.5+); FN-DSA is the opt-in AtlasPCAFnDsa product below).
//
//  * AtlasPCAMpcNet (opt-in with AtlasPCAMpc, see the end of this file) — the TLS-mesh network driver of the MPC engines.
//
//  * AtlasPCASQLite — durable stores on the system SQLite3 (no package dependency): the replay store with an atomic single-statement
//    claim, the operation-record store, and an atomic key/value store for the plan registry. Opt-in, a separate product.
//
// The Vapor and Hummingbird integrations are separate packages (Integrations/AtlasPCAVapor, Integrations/AtlasPCAHummingbird) that depend on this one
// by path, so this package stays dependency-free.
//
// One third-party dependency on Apple platforms, for the ratchet group only (swift-sodium's Clibsodium: libsodium ristretto255); Linux builds libsodium from vendored sources (CSodium). Apart from that: Ed25519 is CryptoKit's Curve25519.Signing (equation) layered
// with a pure-Swift strict RFC 8032 check (S < L, small-/mixed-order rejection); SHA-256/512 are
// CryptoKit; the key store uses the Keychain. `swift build` needs no network.
// libsodium for the ratchet group, FROST, OPRF and MPC: the xcframework from swift-sodium on Apple platforms; on Linux the official release
// (1.0.20, SHA-256 pinned, checked by the ada workflow) is vendored as the CSodium C target and built from source, so Linux needs no libsodium package.
// Its build flags (-fwrapv, -fno-strict-aliasing, -fno-strict-overflow, -flax-vector-conversions, as the upstream build uses) are unsafeFlags, which
// SwiftPM only allows in a dependency from tools version 6.2 on.
#if os(Linux)
let sodium: Target.Dependency = "CSodium"
#else
let sodium: Target.Dependency = .product(name: "Clibsodium", package: "swift-sodium")
#endif

let package = Package(
    name: "AtlasPCA",
    platforms: [.iOS(.v16), .macOS(.v13)],
    products: [
        .library(name: "AtlasPCAStepUp", targets: ["AtlasPCAStepUp"]),
        .library(name: "AtlasPCAVerify", targets: ["AtlasPCAVerify"]),
        .library(name: "AtlasPCASQLite", targets: ["AtlasPCASQLite"]),
    ],
    dependencies: [],
    targets: [
        .target(name: "AtlasPCAStepUp", path: "Sources/AtlasPCAStepUp"),
        .testTarget(name: "AtlasPCAStepUpTests", dependencies: ["AtlasPCAStepUp"], path: "Tests/AtlasPCAStepUpTests"),
        .target(name: "AtlasPCAVerify", dependencies: [sodium, "CAda", "CYaml", "CMLDSA"], path: "Sources/AtlasPCAVerify"),
        // ML-DSA-65 / ML-DSA-87 (FIPS 204) from liboqs 0.14.0's pq-crystals reference code, vendored with its Keccak (see Sources/CMLDSA/NOTICE): the fallback backend where CryptoKit has no ML-DSA (macOS and iOS before 26, Linux), so every consumer verifies and signs with no setup
        .target(name: "CMLDSA", path: "Sources/CMLDSA", exclude: ["LICENSE-liboqs", "LICENSE-pqcrystals-dilithium", "NOTICE", "vendored.sha256", "keccak/KeccakP-1600-64.macros", "keccak/KeccakP-1600-unrolling.macros"],
                publicHeadersPath: "include", cSettings: [.headerSearchPath("glue"), .headerSearchPath("keccak")],
                linkerSettings: [.linkedFramework("Security", .when(platforms: [.macOS, .iOS, .tvOS, .watchOS, .visionOS, .macCatalyst])), .linkedLibrary("pthread", .when(platforms: [.linux]))]),
        // libyaml 0.2.5 (the C parser PyYAML, Ruby's Psych and PHP's ext-yaml use), vendored as released (SHA-256 checked by the ci workflow): the authoring-file loader reads its EVENT stream and decides meaning itself
        .target(name: "CYaml", path: "Sources/CYaml", exclude: ["LICENSE", "vendored.sha256"], publicHeadersPath: "include",
                cSettings: [.define("YAML_VERSION_MAJOR", to: "0"), .define("YAML_VERSION_MINOR", to: "2"), .define("YAML_VERSION_PATCH", to: "5"), .define("YAML_VERSION_STRING", to: "\"0.2.5\"")]),
        // Ada (UTS 46 host parser, the one Node uses), vendored as its pinned single-file release (SHA-256 checked by the ada workflow): the core verifier links it, so a non-ASCII host works with no setup
        .target(name: "CAda", path: "Sources/CAda", sources: ["ada.cpp", "ada_shim.cpp"], publicHeadersPath: "include"),
        .testTarget(name: "AtlasPCAVerifyTests", dependencies: ["AtlasPCAVerify", "CAda"], path: "Tests/AtlasPCAVerifyTests"),
        .systemLibrary(name: "CSQLite3", path: "Sources/CSQLite3", pkgConfig: "sqlite3", providers: [.apt(["libsqlite3-dev"]), .brew(["sqlite"])]),
        .target(name: "AtlasPCASQLite", dependencies: ["AtlasPCAVerify", .target(name: "CSQLite3", condition: .when(platforms: [.linux]))], path: "Sources/AtlasPCASQLite"),
        // the child process of the pca-state conformance run over the SQLite stores (the process checks start it)
        .executableTarget(name: "pca-state-worker", dependencies: ["AtlasPCASQLite", "AtlasPCAVerify"], path: "Sources/pca-state-worker"),
        .testTarget(name: "AtlasPCASQLiteTests", dependencies: ["AtlasPCASQLite", "AtlasPCAVerify", "pca-state-worker"], path: "Tests/AtlasPCASQLiteTests"),
    ]
)

// The sources are Swift 5 language mode (tools version 6.2 would default to 6).
package.swiftLanguageModes = [.v5]

#if os(Linux)
// CSodium: libsodium 1.0.20, upstream sources as released (src/libsodium: every .c/.h, no assembly, no SIMD feature macros, so the portable C paths run),
// plus the release's prebuilt include/sodium/version.h. The settings mirror upstream's own configure-free (zig) build. The module is named Clibsodium so
// the verifier's `import Clibsodium` is the same on every platform.
package.targets.append(.target(
    name: "CSodium", path: "Sources/CSodium", exclude: ["LICENSE"], publicHeadersPath: "include",
    cSettings: [
        .headerSearchPath("include/sodium"),
        .define("_GNU_SOURCE", to: "1"), .define("CONFIGURED", to: "1"), .define("SODIUM_STATIC", to: "1"), .define("NATIVE_LITTLE_ENDIAN", to: "1"),
        .define("HAVE_ATOMIC_OPS", to: "1"), .define("HAVE_C11_MEMORY_FENCES", to: "1"), .define("HAVE_GCC_MEMORY_FENCES", to: "1"), .define("HAVE_INLINE_ASM", to: "1"),
        .define("HAVE_INTTYPES_H", to: "1"), .define("HAVE_STDINT_H", to: "1"), .define("TLS", to: "_Thread_local"),
        .define("HAVE_CATCHABLE_ABRT", to: "1"), .define("HAVE_CATCHABLE_SEGV", to: "1"), .define("HAVE_CLOCK_GETTIME", to: "1"), .define("HAVE_GETPID", to: "1"),
        .define("HAVE_MADVISE", to: "1"), .define("HAVE_MLOCK", to: "1"), .define("HAVE_MMAP", to: "1"), .define("HAVE_MPROTECT", to: "1"), .define("HAVE_NANOSLEEP", to: "1"),
        .define("HAVE_POSIX_MEMALIGN", to: "1"), .define("HAVE_PTHREAD_PRIO_INHERIT", to: "1"), .define("HAVE_PTHREAD", to: "1"), .define("HAVE_RAISE", to: "1"),
        .define("HAVE_SYSCONF", to: "1"), .define("HAVE_SYS_MMAN_H", to: "1"), .define("HAVE_SYS_PARAM_H", to: "1"), .define("HAVE_SYS_RANDOM_H", to: "1"),
        .define("HAVE_WEAK_SYMBOLS", to: "1"),
        .unsafeFlags(["-fvisibility=hidden", "-fno-strict-aliasing", "-fno-strict-overflow", "-fwrapv", "-flax-vector-conversions"]),
    ],
    linkerSettings: [.linkedLibrary("pthread")]))
#else
package.dependencies.append(.package(url: "https://github.com/jedisct1/swift-sodium", exact: "0.11.0"))
#endif

// Native pieces that ship inside the package, so no product needs a manual native build:
//  * AtlasPCAPairing: blst (BLS12-381, pinned v0.3.16) is vendored as C sources in Sources/CBlst/blst, with our GT shim (pca_gt.c).
//  * AtlasPCAFhe: Microsoft SEAL 4.1.2 (with its own C export API) plus zlib and zstd (for SEAL's serialization) and the GSL headers are vendored as C/C++ sources in Sources/CSealC/vendor.
//  * AtlasPCALweOt, AtlasPCAFnDsa: Rust cores (a Rust crate cannot be a SwiftPM source target) ship as prebuilt static libraries per platform in
//    Sources/<target>/lib/<os>-<arch>/ (macos-arm64, macos-x86_64, linux-x86_64, linux-arm64), built on native runners by the native-libs workflow. A shared
//    library placed directly in Sources/<target>/lib (the older layout) still works when no static one is present.
// Tools (Sources/vendor-natives.sh, the vendor and native-libs workflows) fetch and verify the pinned inputs. A product is declared when its inputs are on disk.
let pkgDir = URL(fileURLWithPath: #filePath).deletingLastPathComponent().path
func present(_ rel: String) -> Bool { FileManager.default.fileExists(atPath: pkgDir + "/" + rel) }
#if os(macOS)
let nativeOS = "macos"
#else
let nativeOS = "linux"
#endif
#if arch(arm64)
let nativePlat = nativeOS + "-arm64"
#else
let nativePlat = nativeOS + "-x86_64"
#endif
/// Linker settings for a Rust core: the packaged static archive for this platform first, else a shared library in lib/ (older layout); nil when neither exists.
func rustCore(_ target: String, _ name: String) -> [LinkerSetting]? {
    let lib = pkgDir + "/Sources/\(target)/lib"
    if present("Sources/\(target)/lib/\(nativePlat)/lib\(name).a") {
        return [.unsafeFlags([lib + "/" + nativePlat + "/lib\(name).a"]), .linkedLibrary("m"),
                .linkedLibrary("dl", .when(platforms: [.linux])), .linkedLibrary("pthread", .when(platforms: [.linux])), .linkedLibrary("iconv", .when(platforms: [.macOS]))]
    }
    if ["so", "dylib"].contains(where: { present("Sources/\(target)/lib/lib\(name).\($0)") }) {
        return [.linkedLibrary(name), .unsafeFlags(["-L", lib, "-Xlinker", "-rpath", "-Xlinker", lib])]
    }
    return nil
}

// AtlasPCAPairing (separate product): aggsig, BBS and ABE on supranational blst (BLS12-381).
if present("Sources/CBlst/blst/src/server.c") {
    package.products.append(.library(name: "AtlasPCAPairing", targets: ["AtlasPCAPairing"]))
    package.targets += [
        .target(name: "CBlst", path: "Sources/CBlst", sources: ["pca_gt.c", "blst/src/server.c", "blst/build/assembly.S"],
                publicHeadersPath: "include", cSettings: [.define("__BLST_PORTABLE__")]),
        .target(name: "AtlasPCAPairing", dependencies: ["CBlst", "AtlasPCAVerify"], path: "Sources/AtlasPCAPairing"),
        .testTarget(name: "AtlasPCAPairingTests", dependencies: ["AtlasPCAPairing", "AtlasPCAVerify", "CBlst"], path: "Tests/AtlasPCAPairingTests"),
    ]
}

// AtlasPCAAda (kept for source compatibility): AtlasPCAVerify now links Ada itself (CAda above), so the WHATWG host parser's UTS 46 domain-to-ASCII is
// always registered; PCAAda.register() only re-installs it.
package.cxxLanguageStandard = .cxx20
package.products.append(.library(name: "AtlasPCAAda", targets: ["AtlasPCAAda"]))
package.targets.append(.target(name: "AtlasPCAAda", dependencies: ["AtlasPCAVerify", "CAda"], path: "Sources/AtlasPCAAda"))
// the verifier tests link it, so the opt-in shim they import is linked, not just visible
package.targets.first(where: { $0.name == "AtlasPCAVerifyTests" })?.dependencies.append("AtlasPCAAda")

// AtlasPCAVDF (separate product): the Wesolowski VDF and the PCA timelock on attaswift/BigInt, so AtlasPCAVerify stays light.
package.dependencies.append(.package(url: "https://github.com/attaswift/BigInt", exact: "5.5.1"))
package.products.append(.library(name: "AtlasPCAVDF", targets: ["AtlasPCAVDF"]))
package.targets += [
    .target(name: "AtlasPCAVDF", dependencies: ["AtlasPCAVerify", .product(name: "BigInt", package: "BigInt")], path: "Sources/AtlasPCAVDF"),
    .testTarget(name: "AtlasPCAVDFTests", dependencies: ["AtlasPCAVDF", "AtlasPCAVerify", .product(name: "BigInt", package: "BigInt")], path: "Tests/AtlasPCAVDFTests"),
]

// AtlasPCAFhe (separate product): the homomorphic risk gate (BFV) through Microsoft SEAL's own C export API, compiled from the vendored SEAL 4.1.2 sources
// (Sources/CSealC/vendor, laid out by vendor-natives.sh). zlib/zstd are compiled in because the TypeScript reference (node-seal) saves ciphertexts compressed
// and the native must load them; the C++ standard is the package's (c++20, SEAL needs 17).
if present("Sources/CSealC/vendor/seal/seal/c/evaluator.cpp") {
    // SEAL's blake2/fips202 export plain C names that libsodium and CLess export too: prefix them (headers and callers see the same macros).
    let sealNames = ["blake2b", "blake2b_init", "blake2b_init_key", "blake2b_init_param", "blake2b_update", "blake2b_final", "blake2xb", "blake2xb_init", "blake2xb_init_key",
                     "blake2xb_update", "blake2xb_final", "sha3_256", "sha3_384", "sha3_512", "shake128", "shake256", "shake128_absorb", "shake128_squeezeblocks",
                     "shake256_absorb", "shake256_squeezeblocks"]
    let sealC: [CSetting] = sealNames.map { .define($0, to: "seal_" + $0) }
    let sealCxx: [CXXSetting] = sealNames.map { .define($0, to: "seal_" + $0) }
    package.products.append(.library(name: "AtlasPCAFhe", targets: ["AtlasPCAFhe"]))
    package.targets += [
        .target(name: "CSealC", path: "Sources/CSealC", exclude: ["lib", "vendor/LICENSES"], sources: ["csealc.c", "vendor/seal", "vendor/zlib", "vendor/zstd"], publicHeadersPath: "include",
                cSettings: [.headerSearchPath("vendor/seal"), .headerSearchPath("vendor/zlib"), .headerSearchPath("vendor/zstd"), .define("ZSTD_DISABLE_ASM", to: "1"), .define("Z_HAVE_UNISTD_H", to: "1"), .define("fdopen", to: "fdopen")] + sealC,
                cxxSettings: [.headerSearchPath("vendor/seal"), .headerSearchPath("vendor/gsl"), .headerSearchPath("vendor/zlib"), .headerSearchPath("vendor/zstd"), .define("ZSTD_DISABLE_ASM", to: "1")] + sealCxx,
                linkerSettings: [.linkedLibrary("pthread", .when(platforms: [.linux]))]),
        .target(name: "AtlasPCAFhe", dependencies: ["CSealC", "AtlasPCAVerify"], path: "Sources/AtlasPCAFhe"),
        .testTarget(name: "AtlasPCAFheTests", dependencies: ["AtlasPCAFhe", "AtlasPCAVerify"], path: "Tests/AtlasPCAFheTests"),
    ]
}

// AtlasPCALweOt (separate product): the post-quantum endemic base OT (Masny-Rindal over Module-LWE). Its Kyber-768 K-PKE core is the audited pqc_kyber reference
// behind a small C library (liblweot), shipped as a prebuilt static library per platform (see above). The CLweOt target only carries the prototypes.
if let lweotLink = rustCore("CLweOt", "lweot") {
    package.products.append(.library(name: "AtlasPCALweOt", targets: ["AtlasPCALweOt"]))
    package.targets += [
        .target(name: "CLweOt", path: "Sources/CLweOt", exclude: ["lib"], publicHeadersPath: "include", linkerSettings: lweotLink),
        .target(name: "AtlasPCALweOt", dependencies: ["CLweOt"], path: "Sources/AtlasPCALweOt"),
        .testTarget(name: "AtlasPCALweOtTests", dependencies: ["AtlasPCALweOt"], path: "Tests/AtlasPCALweOtTests"),
    ]
}

// AtlasPCAFnDsa (separate product): FN-DSA (Falcon) suite registry, wire framing and the Ed25519 hybrid, plus the real primitive (Pornin's fn-dsa 0.4.0)
// behind a small C library (libfndsa), shipped as a prebuilt static library per platform (see above). The CFnDsa target only carries the prototypes.
if let fndsaLink = rustCore("CFnDsa", "fndsa") {
    package.products.append(.library(name: "AtlasPCAFnDsa", targets: ["AtlasPCAFnDsa"]))
    package.targets += [
        .target(name: "CFnDsa", path: "Sources/CFnDsa", exclude: ["lib"], publicHeadersPath: "include", linkerSettings: fndsaLink),
        .target(name: "AtlasPCAFnDsa", dependencies: ["AtlasPCAVerify", "CFnDsa"], path: "Sources/AtlasPCAFnDsa"),
        .testTarget(name: "AtlasPCAFnDsaTests", dependencies: ["AtlasPCAFnDsa", "AtlasPCAVerify"], path: "Tests/AtlasPCAFnDsaTests"),
    ]
}

// AtlasPCAZk (separate product, opt-in): Groth16 verification and proving for snarkjs / circom artifacts on BN254 and BLS12-381 (arkworks) behind a small C
// library (libpcazk), shipped as a prebuilt static library per platform like the two cores above. The CPcaZk target only carries the prototypes.
if let zkLink = rustCore("CPcaZk", "pcazk") {
    package.products.append(.library(name: "AtlasPCAZk", targets: ["AtlasPCAZk"]))
    package.targets += [
        // the static archive's randomness and time sources live in these two frameworks on Apple platforms
        .target(name: "CPcaZk", path: "Sources/CPcaZk", exclude: ["lib"], publicHeadersPath: "include",
                linkerSettings: zkLink + [.linkedFramework("Security", .when(platforms: [.macOS])), .linkedFramework("CoreFoundation", .when(platforms: [.macOS]))]),
        .target(name: "AtlasPCAZk", dependencies: ["CPcaZk", "AtlasPCAVerify"], path: "Sources/AtlasPCAZk"),
        .testTarget(name: "AtlasPCAZkTests", dependencies: ["AtlasPCAZk", "AtlasPCAVerify"], path: "Tests/AtlasPCAZkTests"),
    ]
    // the verifier tests link it too, so their zk corpus replay runs the pairing cases through the library instead of listing them
    package.targets.first(where: { $0.name == "AtlasPCAVerifyTests" })?.dependencies.append("AtlasPCAZk")
}

// The zk module's bundled files (the two committed Policy-VM verifying keys and the circuit version table, byte copies of the reference package's).
package.targets.first(where: { $0.name == "AtlasPCAVerify" })?.resources = [.copy("Resources/zk")]

// AtlasPCAOpenSSL (opt-in, separate product): the algorithms AtlasPCAVerify has no vetted implementation for, on OpenSSL libcrypto (RSA RS/PS signing; Ed448
// sign/verify; SLH-DSA through PCAOpenSSL.registerSlhDsa(), libcrypto 3.5+). They register through PCAExtraCrypto, so the verifier tests also link it and run those corpus cases instead of skipping them. Declared only
// when ATLAS_PCA_OPENSSL=1 or ATLAS_PCA_MPC=1; CLibcrypto (the libcrypto system library) is shared with the MPC product.
let wantOpenSSL = ProcessInfo.processInfo.environment["ATLAS_PCA_OPENSSL"] == "1"
if wantOpenSSL || ProcessInfo.processInfo.environment["ATLAS_PCA_MPC"] == "1" {
    package.targets.append(.systemLibrary(name: "CLibcrypto", path: "Sources/CLibcrypto", pkgConfig: "libcrypto", providers: [.apt(["libssl-dev"]), .brew(["openssl@3"])]))
}
if wantOpenSSL {
    package.products.append(.library(name: "AtlasPCAOpenSSL", targets: ["AtlasPCAOpenSSL"]))
    package.targets.append(.target(name: "AtlasPCAOpenSSL", dependencies: ["AtlasPCAVerify", "CLibcrypto"], path: "Sources/AtlasPCAOpenSSL"))
    package.targets.first(where: { $0.name == "AtlasPCAVerifyTests" })?.dependencies.append("AtlasPCAOpenSSL")
}

// The NIO packages (swift-nio + swift-nio-ssl) are pulled only by the two opt-in network products: AtlasPCAMpcNet (ATLAS_PCA_MPC=1) and AtlasPCADkgNet (ATLAS_PCA_DKGNET=1).
let wantMpc = ProcessInfo.processInfo.environment["ATLAS_PCA_MPC"] == "1"
let wantDkgNet = ProcessInfo.processInfo.environment["ATLAS_PCA_DKGNET"] == "1"
if wantMpc || wantDkgNet {
    package.dependencies += [
        .package(url: "https://github.com/apple/swift-nio", exact: "2.65.0"),
        .package(url: "https://github.com/apple/swift-nio-ssl", exact: "2.26.0"),
    ]
}

// AtlasPCADkgNet (opt-in, separate product): the reference mutual-TLS 1.3 channel of the FROST DKG (startTlsDkgNode) on swift-nio-ssl (BoringSSL, so the same stack on Apple
// platforms and Linux), pinned peer certificates by SHA-256 fingerprint. Needs no OpenSSL. Declared only when ATLAS_PCA_DKGNET=1.
if wantDkgNet {
    package.products.append(.library(name: "AtlasPCADkgNet", targets: ["AtlasPCADkgNet"]))
    package.targets += [
        .target(name: "AtlasPCADkgNet", dependencies: [
            "AtlasPCAVerify",
            .product(name: "NIOCore", package: "swift-nio"), .product(name: "NIOPosix", package: "swift-nio"), .product(name: "NIOTLS", package: "swift-nio"), .product(name: "NIOSSL", package: "swift-nio-ssl"),
        ], path: "Sources/AtlasPCADkgNet"),
        .testTarget(name: "AtlasPCADkgNetTests", dependencies: [
            "AtlasPCADkgNet", "AtlasPCAVerify",
            .product(name: "NIOCore", package: "swift-nio"), .product(name: "NIOPosix", package: "swift-nio"), .product(name: "NIOTLS", package: "swift-nio"), .product(name: "NIOSSL", package: "swift-nio-ssl"),
        ], path: "Tests/AtlasPCADkgNetTests"),
    ]
}

// AtlasPCAMpc (opt-in, separate product): secret-shared computation (SPDZ / MASCOT, base OTs and the OT extension). Its primitives (SHAKE256, AES-128-ECB, ML-KEM-768)
// are OpenSSL libcrypto's through CLibcrypto (never a hand-written cipher or permutation); AtlasPCAVerify does not link it. ML-KEM needs OpenSSL >= 3.5 at runtime.
// Declared only when ATLAS_PCA_MPC=1 (the mpc workflow sets it with libcrypto's pkg-config on the path), so every other product builds without OpenSSL.
if wantMpc {
    package.products.append(.library(name: "AtlasPCAMpc", targets: ["AtlasPCAMpc"]))
    package.targets += [
        .target(name: "AtlasPCAMpc", dependencies: ["AtlasPCAVerify", "CLibcrypto", sodium], path: "Sources/AtlasPCAMpc"),
        .testTarget(name: "AtlasPCAMpcTests", dependencies: ["AtlasPCAMpc", "AtlasPCAVerify"], path: "Tests/AtlasPCAMpcTests"),
    ]

    // AtlasPCAMpcNet (same opt-in): the networked runner of the MPC engines over mutual TLS 1.3 (swift-nio + swift-nio-ssl, certificate pinning by
    // SHA-256), the loopback launcher, the fault proxy, and the `pca-mpc-party` node executable. Only this opt-in block pulls the NIO packages.
    package.products += [
        .library(name: "AtlasPCAMpcNet", targets: ["AtlasPCAMpcNet"]),
        .executable(name: "pca-mpc-party", targets: ["pca-mpc-party"]),
    ]
    package.targets += [
        .target(name: "AtlasPCAMpcNet", dependencies: [
            "AtlasPCAMpc", "AtlasPCAVerify",
            .product(name: "NIOCore", package: "swift-nio"), .product(name: "NIOPosix", package: "swift-nio"), .product(name: "NIOTLS", package: "swift-nio"), .product(name: "NIOSSL", package: "swift-nio-ssl"),
        ], path: "Sources/AtlasPCAMpcNet"),
        .executableTarget(name: "pca-mpc-party", dependencies: ["AtlasPCAMpcNet"], path: "Sources/pca-mpc-party"),
        .testTarget(name: "AtlasPCAMpcNetTests", dependencies: [
            "AtlasPCAMpcNet", "AtlasPCAMpc", "AtlasPCAVerify",
            .product(name: "NIOCore", package: "swift-nio"), .product(name: "NIOPosix", package: "swift-nio"), .product(name: "NIOTLS", package: "swift-nio"), .product(name: "NIOSSL", package: "swift-nio-ssl"),
        ], path: "Tests/AtlasPCAMpcNetTests"),
    ]

    // Second opt-in, ATLAS_PCA_LWEOT=1 (needs liblweot in Sources/CLweOt/lib, so the AtlasPCALweOt product above exists; macOS/iOS only): the network driver then runs
    // the post-quantum "lwe" base OT in the ot-sender / ot-receiver roles. Without it that kind aborts locally and plain mpc builds do not need the library.
    if ProcessInfo.processInfo.environment["ATLAS_PCA_LWEOT"] == "1" {
        package.targets.first(where: { $0.name == "AtlasPCAMpcNet" })?.dependencies.append("AtlasPCALweOt")
        package.targets.first(where: { $0.name == "AtlasPCAMpcNetTests" })?.dependencies.append("AtlasPCALweOt")
    }
}

// AtlasPCAWasm (opt-in, separate product): the in-process core-module WebAssembly host on WasmKit (fuel-metered, memory-capped, no WASI; see
// Sources/AtlasPCAWasm). The subprocess hosts (component host and the core mode of the pinned reference binary) are in AtlasPCAVerify and need nothing.
// Declared only when ATLAS_PCA_WASMKIT=1: WasmKit 0.4.2 needs a Swift 6.3 toolchain and macOS 15 / iOS 18, so enabling it raises this package's platforms.
if ProcessInfo.processInfo.environment["ATLAS_PCA_WASMKIT"] == "1" {
    package.platforms = [.iOS(.v18), .macOS(.v15)]
    package.dependencies.append(.package(url: "https://github.com/swiftwasm/WasmKit", exact: "0.4.2"))
    package.products.append(.library(name: "AtlasPCAWasm", targets: ["AtlasPCAWasm"]))
    package.targets += [
        .target(name: "AtlasPCAWasm", dependencies: ["AtlasPCAVerify", .product(name: "WasmKit", package: "WasmKit"), .product(name: "WasmParser", package: "WasmKit")], path: "Sources/AtlasPCAWasm"),
        .testTarget(name: "AtlasPCAWasmTests", dependencies: ["AtlasPCAWasm", "AtlasPCAVerify"], path: "Tests/AtlasPCAWasmTests"),
    ]
}

// AtlasPCALess (separate product): the LESS (less-cat1) suites on the patched reference C. The C sources are checked in (Sources/CLess is a copy of the repository's
// LESS verifier, kept by Sources/CLess/sync.sh), so the product is always declared and needs nothing installed. The core's `PCALessHook` stays empty (the two LESS
// suites refused `unsupported_suite`) until `LessNative.registerCoreSuites()` is called.
package.products.append(.library(name: "AtlasPCALess", targets: ["AtlasPCALess"]))
package.targets += [
    .target(name: "CLess", path: "Sources/CLess", exclude: ["LICENSE", "sync.sh"], sources: ["atlas_less.c", "lib"], publicHeadersPath: "include",
            cSettings: [.headerSearchPath("ref"), .define("CATEGORY", to: "252"), .define("TARGET", to: "45"),
                        // LESS exports the SUPERCOP names crypto_sign*, which libsodium (CSodium) exports too: keep LESS's private
                        .define("crypto_sign", to: "less_crypto_sign"), .define("crypto_sign_open", to: "less_crypto_sign_open"), .define("crypto_sign_keypair", to: "less_crypto_sign_keypair"),
                        .unsafeFlags(["-O2"], .when(configuration: .debug))],
            linkerSettings: [.linkedLibrary("pthread", .when(platforms: [.linux]))]),
    .target(name: "AtlasPCALess", dependencies: ["AtlasPCAVerify", "CLess"], path: "Sources/AtlasPCALess"),
    .testTarget(name: "AtlasPCALessTests", dependencies: ["AtlasPCALess", "AtlasPCAVerify"], path: "Tests/AtlasPCALessTests"),
]
