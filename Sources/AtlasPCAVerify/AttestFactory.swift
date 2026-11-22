import Foundation

// verifier_from_config: build a vendor attestation verifier from the language-neutral configuration documented in the conformance
// vector file (`verifier_config_schema`), and the default-verifier seam of `PCA.verifyPassport` (`DefaultHardware`).

/// The constructor's refusal of a configuration (a missing allowlist, an absent trust anchor, a malformed pin: there is no accept-all).
public struct AttestationConfigError: Error, Equatable, CustomStringConvertible {
    public let message: String
    public var description: String { message }
}

/// The vendors `VendorVerifier` builds a verifier for.
public enum AttestationVendors {
    public static let all = ["amd-sev-snp", "intel-tdx-dcap", "azure-maa", "gcp-confidential-space", "nvidia-gpu-spdm"]

    /// The audit labels of each root's suite family and the constants the reference's vendor modules export.
    public static let AMD_SNP_SUITE = "amd-sev-snp-ecdsa-p384"
    public static let INTEL_DCAP_SUITE = "intel-tdx-dcap-ecdsa-p256"
    public static let AZURE_MAA_SUITE = "azure-maa-jwt"
    /// The JOSE `alg` values accepted for an MAA JWS and for a Confidential Space JWS.
    public static let AZURE_MAA_SUITES = ["ES256", "RS256"]
    public static let GCP_CS_SUITE = "gcp-confidential-space-jwt"
    public static let GCP_CS_SUITES = ["RS256", "ES256"]
    /// The canonical Google Confidential Space attestation issuer.
    public static let GCP_CS_DEFAULT_ISSUER = "https://confidentialcomputing.googleapis.com"
    /// SHA-256 (lowercase hex) of the SPKI of Intel's SGX root CA, the pin of a PCK chain.
    public static let INTEL_SGX_ROOT_CA_SPKI_SHA256 = "a0af031289f5d5d4132f9186068a7fc13628633ba235777472e29b6b6c67a49e"
    /// SHA-384 (lowercase hex) of the SPKI of each AMD family's ARK, from the AMD KDS cert chain.
    public static let AMD_ARK_SPKI_SHA384: [String: String] = [
        "milan": "1249f67f15cf229a4069195e1a9ce537d1765ef706a1f4a123c36be9518786515d25ecc007f366b564d2b3f31c48082e",
        "genoa": "32ab53a6ce5ec14926207396e5c475ae768a6a9831b7e860b5acf2e1c1dff222bc5a8bfc43eb5e06393189c1f246d880",
        "turin": "3475f08a9727f8ac9a1deaea5f2a2097aa59d64d05c2a678c229c873e6359d3a6926287a2a22cd5f88a385e333a2fcc5",
    ]
    /// The Intel TCB statuses a TDX collateral check accepts unless told otherwise.
    public static let DEFAULT_ACCEPTED_STATUSES = ["UpToDate", "SWHardeningNeeded"]

    /// A Confidential Space `hwmodel`'s isolation family (`sev-snp` or `tdx`), nil when unrecognised.
    public static func teeTypeOfHwModel(_ hwmodel: String) -> String? {
        let t = GcpVerifier.teeType(hwmodel)
        return t.isEmpty ? nil : t
    }

    /// The DER of the first certificate in a PEM text (the whitespace inside the block is ignored). Throws when the text holds none.
    public static func pemToDer(_ pem: String) throws -> [UInt8] {
        guard let a = pem.range(of: "-----BEGIN CERTIFICATE-----"), let b = pem.range(of: "-----END CERTIFICATE-----", range: a.upperBound..<pem.endIndex) else {
            throw AttestationConfigError(message: "pemToDer: no certificate found")
        }
        let body = pem[a.upperBound..<b.lowerBound].filter { !$0.isWhitespace }
        return Array(Data(base64Encoded: String(body), options: .ignoreUnknownCharacters) ?? Data())
    }
}

/// Verifies the hardware evidence of one vendor under a fixed configuration. Immutable after construction.
public final class VendorVerifier: HardwareAttestationVerifier {
    public let vendor: String
    private let impl: HardwareAttestationVerifier
    private let overrides: JObject?

    /// `identity_overrides`, if present in `config`, are merged over the measured identity of every successful verification.
    public convenience init(vendor: String, config: JObject?) throws {
        try self.init(vendor: vendor, config: config, testArkPin: nil)
    }

    /// The conformance harness only: the vector configurations carry `trustAnchorArkSpkiSha384` for chains rooted in a test ARK.
    static func forConformance(vendor: String, config: JObject?) throws -> VendorVerifier {
        try VendorVerifier(vendor: vendor, config: config, testArkPin: config?["trustAnchorArkSpkiSha384"]?.asString)
    }

    private init(vendor: String, config: JObject?, testArkPin: String?) throws {
        let cfg = config ?? [:]
        do {
            switch vendor {
            case "amd-sev-snp": impl = try AmdVerifier(cfg, testArkPin: testArkPin)
            case "intel-tdx-dcap": impl = try DcapVerifier(cfg)
            case "azure-maa": impl = try MaaVerifier(cfg)
            case "gcp-confidential-space": impl = try GcpVerifier(cfg)
            case "nvidia-gpu-spdm": impl = try NvidiaVerifier(cfg)
            default: throw AttestError("unknown attestation vendor \"\(vendor)\"")
            }
        } catch {
            throw AttestationConfigError(message: (error as? AttestError)?.message ?? "invalid configuration")
        }
        self.vendor = vendor
        overrides = cfg["identity_overrides"]?.asObject
    }

    /// Verifies the vendor evidence (nil: none supplied for this action) against the expected binding at the clock `nowMs` (epoch ms).
    public func verify(evidence: JSONValue?, expected: AttestationBinding?, nowMs: Int64) -> HardwareResult {
        var res = impl.verify(evidence: evidence, expected: expected, nowMs: nowMs)
        if res.ok, var m = res.measured, let ov = overrides, !ov.isEmpty {
            for (k, v) in ov { m[k] = v }
            res.measured = m
        }
        return res
    }
}
