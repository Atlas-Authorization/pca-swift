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
}

/// Verifies the hardware evidence of one vendor under a fixed configuration. Immutable after construction.
public final class VendorVerifier: HardwareAttestationVerifier {
    public let vendor: String
    private let impl: HardwareAttestationVerifier
    private let overrides: JObject?

    /// `identity_overrides`, if present in `config`, are merged over the measured identity of every successful verification.
    public init(vendor: String, config: JObject?) throws {
        let cfg = config ?? [:]
        do {
            switch vendor {
            case "amd-sev-snp": impl = try AmdVerifier(cfg)
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
