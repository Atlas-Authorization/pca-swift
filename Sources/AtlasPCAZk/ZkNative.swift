import Foundation
import CPcaZk

/// Groth16 verification and proving for snarkjs / circom artifacts on BN254 and BLS12-381, through libpcazk (arkworks behind a small C
/// library; the circom witness program runs on an interpreter). Inputs are UTF-8 JSON in the snarkjs encoding: decimal-string field elements,
/// G1 `[x, y, "1"]`, G2 `[[x0, x1], [y0, y1], ["1", "0"]]`. The library only answers the pairing question: the envelope, circuit and context
/// checks of a compliance proof belong to the caller. A usage error or a failing library call throws; it is never reported as "invalid".
public enum PCAZkNative {
    public enum Curve: Int32, Sendable {
        case bn254 = 0
        case bls12381 = 1
    }

    public struct ZkError: Error, CustomStringConvertible {
        /// The library's negative return code.
        public let code: Int32
        public let description: String
    }

    public struct Verdict: Equatable, Sendable {
        public let valid: Bool
        /// Why an invalid proof was refused (`ok` for a valid one): bad_json, bad_protocol, bad_curve, bad_encoding, not_in_subgroup, not_affine,
        /// bad_shape, signal_count, ic_short or pairing_failed, in the library's wording.
        public let reason: String
        public let reasonCode: Int32
    }

    /// The linked library's version.
    public static var version: String { String(cString: pca_zk_version()) }

    private static func with<R>(_ b: [UInt8], _ body: (UnsafePointer<UInt8>, Int) -> R) -> R {
        // a one-byte buffer stands in for empty input so the pointer is never nil
        if b.isEmpty { return [UInt8](repeating: 0, count: 1).withUnsafeBufferPointer { body($0.baseAddress!, 0) } }
        return b.withUnsafeBufferPointer { body($0.baseAddress!, b.count) }
    }

    /// Verifies a snarkjs Groth16 proof: `vkey` is the verification key object, `proof` the proof object, `signals` the array of public signals.
    /// The default accepts exactly what snarkjs' verifier accepts (the key's protocol and nPublic and the proof's protocol and curve tags are not
    /// read, IC entries beyond signals + 1 are ignored); `strict` also requires those to agree. Group, field and subgroup checks run in both.
    public static func verify(curve: Curve, vkey: [UInt8], proof: [UInt8], signals: [UInt8], strict: Bool = false) throws -> Verdict {
        var reason: Int32 = -1
        let rc = with(vkey) { vk, vkN in with(proof) { pr, prN in with(signals) { sg, sgN in
            pca_zk_verify(curve.rawValue, strict ? 0 : UInt32(PCA_ZK_FLAG_SNARKJS_COMPAT), vk, vkN, pr, prN, sg, sgN, &reason)
        } } }
        guard rc == PCA_ZK_VALID || rc == PCA_ZK_INVALID else { throw ZkError(code: rc, description: "zk verify: the library refused the call (\(rc))") }
        return Verdict(valid: rc == PCA_ZK_VALID, reason: String(cString: pca_zk_reason_text(reason)), reasonCode: reason)
    }

    /// Verifies a snarkjs Groth16 proof taking the curve from the verification key's own `curve` name, as snarkjs does (upper-cased, only ASCII letters and
    /// digits kept: `bn128`, `BN254`, `alt_bn128`, `bls12381`, `bls12-381` each name a curve; any other name, or none, is refused as `bad_curve`). Accepts
    /// exactly what snarkjs' verifier accepts; group, field and subgroup checks run.
    public static func verifyFromKey(vkey: [UInt8], proof: [UInt8], signals: [UInt8]) throws -> Verdict {
        var reason: Int32 = -1
        let rc = with(vkey) { vk, vkN in with(proof) { pr, prN in with(signals) { sg, sgN in
            pca_zk_verify(Int32(PCA_ZK_CURVE_FROM_KEY), UInt32(PCA_ZK_FLAG_SNARKJS_COMPAT), vk, vkN, pr, prN, sg, sgN, &reason)
        } } }
        guard rc == PCA_ZK_VALID || rc == PCA_ZK_INVALID else { throw ZkError(code: rc, description: "zk verify: the library refused the call (\(rc))") }
        return Verdict(valid: rc == PCA_ZK_VALID, reason: String(cString: pca_zk_reason_text(reason)), reasonCode: reason)
    }

    /// Runs the circom witness program `wasm` over the `input` JSON object, reads the snarkjs `zkey` and proves. Returns the UTF-8 JSON
    /// `{"proof": {...}, "publicSignals": [...]}`. `seed` (exactly 32 bytes) makes the blinding deterministic and is for tests only; production
    /// passes nil (operating-system randomness).
    public static func prove(curve: Curve, wasm: [UInt8], zkey: [UInt8], input: [UInt8], seed: [UInt8]? = nil) throws -> [UInt8] {
        if let s = seed, s.count != 32 { throw ZkError(code: -1, description: "zk prove: the seed must be 32 bytes") }
        var out: UnsafeMutablePointer<UInt8>?
        var outLen = 0
        let rc: Int32 = with(wasm) { w, wN in with(zkey) { z, zN in with(input) { i, iN -> Int32 in
            if let s = seed { return s.withUnsafeBufferPointer { pca_zk_prove(curve.rawValue, w, wN, z, zN, i, iN, $0.baseAddress, 32, &out, &outLen) } }
            return pca_zk_prove(curve.rawValue, w, wN, z, zN, i, iN, nil, 0, &out, &outLen)
        } } }
        var bytes: [UInt8] = []
        if let p = out {
            bytes = Array(UnsafeBufferPointer(start: p, count: outLen))
            pca_zk_free(p, outLen)
        }
        guard rc == PCA_ZK_OK else { throw ZkError(code: rc, description: bytes.isEmpty ? "zk prove failed (\(rc))" : String(decoding: bytes, as: UTF8.self)) }
        return bytes
    }
}
