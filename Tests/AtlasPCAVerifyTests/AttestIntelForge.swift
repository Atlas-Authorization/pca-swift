import XCTest
import Foundation
#if canImport(CryptoKit)
import CryptoKit
#else
import Crypto // Linux: swift-crypto
#endif
@testable import AtlasPCAVerify

/// A really-signed DCAP v4 TDX quote and PCS collateral under a throwaway P-256 root (pinned by the caller), in the wire formats of
/// packages/pca/src/attest-intel-tdx.ts and attest-intel-collateral.ts. The certificate shapes are StrictChainForge's, on P-256.
enum IntelForge {
    typealias Key = P256.Signing.PrivateKey

    static func key(_ seed: UInt8) -> Key { try! Key(rawRepresentation: Data(repeating: seed, count: 32)) }

    static let rootKey = key(0x21), caKey = key(0x22), leafKey = key(0x23), akKey = key(0x24)
    static let NOW = StrictChainForge.NOW
    static let T2025: Int64 = 1_735_689_600_000 // 2025-01-01T00:00:00Z
    static let T2035: Int64 = 2_051_222_400_000 // 2035-01-01T00:00:00Z

    static let OID_P256: [UInt8] = [0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07]
    static let OID_ECDSA_SHA256: [UInt8] = [0x2a, 0x86, 0x48, 0xce, 0x3d, 0x04, 0x03, 0x02]
    static let OID_SGX: [UInt8] = [0x2a, 0x86, 0x48, 0x86, 0xf8, 0x4d, 0x01, 0x0d, 0x01]
    static let FMSPC: [UInt8] = [1, 2, 3, 4, 5, 6]

    static func seq(_ c: [UInt8]) -> [UInt8] { StrictChainForge.seq(c) }
    static func oid(_ c: [UInt8]) -> [UInt8] { StrictChainForge.oid(c) }
    static func zeros(_ n: Int) -> [UInt8] { [UInt8](repeating: 0, count: n) }
    static func le16(_ v: Int) -> [UInt8] { [UInt8(v & 0xff), UInt8((v >> 8) & 0xff)] }
    static func le32(_ v: Int) -> [UInt8] { [UInt8(v & 0xff), UInt8((v >> 8) & 0xff), UInt8((v >> 16) & 0xff), UInt8((v >> 24) & 0xff)] }
    static func utc(_ s: String) -> [UInt8] { DERB.tlv(0x17, Array(s.utf8)) }

    /// One {OID, INTEGER} TCB component whose OID ends in `last`.
    static func component(_ last: UInt8, _ value: [UInt8]) -> [UInt8] {
        let body: [UInt8] = oid([0x2a, last]) + DERB.tlv(0x02, value)
        return seq(body)
    }

    static func fmspcField() -> [UInt8] { DcapVerifier.OID_SGX_FMSPC + DERB.tlv(0x04, FMSPC) }
    static func tcbField(_ components: [[UInt8]]) -> [UInt8] { DcapVerifier.OID_SGX_TCB + seq(components.flatMap { $0 }) }

    // ---- certificates ----

    static func spki(_ k: Key) -> [UInt8] {
        let bits: [UInt8] = [0x00] + Array(k.publicKey.x963Representation)
        let alg = seq(oid(StrictChainForge.OID_EC) + oid(OID_P256))
        return seq(alg + DERB.tlv(0x03, bits))
    }

    static let pin: String = ACrypto.hex(ACrypto.sha256(spki(rootKey)))

    static func cert(subject: String, issuer: String, subjectKey: Key, signer: Key, serial: UInt8, exts: [[UInt8]]) -> [UInt8] {
        let alg = seq(oid(OID_ECDSA_SHA256))
        var body: [UInt8] = DERB.tlv(0xa0, DERB.tlv(0x02, [0x02]))
        body += DERB.tlv(0x02, [serial])
        body += alg
        body += StrictChainForge.name(issuer)
        body += seq(utc("250101000000Z") + utc("350101000000Z"))
        body += StrictChainForge.name(subject)
        body += spki(subjectKey)
        body += DERB.tlv(0xa3, seq(exts.flatMap { $0 }))
        let tbs = seq(body)
        let signature = try! signer.signature(for: Data(tbs))
        let sig: [UInt8] = [0x00] + Array(signature.derRepresentation)
        return seq(tbs + alg + DERB.tlv(0x03, sig))
    }

    static let chainPem: String = {
        let sgx = seq(seq(tcbField([component(17, [0])])) + seq(fmspcField()))
        let leafExts: [[UInt8]] = StrictChainForge.LEAF + [StrictChainForge.ext(OID_SGX, critical: false, sgx)]
        let root = cert(subject: "Intel Forge Root", issuer: "Intel Forge Root", subjectKey: rootKey, signer: rootKey, serial: 1, exts: StrictChainForge.CA)
        let ca = cert(subject: "Intel Forge CA", issuer: "Intel Forge Root", subjectKey: caKey, signer: rootKey, serial: 2, exts: StrictChainForge.CA)
        let leaf = cert(subject: "Intel Forge Leaf", issuer: "Intel Forge CA", subjectKey: leafKey, signer: caKey, serial: 3, exts: leafExts)
        return [leaf, ca, root].map { StrictChainForge.pem($0) }.joined(separator: "\n")
    }()

    // ---- the quote ----

    /// `tdAttr0` is TD_ATTRIBUTES[0] (bit 0 is DEBUG), `seamAttr7` the last byte of SEAM_ATTRIBUTES. Both sit under the quote signature.
    static func quote(tdAttr0: UInt8 = 0, seamAttr7: UInt8 = 0) -> [UInt8] {
        var head = zeros(48)
        head[0] = 4
        head[2] = 2
        head[4] = 0x81
        var body = zeros(584)
        body[119] = seamAttr7
        body[120] = tdAttr0
        let signed: [UInt8] = head + body
        let sig = Array(try! akKey.signature(for: Data(signed)).rawRepresentation)
        let ak = Array(akKey.publicKey.rawRepresentation)
        var qe = zeros(384)
        qe.replaceSubrange(320..<352, with: ACrypto.sha256(ak))
        let qeSig = Array(try! leafKey.signature(for: Data(qe)).rawRepresentation)
        let pem = Array(chainPem.utf8)
        var qeData: [UInt8] = qe
        qeData += qeSig
        qeData += le16(0) // QE auth data: none
        qeData += le16(5)
        qeData += le32(pem.count)
        qeData += pem
        var sigData: [UInt8] = sig
        sigData += ak
        sigData += le16(6)
        sigData += le32(qeData.count)
        sigData += qeData
        return signed + le32(sigData.count) + sigData
    }

    // ---- CRLs ----

    static func crlAlg() -> [UInt8] { seq(oid(OID_ECDSA_SHA256)) }

    /// TBSCertList: no version, the signature algorithm, an issuer, thisUpdate 2025-01-01, then `tail`.
    static func crlTbs(_ tail: [UInt8]) -> [UInt8] {
        var body: [UInt8] = crlAlg()
        body += StrictChainForge.name("Intel Forge CRL")
        body += utc("250101000000Z")
        body += tail
        return seq(body)
    }

    static func crlWrap(_ tbs: [UInt8], _ sigField: [UInt8]) -> [UInt8] { seq(tbs + crlAlg() + sigField) }

    /// A CRL under `signer`, nextUpdate 2035-01-01.
    static func crl(_ signer: Key, tail: [UInt8] = IntelForge.utc("350101000000Z")) -> [UInt8] {
        let tbs = crlTbs(tail)
        let sig: [UInt8] = [0x00] + Array(try! signer.signature(for: Data(tbs)).derRepresentation)
        return crlWrap(tbs, DERB.tlv(0x03, sig))
    }

    // ---- collateral ----

    static func signedDoc(_ name: String, _ body: String) -> String {
        let sig = ACrypto.hex(Array(try! leafKey.signature(for: Data(body.utf8)).rawRepresentation))
        return [#"{""#, name, #"":"#, body, #","signature":""#, sig, #""}"#].joined()
    }

    static func jsonList(_ a: [String]) -> String { "[" + a.map { "\"" + $0 + "\"" }.joined(separator: ",") + "]" }

    /// Accepted as UpToDate by `IntelCollateral.verify`. An eval number of nil leaves the member out.
    static func collateral(tcbEval: String? = "17", qeEval: String? = "17", tcbAdv: [String] = [], qeAdv: [String] = []) -> IntelCollateral {
        let dates = #""issueDate":"2025-01-01T00:00:00Z","nextUpdate":"2035-01-01T00:00:00Z""#
        func evalField(_ v: String?) -> String {
            guard let n = v else { return "" }
            return #","tcbEvaluationDataNumber":"# + n
        }
        let comps = Array(repeating: #"{"svn":0}"#, count: 16).joined(separator: ",")
        let zero96 = String(repeating: "00", count: 48)
        let module = [#"{"mrsigner":""#, zero96, #"","attributes":"0000000000000000","attributesMask":"ffffffffffffffff"}"#].joined()
        let tcb = [
            #"{"id":"TDX","version":3,"fmspc":"010203040506","#, dates, evalField(tcbEval), #","tdxModule":"#, module,
            #","tcbLevels":[{"tcb":{"sgxtcbcomponents":["#, comps, #"],"tdxtcbcomponents":["#, comps,
            #"],"pcesvn":0},"tcbStatus":"UpToDate","advisoryIDs":"#, jsonList(tcbAdv), "}]}",
        ].joined()
        let qe = [
            #"{"id":"TD_QE","version":2,"#, dates, evalField(qeEval),
            #","miscselect":"00000000","miscselectMask":"ffffffff","attributes":""#, String(repeating: "00", count: 16),
            #"","attributesMask":""#, String(repeating: "ff", count: 16),
            #"","mrsigner":""#, String(repeating: "00", count: 32),
            #"","isvprodid":0,"tcbLevels":[{"tcb":{"isvsvn":0},"tcbStatus":"UpToDate","advisoryIDs":"#, jsonList(qeAdv), "}]}",
        ].joined()
        var c = IntelCollateral()
        c.tcbInfoJSON = signedDoc("tcbInfo", tcb)
        c.tcbInfoChain = chainPem
        c.qeIdentityJSON = signedDoc("enclaveIdentity", qe)
        c.qeIdentityChain = chainPem
        c.rootCrl = crl(rootKey)
        c.pckCrl = crl(caKey)
        return c
    }

    /// The AttestError message of `f`, nil when it does not throw.
    static func refusal<T>(_ f: () throws -> T) -> String? {
        do {
            _ = try f()
            return nil
        } catch {
            return (error as? AttestError)?.message ?? "not an AttestError"
        }
    }
}
