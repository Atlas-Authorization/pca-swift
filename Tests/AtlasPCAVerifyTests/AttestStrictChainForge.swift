import XCTest
import Foundation
#if canImport(CryptoKit)
import CryptoKit
#else
import Crypto // Linux: swift-crypto (tools/pca-audit/swift-mutate/linux-prep.sh)
#endif
@testable import AtlasPCAVerify

/// Really-signed P-384 certificate chains for the strict chain profile tests (the shapes of packages/pca/src/x509-chain-unification.test.ts):
/// every chain is correctly signed, inside its validity window and anchorable, so a refusal can only come from the profile.
enum StrictChainForge {
    typealias Key = P384.Signing.PrivateKey
    typealias Ext = [UInt8]

    static let NOW: Int64 = 1_800_000_000_000 // inside 2025-01-01 .. 2035-01-01

    static func key(_ seed: UInt8) -> Key { try! Key(rawRepresentation: Data(repeating: seed, count: 48)) }

    static let rootKey = key(0x11), midKey = key(0x22), leafKey = key(0x33), externalKey = key(0x44), strangerKey = key(0x55)

    // ---- DER ----

    static func seq(_ c: [UInt8]) -> [UInt8] { DERB.tlv(0x30, c) }
    static func oid(_ c: [UInt8]) -> [UInt8] { DERB.tlv(0x06, c) }

    static let OID_BC: [UInt8] = [0x55, 0x1d, 0x13]
    static let OID_KU: [UInt8] = [0x55, 0x1d, 0x0f]
    static let OID_EKU: [UInt8] = [0x55, 0x1d, 0x25]
    static let OID_UNKNOWN: [UInt8] = [0x2a, 0x03, 0x04] // 1.2.3.4
    static let OID_SERVER_AUTH: [UInt8] = [0x2b, 0x06, 0x01, 0x05, 0x05, 0x07, 0x03, 0x01]
    static let OID_CN: [UInt8] = [0x55, 0x04, 0x03]
    static let OID_EC: [UInt8] = [0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01]
    static let OID_P384: [UInt8] = [0x2b, 0x81, 0x04, 0x00, 0x22]
    static let OID_ECDSA_SHA384: [UInt8] = [0x2a, 0x86, 0x48, 0xce, 0x3d, 0x04, 0x03, 0x03]

    static func ext(_ id: [UInt8], critical: Bool, _ value: [UInt8]) -> Ext {
        var body: [UInt8] = oid(id)
        if critical { body += [0x01, 0x01, 0xff] }
        body += DERB.tlv(0x04, value)
        return seq(body)
    }

    static func bc(_ ca: Bool, pathLen: UInt8? = nil) -> Ext {
        var body: [UInt8] = []
        if ca { body += [0x01, 0x01, 0xff] }
        if let p = pathLen { body += DERB.tlv(0x02, [p]) }
        return ext(OID_BC, critical: true, seq(body))
    }

    static func ku(_ bits: UInt8, unused: UInt8) -> Ext { ext(OID_KU, critical: true, DERB.tlv(0x03, [unused, bits])) }

    static let KU_CA = ku(0x06, unused: 1)      // keyCertSign, cRLSign
    static let KU_CERT_SIGN = ku(0x04, unused: 2)
    static let KU_SIGN = ku(0x80, unused: 7)    // digitalSignature
    static let CRITICAL_UNKNOWN = ext(OID_UNKNOWN, critical: true, seq([0x01, 0x01, 0xff]))
    static let CRITICAL_EKU = ext(OID_EKU, critical: true, seq(oid(OID_SERVER_AUTH)))
    static let CA: [Ext] = [bc(true), KU_CA]
    static let LEAF: [Ext] = [bc(false), KU_SIGN]

    static func name(_ cn: String) -> [UInt8] { seq(DERB.tlv(0x31, seq(oid(OID_CN) + DERB.tlv(0x0c, Array(cn.utf8))))) }

    static func spki(_ k: Key) -> [UInt8] {
        let bits: [UInt8] = [0x00] + Array(k.publicKey.x963Representation)
        return seq(seq(oid(OID_EC) + oid(OID_P384)) + DERB.tlv(0x03, bits))
    }

    static func pin(_ k: Key) -> String { ACrypto.hex(ACrypto.sha256(spki(k))) }

    static func cert(subject: String, issuer: String, subjectKey: Key, signer: Key, serial: UInt8, exts: [Ext]) -> [UInt8] {
        let alg = seq(oid(OID_ECDSA_SHA384))
        var body: [UInt8] = DERB.tlv(0xa0, DERB.tlv(0x02, [0x02]))
        body += DERB.tlv(0x02, [serial])
        body += alg
        body += name(issuer)
        body += seq(DERB.tlv(0x17, Array("250101000000Z".utf8)) + DERB.tlv(0x17, Array("350101000000Z".utf8)))
        body += name(subject)
        body += spki(subjectKey)
        if !exts.isEmpty { body += DERB.tlv(0xa3, seq(exts.flatMap { $0 })) }
        let tbs = seq(body)
        let signature = try! signer.signature(for: Data(tbs))
        let sig: [UInt8] = [0x00] + Array(signature.derRepresentation)
        return seq(tbs + alg + DERB.tlv(0x03, sig))
    }

    static func pem(_ der: [UInt8]) -> String { RIM.pemOfDerB64(Attest.base64StdEncode(der)) }

    /// A self-signed CA outside the presented chain.
    static func selfSigned(_ k: Key, _ cn: String, exts: [Ext] = CA) -> [UInt8] { cert(subject: cn, issuer: cn, subjectKey: k, signer: k, serial: 9, exts: exts) }

    // ---- chains ----

    struct Shape {
        var root: [Ext]? = nil
        var mid: [Ext]? = nil
        var leaf: [Ext]? = nil
    }

    struct Chain {
        var ders: [[UInt8]]
        var b64: [String]
        var x5c: [JSONValue]
        var pem: String
    }

    /// [leaf, mid, root]. `topSigner`: the top certificate is signed by that external key rather than self-signed. `leafSigner`: a broken first link.
    static func chain(_ s: Shape = Shape(), topSigner: Key? = nil, leafSigner: Key? = nil) -> Chain {
        let topIssuer = topSigner == nil ? "Strict Root" : "Strict External Root"
        let root = cert(subject: "Strict Root", issuer: topIssuer, subjectKey: rootKey, signer: topSigner ?? rootKey, serial: 1, exts: s.root ?? CA)
        let mid = cert(subject: "Strict Mid", issuer: "Strict Root", subjectKey: midKey, signer: rootKey, serial: 2, exts: s.mid ?? CA)
        let leaf = cert(subject: "Strict Leaf", issuer: "Strict Mid", subjectKey: leafKey, signer: leafSigner ?? midKey, serial: 3, exts: s.leaf ?? LEAF)
        let ders = [leaf, mid, root]
        let b64 = ders.map { Attest.base64StdEncode($0) }
        return Chain(ders: ders, b64: b64, x5c: b64.map { JSONValue.string($0) }, pem: ders.map { pem($0) }.joined(separator: "\n"))
    }

    /// Each row: correctly signed and anchored, but violating one profile rule. Reasons are the reference's, byte for byte.
    static let LEAF_CA_TRUE = "leaf certificate asserts BasicConstraints CA:TRUE (an end-entity must not be a CA)"
    static let bad: [(name: String, shape: Shape, reason: String)] = [
        ("leaf CA:TRUE", Shape(leaf: [bc(true), KU_SIGN]), LEAF_CA_TRUE),
        ("issuer CA:FALSE", Shape(mid: [bc(false), KU_CERT_SIGN]), "issuer certificate at depth 1 is not a CA (BasicConstraints CA:FALSE)"),
        ("issuer without BasicConstraints", Shape(mid: [KU_CERT_SIGN]), "issuer certificate at depth 1 has no BasicConstraints (not a CA)"),
        ("issuer keyUsage without keyCertSign", Shape(mid: [bc(true), KU_SIGN]), "issuer certificate at depth 1 keyUsage lacks keyCertSign"),
        ("pathLen exceeded", Shape(root: [bc(true, pathLen: 0), KU_CERT_SIGN]), "issuer certificate at depth 2 pathLenConstraint 0 is exceeded (1 intermediate(s) below)"),
        ("critical 1.2.3.4 on the leaf", Shape(leaf: LEAF + [CRITICAL_UNKNOWN]), "certificate at depth 0 has an unrecognised critical extension 1.2.3.4"),
        ("critical 1.2.3.4 on the intermediate", Shape(mid: CA + [CRITICAL_UNKNOWN]), "certificate at depth 1 has an unrecognised critical extension 1.2.3.4"),
    ]

    /// A token whose only meaningful content is its header x5c: the chain check runs before the JWS signature is looked at.
    static func es256Token(x5c: [String]) -> String {
        let list = x5c.map { "\"" + $0 + "\"" }.joined(separator: ",")
        let header = "{\"alg\":\"ES256\",\"x5c\":[" + list + "]}"
        return Base64URLStrict.encode(Array(header.utf8)) + "." + Base64URLStrict.encode(Array("{}".utf8)) + "." + Base64URLStrict.encode([0])
    }

    /// The vendor's accepted rows of the conformance corpus (real vendor chains among them) are still accepted, end to end.
    static func assertAcceptedRowsStillPass(_ vendor: String, idPrefix: String = "", file: StaticString = #filePath, line: UInt = #line) throws {
        let doc = try AttestVectorTests.loadVectors()
        let blobs = doc.get("blobs")?.asObject ?? [:]
        var n = 0
        for r in doc.get("attestation_vectors")?.asArray ?? [] {
            let id = r.get("id")?.asString ?? "?"
            guard r.get("vendor")?.asString == vendor, id.hasPrefix(idPrefix), r.get("expect")?.get("ok") == JSONValue.bool(true) else { continue }
            n += 1
            let got = AttestVectorTests.runRow(AttestVectorTests.hydrate(r, blobs))
            XCTAssertEqual(got.get("ok"), JSONValue.bool(true), "\(id): \(got.get("reason")?.asString ?? "?")", file: file, line: line)
        }
        XCTAssertGreaterThan(n, 0, "no accepted \(vendor) rows with prefix '\(idPrefix)'", file: file, line: line)
    }
}
