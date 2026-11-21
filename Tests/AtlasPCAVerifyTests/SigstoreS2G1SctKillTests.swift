import XCTest
import Foundation
#if canImport(CryptoKit)
import CryptoKit
#else
import Crypto // Linux: swift-crypto (tools/pca-audit/swift-mutate/linux-prep.sh)
#endif
@testable import AtlasPCAVerify

/// Kill tests for Sigstore.verifySct (RFC 6962 3.2) on a synthetic precertificate, and for the CA validity-start boundary of the
/// certificate path (mutation sheet swift-k05 group 1).
final class S2G1SctKillTests: XCTestCase {
    private static let key = try! P256.Signing.PrivateKey(rawRepresentation: Data(repeating: 0x55, count: 32))
    private static let logId = [UInt8](repeating: 0xAB, count: 32)
    private static let sctOid: [UInt8] = [0x2b, 0x06, 0x01, 0x04, 0x01, 0xd6, 0x79, 0x02, 0x04, 0x02]
    private static let padOid: [UInt8] = [0x2b, 0x06, 0x01, 0x04, 0x01, 0xd6, 0x79, 0x02, 0x04, 0x09]
    private static let issuerSpki: [UInt8] = [1, 2, 3, 4, 5]

    private static func roots() -> SigstoreRoots {
        let k = try! Cert.keyOfSPKI(Array(key.publicKey.derRepresentation))
        let log = SigstoreRoots.Log(keyId: logId, key: k, start: 0, end: Int64.max, v2Name: nil)
        return SigstoreRoots(tlogs: [], ctlogs: [log], cas: [], tsas: [])
    }
    private static func issuer() -> AttCert {
        var c = AttCert()
        c.rawSPKI = issuerSpki
        return c
    }

    private static func ext(_ oid: [UInt8], _ value: [UInt8]) -> [UInt8] {
        Sigstore.enc(0x30, Sigstore.enc(0x06, oid) + Sigstore.enc(0x04, value))
    }
    /// A certificate whose extensions are the SCT list extension followed by `kept` (the bytes of the other extensions).
    private static func leaf(list: [UInt8], kept: [UInt8]) throws -> Sigstore.Parsed {
        let sct = ext(sctOid, Sigstore.enc(0x04, list))
        let exts = Sigstore.enc(0x30, sct + kept)
        let tbs = Sigstore.enc(0x30, Sigstore.enc(0xa3, exts))
        return try Sigstore.parseCert(Sigstore.enc(0x30, tbs))
    }
    /// The precertificate TBS the log signed: the certificate without its SCT extension.
    private static func precert(kept: [UInt8]) -> [UInt8] {
        Sigstore.enc(0x30, Sigstore.enc(0xa3, Sigstore.enc(0x30, kept)))
    }

    private static func u16(_ n: Int) -> [UInt8] { [UInt8((n >> 8) & 0xff), UInt8(n & 0xff)] }
    private static func be8(_ v: UInt64) -> [UInt8] { (0..<8).map { UInt8(truncatingIfNeeded: v >> (56 - 8 * UInt64($0))) } }

    private static func sct(ts: UInt64, ext: [UInt8], sig: [UInt8]) -> [UInt8] {
        var s: [UInt8] = [0]
        s += logId
        s += be8(ts)
        s += u16(ext.count)
        s += ext
        s += [4, 3]
        s += u16(sig.count)
        s += sig
        return s
    }
    private static func list(_ entries: [[UInt8]]) -> [UInt8] {
        var body: [UInt8] = []
        for e in entries { body += u16(e.count); body += e }
        return u16(body.count) + body
    }

    /// The bytes RFC 6962 3.2 has the log sign for a precertificate entry.
    private static func signedBytes(ts: UInt64, tbs: [UInt8], ext: [UInt8]) -> [UInt8] {
        var m: [UInt8] = [0, 0]
        m += be8(ts)
        m += [0, 1]
        m += ACrypto.sha256(issuerSpki)
        m += [UInt8((tbs.count >> 16) & 0xff), UInt8((tbs.count >> 8) & 0xff), UInt8(tbs.count & 0xff)]
        m += tbs
        m += [UInt8((ext.count >> 8) & 0xff), UInt8(ext.count & 0xff)]
        m += ext
        return m
    }

    func testSignedBytesCarryTheHighLengthOctets() throws {
        // lines 308, 343, 344: a 70 000-byte precertificate (24-bit length with a non-zero high octet) and a 300-byte SCT extension
        // (16-bit length with a non-zero high octet), in an SCT longer than 255 bytes (16-bit entry and list lengths)
        let kept = Self.ext(Self.padOid, [UInt8](repeating: 0x5a, count: 70_000))
        let tbs = Self.precert(kept: kept)
        XCTAssertGreaterThan(tbs.count, 65_536)
        let extBytes = [UInt8](repeating: 0x07, count: 300)
        let ts: UInt64 = 1_700_000_000_000
        let signed = Self.signedBytes(ts: ts, tbs: tbs, ext: extBytes)
        let sig = [UInt8](try Self.key.signature(for: Data(signed)).derRepresentation)
        let list = Self.list([Self.sct(ts: ts, ext: extBytes, sig: sig)])
        XCTAssertGreaterThan(list.count, 256)
        let leaf = try Self.leaf(list: list, kept: kept)
        XCTAssertNil(try Sigstore.verifySct(leaf, Self.issuer(), Self.roots()))
    }

    func testTruncatedEntries() throws {
        // line 323: an entry of 46 bytes with an unknown version is truncated, not skipped
        let s46: [UInt8] = [1] + [UInt8](repeating: 0, count: 45)
        let l46 = try Self.leaf(list: Self.list([s46]), kept: [])
        XCTAssertEqual(try Sigstore.verifySct(l46, Self.issuer(), Self.roots()), "SCT truncated")
        // line 330: 3 bytes after the extension (hash, signature algorithm, one length octet)
        var s47: [UInt8] = [0]
        s47 += Self.logId
        s47 += Self.be8(1_700_000_000_000)
        s47 += [0, 1, 0xEE, 4, 3, 0]
        XCTAssertEqual(s47.count, 47)
        let l47 = try Self.leaf(list: Self.list([s47]), kept: [])
        XCTAssertEqual(try Sigstore.verifySct(l47, Self.issuer(), Self.roots()), "SCT truncated")
        // control: an unknown version of 47 bytes is skipped, and nothing pinned signs
        var skipped = s47
        skipped[0] = 1
        let lSkip = try Self.leaf(list: Self.list([skipped]), kept: [])
        XCTAssertEqual(try Sigstore.verifySct(lSkip, Self.issuer(), Self.roots()), "no SCT from a pinned CT log")
    }
}

/// The certificate authority's `validFor.start` is inclusive: a signing time equal to it is inside (line 566).
final class S2G1CaStartKillTests: XCTestCase {
    func testCaValidFromEqualToTheSigningTimeIsAccepted() throws {
        let d = try ConformanceTests.load("sigstore-vectors.json")
        guard let c = (d.get("cases")?.asArray ?? []).first(where: { $0.get("name")?.asString == "intoto/set-only" }),
              let root = d.get("roots")?.get(c.get("roots")?.asString ?? "")?.asObject else { return XCTFail("the intoto/set-only vector is missing") }
        func withStart(_ start: String) -> JSONValue {
            var r = root
            let cas = (r["certificateAuthorities"]?.asArray ?? []).map { (ca: JSONValue) -> JSONValue in
                guard var o = ca.asObject else { return ca }
                o["validFor"] = .object(["start": .string(start)])
                return .object(o)
            }
            r["certificateAuthorities"] = .array(cas)
            return .object(r)
        }
        // the only verified time of this bundle is its Rekor v1 SET: 1675209600 s = 2023-02-01T00:00:00Z
        let atStart = try PCA.parseSigstoreTrustedRoot(withStart("2023-02-01T00:00:00Z"))
        let ok = PCA.verifySigstoreBundleCore(c.get("bundle") ?? .null, roots: atStart)
        XCTAssertTrue(ok.ok, "\(ok.code) \(ok.detail)")
        XCTAssertEqual(ok.core.get("signed_time"), .int(1_675_209_600))
        let after = try PCA.parseSigstoreTrustedRoot(withStart("2023-02-01T00:00:00.001Z"))
        let late = PCA.verifySigstoreBundleCore(c.get("bundle") ?? .null, roots: after)
        XCTAssertFalse(late.ok)
        XCTAssertEqual(late.code, "cert_chain")
    }
}
