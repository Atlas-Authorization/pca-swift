import XCTest
import Foundation
@testable import AtlasPCAVerify

/// Differential test of Sigstore.swift against the TS reference (pca-attest-eat sigstore.ts): test-data/k05-sigstore.json.gz (7005
/// cases over a deterministic synthetic PKI, the published vectors, structural bundle mutations and blind DER mutations). Every trusted
/// root is a `parseTrustedRoot/<id>` case (compared on its summary); later cases name it as {"$root": id} and use the root Swift parsed
/// from the same JSON. `@suspect` cases (TS behaviour the generator flags as questionable) are reported, never failed.
final class K05SigstoreOracleTests: XCTestCase {
    static let file = "k05-sigstore.json.gz"
    static let covers = ["Sigstore", "Attest", "ProvenanceGate", "BigUInt", "IntentValues", "StrictJSON", "Canonical", "Ed25519Strict", "JSONValue"]

    static func summary(_ r: SigstoreRoots) -> JSONValue {
        func end(_ e: Int64) -> JSONValue { e == Int64.max ? .null : .int(e) }
        func lg(_ l: SigstoreRoots.Log) -> JSONValue {
            .object(["keyId": .string(Data(l.keyId).base64EncodedString()), "start": .int(l.start), "end": end(l.end), "v2": K05.opt(l.v2Name)])
        }
        func ca(_ c: SigstoreRoots.CA) -> JSONValue { .object(["chain": .int(Int64(c.chain.count)), "start": .int(c.start), "end": end(c.end)]) }
        return .object(["tlogs": .array(r.tlogs.map(lg)), "ctlogs": .array(r.ctlogs.map(lg)), "cas": .array(r.cas.map(ca)), "tsas": .array(r.tsas.map(ca))])
    }

    /// A refusal whose reference detail is "fail closed: <runtime message>" carries a Node / OpenSSL / JSON.parse internal text no native
    /// reproduces ("error:0480006C:PEM routines::no start line", "Unexpected token ..."): such a case is compared on ok and code only
    /// (as the .NET suite does); every other detail is the reference's own wording and compared exactly.
    static func refusal(_ d: K05.Diffs, _ c: K05Case, _ got: JSONValue) {
        guard case var .object(want) = c.out, want["detail"]?.asString?.hasPrefix("fail closed: ") == true, case var .object(g) = got else {
            d.add(c, K05.diff(c, .value(got))); return
        }
        want["detail"] = nil
        g["detail"] = nil
        let c2 = K05Case(fn: c.fn, name: c.name, args: c.args, out: .object(want), suspect: c.suspect, raw: c.raw)
        d.add(c2, K05.diff(c2, .value(.object(g))))
    }

    static func std(_ v: JSONValue?) -> [UInt8]? { v?.asString.flatMap { Data(base64Encoded: $0) }.map { Array($0) } }

    func testSigstore() throws {
        try K042.requireCovers(Self.covers)
        let d = K05.Diffs()
        var roots: [String: SigstoreRoots] = [:]
        func rootOf(_ v: JSONValue?) -> SigstoreRoots? { v?.get("$root")?.asString.flatMap { roots[$0] } }
        try K05.each(Self.file) { c in
            switch c.fn {
            case "parseTrustedRoot":
                let id = c.name.split(separator: "/", maxSplits: 1).last.map(String.init) ?? c.name
                let got = K05.run {
                    let r = try PCA.parseSigstoreTrustedRoot(c.arg(0) ?? .null)
                    roots[id] = r
                    return Self.summary(r)
                }
                d.add(c, K05.diff(c, got))
            case "verifySigstoreBundleCore":
                guard let r = rootOf(c.arg(1)) else { d.skip("bundle core: its root did not parse in Swift (see parseTrustedRoot)"); return }
                let v = PCA.verifySigstoreBundleCore(c.arg(0) ?? .null, roots: r)
                let got: JSONValue = v.ok ? .object(["ok": .bool(true), "core": v.core])
                    : .object(["ok": .bool(false), "code": .string(v.code), "detail": .string(v.detail)])
                Self.refusal(d, c, got)
            case "verifySigstoreBundle":
                guard let r = rootOf(c.arg(1)) else { d.skip("bundle: its root did not parse in Swift (see parseTrustedRoot)"); return }
                let v = PCA.verifySigstoreBundle(c.arg(0) ?? .null, roots: r)
                let got: JSONValue = v.ok ? .object(["ok": .bool(true), "facts": v.facts])
                    : .object(["ok": .bool(false), "code": .string(v.code), "detail": .string(v.detail)])
                Self.refusal(d, c, got)
            case "verifyRfc3161":
                guard let r = rootOf(c.arg(2)) else { d.skip("rfc3161: its root did not parse in Swift"); return }
                guard let tok = Self.std(c.arg(0)), let data = Self.std(c.arg(1)) else { d.skip("rfc3161: undecodable args"); return }
                d.add(c, K05.diff(c, K05.run { .int(try Sigstore.verifyRfc3161(tok, data, r.tsas)) }))
            case "dssePae":
                guard let t = c.arg(0)?.asString, let p = Self.std(c.arg(1)) else { d.skip("dssePae: untyped args"); return }
                d.add(c, K05.diff(c, .value(K05.bytesValue(Sigstore.pae(t, p)))))
            default:
                d.skip("\(c.fn): not mapped")
            }
        }
        d.finish(6500)   // 7005 cases, 468 of them carry a lone surrogate (skipped)
    }
}
