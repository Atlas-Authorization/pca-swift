import XCTest
import Foundation
@testable import AtlasPCAVerify

/// Differential replay of TxnTokens against the reference (@atlasauth/pca-txn-tokens). An issued token is compared the way the
/// generator records it: {header, claims} with iat removed, exp replaced by ttl (= exp - iat), a generated jti / txn as `true`.
final class RefTxnTokensTests: XCTestCase {
    static func decode(_ token: String) -> JSONValue {
        let p = token.split(separator: ".").map(String.init)
        func seg(_ s: String) -> JSONValue { (try? StrictJSON.parse(String(decoding: Base64URLStrict.decode(s) ?? [], as: UTF8.self))) ?? .null }
        let header = seg(p[0])
        guard var c = seg(p[1]).asObject, let iat = IV.num(c["iat"]), let exp = IV.num(c["exp"]) else { return .null }
        c["iat"] = nil
        c["exp"] = nil
        let ttl = exp - iat
        c["ttl"] = ttl.rounded() == ttl ? .int(Int64(ttl)) : .double(ttl)
        return .object(["header": header, "claims": .object(c)])
    }

    func testTxnTokens() throws {
        try K042.requireCovers(["TxnTokens", "Jose", "JSInterop"])
        let d = Base.Diffs()
        try Base.each("ref-txn-tokens.json.gz", seeds: true) { c in
            let got: BaseGot
            switch c.fn {
            case "subActChain": got = Ref.v { try TxnTokens.subActChain(c.arg(0)) }
            case "actDepth": got = Ref.v { .int(Int64(try TxnTokens.actDepth(c.arg(0)))) }
            case "toRfc8693Act": got = Ref.v { try TxnTokens.toRfc8693Act(c.arg(0)) }
            case "toTransactionToken":
                let a = Ref.obj(c.arg(0))
                got = Ref.v {
                    let seed = a["seed"]?.asString.flatMap { Base64URLStrict.decode($0) } ?? []
                    guard case var .object(out) = Self.decode(try TxnTokens.toTransactionToken(a, seed: seed)), var cl = out["claims"]?.asObject else { return .null }
                    if cl["jti"] != nil { cl["jti"] = .bool(true) }
                    if cl["txn"] != nil && a["txn"] == nil { cl["txn"] = .bool(true) }
                    out["claims"] = .object(cl)
                    return .object(out)
                }
            case "fromTransactionToken":
                let w = Ref.obj(c.arg(2))
                var o = TxnTokens.VerifyOptions()
                o.profile = w["profile"]?.asString
                o.audience = w["audience"]?.asString
                o.clockToleranceSec = IV.num(w["clockToleranceSec"])
                o.nowMs = IV.num(w["nowMs"])
                if let seen = w["seen"]?.asArray { o.seenTxn = { id, _ in seen.contains(.string(id)) } }
                o.replayUnchecked = w["unchecked"] == .bool(true)
                let pk = c.arg(1)?.asString.flatMap { Base64URLStrict.decode($0) } ?? []
                got = Ref.v { try TxnTokens.fromTransactionToken(c.arg(0), verifyKey: pk, o) }
            default:
                d.skip("\(c.fn): not mapped"); return
            }
            d.add(c, Base.diff(c, got))
        }
        d.finish(100)
    }
}
