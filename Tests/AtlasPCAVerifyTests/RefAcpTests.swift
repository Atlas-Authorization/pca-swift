import XCTest
import Foundation
@testable import AtlasPCAVerify

/// Differential replay of PCAAcp against the reference (@atlasauth/pca-acp): ACP delegated payment tokens (mint, verify, the allowance),
/// the x402 v1 challenge and settle flow, x402 v2 (requirements, headers, negotiation), its HTTP transport and Stripe Shared Payment
/// Granted Tokens. Single-use stores, the verifier and the settle step are built from the specs the corpus names; the signing key is
/// derived here from its seed label (the corpus carries no private key material).
final class RefAcpTests: XCTestCase {
    static let files = ["ref-acp.json.gz", "ref-acp-java-extra.json.gz"]

    /// A `{"$seed": label}` private-key member `d` becomes the base64url of the seed the reference derived the test key from.
    static func unseed(_ v: JSONValue) -> JSONValue {
        switch v {
        case let .array(a): return .array(a.map { unseed($0) })
        case let .object(o):
            var out: JObject = [:]
            for (k, x) in o {
                if k.s == "d", let label = x.get("$seed")?.asString { out[k] = .string(Base64URLStrict.encode(RefKeys.seed(label))) } else { out[k] = unseed(x) }
            }
            return .object(out)
        default: return v
        }
    }

    final class Seen { var set = Set<String>() }

    /// The single-use store a spec names; any other value is passed through as is (and is not a store).
    static func store(_ spec: JSONValue?) -> PCAAcp.SingleUse {
        guard let s = spec else { return .absent }
        switch s.asString ?? "" {
        case "once":
            let seen = Seen()
            return .store(PCAAcp.SingleUseStore { jti, _ in .bool(seen.set.insert(jti).inserted) })
        case "always": return .store(PCAAcp.SingleUseStore { _, _ in .bool(true) })
        case "never": return .store(PCAAcp.SingleUseStore { _, _ in .bool(false) })
        case "throw": return .store(PCAAcp.SingleUseStore { _, _ in throw JSError("store down") })
        case "truthy": return .store(PCAAcp.SingleUseStore { _, _ in .int(1) })
        default: return .other
        }
    }

    /// The library message after these prefixes is not compared; pcaResult keeps only {allow}.
    static func norm(_ v: JSONValue) -> JSONValue {
        guard case var .object(o) = v else { return v }
        if let r = o["reason"]?.asString {
            for p in ["token signature did not verify", "bound proof failed to verify"] where r.hasPrefix(p + ":") { o["reason"] = .string(p) }
        }
        if let pr = o["pcaResult"], pr != .null { o["pcaResult"] = .object(["allow": pr.get("allow") ?? .null]) }
        return .object(o)
    }

    static func times(_ v: JSONValue?) -> Int { IV.num(v).map { Int($0) } ?? 1 }

    static func settle(_ c: BaseCase) -> BaseGot {
        let payload = c.arg(0)
        let vspec = c.arg(1) ?? .null
        let verify: PCAAcp.Verify = { _ in
            if vspec == .string("throw") { throw JSError("verify down") }
            return vspec
        }
        var step: PCAAcp.Settle? = nil
        switch c.arg(2)?.asString {
        case "echo"?:
            step = { p, claims in
                var o: JObject = [:]
                if let j = try PayJS.prop(claims, "jti") { o["jti"] = j }
                if let t = try PayJS.prop(p, "token") { o["token"] = t }
                return .object(o)
            }
        case "value"?: step = { _, _ in .string("receipt-1") }
        case "throw"?: step = { _, _ in throw JSError("settle down") }
        case "undef"?: step = { _, _ in nil }
        default: break
        }
        return Ref.v { try PCAAcp.x402Settle(payload, verify: verify, settle: step) }
    }

    static func replay(_ file: String, _ d: Base.Diffs) throws {
        try Base.each(file) { c in
            let a0 = c.arg(0), a1 = c.arg(1)
            let got: BaseGot
            switch c.fn {
            case "constants":
                got = .value(.object(["v": .int(1), "t": .string(PCAAcp.ACP_DELEGATED_TOKEN_TYPE), "s": .string(PCAAcp.SPEND_CAP_CAVEAT), "m": .string(PCAAcp.MERCHANT_ALLOW_CAVEAT),
                                      "c": .string(PCAAcp.MERCHANT_CATEGORY_CAVEAT), "h": .string(PCAAcp.HUMAN_PRESENT_CAVEAT), "x1": .int(Int64(PCAAcp.X402_VERSION_1)),
                                      "x2": .int(Int64(PCAAcp.X402_VERSION_2)), "sup": .array(PCAAcp.X402_SUPPORTED_VERSIONS.map { .int(Int64($0)) }),
                                      "pr": .string(PCAAcp.X402_V2_PAYMENT_REQUIRED_HEADER), "ps": .string(PCAAcp.X402_PAYMENT_SIGNATURE_HEADER),
                                      "pe": .string(PCAAcp.X402_PAYMENT_RESPONSE_HEADER),
                                      "st": .object(Dictionary(uniqueKeysWithValues: PCAAcp.X402_HTTP_STATUS.map { (JKey($0.key), JSONValue.int(Int64($0.value))) })),
                                      "spt": .string(PCAAcp.STRIPE_SPT_OBJECT)]))
            case "spendCapCaveat": got = .value(PCAAcp.spendCapCaveat(a0, a1))
            case "merchantAllowCaveat": got = Ref.v { try PCAAcp.merchantAllowCaveat(a0) }
            case "merchantCategoryCaveat": got = Ref.v { try PCAAcp.merchantCategoryCaveat(a0) }
            case "humanPresentCaveat": got = .value(PCAAcp.humanPresentCaveat(a0))
            case "extractPaymentAuthority": got = Ref.v { try PCAAcp.extractPaymentAuthority(a0) }
            case "checkPaymentAuthority": got = Ref.v { try PCAAcp.checkPaymentAuthority(a0, a1) }
            case "mintDelegatedPaymentToken":
                let opts = a1.map { unseed($0) }
                got = Ref.s { try PCAAcp.mintDelegatedPaymentToken(a0, opts) }
            case "verifyDelegatedPaymentToken":
                let opts = a1.map { unseed($0) }
                let n = times(c.arg(2)), st = store(a1?.get("singleUse"))
                got = Ref.v {
                    var rs: [JSONValue] = []
                    for _ in 0..<n { rs.append(norm(try PCAAcp.verifyDelegatedPaymentToken(a0, opts, singleUse: st))) }
                    return n == 1 ? rs[0] : .array(rs)
                }
            case "acpX402Verifier":
                let opts = a1.map { unseed($0) }
                let n = times(c.arg(2)), fn = PCAAcp.acpX402Verifier(opts, singleUse: store(a1?.get("singleUse")))
                got = Ref.v {
                    var rs: [JSONValue] = []
                    for _ in 0..<n { rs.append(norm(try fn(a0))) }
                    return n == 1 ? rs[0] : .array(rs)
                }
            case "x402Challenge": got = Ref.v { try PCAAcp.x402Challenge(a0, a1) }
            case "x402ChallengeV2": got = Ref.v { try PCAAcp.x402ChallengeV2(a0, a1) }
            case "x402Settle": got = settle(c)
            case "toAcpAllowance": got = Ref.v { try PCAAcp.toAcpAllowance(a0) }
            case "resourceInfoProblems": got = .value(.array(PCAAcp.resourceInfoProblems(a0).map { .string($0) }))
            case "requirementV2Problems": got = .value(.array(PCAAcp.requirementV2Problems(a0).map { .string($0) }))
            case "paymentRequiredV2Problems": got = .value(.array(PCAAcp.paymentRequiredV2Problems(a0).map { .string($0) }))
            case "paymentPayloadV2Problems": got = .value(.array(PCAAcp.paymentPayloadV2Problems(a0).map { .string($0) }))
            case "settlementResponseProblems": got = .value(.array(PCAAcp.settlementResponseProblems(a0).map { .string($0) }))
            case "stripeSptProblems": got = .value(.array(PCAAcp.stripeSptProblems(a0).map { .string($0) }))
            case "encodePaymentRequiredHeader": got = Ref.s { try PCAAcp.encodePaymentRequiredHeader(a0) }
            case "decodePaymentRequiredHeader": got = Ref.v { try PCAAcp.decodePaymentRequiredHeader(a0) }
            case "encodePaymentSignatureHeader": got = Ref.s { try PCAAcp.encodePaymentSignatureHeader(a0) }
            case "decodePaymentSignatureHeader": got = Ref.v { try PCAAcp.decodePaymentSignatureHeader(a0) }
            case "encodePaymentResponseHeader": got = Ref.s { try PCAAcp.encodePaymentResponseHeader(a0) }
            case "decodePaymentResponseHeader": got = Ref.v { try PCAAcp.decodePaymentResponseHeader(a0) }
            case "x402Negotiate":
                got = Ref.v { (try PCAAcp.x402Negotiate(a0, supported: a1)).map { JSONValue.int(Int64($0)) } ?? JSONValue.null }
            case "x402AcceptedMatches": got = Ref.v { .bool(try PCAAcp.x402AcceptedMatches(a0, a1)) }
            case "normalizeX402Payload": got = .value(PCAAcp.normalizeX402Payload(a0))
            case "readPaymentSignature": got = Ref.v { try PCAAcp.readPaymentSignature(a0) }
            case "x402SettlementResponse": got = Ref.v { try PCAAcp.x402SettlementResponse(a0, a1) }
            case "x402PaymentSignatureHeaders": got = Ref.v { try PCAAcp.x402PaymentSignatureHeaders(a0) }
            case "parseStripeSpt": got = Ref.v { try PCAAcp.parseStripeSpt(a0) }
            case "stripeSptUsable": got = Ref.v { try PCAAcp.stripeSptUsable(a0, a1) }
            case "stripeUsageLimitsFor": got = Ref.v { try PCAAcp.stripeUsageLimitsFor(a0) }
            case "stripeSptWithinClaims": got = Ref.v { try PCAAcp.stripeSptWithinClaims(a0, a1) }
            default:
                d.skip("\(c.fn): not mapped"); return
            }
            d.add(c, Base.diff(c, got))
        }
    }

    func testAcp() throws {
        try K042.requireCovers(["Acp", "JSInterop"])
        let d = Base.Diffs()
        try Self.replay(Self.files[0], d)
        d.finish(5000)
    }

    /// The Java lane's extra verify cases (a bound proof re-verified end to end).
    func testAcpBoundProof() throws {
        try K042.requireCovers(["Acp", "PCActn"])
        let d = Base.Diffs()
        try Self.replay(Self.files[1], d)
        d.finish(10)
    }

    /// The corpora carry the signing key as a seed label, never as key material.
    func testCorporaCarryNoPrivateKeys() throws {
        let re = try NSRegularExpression(pattern: "\"d\":\"[A-Za-z0-9_-]{43}\"")
        for f in Self.files {
            let text = String(decoding: try K042.bytes(f), as: UTF8.self)
            XCTAssertNil(re.firstMatch(in: text, range: NSRange(text.startIndex..., in: text)), "\(f) carries a private key member")
        }
    }

    func testStrictSettlementFailsClosed() throws {
        let key = try RefKeys.edKey(.object(["$seed": .string("acp/signer")]))
        let jwk: JSONValue = .object(["kty": .string("OKP"), "crv": .string("Ed25519"), "x": .string(Base64URLStrict.encode(key.pub))])
        // a token that is not a JWS is refused before any store is touched
        let opts: JSONValue = .object(["expectedMerchant": .string("m"), "amount": .int(1), "verifyKey": jwk, "expectedCurrency": .string("usd"), "now": .int(1)])
        let st = Self.store(.string("once"))
        let r = try PCAAcp.verifyDelegatedPaymentToken(.string("not-a-token"), opts, singleUse: st)
        XCTAssertEqual(r.get("ok"), .bool(false))
        // strict settlement without a store is refused
        let r2 = try PCAAcp.verifyDelegatedPaymentToken(.string("not-a-token"), opts)
        XCTAssertEqual(r2.get("reason"), .string("strict settlement requires a singleUse store (fail closed)"))
    }
}
