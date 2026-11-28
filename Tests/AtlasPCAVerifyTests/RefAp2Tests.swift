import XCTest
import Foundation
import CryptoKit
@testable import AtlasPCAVerify

/// Differential replay of PCAAp2 against the reference (@atlasauth/pca-ap2): strict SD-JWT parsing and disclosure processing, ES256, RFC 7638
/// thumbprints, the mandate validators and minor units, open-mandate constraint evaluation, issuance / presentation / verification of delegation
/// chains and purchases, the redeem ledger, the PCA terms bridge, the settlement payloads and the PCA payment binding.
///
/// Keys are derived from labels (d = sha256("atlas-pca-conformance/ap2/<label>")); ECDSA signatures are randomized, so every token the
/// reference signed was verified at generation time, and a function that SIGNS is compared with each signature segment replaced by `SIG`.
final class RefAp2Tests: XCTestCase {
    static let file = "ref-ap2.json.gz"
    static let T0 = 1_800_000_000.0
    typealias A = PCAAp2

    // ---- label-derived keys ----

    static func d(_ label: String) -> [UInt8] { Array(SHA256.hash(data: Data("atlas-pca-conformance/ap2/\(label)".utf8))) }

    static func key(_ label: String) throws -> A.PrivateKey { try A.PrivateKey(rawRepresentation: Data(d(label))) }

    /// The private JWK of a label's key (what the reference fed to `ap2KeyPairFromPrivateJwk`).
    static func privJwk(_ label: String) throws -> JObject {
        var o = A.publicJwk(try key(label), kid: label)
        o["d"] = .string(Base64URLStrict.encode(d(label)))
        return o
    }

    static func pubJwk(_ label: String) throws -> JSONValue {
        var o = A.publicJwk(try key(label))
        o["kid"] = nil
        return .object(o)
    }

    static func counterSalt() -> () -> String {
        var n = 0
        return { n += 1; return Base64URLStrict.encode(Array("salt-\(String(format: "%012d", n))".utf8)) }
    }

    // ---- projections the reference's wrappers apply ----

    /// Every compact JWT's signature segment replaced by SIG.
    static func stripSig(_ t: String) -> String {
        A.splitS(t, "~").map { seg -> String in
            let p = A.splitS(seg, ".")
            let b64u: (String) -> Bool = { !$0.isEmpty && $0.utf8.allSatisfy { ($0 >= 0x30 && $0 <= 0x39) || ($0 >= 0x41 && $0 <= 0x5a) || ($0 >= 0x61 && $0 <= 0x7a) || $0 == 0x2d || $0 == 0x5f } }
            return p.count == 3 && p.allSatisfy(b64u) ? p[0] + "." + p[1] + ".SIG" : seg
        }.joined(separator: "~")
    }

    static func maskReason(_ s: String) -> String {
        guard let re = try? NSRegularExpression(pattern: "invalid JSON \\(.*\\)\\z", options: [.dotMatchesLineSeparators]) else { return s }
        let ns = s as NSString
        return re.stringByReplacingMatches(in: s, options: [], range: NSRange(location: 0, length: ns.length), withTemplate: "invalid JSON (*)")
    }

    static func resolver(_ m: JSONValue?) -> A.KeyResolver {
        { h in
            guard case let .object(mo)? = m, let kid = h[JKey("kid")]?.asString else { return nil }
            return mo[JKey(kid)]
        }
    }

    static func strs(_ a: [String]) -> JSONValue { .array(a.map { .string($0) }) }

    static func projChain(_ r: A.ChainOutcome) -> JSONValue {
        if !r.ok {
            var o: JObject = ["ok": .bool(false), "reason": .string(maskReason(r.reason))]
            if let v = r.violations { o["violations"] = strs(v) }
            return .object(o)
        }
        var o: JObject = ["ok": .bool(true), "hops": .array(r.hops.map { $0.json })]
        if let op = r.open { o["open"] = op; o["closed"] = r.closed ?? .null }
        if let j = r.checkoutJwt, !j.isEmpty { o["checkoutJwt"] = .string(j); o["checkout"] = r.checkout ?? .null }
        if let h = r.openHash, !h.isEmpty { o["openHash"] = .string(h) }
        return .object(o)
    }

    static func projPurchase(_ r: A.PurchaseOutcome) -> JSONValue {
        if r.ok, let co = r.checkout, let pay = r.payment { return .object(["ok": .bool(true), "checkout": projChain(co), "payment": projChain(pay)]) }
        return .object(["ok": .bool(false), "reason": .string(maskReason(r.reason))])
    }

    static func num(_ v: JSONValue?) -> Double? { IV.num(v) }

    static func chainOpts(_ c: JSONValue?) -> A.ChainOptions {
        A.ChainOptions(resolveIssuerKey: resolver(c?.get("issuerKeys")), expectedAudience: c?.get("expectedAudience"), expectedNonce: c?.get("expectedNonce"),
                       now: num(c?.get("now")), clockSkewSeconds: num(c?.get("clockSkewSeconds")))
    }

    static func purchaseOpts(_ c: JSONValue?) -> A.PurchaseOptions {
        func expect(_ v: JSONValue?) -> A.ChainExpect { A.ChainExpect(expectedAudience: v?.get("expectedAudience"), expectedNonce: v?.get("expectedNonce")) }
        var ctx = c?.get("context")
        if ctx == .null { ctx = nil }
        return A.PurchaseOptions(resolveIssuerKey: resolver(c?.get("issuerKeys")), resolveMerchantKey: resolver(c?.get("merchantKeys")), checkout: expect(c?.get("checkout")),
                                 payment: expect(c?.get("payment")), context: ctx, now: num(c?.get("now")), clockSkewSeconds: num(c?.get("clockSkewSeconds")))
    }

    final class SpecLedger: PCAAp2PurchaseLedger {
        var calls: [JSONValue] = []
        let spec: JSONValue
        init(_ spec: JSONValue) { self.spec = spec }
        func reserve(_ h: String, _ t: String, _ amount: JSONValue) throws -> JSONValue? {
            calls.append(.array([.string("reserve"), .string(h), .string(t), amount]))
            switch spec.get("mode")?.asString {
            case "throw"?: throw JSError("down")
            case "replayed"?: return .string("replayed")
            case "undefined"?: return nil
            default: return spec.get("ctx").flatMap { $0.isNull ? nil : $0 } ?? .object(["totalAmount": .int(0), "totalUses": .int(0)])
            }
        }
        func release(_ h: String, _ t: String) throws {
            calls.append(.array([.string("release"), .string(h), .string(t)]))
            if JS.truthy(spec.get("releaseThrows")) { throw JSError("release failed") }
        }
    }

    // ---- inputs the reference's wrappers build ----

    static func present(_ v: JSONValue?) -> JSONValue? { JS.present(v) }

    static func openInput(_ a: JSONValue) throws -> (input: JObject, issuer: A.MandateIssuer) {
        var issuer = A.MandateIssuer(privateKey: try key(a.get("issuerKey")?.asString ?? "issuer"))
        if let k = a.get("kid") { issuer.kid = k }
        if let x = a.get("x5c"), JS.truthy(x) { issuer.x5c = x }
        var i: JObject = [:]
        i["agentJwk"] = try present(a.get("agentJwk")) ?? pubJwk(a.get("agentKey")?.asString ?? "agent")
        if let v = a.get("iat") { i["iat"] = v }
        if let v = a.get("exp") { i["exp"] = v }
        for k in ["pca", "sdAlg"] { if let v = a.get(k), JS.truthy(v) { i[o: k] = v } }
        if let t = a.get("typ") { i["typ"] = t }
        return (i, issuer)
    }

    static func presentInput(_ a: JSONValue) -> JObject {
        var i: JObject = [:]
        for k in ["open", "aud", "nonce", "iat"] { if let v = a.get(k) { i[o: k] = v } }
        if let v = a.get("exp") { i["exp"] = v }
        for k in ["pca", "hashMode"] { if let v = a.get(k), JS.truthy(v) { i[o: k] = v } }
        return i
    }

    static func fromInput(_ x: JSONValue) throws -> (o: JObject, issuer: A.MandateIssuer) {
        let merch: JSONValue = .object(["id": .string("merchant_1"), "name": .string("Demo Merchant"), "website": .string("https://demo-merchant.example")])
        let merch2: JSONValue = .object(["id": .string("merchant_2"), "name": .string("Other Merchant")])
        var o: JObject = ["agentJwk": try pubJwk("agent"), "merchants": present(x.get("merchants")) ?? .array([merch, merch2]), "iat": present(x.get("iat")) ?? .int(Int64(T0))]
        if let e = x.get("exp") { o["exp"] = e }
        return (o, A.MandateIssuer(privateKey: try key("issuer"), kid: .string("issuer-1")))
    }

    // ---- token comparison: byte-identical, else equal once member order is set aside ----

    /// The token with every digest replaced by the disclosure it names, decoded (member order set aside): equal content, whatever the order
    /// of the members inside a signed document.
    static func normalized(_ t: String) -> String? {
        let segs = A.splitS(t, "~")
        func decode(_ s: String) -> JSONValue? {
            guard let b = Base64URLStrict.decode(s), let text = String(data: Data(b), encoding: .utf8) else { return nil }
            return try? StrictJSON.parseLenient(text)
        }
        let isJwt: (String) -> Bool = { A.splitS($0, ".").count == 3 }
        guard let first = segs.first(where: isJwt), let payload = decode(A.splitS(first, ".")[1]) else { return nil }
        let alg = payload.get("_sd_alg")?.asString ?? "sha-256"
        var byDigest: [String: JSONValue] = [:]
        for s in segs where !s.isEmpty && !isJwt(s) {
            guard let v = decode(s), let dg = try? A.sdDigest(.string(s), .string(alg)) else { return nil }
            byDigest[dg] = v
        }
        func resolve(_ v: JSONValue, _ depth: Int) -> JSONValue {
            if depth > 40 { return v }
            switch v {
            case let .string(s): if let d = byDigest[s] { return .object(["$disclosure": resolve(d, depth + 1)]) }; return v
            case let .array(a): return .array(a.map { resolve($0, depth + 1) })
            case let .object(o): return .object(o.mapValues { resolve($0, depth + 1) })
            default: return v
            }
        }
        var parts: [JSONValue] = []
        for s in segs {
            if s.isEmpty { parts.append(.string("")); continue }
            if isJwt(s) {
                let p = A.splitS(s, ".")
                guard let h = decode(p[0]), let pl = decode(p[1]) else { return nil }
                parts.append(.object(["h": h, "p": resolve(pl, 0)]))
            } else { parts.append(.null) } // a disclosure is part of the JWT that cites it
        }
        return Base.canon(.array(parts))
    }

    func addToken(_ c: BaseCase, _ token: @autoclosure () throws -> String, _ d: Base.Diffs) {
        let got = Ref.s { Self.stripSig(try token()) }
        guard let why = Base.diff(c, got) else { d.add(c, nil); return }
        if case let .value(.string(g)) = got, let want = c.out.asString, let a = Self.normalized(g), let b = Self.normalized(want), a == b {
            d.skip("token members in another order (a parsed JSON value keeps no insertion order); every disclosure and claim is identical")
            return
        }
        d.add(c, why)
    }

    // ---- the replay ----

    func testAp2() throws {
        try K042.requireCovers(["Ap2", "Ap2Chain", "Ap2Constraints", "Ap2Pca", "Payments", "JSInterop"])
        let d = Base.Diffs()
        let problems: [String: (JSONValue?) -> [String]] = [
            "openPaymentMandateProblems": A.openPaymentMandateProblems, "paymentMandateProblems": A.paymentMandateProblems,
            "openCheckoutMandateProblems": A.openCheckoutMandateProblems, "checkoutMandateProblems": A.checkoutMandateProblems,
        ]
        try Base.each(Self.file) { c in
            let a0 = c.arg(0), a1 = c.arg(1), a2 = c.arg(2)
            let n0 = a0 ?? .null
            let got: BaseGot
            switch c.fn {
            case "b64uEncode":
                guard let s = a0?.asString else { d.skip("b64uEncode: non-string"); return }
                got = .value(.string(A.b64uEncode(s)))
            case "b64uDecode": got = Ref.v { Base.bytesValue(try A.b64uDecode(a0, a1?.asString ?? "")) }
            case "parseJson": got = Ref.v { try A.parseJson(a0, a1?.asString ?? "") }
            case "isSdAlg": got = .value(.bool(A.isSdAlg(a0)))
            case "sdDigest": got = Ref.s { try A.sdDigest(a0, a1) }
            case "assertP256Jwk": got = Ref.v { .object(try A.assertP256Jwk(a0, a1?.asString ?? "")) }
            case "jwkThumbprint": got = Ref.s { try A.jwkThumbprint(a0) }
            case "ap2KeyPairFromPrivateJwk":
                got = Ref.v {
                    guard let label = a0?.asString else { throw JSError("label") }
                    var jwk = try Self.privJwk(label)
                    for (k, v) in a1?.asObject ?? [:] { jwk[k] = v }
                    return .object(try A.ap2KeyPairFromPrivateJwk(.object(jwk)).publicJwk)
                }
            case "parseSdJwtHop": got = Ref.v { try A.parseSdJwtHop(a0).json }
            case "hopSdJwt": got = Ref.s { A.hopSdJwt(try A.parseSdJwtHop(a0)) }
            case "sdHashOf": got = Ref.s { try A.sdHashOf(try A.parseSdJwtHop(a0), a1) }
            case "issuerJwtHashOf": got = Ref.s { try A.issuerJwtHashOf(try A.parseSdJwtHop(a0), a1) }
            case "processDisclosures":
                if a0?.asString != nil {
                    got = Ref.v { let h = try A.parseSdJwtHop(a0); return try A.processDisclosures(.object(h.payload), h.disclosures, h.sdAlg) }
                } else {
                    guard let ds = a1?.asArray, ds.allSatisfy({ $0.asString != nil }), let alg = a2?.asString else { d.skip("processDisclosures: non-string disclosure list or algorithm"); return }
                    got = Ref.v { try A.processDisclosures(n0, ds.compactMap { $0.asString }, alg) }
                }
            case "splitChain": got = Ref.v { Self.strs(try A.splitChain(a0)) }
            case "disclosureBuilder":
                got = Ref.v {
                    let b = A.disclosureBuilder(a0, salt: Self.counterSalt())
                    var results: [JSONValue] = []
                    for op in a1?.asArray ?? [] {
                        if op.get("kind")?.asString == "element" { results.append(try b.element(op.get("value"))) }
                        else { results.append(try b.property(op.get("name")?.asString ?? "", op.get("value"))) }
                    }
                    return .object(["results": .array(results), "disclosures": Self.strs(b.disclosures)])
                }
            case "parseJwt": got = Ref.v { try A.parseJwt(a0, a1?.asString ?? "").json }
            case "verifyJwtEs256": got = Ref.v { .bool(try A.verifyJwtEs256(try A.parseJwt(a0, "jwt"), a1)) }
            case "verifyHopSignature": got = Ref.v { .bool(try A.verifyHopSignature(try A.parseSdJwtHop(a0), a1)) }
            case "signSdJwt":
                guard let ds = a0?.get("disclosures")?.asArray, ds.allSatisfy({ $0.asString != nil }), let label = a0?.get("key")?.asString, let payload = a0?.get("payload") else {
                    d.skip("signSdJwt: unusable arguments"); return
                }
                addToken(c, try A.signSdJwt(header: a0?.get("header"), payload: payload, disclosures: ds.compactMap { $0.asString }, privateKey: try Self.key(label)), d)
                return
            case "signJwtEs256":
                guard let label = a0?.get("key")?.asString, let payload = a0?.get("payload") else { d.skip("signJwtEs256: unusable arguments"); return }
                addToken(c, try A.signJwtEs256(header: a0?.get("header"), payload: payload, privateKey: try Self.key(label)), d)
                return
            case "currencyExponent": got = Ref.v { .int(Int64(try A.currencyExponent(a0))) }
            case "toMinorUnits": got = Ref.v { try A.toMinorUnits(a0, a1) }
            case "fromMinorUnits": got = Ref.v { try A.fromMinorUnits(a0, a1) }
            case "openPaymentMandateProblems", "paymentMandateProblems", "openCheckoutMandateProblems", "checkoutMandateProblems":
                got = .value(Self.strs(problems[c.fn]!(a0)))
            case "assertValid":
                guard let kind = a0?.asString, let f = problems[kind] else { d.skip("assertValid: unknown kind"); return }
                got = Ref.v { try A.assertValid(a1, f, a2?.asString ?? "") ?? .null }
            case "constants":
                got = .value(.object(["VCT_CHECKOUT": .string(A.VCT_CHECKOUT), "VCT_CHECKOUT_OPEN": .string(A.VCT_CHECKOUT_OPEN), "VCT_PAYMENT": .string(A.VCT_PAYMENT),
                                      "VCT_PAYMENT_OPEN": .string(A.VCT_PAYMENT_OPEN), "PCA_CLAIM": .string(A.PCA_CLAIM), "FREQUENCIES": Self.strs(A.FREQUENCIES),
                                      "AP2_COMMIT": .string(A.AP2_COMMIT), "PCA_BINDING_VERSION": .int(Int64(A.PCA_BINDING_VERSION)),
                                      "TYP_TERMINAL": Self.strs(A.TYP_TERMINAL), "TYP_INTERMEDIATE": Self.strs(A.TYP_INTERMEDIATE)]))
            case "merchantMatches": got = Ref.v { .bool(try A.merchantMatches(a0, a1)) }
            case "checkPaymentConstraints": got = Ref.v { Self.strs(try A.checkPaymentConstraints(a0, a1, a2)) }
            case "projectCheckout": got = Ref.v { try A.projectCheckout(a0) }
            case "checkoutTotal": got = Ref.v { try A.checkoutTotal(a0) ?? .null }
            case "checkCheckoutConstraints": got = Ref.v { Self.strs(try A.checkCheckoutConstraints(a0, a1)) }
            case "verifyDelegationChain":
                got = .value(Self.projChain(A.verifyDelegationChain(a0?.asString ?? "", Self.chainOpts(a1))))
            case "verifyKbHop":
                got = Ref.v {
                    guard let op = c.arg(3), let now = Self.num(op.get("now")), let skew = Self.num(op.get("skew")), case let .object(pm)? = a2 else { throw JSError("unusable arguments") }
                    let v = try A.verifyKbHop(try A.parseSdJwtHop(a0), prev: (try A.parseSdJwtHop(a1), pm), terminal: op.get("terminal") == .bool(true),
                                              expectedAudience: op.get("expectedAudience"), expectedNonce: op.get("expectedNonce"), now: now, skew: skew, label: c.arg(4)?.asString ?? "")
                    return v.json
                }
            case "verifyCheckoutChain":
                got = .value(Self.projChain(A.verifyCheckoutChain(a0?.asString ?? "", Self.chainOpts(a1), resolveMerchantKey: Self.resolver(a1?.get("merchantKeys")))))
            case "verifyPaymentChain":
                got = .value(Self.projChain(A.verifyPaymentChain(a0?.asString ?? "", Self.chainOpts(a1), openCheckoutHash: a1?.get("openCheckoutHash"),
                                                                 context: a1?.get("context"), expectedTransactionId: a1?.get("expectedTransactionId"))))
            case "verifyPurchase":
                got = .value(Self.projPurchase(A.verifyPurchase(a0?.asString ?? "", a1?.asString ?? "", Self.purchaseOpts(a2))))
            case "redeemPurchase":
                let spec = c.arg(3) ?? .null
                let ledger: SpecLedger? = spec.asString == "none" ? nil : SpecLedger(spec)
                let r = A.redeemPurchase(a0?.asString ?? "", a1?.asString ?? "", Self.purchaseOpts(a2), ledger: ledger)
                got = .value(.object(["result": Self.projPurchase(r), "calls": .array(ledger?.calls ?? [])]))
            case "issueOpenPaymentMandate", "issueOpenCheckoutMandate":
                guard let a = a0 else { d.skip("\(c.fn): no input"); return }
                let (i0, issuer) = try Self.openInput(a)
                var i = i0
                if let cs = a.get("constraints") { i["constraints"] = cs }
                if c.fn == "issueOpenPaymentMandate" {
                    for (k, m) in [("payee", "payee"), ("paymentAmount", "paymentAmount"), ("paymentInstrument", "paymentInstrument"), ("pisp", "pisp")] { if let v = a.get(k), JS.truthy(v) { i[o: m] = v } }
                    if let e = a.get("executionDate") { i["executionDate"] = e }
                    addToken(c, try A.issueOpenPaymentMandate(.object(i), issuer: issuer, salt: Self.counterSalt()), d)
                } else {
                    addToken(c, try A.issueOpenCheckoutMandate(.object(i), issuer: issuer, salt: Self.counterSalt()), d)
                }
                return
            case "presentClosedPayment":
                guard let a = a0 else { d.skip("presentClosedPayment: no input"); return }
                var i = Self.presentInput(a)
                for (k, v) in [("transactionId", a.get("transactionId")), ("payee", a.get("payee")), ("paymentAmount", a.get("paymentAmount")), ("paymentInstrument", a.get("paymentInstrument"))] {
                    if let x = v { i[o: k] = x }
                }
                for k in ["pisp", "riskData"] { if let v = a.get(k), JS.truthy(v) { i[o: k] = v } }
                if let e = a.get("executionDate") { i["executionDate"] = e }
                addToken(c, try A.presentClosedPayment(.object(i), agentKey: try Self.key(a.get("agentKey")?.asString ?? "agent"), salt: Self.counterSalt()), d)
                return
            case "presentClosedCheckout":
                guard let a = a0 else { d.skip("presentClosedCheckout: no input"); return }
                var i = Self.presentInput(a)
                if let j = a.get("checkoutJwt") { i["checkoutJwt"] = j }
                addToken(c, try A.presentClosedCheckout(.object(i), agentKey: try Self.key(a.get("agentKey")?.asString ?? "agent"), salt: Self.counterSalt()), d)
                return
            case "ap2BudgetMax": got = Ref.v { try A.ap2BudgetMax(a0, a1) }
            case "ap2BudgetReads": got = Ref.v { try A.ap2BudgetReads(a0, a1) }
            case "riskRatio": got = .value(A.riskRatio(a0, a1))
            case "pcaBindingNonce": got = Ref.s { try A.pcaBindingNonce(a0) }
            case "paymentConstraintsFromTerms": got = Ref.v { .array(try A.paymentConstraintsFromTerms(a0, a1, a2)) }
            case "pcaOpenClaim": got = Ref.v { try A.pcaOpenClaim(a0) }
            case "openPaymentMandateFromPca":
                guard let x = a0 else { d.skip("\(c.fn): no input"); return }
                var (o, issuer) = try Self.fromInput(x)
                o["checkoutReference"] = Self.present(x.get("checkoutReference")) ?? .string("REF")
                addToken(c, try A.openPaymentMandateFromPca(x.get("mandate"), .object(o), issuer: issuer, salt: Self.counterSalt()), d)
                return
            case "openCheckoutMandateFromPca":
                guard let x = a0 else { d.skip("\(c.fn): no input"); return }
                var (o, issuer) = try Self.fromInput(x)
                let item: JSONValue = .object(["id": .string("line_1"), "acceptable_items": .array([.object(["id": .string("sku-1"), "title": .string("Widget")])]), "quantity": .int(2)])
                o["lineItems"] = Self.present(x.get("lineItems")) ?? .array([item])
                addToken(c, try A.openCheckoutMandateFromPca(x.get("mandate"), .object(o), issuer: issuer, salt: Self.counterSalt()), d)
                return
            case "toAtomicUnits": got = Ref.s { try A.toAtomicUnits(a0, a1) }
            case "x402Settlement": got = Ref.v { try A.x402Settlement(a0, a1) }
            case "stripeSptSettlement": got = Ref.v { try A.stripeSptSettlement(a0, a1) }
            case "buildPcaPaymentBinding":
                guard let a = a0, let seed = a.get("agentSeed")?.asString else { d.skip("buildPcaPaymentBinding: no seed"); return }
                got = Ref.v {
                    var i = a.asObject ?? [:]
                    i["agentSeed"] = nil
                    i["agentJwk"] = try Self.pubJwk("agent")
                    let signer = PCASuiteKey.ed25519(try Ed25519Deterministic.key(seed: RefKeys.seed(seed)))
                    let cosign = a.get("cosign")
                    i["cosign"] = nil
                    return try A.buildPcaPaymentBinding(.object(i), agentKey: signer, cosign: cosign.map { v in { _ in v } })
                }
            default:
                d.skip("\(c.fn): not mapped"); return
            }
            d.add(c, Base.diff(c, got))
        }
        d.finish(3000)
    }

    // ---- behaviour the reference corpus does not generate ----

    func testBindingNeedsTheServerHeldMandate() {
        let open: JSONValue = .object([:])
        let input = A.VerifyPcaBindingInput(open: open, closed: open, openHash: .string("h"), expectedPrincipal: "p", audience: "aud", mandate: nil)
        XCTAssertThrowsError(try A.verifyPcaBinding(input, decide: { _ in .null })) { e in XCTAssertEqual((e as? A.PcaBindingError)?.code, "mandate_required") }
        // a mandate that limits the charge count needs the verifier's own history
        let limited: JSONValue = .object(["terms": .object(["maxTransactionsPerPeriod": .int(3)]), "grant": .object([:])])
        let input2 = A.VerifyPcaBindingInput(open: open, closed: open, openHash: .string("h"), expectedPrincipal: "p", audience: "aud", mandate: limited)
        XCTAssertThrowsError(try A.verifyPcaBinding(input2, decide: { _ in .null })) { e in XCTAssertEqual((e as? A.PcaBindingError)?.code, "charge_history_required") }
    }

    func testRedeemWithoutALedgerDenies() {
        let o = A.PurchaseOptions(resolveIssuerKey: { _ in nil }, resolveMerchantKey: { _ in nil }, checkout: A.ChainExpect(expectedAudience: nil, expectedNonce: nil),
                                  payment: A.ChainExpect(expectedAudience: nil, expectedNonce: nil))
        let r = A.redeemPurchase("a", "b", o, ledger: nil)
        XCTAssertFalse(r.ok)
        XCTAssertEqual(r.reason, "ledger_required")
    }
}
