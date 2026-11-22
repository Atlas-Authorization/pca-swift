import XCTest
import Foundation
import CryptoKit
@testable import AtlasPCAVerify

/// Shared helpers of the payments / AP2 / ACP replay tests: the corpora carry key material as a `{"$seed": label}` reference and the
/// key is derived here (a deterministic Ed25519 signer, so signatures compare byte for byte).
enum RefKeys {
    static func seed(_ label: String) -> [UInt8] { Array(SHA256.hash(data: Data("atlas-pca-conformance/\(label)".utf8))) }

    static func edKey(_ v: JSONValue?) throws -> PCAEdKey {
        guard let label = v?.get("$seed")?.asString else { throw JSError("no key in the case") }
        return try Ed25519Deterministic.key(seed: seed(label))
    }

    static func suite(_ v: JSONValue?) throws -> PCASuiteKey { PCASuiteKey.ed25519(try edKey(v)) }
}

/// Differential replay of PCAPayments against the reference (@atlasauth/pca-payments): mandates, the charge decision (the reference's
/// recorded decide() result fed back through the injected decider), the charge PCActn, spend rails, Shared Payment Token limits, the
/// Stripe Issuing adapter and agent network tokens.
final class RefPaymentsTests: XCTestCase {
    static let file = "ref-payments.json.gz"

    func testPayments() throws {
        try K042.requireCovers(["Payments", "JSInterop"])
        let d = Base.Diffs()
        try Base.each(Self.file) { c in
            let a0 = c.arg(0), a1 = c.arg(1), a2 = c.arg(2), a3 = c.arg(3)
            let n0 = a0 ?? .null, n1 = a1 ?? .null, n2 = a2 ?? .null, n3 = a3 ?? .null
            let got: BaseGot
            switch c.fn {
            case "isPlainId": got = .value(.bool(PCAPayments.isPlainId(a0)))
            case "isMinorUnits": got = .value(.bool(PCAPayments.isMinorUnits(a0)))
            case "mandatePredicates": got = Ref.v { try PCAPayments.mandatePredicates(n0) }
            case "mandateCaveats": got = Ref.v { try PCAPayments.mandateCaveats(n0) }
            case "mandateRiskPolicy": got = Ref.v { try PCAPayments.mandateRiskPolicy(n0, n1) }
            case "autoSpendBound": got = Ref.v { try PCAPayments.autoSpendBound(n0) }
            case "buildPaymentMandate":
                got = Ref.v { try PCAPayments.buildPaymentMandate(n0, principal: try RefKeys.suite(a0?.get("principalSecret"))) }
            case "chargeParams": got = Ref.v { try PCAPayments.chargeParams(n0, n1) }
            case "chargeActionContext": got = Ref.v { try PCAPayments.chargeActionContext(n0, n1) }
            case "chargePlanNode":
                guard let id = a2?.asString else { d.skip("chargePlanNode: non-string id"); return }
                got = Ref.v { try PCAPayments.chargePlanNode(n0, n1, id) }
            case "chargeDecideInput": got = Ref.v { try PCAPayments.chargeDecideInput(n0, n1, n2, n3) }
            case "authorizeCharge":
                got = Ref.v { try PCAPayments.authorizeCharge(n0, n1, n2, decide: { _ in n3 }) }
            case "chargeToPCActn":
                got = Ref.v { try PCAPayments.chargeToPCActn(n0, n1, n2, signer: try RefKeys.suite(a2?.get("signerSecret"))) }
            case "settleCharge": got = Ref.v { try PCAPayments.settleCharge(n0, n1) }
            case "applyHumanCosign": got = Ref.v { try PCAPayments.applyHumanCosign(n0, n1, a2) }
            case "sharedPaymentTokenLimits": got = Ref.v { try PCAPayments.sharedPaymentTokenLimits(n0, n1) }
            case "railLimits": got = Ref.v { try PCAPayments.railLimits(n0, n1, a2) }
            case "categoriesFromTraits": got = Ref.v { try PCAPayments.categoriesFromTraits(n0) }
            case "reconcileSettlement": got = Ref.v { try PCAPayments.reconcileSettlement(n0, n1) }
            case "verifyStripeSignature":
                guard let raw = a0?.asString, let now = IV.num(a3), a2 == nil || a2 == .null || a2?.asString != nil, a1 == nil || a1 == .null || a1?.asString != nil else {
                    d.skip("verifyStripeSignature: non-string / non-number argument"); return
                }
                let tol = IV.num(a4(c)) ?? PCAPayments.STRIPE_WEBHOOK_TOLERANCE_SEC
                got = .value(.bool(PCAPayments.verifyStripeSignature(raw, a1?.asString, a2?.asString, nowSec: now, toleranceSec: tol)))
            case "signStripePayload":
                guard let raw = a0?.asString, let secret = a1?.asString, let t = IV.num(a2) else { d.skip("signStripePayload: non-string / non-number argument"); return }
                got = .value(.string(PCAPayments.signStripePayload(raw, secret, t)))
            case "stripeCardParams": got = Ref.v { try PCAPayments.stripeCardParams(n0, n1, n2, a3) }
            case "stripeAuthorizationFromEvent": got = .value(PCAPayments.stripeAuthorizationFromEvent(n0) ?? .null)
            case "stripeIssuingWebhook":
                guard let raw = a0?.asString, let now = IV.num(a3), a2 == nil || a2 == .null || a2?.asString != nil, a1 == nil || a1 == .null || a1?.asString != nil else {
                    d.skip("stripeIssuingWebhook: non-string / non-number argument"); return
                }
                let approved = c.arg(4) ?? .null
                got = .value(PCAPayments.stripeIssuingWebhook(raw, signature: a1?.asString, secret: a2?.asString, nowSec: now,
                                                              authorize: { _ in .object(["approved": approved, "reasons": .array([])]) }))
            case "stripeSettlementFromTransaction": got = .value(PCAPayments.stripeSettlementFromTransaction(n0) ?? .null)
            case "looksLikePan":
                guard let s = a0?.asString else { d.skip("looksLikePan: non-string"); return }
                got = .value(.bool(PCAPayments.looksLikePan(s)))
            case "tokenRefError": got = .value(Base.opt(PCAPayments.tokenRefError(a0)))
            case "bindingMessage": got = Ref.v { Base.bytesValue(try PCAPayments.bindingMessage(n0)) }
            case "bindNetworkToken":
                got = Ref.v {
                    guard let pub = Base.bytes(a0?.get("holderPublic")) else { throw JSError("holderPublic is not bytes") }
                    return try PCAPayments.bindNetworkToken(n0, holder: try RefKeys.edKey(a0?.get("holderSecret")), holderPublic: pub)
                }
            case "verifyNetworkTokenBinding": got = .value(Base.opt(PCAPayments.verifyNetworkTokenBinding(n0, n1)))
            case "controlsFromLimits": got = Ref.v { try PCAPayments.controlsFromLimits(n0, n1) }
            case "settlementMetadata": got = Ref.v { try PCAPayments.settlementMetadata(n0, n1) }
            case "reconcileNetworkSettlement": got = Ref.v { try PCAPayments.reconcileNetworkSettlement(n0, n1) }
            case "chargeWithNetworkToken":
                got = Ref.v { try PCAPayments.chargeWithNetworkToken(n0, n1, n2, n3, signer: try RefKeys.suite(a3?.get("signerSecret"))) }
            default:
                d.skip("\(c.fn): not mapped"); return
            }
            d.add(c, Base.diff(c, got))
        }
        d.finish(2500)
    }

    private func a4(_ c: BaseCase) -> JSONValue? { c.arg(4) }

    // ---- behaviour the reference corpus does not generate ----

    static func mandate() throws -> (m: JSONValue, grant: JSONValue) {
        let principal = try RefKeys.suite(.object(["$seed": .string("pay-principal")]))
        let agent = try RefKeys.edKey(.object(["$seed": .string("pay-agent")]))
        let p: JSONValue = .object(["principalPublic": .string(principal.id ?? ""), "agentPublic": .string(agent.id), "merchants": .array([.string("openai")]), "categories": .array([.string("5734")]),
                                    "currency": .string("USD"), "perTransactionCap": .int(500), "autoApproveThreshold": .int(200), "cumulativeCap": .int(1000),
                                    "goal": .string("buy compute"), "goalSalt": .string("c2FsdC0wMDAx"), "now": .int(1_800_000_000_000)])
        let m = try PCAPayments.buildPaymentMandate(p, principal: principal)
        return (m, m.get("grant") ?? .null)
    }

    func testAtomicStoreFailsClosed() throws {
        let (m, grant) = try Self.mandate()
        let auto: JSONValue = .object(["admit": .bool(true), "releaseGuardianShare": .bool(true), "r": .double(0.1), "reasons": .array([]),
                                       "requiredThreshold": .object(["t": .int(1), "proof": .string("weak"), "optimisticAllowed": .bool(true)]),
                                       "budget": .object(["B": .int(950), "tau": .int(1_800_000_000_000), "asOf": .int(1_800_000_000_000)])])
        let charge: JSONValue = .object(["merchant": .string("openai"), "amount": .int(50), "category": .string("5734"), "now": .int(1_800_000_001_000)])
        // a malformed record is an error, never a decision
        let bad = PCAPayments.BudgetStore(get: { _ in .object(["budget": .object([:]), "version": .int(1)]) }, compareAndSet: { _, _, _ in true })
        XCTAssertThrowsError(try PCAPayments.authorizeChargeAtomic(m, charge, grant, store: bad, decide: { _ in auto }))
        // a store that keeps losing the race: a deny, with the conflict reason first
        let racing = PCAPayments.BudgetStore(get: { _ in nil }, compareAndSet: { _, _, _ in false })
        let d = try PCAPayments.authorizeChargeAtomic(m, charge, grant, store: racing, decide: { _ in auto })
        XCTAssertEqual(d.get("outcome"), .string("deny"))
        XCTAssertEqual(d.get("reasons")?.asArray?.first, .string("budget_store_conflict"))
        // a store that commits: the debit is the exact integer amount
        var committed: JSONValue?
        let ok = PCAPayments.BudgetStore(get: { _ in nil }, compareAndSet: { _, _, b in committed = b; return true })
        let a = try PCAPayments.authorizeChargeAtomic(m, charge, grant, store: ok, decide: { _ in auto })
        XCTAssertEqual(a.get("outcome"), .string("auto"))
        XCTAssertEqual(committed?.get("B"), .int(950))
        // a co-sign that cannot commit is an error, never dropped
        XCTAssertThrowsError(try PCAPayments.applyHumanCosignAtomic(m, grant, store: racing, now: .int(1_800_000_002_000)))
        // another grant is refused before any decision
        XCTAssertThrowsError(try PCAPayments.authorizeCharge(m, charge, .object(["id": .string("x")]), decide: { _ in auto }))
    }

    func testStripeSignatureFailsClosed() {
        let body = "{\"id\":\"evt_1\"}"
        let header = PCAPayments.signStripePayload(body, "whsec_test", 1_800_000_000)
        XCTAssertTrue(PCAPayments.verifyStripeSignature(body, header, "whsec_test", nowSec: 1_800_000_100))
        XCTAssertFalse(PCAPayments.verifyStripeSignature(body, header, "whsec_test", nowSec: 1_800_000_301))
        // a NaN clock must not skip the freshness check (the reference's `abs(NaN) > tolerance` is false)
        XCTAssertFalse(PCAPayments.verifyStripeSignature(body, header, "whsec_test", nowSec: .nan))
        XCTAssertFalse(PCAPayments.verifyStripeSignature(body, header, "", nowSec: 1_800_000_100))
        XCTAssertFalse(PCAPayments.verifyStripeSignature(body, header, "whsec_test", nowSec: 1_800_000_100, toleranceSec: 0))
    }
}
