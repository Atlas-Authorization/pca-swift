import XCTest
import Foundation
@testable import AtlasPCAVerify

/// Strict profile: -0 is never a wire integer (mirrors the TS -0 sweep). Each check: 0 is read as an integer, -0 is refused.
final class NegZeroStrictTests: XCTestCase {
    static let negZero = JSONValue.double(-0.0)

    /// `v` with the member at `path` (object keys; an all-digit key indexes an array) replaced by `x`.
    static func set(_ v: JSONValue, _ path: [String], _ x: JSONValue) -> JSONValue {
        guard let k = path.first else { return x }
        let rest = Array(path.dropFirst())
        if case var .array(a) = v, let i = Int(k), a.indices.contains(i) { a[i] = set(a[i], rest, x); return .array(a) }
        var o = v.asObject ?? [:]
        o[JKey(k)] = set(o[JKey(k)] ?? .null, rest, x)
        return .object(o)
    }

    func testToolSchemaBoundsConstEnumAndIntegerArgs() {
        XCTAssertEqual(ToolSchema.validateArgSchema(.object(["props": .object(["a": .object(["type": .string("string"), "maxLength": Self.negZero])])])), "a: bad maxLength")
        XCTAssertEqual(ToolSchema.validateArgSchema(.object(["props": .object(["a": .object(["type": .string("array"), "items": .object(["type": .string("string")]), "minItems": Self.negZero])])])), "a: bad minItems")
        XCTAssertEqual(ToolSchema.validateArgSchema(.object(["props": .object(["a": .object(["type": .string("integer"), "enum": .array([Self.negZero])])])])), "a: bad enum")
        XCTAssertNil(ToolSchema.validateArgSchema(.object(["props": .object(["a": .object(["type": .string("integer"), "enum": .array([.int(0)])])])])))
        XCTAssertEqual(ToolSchema.validateArgSchema(.object(["props": .object(["a": .object(["type": .string("integer"), "const": Self.negZero])])])), "a: bad const")
        let spec: JObject = ["type": .string("integer")]
        XCTAssertNil(ToolSchema.checkValue(spec, .int(0), "args.n", 1, ToolSchema.Counter()))
        XCTAssertEqual(ToolSchema.checkValue(spec, Self.negZero, "args.n", 1, ToolSchema.Counter()), "args.n: wrong type (expected integer)")
    }

    func testLedgerConsistencySizes() {
        let e = JSONValue.string(Ledger.EMPTY_TREE_ROOT)
        let proof: JSONValue = .object(["oldSize": .int(0), "newSize": .int(0), "path": .array([])])
        XCTAssertTrue(Ledger.verifyConsistency(e, e, proof))
        XCTAssertFalse(Ledger.verifyConsistency(e, e, Self.set(proof, ["oldSize"], Self.negZero)))
        XCTAssertFalse(Ledger.verifyConsistency(e, e, Self.set(proof, ["newSize"], Self.negZero)))
    }

    func testRevocationNonMembershipSizeAndEpochFields() throws {
        let root = try XCTUnwrap(IntentRevocation.bindRoot(.int(0), IntentRevocation.EMPTY_TREE))
        XCTAssertTrue(PCA.verifyNonMembership(root: root, proof: .object(["size": .int(0)]), id: "b"))
        XCTAssertFalse(PCA.verifyNonMembership(root: root, proof: .object(["size": Self.negZero]), id: "b"))
        let ep = try XCTUnwrap(PCA.signRevocationEpoch(guardianSeed: [UInt8](repeating: 11, count: 32),
                                                       RevocationEpochBody(instanceId: "i", grantRef: "g1", root: "r", issuedAt: 1000, notAfter: 2000)))
        let o = EpochCheckOptions(guardianPublic: try XCTUnwrap(ep.get("guardian")?.asString), now: 1500)
        XCTAssertTrue(PCA.checkRevocationEpoch(ep, o).ok)
        for k in ["epoch", "set_size"] { // signed as 0: the signature over 0 also covers -0, so only the shape check refuses it
            XCTAssertEqual(PCA.checkRevocationEpoch(Self.set(ep, [k], Self.negZero), o).reason, "malformed revocation epoch", k)
        }
    }

    func testPolicyClassesRevision() {
        let row: JSONValue = .object(["class": .string("org"), "revision": .int(0), "digest": .string("d"), "decision": .string("allow")])
        XCTAssertNil(PolicyClasses.classVerdictsError(.array([row])))
        XCTAssertEqual(PolicyClasses.classVerdictsError(.array([Self.set(row, ["revision"], Self.negZero)])), "policy_classes[0].revision must be a non-negative safe integer")
    }

    func testPcaGrantBundleRevision() {
        let ok: JSONValue = .object(["type": .string("pca_grant"), "chain_digest": .string("Da5N4WgHpgmhoJx4nG8vcGhp_4W59dJvpy-TLs7sRIA"), "chain_len": .int(1)])
        XCTAssertNil(PcaGrant.validate(Self.set(ok, ["bundle_revision"], .int(0))))
        XCTAssertEqual(PcaGrant.validate(Self.set(ok, ["bundle_revision"], Self.negZero)), "bad_bundle_revision")
    }

    func testObligationDueAndWindowEnd() {
        XCTAssertEqual(Obligations.obligationError(.object(["kind": .string("log"), "due": Self.negZero])), "due must be a non-negative safe integer")
        let uw: JSONValue = .object(["kind": .string("undo_window"), "params": .object(["id": .string("u"), "window_end": .int(0)])])
        XCTAssertNil(Obligations.obligationError(uw))
        XCTAssertEqual(Obligations.obligationError(Self.set(uw, ["params", "window_end"], Self.negZero)),
                       "undo_window needs id (a non-empty string of at most 128 characters) and window_end (a non-negative safe integer)")
    }

    func testFreshAtWireCounters() {
        var w: JObject = ["v": .int(1), "scope": .string("s"), "policy_digest": .string("d")]
        for k in ["revocation_epoch", "ledger_tree_size", "budget_version", "policy_revision", "issued_at"] { w[JKey(k)] = .int(0) }
        XCTAssertEqual(FreshAt.validateWire(Self.set(.object(w), ["revocation_epoch"], Self.negZero)), "'fresh_at.revocation_epoch' must be a non-negative safe integer")
        XCTAssertEqual(FreshAt.validateWire(Self.set(.object(w), ["issued_at"], Self.negZero)), "'fresh_at.issued_at' must be a non-negative safe integer")
        XCTAssertNotEqual(FreshAt.validateWire(.object(w)), "'fresh_at.revocation_epoch' must be a non-negative safe integer")
    }

    func testPolicyTemplateIntegerSlots() throws {
        let doc = try ConformanceTests.load("policy-link-vectors.json")
        let def = doc.get("template")?.get("def") ?? .null
        XCTAssertEqual(PCA.templateDefError(Self.set(def, ["slots", "cap", "min"], Self.negZero)), "slot 'cap'.min must be a safe integer")
        let slots: JSONValue = .object(["acct": .string("a42"), "cap": .int(200), "region": .string("eu"), "verbs": .array([.string("mail.send")])])
        XCTAssertNotNil(PCA.instantiateTemplate(def, slots).policy)
        XCTAssertEqual(PCA.instantiateTemplate(def, Self.set(slots, ["cap"], Self.negZero)).reason, "slot 'cap' must be a safe integer")
    }

    func testSettlementGuardianEpoch() throws {
        let doc = try ConformanceTests.load("optimistic-vectors.json")
        let v = try XCTUnwrap(doc.get("optimistic_settlement")?.asArray?.first)
        let rec = v.get("record") ?? .null, g = v.get("guardian_public")?.asString ?? ""
        XCTAssertEqual(Optimistic.settlementWireCheck(rec, guardianPublic: g), "ok")
        XCTAssertNotEqual(Optimistic.settlementWireCheck(Self.set(rec, ["guardian_epoch"], .int(0)), guardianPublic: g), "shape")
        XCTAssertEqual(Optimistic.settlementWireCheck(Self.set(rec, ["guardian_epoch"], Self.negZero), guardianPublic: g), "shape")
    }

    func testK4RiskInputsAndErc7715Expiry() throws {
        let doc = try ConformanceTests.load("k4-vectors.json")
        let cfg = doc.get("escalation")?.get("config")
        let risk: JSONValue = .object(["currency": .string("USD"), "loss": .int(0), "pBadUpperPpm": .int(0)])
        XCTAssertEqual(K4.decide(config: cfg, calibration: nil, risk: risk).reason, "calibration_invalid")
        XCTAssertEqual(K4.decide(config: cfg, calibration: nil, risk: Self.set(risk, ["loss"], Self.negZero)).reason, "risk_input_invalid")
        XCTAssertEqual(K4.decide(config: cfg, calibration: nil, risk: Self.set(risk, ["pBadUpperPpm"], Self.negZero)).reason, "risk_input_invalid")
        let c = try XCTUnwrap(doc.get("erc7715")?.get("cases")?.asArray?.first)
        let ctx = c.get("opts")?.get("contexts")?.asObject ?? [:]
        let mgrs = (c.get("opts")?.get("allowedManagers")?.asArray ?? []).compactMap { $0.asString }
        func run(_ got: JSONValue) -> String? {
            K4.verifyGranted(g: c.get("envelope") ?? .null, sent: c.get("sent") ?? .null, got: got, allowedManagers: mgrs, contextOwner: { ctx[JKey($0)]?.asString })
        }
        let got = c.get("got") ?? .null
        XCTAssertNotEqual(run(Self.set(got, ["rules", "0", "data", "timestamp"], .int(0))), "expiry_malformed")
        XCTAssertEqual(run(Self.set(got, ["rules", "0", "data", "timestamp"], Self.negZero)), "expiry_malformed")
    }

    func testA2aReceiptSeq() throws {
        let doc = try ConformanceTests.load("a2a-vectors.json")
        let r = doc.get("receipts")
        let rec = try XCTUnwrap(r?.get("records")?.asArray?.first), signer = r?.get("signer")?.asString ?? ""
        XCTAssertTrue(A2a.verifyReceipt(rec, signer: signer))
        XCTAssertFalse(A2a.verifyReceipt(Self.set(rec, ["seq"], Self.negZero), signer: signer))
    }
}
