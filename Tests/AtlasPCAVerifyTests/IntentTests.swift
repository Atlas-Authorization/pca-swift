import XCTest
import Foundation
#if canImport(CryptoKit)
import CryptoKit
#else
import Crypto // Linux: swift-crypto (tools/pca-audit/swift-mutate/linux-prep.sh)
#endif
@testable import AtlasPCAVerify

/// Intent Layer M2: the signed `envelope.intent` slot (wire rules) and the `intent` check (binding to the root grant's
/// first `envelope` caveat `goal_commit`, policy floor / ceiling, fail-closed misconfiguration).
final class IntentTests: XCTestCase {
    static let AUD = "rs-intent"
    static let IAT: Int64 = 1_800_000_000_000
    static let NOW: Int64 = IAT + 1_000
    static let SALT = "c2FsdC1pbnRlbnQtdGVzdA"

    static func key(_ label: String) -> Curve25519.Signing.PrivateKey {
        try! Curve25519.Signing.PrivateKey(rawRepresentation: Data(Canonical.sha256(Canonical.utf8(label))))
    }
    static func pub(_ k: Curve25519.Signing.PrivateKey) -> String { Base64URLStrict.encode(Array(k.publicKey.rawRepresentation)) }
    static func digest(_ s: String) -> String { Base64URLStrict.encode(Canonical.sha256(Canonical.utf8(s))) }
    static let REF = digest("intent/ref")
    static let MAP = digest("intent/map")

    static func commit(_ salt: String = SALT) -> String { PCA.intentGoalCommit(ref: REF, mapDigest: MAP, goalSalt: salt)! }
    static func envelope(_ gc: JSONValue) -> JSONValue { .object(["type": .string("envelope"), "goal_commit": gc]) }
    static func theIntent(_ patch: [String: JSONValue?] = [:]) -> JSONValue {
        var o: JObject = ["ref": .string(REF), "map_digest": .string(MAP), "goal_salt": .string(SALT),
                          "fidelity_ppm": .int(950_000), "residual_risk_ppm": .int(4_310_000)]
        for (k, v) in patch { o[JKey(k)] = v }
        return .object(o)
    }

    static func rootGrant(_ caveats: [JSONValue]) -> JSONValue {
        let (iss, hol) = (key("principal"), key("agent"))
        let body: JSONValue = .object(["issuer": .string(pub(iss)), "holder": .string(pub(hol)), "caveats": .array(caveats), "parent": .null])
        let d = Canonical.hashCanonical(body)
        let sig = try! iss.signature(for: Data(Capability.CAP_DOMAIN + Base64URLStrict.decode(d)!))
        return .object(["id": .string(d), "issuer": .string(pub(iss)), "holder": .string(pub(hol)), "caveats": .array(caveats),
                        "body_digest": .string(d), "sig": .string(Base64URLStrict.encode(Array(sig)))])
    }

    /// A signed single-node PCActn over `grant`, optionally carrying `intent`.
    static func pcactn(_ grant: JSONValue, _ intent: JSONValue?) -> JSONValue {
        let action: JObject = ["verb": .string("read"), "resource": .string("db/users"), "params_digest": .string(digest("p")),
                               "reversibility_class": .string("reversible")]
        let cond = digest("cond")
        let root = Merkle.merkleRoot([Merkle.planLeaf(.string("only"), action, cond)!])!
        var p: JObject = [
            "ver": .int(2), "action": .object(action), "grant_ref": grant.get("id")!, "cap_chain": .array([grant]),
            "plan": .object(["root": .string(root), "node_id": .string("only"), "conditions_digest": .string(cond),
                             "inclusion_proof": .object(["index": .int(0), "size": .int(1), "path": .array([])])]),
            "attestation": .object(["epoch": .int(1), "quote_digest": .string("q"), "model_id": .string("m"), "measurement": .string("x"), "operator": .string("o")]),
            "provenance": .object(["causal_hash": .string("h"), "taint_level": .int(0), "trusted_refs": .array([])]),
            "freshness": .object(["beacon_ref": .string("b"), "accumulator_witness": .string("w"), "epoch": .int(1)]),
            "counter": .int(1), "risk_claim": .object(["r": .double(0.5), "inputs": .object([:])]),
            "aud": .string(AUD), "iat": .int(IAT), "exp": .int(IAT + 600_000),
        ]
        if let i = intent { p["intent"] = i }
        let sig = try! key("agent").signature(for: Data(try! PCA.thresholdMessage(p)))
        p["sig"] = .string(Base64URLStrict.encode(Array(sig)))
        return .object(p)
    }

    static func verify(_ p: JSONValue, _ g: JSONValue, _ pol: IntentPolicy? = nil) -> PCA.Verdict {
        PCA.verify(pcactn: p, grant: g, now: NOW, audience: AUD, intentPolicy: pol)
    }

    func testAbsentSlotAndInactivePolicyIsThePreM2Verdict() {
        let g = Self.rootGrant([Self.envelope(.string(Self.commit()))])
        let p = Self.pcactn(g, nil)
        let base = PCA.verify(pcactn: p, grant: g, now: Self.NOW, audience: Self.AUD)
        XCTAssertTrue(base.allow, base.reason)
        for pol in [nil, IntentPolicy(), IntentPolicy(require: false)] {
            let v = Self.verify(p, g, pol)
            XCTAssertTrue(v.allow, v.reason)
            XCTAssertNil(v.checks["intent"])
            XCTAssertEqual(v.checks, base.checks)
        }
    }

    func testBoundIntentPassesWithInclusiveThresholds() {
        let g = Self.rootGrant([.object(["type": .string("max_spend"), "usd": .int(100)]), Self.envelope(.string(Self.commit()))])
        let p = Self.pcactn(g, Self.theIntent())
        for pol in [nil, IntentPolicy(require: true, minFidelityPpm: 950_000, maxResidualRiskPpm: 4_310_000)] {
            let v = Self.verify(p, g, pol)
            XCTAssertTrue(v.allow, v.reason)
            XCTAssertEqual(v.checks["intent"], true)
            XCTAssertEqual(v.checks.count, 10)
        }
    }

    func testIntentCheckFailures() {
        let good = Self.rootGrant([Self.envelope(.string(Self.commit()))])
        let notString = Self.rootGrant([Self.envelope(.int(7))])
        let noEnv = Self.rootGrant([])
        let firstWins = Self.rootGrant([Self.envelope(.string("decoy")), Self.envelope(.string(Self.commit()))])
        let cases: [(String, JSONValue, JSONValue?, IntentPolicy?, String)] = [
            ("absent-required", good, nil, IntentPolicy(require: true), "requires an intent"),
            ("threshold-implies-require", good, nil, IntentPolicy(minFidelityPpm: 1), "requires an intent"),
            ("misconfig-negative", good, Self.theIntent(), IntentPolicy(minFidelityPpm: -1), "misconfigured"),
            ("misconfig-fraction", good, Self.theIntent(), IntentPolicy(maxResidualRiskPpm: 0.5), "misconfigured"),
            ("salt-mismatch", good, Self.theIntent(["goal_salt": .string("wrong")]), nil, "do not open"),
            ("goal-commit-not-string", notString, Self.theIntent(), nil, "no envelope goal commitment"),
            ("no-envelope", noEnv, Self.theIntent(), nil, "no envelope goal commitment"),
            ("first-envelope-wins", firstWins, Self.theIntent(), nil, "do not open"),
            ("fidelity-below-min", good, Self.theIntent(), IntentPolicy(minFidelityPpm: 950_001), "below the policy minimum"),
            ("residual-above-max", good, Self.theIntent(), IntentPolicy(maxResidualRiskPpm: 4_309_999), "exceeds the policy maximum"),
        ]
        for (name, g, intent, pol, why) in cases {
            let v = Self.verify(Self.pcactn(g, intent), g, pol)
            XCTAssertFalse(v.allow, name)
            XCTAssertEqual(v.checks["intent"], false, name)
            XCTAssertEqual(v.checks["leaf_signature"], true, name)
            XCTAssertTrue(v.reason.hasPrefix("intent: ") && v.reason.contains(why), "\(name): \(v.reason)")
        }
    }

    func testWireRefusalsAreTerminal() {
        let g = Self.rootGrant([Self.envelope(.string(Self.commit()))])
        let bad: [JSONValue] = [
            .string("x"), .null, .array([Self.theIntent()]),
            Self.theIntent(["note": .string("x")]),
            Self.theIntent(["residual_risk_ppm": nil]),
            Self.theIntent(["ref": .string(Base64URLStrict.encode([UInt8](repeating: 0, count: 31)))]),
            Self.theIntent(["ref": .string(Self.REF + "=")]),
            Self.theIntent(["map_digest": .int(1)]),
            Self.theIntent(["goal_salt": .string("")]),
            Self.theIntent(["goal_salt": .string(String(repeating: "\u{e9}", count: 64) + "a")]),
            Self.theIntent(["fidelity_ppm": .int(1_000_001)]),
            Self.theIntent(["fidelity_ppm": .int(-1)]),
            Self.theIntent(["fidelity_ppm": .double(1.5)]),
            Self.theIntent(["fidelity_ppm": .string("950000")]),
            Self.theIntent(["residual_risk_ppm": .int(-1)]),
            Self.theIntent(["residual_risk_ppm": .bool(true)]),
        ]
        for i in bad {
            let v = Self.verify(Self.pcactn(g, i), g)
            XCTAssertEqual(v.checks, ["wire": false], "\(i)")
            XCTAssertFalse(v.allow)
        }
        // 128 UTF-8 bytes is the inclusive edge
        let salt = String(repeating: "\u{e9}", count: 64)
        let g2 = Self.rootGrant([Self.envelope(.string(Self.commit(salt)))])
        let v = Self.verify(Self.pcactn(g2, Self.theIntent(["goal_salt": .string(salt)])), g2)
        XCTAssertTrue(v.allow, v.reason)
        XCTAssertEqual(v.checks["intent"], true)
    }

    func testPolicyFromJSONIsLenient() throws {
        let p = IntentPolicy.fromJSON(try StrictJSON.parse(#"{"require":false,"min_fidelity_ppm":-1,"max_residual_risk_ppm":0.5}"#))
        XCTAssertEqual(p, IntentPolicy(require: false, minFidelityPpm: -1, maxResidualRiskPpm: 0.5))
        XCTAssertTrue(p?.isActive ?? false)
        XCTAssertFalse(Intent.okThreshold(-1))
        XCTAssertFalse(Intent.okThreshold(0.5))
        XCTAssertFalse(IntentPolicy.fromJSON(try StrictJSON.parse(#"{"require":false}"#))?.isActive ?? true)
        XCTAssertNil(IntentPolicy.fromJSON(.null))
    }
}
