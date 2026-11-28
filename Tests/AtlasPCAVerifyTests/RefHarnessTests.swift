import XCTest
import Foundation
@testable import AtlasPCAVerify

/// Differential replay of PCAHarness (the measurement, the allowlisting attestation verifier and the orchestration harness: plan inclusion,
/// taint fold, trust budget, signing) against the reference. The agent key is derived from the case's label (sha256 of
/// "atlas-pca-conformance/<label>"): the corpus carries no key material. The nonce of the k-th build attempt is "n<k>".
final class RefHarnessTests: XCTestCase {
    static let file = "ref-harness.json.gz"
    typealias H = PCAHarness

    static func seed(_ label: String) -> [UInt8] { Canonical.sha256(Array("atlas-pca-conformance/\(label)".utf8)) }

    static func scenario(_ spec: JSONValue) -> JSONValue? {
        guard let op = spec.get("opts") else { return nil }
        final class Clock { var t: Int64 = 0; var k = 0 }
        let clock = Clock()
        clock.t = 1_800_000_000_000
        let err = JSONValue.object(["$err": .bool(true)])
        guard let audience = op.get("audience")?.asString, let planV = op.get("plan")?.asArray, let b = op.get("budget")?.asObject, let label = op.get("label")?.asString else { return err }
        var plan: [JObject] = []
        for n in planV { guard let o = n.asObject else { return err }; plan.append(o) }
        guard let bv = IV.num(b[JKey("B")]), let tau = IV.num(b[JKey("tau")]) else { return err }
        var policy: JObject?
        if let p = op.get("policy") { guard let o = p.asObject else { return nil }; policy = o }
        var baseRisk: JObject?
        if let r = op.get("baseRisk") { guard let o = r.asObject else { return nil }; baseRisk = o }
        var chain: [JSONValue]?
        if let c = op.get("chain") { guard let a = c.asArray else { return nil }; chain = a }
        var manifest: [String]?
        if let m = op.get("manifest") { guard let a = RefConnectTests.strings(m) else { return nil }; manifest = a }
        var attestation: (operator: String, epoch: Int64?)?
        if let a = op.get("attestation") { guard let o = a.get("operator")?.asString else { return nil }; attestation = (o, IV.num(a.get("epoch")).map { Int64($0) }) }
        let harness: H.Harness
        do {
            harness = try H.Harness(grant: op.get("grant") ?? .null, chain: chain, agentSeed: seed(label), plan: plan, audience: audience,
                                    budget: Risk.Budget(b: bv, tau: tau, asOf: IV.num(b[JKey("asOf")])), policy: policy, baseRisk: baseRisk, now: { clock.t },
                                    ttlMs: IV.num(op.get("ttlMs")).map { Int64($0) }, measurementManifest: manifest, nonce: { defer { clock.k += 1 }; return "n\(clock.k)" }, attestation: attestation)
        } catch { return err }
        var steps: [JSONValue] = []
        for st in spec.get("steps")?.asArray ?? [] {
            if st.get("op")?.asString == "now" { clock.t = Int64(IV.num(st.get("t")) ?? 0); steps.append(.null); continue }
            guard let orc = st.get("oracle") else { return nil }
            steps.append(harness.step {
                switch orc.get("kind")?.asString {
                case "throw"?: throw JSError(orc.get("msg")?.asString ?? "")
                case "bad"?: return orc.get("v") ?? .null
                default: return orc.get("c") ?? .null
                }
            }.json)
        }
        return .object(["steps": .array(steps), "budget": harness.budget.json, "counter": .int(Int64(harness.counter)), "planRoot": .string(harness.planRoot), "measurement": .string(harness.harnessMeasurement())])
    }

    func testHarness() throws {
        try K042.requireCovers(["Harness"])
        let d = Base.Diffs()
        try Base.each(Self.file) { c in
            let got: BaseGot
            switch c.fn {
            case "consts":
                got = .value(.object(["HARNESS_VERSION": .string(H.HARNESS_VERSION), "HARNESS_MODEL_ID": .string(H.HARNESS_MODEL_ID), "ENFORCED_CHECKS": .array(H.ENFORCED_CHECKS.map { .string($0) })]))
            case "computeHarnessMeasurement":
                if c.name.contains("undefined-checks") { d.skip("computeHarnessMeasurement: the corpus encodes an undefined argument as null"); return }
                got = Base.run { .string(try H.computeHarnessMeasurement(c.arg(0) ?? .null, c.arg(1) ?? .null, c.arg(2) ?? .null)) }
            case "harnessAttest":
                got = Base.run { try H.createHarnessAttestationVerifier(c.arg(0))(c.arg(1)).json }
            case "harness":
                guard let g = Self.scenario(c.arg(0) ?? .null) else { d.skip("harness: untyped options"); return }
                d.add(c, Base.canon(g) == Base.canon(c.out) ? nil : "\(c.name): want \(Base.firstDiff(c.out, g, "@")) || want \(Base.canon(c.out).prefix(300)) got \(Base.canon(g).prefix(300))")
                return
            default: d.skip("\(c.fn): not mapped"); return
            }
            d.add(c, Base.diff(c, got))
        }
        d.finish(790)
    }

    func testToFixedAndRound() {
        XCTAssertEqual(H.toFixed4(0.03125), "0.0313") // an exact tie takes the larger decimal
        XCTAssertEqual(H.toFixed4(0.00015), "0.0001") // below the tie in binary64
        XCTAssertEqual(H.toFixed4(1), "1.0000")
        XCTAssertEqual(H.toFixed4(0.0999999), "0.1000")
        XCTAssertEqual(H.jsRound(2.5), 3)
        XCTAssertEqual(H.jsRound(0.49999999999999994), 0)
        XCTAssertEqual(H.jsRound(-1.5), -1)
    }
}
