import XCTest
import Foundation
@testable import AtlasPCAVerify

/// Differential replay of the pca-grants operational plane against the TypeScript reference: the domain-separated body signature, the lease,
/// lease revocation, blueprint, break-glass and review signers (and what they refuse), attestation-gated blueprint admission, the freshness
/// fold and gate. A reference throw requires a native refusal.
final class RefGrantsTests: XCTestCase {
    static let file = "ref-grants.json.gz"

    /// The key of a label: seed = sha256("atlas-pca-conformance/" + label).
    static func key(_ v: JSONValue?) throws -> PCAEdKey {
        guard let label = v?.asString else { throw JSError("label expected") }
        return try Ed25519Deterministic.key(seed: Canonical.sha256(Array(("atlas-pca-conformance/" + label).utf8)))
    }

    static func obj(_ v: JSONValue?) throws -> JObject {
        guard let o = v?.asObject else { throw JSError("object expected") }
        return o
    }

    static func str(_ v: JSONValue?) throws -> String {
        guard let s = v?.asString else { throw JSError("string expected") }
        return s
    }

    func testGrantsAgainstTheReference() throws {
        let d = Base.Diffs()
        let fns: Set<String> = ["signerOf", "signBody", "verifyBody", "signLease", "signLeaseUnsafeOverCap", "signLeaseRevocation", "signBlueprint",
                                "signBreakGlass", "signBreakGlassReview", "admitWithEvidence", "mergeFreshAt", "gateDecision", "signBundle", "assembleBundle", "maskRecord"]
        let n = try Base.each(Self.file, fns) { c in
            let got: BaseGot = Base.run {
                switch c.fn {
                case "signerOf": return .string(PCAGrants.signerOf(try Self.key(c.arg(0))))
                case "signBody": return .string(try PCAGrants.signBody(try Self.str(c.arg(0)), c.arg(1) ?? .null, try Self.key(c.arg(2))))
                case "verifyBody": return .bool(PCAGrants.verifyBody(try Self.str(c.arg(0)), c.arg(1) ?? .null, try Self.str(c.arg(2)), c.arg(3)))
                case "signLease": return try PCAGrants.signLease(try Self.key(c.arg(0)), try Self.obj(c.arg(1)))
                case "signLeaseUnsafeOverCap": return try PCAGrants.signLeaseUnsafeOverCap(try Self.key(c.arg(0)), try Self.obj(c.arg(1)))
                case "signLeaseRevocation": return try PCAGrants.signLeaseRevocation(try Self.key(c.arg(0)), try Self.obj(c.arg(1)))
                case "signBlueprint": return try PCAGrants.signBlueprint(try Self.key(c.arg(0)), try Self.obj(c.arg(1)))
                case "signBreakGlass": return try PCAGrants.signBreakGlass(try Self.key(c.arg(0)), try Self.obj(c.arg(1)))
                case "signBreakGlassReview": return try PCAGrants.signBreakGlassReview(try Self.key(c.arg(0)), try Self.obj(c.arg(1)))
                case "admitWithEvidence":
                    let ev = c.arg(1)
                    return PCAGrants.admitWithEvidence(c.arg(0) ?? .null) {
                        if ev?.asObject?[JKey("$throw")] != nil { throw JSError("boom") }
                        return ev
                    }
                case "mergeFreshAt": return try PCAGrants.mergeFreshAt(try Self.obj(c.arg(0)), try Self.obj(c.arg(1)))
                case "gateDecision": return .string(PCAGrants.gateDecision(try Self.str(c.arg(0)), c.arg(1)?.get("decision")?.asString ?? ""))
                case "signBundle": return try PCAGrants.signBundle(try Self.obj(c.arg(0)), try Self.key(c.arg(1)))
                case "assembleBundle": return PCAGrants.assembleBundle(try Self.obj(c.arg(0)), c.arg(1)?.asArray ?? [])
                case "maskRecord":
                    let classes = try (c.arg(1)?.asArray ?? []).map { (x: JSONValue) -> String in try Self.str(x) }
                    return .object(try PCAGrants.maskRecord(try Self.obj(c.arg(0)), classes))
                default: throw JSError("unhandled \(c.fn)")
                }
            }
            d.add(c, Base.diff(c, got))
        }
        XCTAssertGreaterThan(n, 2400)
        d.finish(2400)
    }

    static func verdict(_ v: FreshAt.Verdict) -> JSONValue {
        switch v {
        case .ok: return .object(["decision": .string("ok")])
        case let .escalate(behind): return .object(["decision": .string("escalate"), "code": .string("stale_state"), "behind": .array(behind.map { .string($0) })])
        case let .deny(code): return .object(["decision": .string("deny"), "code": .string(code)])
        }
    }

    /// The freshness issuer: advance, check, tamper, current (a thrown step is `{$err: true}`, the state it already moved to stays).
    func testFreshScenarioAgainstTheReference() throws {
        let d = Base.Diffs()
        let n = try Base.each(Self.file, ["freshScenario"]) { c in
            let got: BaseGot = Base.run {
                guard let spec = c.arg(0)?.asObject, let scope = spec["scope"]?.asString, let initial = spec["init"]?.asObject else { throw JSError("spec") }
                let iss = PCAGrants.FreshAtIssuer(try Self.key(spec["label"]), scope: scope, initial: initial)
                var out: [JSONValue] = []
                var last: JSONValue?
                for st in spec["steps"]?.asArray ?? [] {
                    let s = st.asObject ?? [:]
                    do {
                        switch s["op"]?.asString ?? "" {
                        case "advance":
                            last = try iss.advance(s["patch"]?.asObject ?? [:], now: Int64(IV.safe(s["now"]) ?? 0))
                            out.append(last!)
                        case "check":
                            let tok: JSONValue? = s["token"]?.asString == "last" ? last : s["token"]
                            out.append(Self.verdict(iss.check(tok, now: Int64(IV.safe(s["now"]) ?? 0), maxTokenAgeMs: IV.safe(s["maxAge"]).map { Int64($0) })))
                        case "current": out.append(iss.current())
                        case "tamper":
                            guard var t = last?.asObject, let rev = IV.safe(t["policy_revision"]) else { throw JSError("no token") }
                            t["policy_revision"] = .int(Int64(rev) + 1)
                            out.append(Self.verdict(iss.check(.object(t), now: Int64(IV.safe(s["now"]) ?? 0))))
                        default: break
                        }
                    } catch { out.append(.object(["$err": .bool(true)])) }
                }
                return .array(out)
            }
            d.add(c, Base.diff(c, got))
        }
        XCTAssertGreaterThanOrEqual(n, 3)
        d.finish(3)
    }

    /// The group kill moves the epoch strictly forward, disables the blueprint, and voids an admission made under the old epoch.
    func testGroupKillAndAdmissionRegistry() throws {
        let operatorKey = try Self.key(.string("op")), bpKey = try Self.key(.string("bp")), inst = try Self.key(.string("inst"))
        let pin: JSONValue = .object(["runtime_measurement": .string("rt-1"), "operator": .string("acme")])
        let bp = try PCAGrants.signBlueprint(operatorKey, ["id": .string("fleet"), "key": .string(bpKey.id), "ceiling": .array([]), "epoch": .int(1),
                                                            "status": .string("active"), "issued_at": .int(1_800_000_000_000), "runtime_pins": .array([pin])])
        let reg = Blueprint.Registry(operators: [operatorKey.id], store: Blueprint.MemoryStore())
        XCTAssertTrue(reg.accept(bp).ok)
        let adm = PCAGrants.AdmissionRegistry()
        adm.admit(inst.id, bp.asObject!, until: 1_800_000_001_000)
        XCTAssertEqual(try adm.checker(1_800_000_000_000)(inst.id, bp.asObject!), true)
        XCTAssertEqual(try adm.checker(1_800_000_001_000)(inst.id, bp.asObject!), false) // expired
        let killed = try PCAGrants.groupKill(operatorKey, reg, key: bpKey.id, now: 1_800_000_000_500)
        XCTAssertEqual(killed.get("ok"), .bool(true))
        XCTAssertEqual(killed.get("record")?.get("status")?.asString, "disabled")
        XCTAssertEqual(killed.get("record")?.get("epoch"), .int(2))
        XCTAssertEqual(try adm.checker(1_800_000_000_000)(inst.id, killed.get("record")!.asObject!), false) // a new epoch voids the old admission
        XCTAssertEqual(try PCAGrants.groupKill(operatorKey, reg, key: "nobody", now: 1).get("code")?.asString, "unknown_blueprint")
        XCTAssertTrue(adm.revoke(inst.id, bpKey.id))
        XCTAssertFalse(adm.revoke(inst.id, bpKey.id))
    }

    func testAdmitBlueprintInstanceDenies() throws {
        let pin: JSONValue = .object(["runtime_measurement": .string("rt-1")])
        let bp: JSONValue = .object(["runtime_pins": .array([pin])])
        let good = PCAGrants.HardwareResult(ok: true, bound: true, measured: ["runtime_measurement": .string("rt-1")])
        XCTAssertEqual(PCAGrants.admitBlueprintInstance(bp, hasDocument: true) { good }.get("admitted"), .bool(true))
        XCTAssertEqual(PCAGrants.admitBlueprintInstance(bp, hasDocument: false) { good }.get("code")?.asString, "not_ok")
        XCTAssertEqual(PCAGrants.admitBlueprintInstance(bp, hasDocument: true) { PCAGrants.HardwareResult(ok: true, bound: false, measured: good.measured) }.get("code")?.asString, "not_bound")
        XCTAssertEqual(PCAGrants.admitBlueprintInstance(bp, hasDocument: true) { PCAGrants.HardwareResult(ok: true, bound: true) }.get("code")?.asString, "no_identity")
        XCTAssertEqual(PCAGrants.admitBlueprintInstance(bp, hasDocument: true) { throw JSError("x") }.get("code")?.asString, "verifier_error")
        XCTAssertEqual(PCAGrants.admitBlueprintInstance(.object([:]), hasDocument: true) { good }.get("code")?.asString, "no_pins")
    }
}
