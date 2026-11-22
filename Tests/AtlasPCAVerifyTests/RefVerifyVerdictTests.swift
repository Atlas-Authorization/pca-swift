import XCTest
import Foundation
@testable import AtlasPCAVerify

/// The full verdict of the resource-server verifier against the reference corpus (1022 cases): `allow`, `r`, `requiredThreshold`, every check with its
/// status, the exact reasons in order, the budget and the assurance report. Hooks are constant data; an option shape the typed API cannot carry
/// (a `require` that is not a list) is handed over as a fault that fails the verdict closed.
/// The texts of JavaScript engine errors (`verifier error (fail closed): <engine message>`, the strict-JSON parse messages of an encoded PCActn)
/// are compared by their fixed prefix. `allowUnboundPq` is not ported (the verifier never reads PQ keys from the artifact): the option is ignored and
/// its cases, whose artifacts are Ed25519, must still agree with the reference.
final class RefVerifyVerdictTests: XCTestCase {
    struct HookError: Error, CustomStringConvertible { let description: String }

    private static let enginePrefixes = ["verifier error (fail closed): ", "undecodable PCActn: strict JSON: "]

    private static func hook(_ h: JSONValue?) -> PCA.VerifyHook? {
        guard let h = h, !h.isNull else { return nil }
        if let m = h.get("throws")?.asString { return { _, _, _ in throw HookError(description: m) } }
        if let raw = h.get("raw") {
            // the reference reads `.enforced` of the answer: null throws, an object without it is not enforced
            if raw.isNull { return { _, _, _ in throw HookError(description: "Cannot read properties of null (reading 'enforced')") } }
            return { _, _, _ in .notEnforced }
        }
        let outcome = PCAGateway.HookOutcome(enforced: h.get("enforced") == .bool(true), ok: h.get("ok") == .bool(true), reason: h.get("reason")?.asString, t: IV.num(h.get("t")))
        return { _, _, _ in outcome }
    }

    private static func strings(_ v: JSONValue?) -> [String]? { v?.asArray.map { $0.map { $0.asString ?? "" } } }

    static func options(_ j: JSONValue) -> PCA.VerifyVerdictOptions {
        var o = PCA.VerifyVerdictOptions(grant: j.get("grant") ?? .null)
        // a clock that is not a safe integer is the reference's `bad-clock`: any value beyond the safe range reads the same
        if let n = j.get("now") { o.now = IV.num(n).flatMap { $0 == $0.rounded() && abs($0) <= 9007199254740991 ? Int64($0) : nil } ?? 9007199254740992 }
        if let a = j.get("audience") { o.audience = a.isNull ? .any : .id(a.asString ?? "\u{FFFF}not-a-string") }
        o.insecureSkipPlanRootCheck = j.get("insecureSkipPlanRootCheck") == .bool(true)
        if let h = j.get("hooks") {
            o.attestation = hook(h.get("attestation"))
            o.threshold = hook(h.get("threshold"))
            o.revocation = hook(h.get("revocation"))
            o.zk = hook(h.get("zk"))
        }
        if let c = j.get("context"), c.isObject {
            o.context.params = c.get("params")
            o.context.subject = c.get("subject")
            o.context.env = c.get("env")
            o.context.plan = c.get("plan")
            if case let .bool(b)? = c.get("planAuthorized") { o.context.planAuthorized = b }
            o.context.reversibilityClass = c.get("reversibilityClass")?.asString
            o.context.risk = c.get("risk")?.asObject
            o.context.budget = c.get("budget")
            o.context.recentActionTimes = c.get("recentActionTimes")?.asArray?.compactMap { IV.num($0) }
            if let re = c.get("revocationEpoch") {
                o.context.revocationEpoch = PCA.VerdictEpoch(epoch: re.get("epoch") ?? .null, guardianPublic: re.get("guardianPublic")?.asString ?? "",
                                                             lastAcceptedEpoch: IV.num(re.get("lastAcceptedEpoch")), maxAgeMs: IV.num(re.get("maxAgeMs")))
            }
            if let b = c.get("beacon") {
                o.context.beacon = PCA.BeaconInput(beacon: b.get("beacon") ?? .null, issuers: strings(b.get("issuers")) ?? [], instance: b.get("instance")?.asString ?? "",
                                                   pqPins: nil, lastAcceptedSeq: IV.int(b.get("lastAcceptedSeq")))
            }
        }
        if let r = j.get("require"), !r.isNull {
            if let list = strings(r) { o.require = list } else { o.fault = "required.map is not a function" }
        }
        o.allowedSuites = strings(j.get("allowedSuites"))
        if case let .object(pins)? = j.get("pqPins") { o.pqPins = Dictionary(uniqueKeysWithValues: pins.map { ($0.key.s, $0.value.asString ?? "") }) }
        if let i = j.get("intent"), i.isObject {
            o.intent = IntentPolicy(require: i.get("require") == .bool(true), minFidelityPpm: IV.num(i.get("minFidelityPpm")), maxResidualRiskPpm: IV.num(i.get("maxResidualRiskPpm")))
        }
        if let op = j.get("operation"), op.isObject {
            o.operation = PCA.VerdictOperation(verb: op.get("verb")?.asString, resource: op.get("resource")?.asString, params: op.get("params"))
        }
        o.requireRiskInputs = strings(j.get("requireRiskInputs")) ?? []
        o.assurance = j.get("assurance") == .bool(true)
        if let ra = j.get("requireAssurance"), ra.isObject {
            o.requireAssurance = AssuranceRequirement(json: ra)
        }
        o.allowUnsupported = strings(j.get("allowUnsupported")) ?? []
        if let e = j.get("enforce") {
            if let f = e.get("freshness"), f.isObject {
                o.enforce.freshness = PCA.FreshnessGate(maxAgeMs: IV.num(f.get("maxAgeMs")) ?? .nan, epochMs: IV.num(f.get("epochMs")) ?? 60_000, now: IV.num(f.get("now")),
                                                        clockSkewMs: IV.num(f.get("clockSkewMs")))
            }
            if let a = e.get("attestation"), a.isObject, let v = hook(a.get("verifier")) {
                o.enforce.attestation = PCAGateway.AttestationGate(verifier: v, required: a.get("required") != .bool(false))
            }
        }
        return o
    }

    /// The first divergence between the reference verdict and ours, or nil.
    static func compare(_ c: BaseCase, _ g: PCA.PcaVerdict) -> String? {
        let want = c.out, got = g.json
        if want.get("allow") != got.get("allow") { return "\(c.name): allow want \(Base.canon(want.get("allow"))) got \(Base.canon(got.get("allow"))); reasons \(g.reasons)" }
        if let a = IV.num(want.get("r")), let b = IV.num(got.get("r")), abs(a - b) > 1e-12 * max(1, abs(a)) { return "\(c.name): r want \(a) got \(b)" }
        for k in ["requiredThreshold", "checks", "budget", "assurance"] where Base.canon(want.get(k)) != Base.canon(got.get(k)) {
            return "\(c.name): \(k) \(Base.firstDiff(want.get(k), got.get(k), "@")) || want \(Base.canon(want.get(k)).prefix(400)) got \(Base.canon(got.get(k)).prefix(400))"
        }
        let wr = (want.get("reasons")?.asArray ?? []).map { $0.asString ?? "" }
        if wr.count != g.reasons.count { return "\(c.name): reasons want \(wr) got \(g.reasons)" }
        for (w, x) in zip(wr, g.reasons) {
            if let pre = enginePrefixes.first(where: { IV.startsWith(w, $0) }) {
                if !IV.startsWith(x, pre) { return "\(c.name): reason want prefix \(pre) got \(x)" }
            } else if !IV.same(w, x) {
                return "\(c.name): reason want \(w) got \(x)"
            }
        }
        return nil
    }

    func testEveryCaseOfTheReferenceCorpus() throws {
        let d = Base.Diffs()
        var unboundOption = 0
        let n = try Base.each("ref-verify-verdict.json.gz") { c in
            guard c.fn == "verifyVerdict", let p = c.arg(0), let j = c.arg(1) else { XCTFail("unhandled fn \(c.fn)"); return }
            if j.get("allowUnboundPq") == .bool(true) { unboundOption += 1 }
            d.add(c, Self.compare(c, PCA.verifyVerdict(p, Self.options(j))))
        }
        XCTAssertEqual(n, 1022)
        XCTAssertEqual(unboundOption, 2, "the allowUnboundPq cases are replayed with the option ignored")
        d.finish(1022)
    }

    func testAnUnusableGrantFailsClosed() {
        let v = PCA.verifyVerdict(.object(["ver": .int(2)]), PCA.VerifyVerdictOptions(grant: .null))
        XCTAssertFalse(v.allow)
        XCTAssertEqual(v.checks["malformed"], .fail)
        XCTAssertEqual(v.requiredThreshold, PCA.RequiredThresholdVerdict(t: 3, proof: "strong", optimisticAllowed: false))
        XCTAssertTrue(v.reasons[0].hasPrefix("verifier error (fail closed): "))
    }

    func testAnObjectThatIsNotAPCActnIsRefused() {
        var o = PCA.VerifyVerdictOptions(grant: .object(["caveats": .array([])]))
        o.assurance = true
        let v = PCA.verifyVerdict(.int(5), o)
        XCTAssertEqual(v.reasons, ["PCActn is not an object"])
        XCTAssertEqual(v.assurance?["malformed"]?.outcome, "fail")
        XCTAssertEqual(PCA.verifyVerdict(.string("{}"), o).reasons.count, 1)
    }
}
