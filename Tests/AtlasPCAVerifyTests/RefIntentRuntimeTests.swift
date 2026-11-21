import XCTest
import Foundation
@testable import AtlasPCAVerify

/// Differential replay of the runtime intent modules (runtime bridges, routing and conformance, just-in-time elicitation, the trust
/// ramp and its drift detector, trajectory intent, portable profiles, suite signing of profiles) against the reference
/// (@atlasauth/pca-intent). A reference throw requires a native refusal. Doubles are compared bit for bit first and within 1e-12
/// relative otherwise (the reference's fdlibm and the platform libm may round log / exp differently); the count of the latter is
/// printed. Cases of functions that belong to other modules are counted and reported as skipped, never dropped silently.
final class RefIntentRuntimeTests: XCTestCase {
    static let tol = 1e-12
    var inexact = 0

    func close(_ a: JSONValue?, _ b: JSONValue?) -> Bool {
        switch (a, b) {
        case let (.object(x)?, .object(y)?): return Set(x.keys) == Set(y.keys) && x.allSatisfy { close($0.value, y[$0.key]) }
        case let (.array(x)?, .array(y)?): return x.count == y.count && zip(x, y).allSatisfy { close($0, $1) }
        default:
            if let p = IV.num(a), let q = IV.num(b) {
                if p == q || (p.isNaN && q.isNaN) { return true }
                inexact += 1
                return abs(p - q) <= Self.tol * max(abs(p), abs(q)) + 1e-15
            }
            return Base.canon(a) == Base.canon(b)
        }
    }

    /// Runs one case, records the verdict.
    func check(_ d: Base.Diffs, _ c: BaseCase, _ f: () throws -> JSONValue) {
        let got: BaseGot = Base.run { try f() }
        if case let .value(v) = got, !c.threw {
            if close(c.out, v) { d.add(c, nil) } else { d.add(c, "\(c.name): want \(Base.firstDiff(c.out, v, "@")) || want \(Base.canon(c.out).prefix(300)) got \(Base.canon(v).prefix(300))") }
        } else {
            d.add(c, Base.diff(c, got))
        }
    }

    // ---- decoding helpers ----

    static func verbSpace(_ v: JSONValue?) throws -> WalletVerb {
        let om = try WalletOmega(.object(["verbs": .array([v ?? .null])]))
        guard let vs = om.verbs.first else { throw JSError("bad verb space") }
        return vs
    }

    static func dim(_ v: JSONValue?) throws -> WalletDim {
        let vs = try verbSpace(.object(["verb": .string("x"), "reversibility": .string("reversible"), "weight": .int(1), "dims": .array([v ?? .null])]))
        guard let d = vs.dims.first else { throw JSError("bad dimension") }
        return d
    }

    static func ints(_ v: JSONValue?) throws -> [Int] {
        guard let a = v?.asArray else { throw JSError("not an array") }
        return try a.map { guard let i = IV.int($0) else { throw JSError("not an integer") }; return Int(i) }
    }

    static func outcome(_ x: JSONValue) -> JSONValue { .object(["verb": x.get("verb") ?? .null, "values": x.get("values") ?? .null]) }

    static func make(_ omega: JSONValue?, _ mapOpts: JSONValue?, _ obs: JSONValue?) throws -> PCAIntentLearner {
        let l = try PCAIntentMap.createLearner(omega: omega, options: mapOpts)
        for x in obs?.asArray ?? [] {
            guard let y = IV.num(x.get("y")), let src = x.get("source")?.asString else { throw JSError("bad observation") }
            try l.observe(outcome(x), y: Int(y), source: src, region: nil)
        }
        return l
    }

    static func seedBytes(_ v: JSONValue?) throws -> [UInt8] {
        guard let s = v?.asString, let b = Base64URLStrict.decode(s) else { throw JSError("bad seed") }
        return b
    }

    static func edKey(_ v: JSONValue?) throws -> PCASuiteKey { PCASuiteKey.ed25519(try Ed25519Deterministic.key(seed: try seedBytes(v))) }

    static func opt(_ v: JSONValue?) -> JSONValue? { (v == nil || v == .null) ? nil : v }

    static func str(_ v: JSONValue?) -> String? { v?.asString }

    static func obj(_ v: JSONValue?) throws -> JObject {
        guard let o = v?.asObject else { throw JSError("not an object") }
        return o
    }

    /// The shape of a signed artifact the reference reports: suite members, the rest of the body, signature lengths and the verdict.
    static func signShape(_ s: JSONValue, _ ok: Bool) -> JSONValue {
        func sigLen(_ v: JSONValue?) -> JSONValue {
            guard let str = v?.asString, let b = Base64URLStrict.decode(str) else { return .null }
            return .int(Int64(b.count))
        }
        var rest: JObject = s.asObject ?? [:]
        for k in ["sig", "pq_sig", "alg", "pq_pk"] { rest[JKey(k)] = nil }
        return .object(["alg": s.get("alg") ?? .null, "pq_pk": s.get("pq_pk") ?? .null, "rest": .object(rest), "sig_len": sigLen(s.get("sig")),
                        "pq_sig_len": sigLen(s.get("pq_sig")), "ok": .bool(ok)])
    }

    /// The pin map `{who: pq_pk}` a verifier holds for a signed artifact that carries a post-quantum key.
    static func pinsOf(_ s: JSONValue, _ who: String?) -> JObject {
        var pins: JObject = [:]
        if let w = who, let pq = s.get("pq_pk"), !pq.isNull { pins[JKey(w)] = pq }
        return pins
    }

    static func doubles(_ xs: [Double]) -> JSONValue { .array(xs.map { JSONValue.double($0) }) }

    static func intsJSON(_ xs: [Int]) -> JSONValue { .array(xs.map { JSONValue.int(Int64($0)) }) }

    /// `base` with the member at `path` replaced (objects only).
    static func setting(_ base: JSONValue, _ path: [String], _ x: JSONValue) -> JSONValue {
        guard let k = path.first, var o = base.asObject else { return base }
        if path.count == 1 { o[JKey(k)] = x } else { o[JKey(k)] = setting(o[JKey(k)] ?? .null, Array(path.dropFirst()), x) }
        return .object(o)
    }

    // ---- runtime bridges, ramp ----

    func testRuntimeAndRampAgainstTheReference() throws {
        let d = Base.Diffs()
        try Base.each("ref-intent-runtime.json.gz") { c in
            let a = c.args
            switch c.fn {
            case "pcactnActionOf": check(d, c) { PCAIntentRuntime.pcactnActionOf(try Self.verbSpace(a[0]), a[1]) }
            case "judgeInputOf":
                check(d, c) {
                    let om = try WalletOmega(a[0])
                    guard let vs = om.verb(a[1].get("verb")?.asString ?? "") else { throw JSError("no such verb") }
                    return try PCAIntentRuntime.judgeInputOf(vs, a[1], IV.num(a[2]) ?? .nan, a[3])
                }
            case "jitConsentRequest":
                check(d, c) {
                    let om = try WalletOmega(a[0])
                    guard let vs = om.verb(a[1].get("verb")?.asString ?? "") else { throw JSError("no such verb") }
                    return try PCAIntentRuntime.jitConsentRequest(vs, a[1], IV.num(a[2]) ?? .nan, Self.str(a[3].get("intentRef")), Self.str(a[3].get("mapDigest")))
                }
            case "jitConsentDigest": check(d, c) { .string(PCAIntentRuntime.jitConsentDigest(a[0])) }
            case "calibrationDigest": check(d, c) { .string(try PCAIntentRuntime.calibrationDigest(a[0])) }
            case "icAttDigest": check(d, c) { .string(PCAIntentRuntime.icAttDigest(a[0])) }
            case "foldSemanticRisk": check(d, c) { .double(PCAIntentRuntime.foldSemanticRisk(IV.num(a[0]) ?? .nan, a[1])) }
            case "signalLabel": check(d, c) { .int(Int64(PCAIntentRamp.signalLabel(a[0].asString))) }
            case "narrowStart":
                check(d, c) {
                    let o = a[2]
                    return PCAIntentRamp.narrowStart(try WalletOmega(a[0]), a[1], o.get("slotNullMass").flatMap { IV.num($0) }, o.get("otherNullMass").flatMap { IV.num($0) })
                }
            case "driftRun":
                check(d, c) {
                    let o = a[0]
                    let dd = try PCAIntentRamp.DriftDetector(o.get("rho0").flatMap { IV.num($0) }, o.get("rho1").flatMap { IV.num($0) }, o.get("h").flatMap { IV.num($0) })
                    var states: [JSONValue] = []
                    for x in a[1].asArray ?? [] { states.append(dd.update(x == .bool(true)).toJson()) }
                    states.append(dd.state().toJson())
                    dd.reset()
                    states.append(dd.state().toJson())
                    return .array(states)
                }
            case "defaultPostconditions": check(d, c) { .array(PCAIntentEffects.DEFAULT_POSTCONDITIONS) }
            case "effectContext":
                check(d, c) { PCAIntentEffects.effectContext(try Self.verbSpace(a[0]), a[1], .object(try Self.obj(a[2]))) }
            case "checkPostconditions":
                check(d, c) {
                    let vs = try Self.verbSpace(a[0])
                    let effect: JSONValue = .object(try Self.obj(a[2]))
                    if a.count > 3 {
                        guard let pcs = a[3].asArray else { throw JSError("not an array") }
                        return try PCAIntentEffects.checkPostconditions(vs, a[1], effect, pcs)
                    }
                    return try PCAIntentEffects.checkPostconditions(vs, a[1], effect)
                }
            case "questionCard":
                check(d, c) {
                    guard let verb = a[1].get("verb")?.asString else { throw JSError("question has no verb") }
                    return try PCAIntentUx.questionCard(try WalletOmega(a[0]), verb, try Self.ints(a[1].get("cell")))
                }
            case "parseCardAnswer": check(d, c) { try PCAIntentUx.parseCardAnswer(a[0], a[1]) }
            default: d.skip("\(c.fn): not mapped")
            }
        }
        try Base.each("ref-intent-ramp.json.gz", seeds: true) { c in
            let a = c.args
            switch c.fn {
            case "rampScenario":
                check(d, c) {
                    let dd = a[3]
                    let ramp = try PCAIntentTrustRamp(try Self.make(a[0], a[1], a[2]), dd.get("rho0").flatMap { IV.num($0) }, dd.get("rho1").flatMap { IV.num($0) }, dd.get("h").flatMap { IV.num($0) })
                    var out: [JSONValue] = []
                    for op in a[4].asArray ?? [] {
                        switch op.get("op")?.asString {
                        case "record"?:
                            out.append(try ramp.record(op.get("outcome") ?? .null, op.get("signal")?.asString).toJson())
                        case "observe"?:
                            let ctx = op.get("ctx") ?? .null
                            let trusted: [String] = (ctx.get("trustedSigners")?.asArray ?? []).compactMap { $0.asString }
                            let ver = ctx.get("verify")
                            out.append(try ramp.recordObservation(op.get("obs"), ctx.get("mapDigest")?.asString ?? "", trusted, ver?.get("expectedSigner")?.asString, Self.opt(ver?.get("pqPins"))))
                        case "rebase"?:
                            ramp.rebase(try Self.make(op.get("omega"), op.get("mapOpts"), op.get("observations")))
                            out.append(.object(["frozen": .bool(ramp.frozen()), "pending": .int(Int64(ramp.pending().count))]))
                        default:
                            out.append(.object(["frozen": .bool(ramp.frozen()), "pending": .array(ramp.pending()), "drift": ramp.drift.state().toJson()]))
                        }
                    }
                    let end: JSONValue = .object(["log": .array(ramp.log.map { $0.toJson() }), "frozen": .bool(ramp.frozen()), "pending": .array(ramp.pending()),
                                                  "metrics": ramp.learner().metrics().json])
                    return .array([.array(out), end])
                }
            case "signObservation": check(d, c) { try PCAIntentObservation.signIntentObservation(try Self.obj(a[0]), try Self.seedBytes(a[1])) }
            case "verifyObservation":
                check(d, c) {
                    let opts = try Self.obj(a[1])
                    var pins: JObject? = nil
                    if let p = opts[JKey("pqPins")], !p.isNull { pins = try Self.obj(p) }
                    return PCAIntentObservation.verifyIntentObservation(a[0], opts[JKey("expectedSigner")]?.asString, pins)
                }
            default: d.skip("\(c.fn): not mapped")
            }
        }
        print("intent runtime and ramp: \(inexact) numbers not bit-identical (within \(Self.tol) relative)")
        d.finish(100)
    }

    // ---- routing and conformance ----

    static func route(_ a: [JSONValue], veto: Bool) throws -> JSONValue {
        let l = try make(a[0], a[1], a[2])
        let ro = try PCAIntentRouting.RouteOptions(json: a[4])
        if veto { for x in a[3].asArray ?? [] { try l.observe(x, y: 0, source: "runtime", region: nil) } }
        var out: [JSONValue] = []
        for o in a[3].asArray ?? [] { out.append(try PCAIntentRouting.routeAction(l, o, ro)) }
        return .array(out)
    }

    /// The reference writes a non-finite number as the text "inf".
    static func infText(_ x: Double) -> JSONValue { x.isFinite ? .double(x) : .string("inf") }

    static func add(_ x: JSONValue, _ key: String, _ d: Double) -> JSONValue {
        guard let n = IV.num(x.get(key)), n.isFinite, abs(n + d) < 9e15 else { return x }
        return setting(x, [key], .int(Int64(n + d)))
    }

    static func tamper(_ att: JSONValue, _ i: Int) -> JSONValue {
        switch i {
        case 1: return setting(att, ["ok"], .bool(att.get("ok") != .bool(true)))
        case 2: return add(att, "aggregate_score_ppm", 1)
        case 3:
            guard var ds = att.get("verdict_digests")?.asArray, !ds.isEmpty else { return att }
            ds.removeLast()
            return setting(att, ["verdict_digests"], .array(ds))
        case 4: return add(att, "k", 1)
        case 5: return setting(att, ["reason"], .string("x"))
        default: return att
        }
    }

    func testRoutingAgainstTheReference() throws {
        let d = Base.Diffs()
        try Base.each("ref-intent-routing.json.gz") { c in
            let a = c.args
            switch c.fn {
            case "routeScenario": check(d, c) { try Self.route(a, veto: false) }
            case "routeVetoScenario": check(d, c) { try Self.route(a, veto: true) }
            case "conformanceScenario":
                check(d, c) {
                    let l = try Self.make(a[0], a[1], a[2])
                    let input = try PCAIntentRouting.judgeInputOf(l, a[3], a[4])
                    let verdicts: [JSONValue] = a[5].asArray ?? []
                    let copts = a[6]
                    let att = try PCAIntentRouting.intentConformanceAttestation(input, verdicts, copts, nil)
                    var tampered: [JSONValue] = []
                    for i in 0..<6 { tampered.append(try PCAIntentRouting.verifyICAtt(Self.tamper(att, i), input, verdicts, copts, nil)) }
                    tampered.append(try PCAIntentRouting.verifyICAtt(att, input, Array(verdicts.dropFirst(min(1, verdicts.count))), copts, nil))
                    return .object(["input": input, "att": att, "digest": .string(PCAIntentRuntime.icAttDigest(att)),
                                    "verify": try PCAIntentRouting.verifyICAtt(att, input, verdicts, copts, nil), "tampered": .array(tampered),
                                    "check": try PCAIntentRouting.checkIntentConformance({ _ in verdicts }, input, copts, nil)])
                }
            case "jitScenario":
                check(d, c) {
                    let l = try Self.make(a[0], a[1], a[2])
                    let oc = a[3]
                    let req = try PCAIntentRouting.jitConsentRequest(l, oc, Self.str(a[5].get("intentRef")), Self.str(a[5].get("mapDigest")))
                    return .object(["req": req, "digest": .string(PCAIntentRuntime.jitConsentDigest(req)),
                                    "result": try PCAIntentRouting.recordJitDecision(l, req, a[4].asString), "metrics": l.metrics().json,
                                    "route": try PCAIntentRouting.routeAction(l, oc, PCAIntentRouting.RouteOptions())])
                }
            case "bondAmount":
                check(d, c) { .double(try PCAIntentBond.bondAmount(try PCAIntentBond.BondPolicy.fromJson(a[0]), try IntentTree.dbl(a[1]))) }
            case "quantizeScore": check(d, c) { .int(PCAIntentSemantic.quantizeScore(try IntentTree.dbl(a[0]))) }
            case "verifyJudgeVerdict":
                check(d, c) {
                    let e = try Self.obj(a[1])
                    var pins: JSONValue? = nil
                    if let p = a[2].asObject?[JKey("pqPins")], !p.isNull { pins = p }
                    return .bool(PCAIntentSemantic.verifyJudgeVerdict(a[0], e[JKey("actionDigest")]?.asString, e[JKey("goalCommitment")]?.asString, pins))
                }
            case "conformalThreshold": check(d, c) { Self.infText(PCAIntentSemantic.conformalThreshold(a[0])) }
            case "empiricalFalseAllowRate": check(d, c) { .double(PCAIntentSemantic.empiricalFalseAllowRate(a[0], try IntentTree.dbl(a[1]))) }
            case "verifySemanticThreshold":
                check(d, c) {
                    var r = try Self.obj(PCAIntentSemantic.verifySemanticThreshold(a[0], .object(try Self.obj(a[1])), nil))
                    if let cut = r[JKey("cutoff")], let x = IV.num(cut) { r[JKey("cutoff")] = Self.infText(x) }
                    return .object(r)
                }
            default: d.skip("\(c.fn): not mapped")
            }
        }
        print("intent routing: \(inexact) numbers not bit-identical (within \(Self.tol) relative)")
        d.finish(50)
    }

    // ---- just-in-time elicitation ----

    static func ceiling(_ name: String?) -> PCAIntentJit.Ceiling {
        switch name {
        case "all"?: return { _, _ in true }
        case "none"?: return { _, _ in false }
        case "amountLe60"?: return { _, o in
            guard let x = IV.num(o.get("values")?.get("action.params.amount")) else { return true }
            return x <= 60
        }
        default: return { _, o in !IV.same(o.get("verb")?.asString, "gmail.send") }
        }
    }

    func testJitAgainstTheReference() throws {
        let d = Base.Diffs()
        try Base.each("ref-intent-jit.json.gz", seeds: true) { c in
            let a = c.args
            switch c.fn {
            case "visitScenario":
                check(d, c) {
                    let cs: [PCAIntentJit.Ceiling] = (a[5].asArray ?? []).map { Self.ceiling($0.asString) }
                    return try PCAIntentJit.decideVisit(try Self.make(a[0], a[1], a[2]), a[3], a[4], cs, a[6] == .bool(true))
                }
            case "cellCoords": check(d, c) { try PCAIntentJit.cellCoords(try Self.verbSpace(a[0]), try Self.ints(a[1])) }
            case "cellFromCoords":
                check(d, c) {
                    guard let r = PCAIntentJit.cellFromCoords(try Self.verbSpace(a[0]), a[1]) else { return .null }
                    return Self.doubles(r)
                }
            case "deltaScenario":
                check(d, c) {
                    let both: JSONValue = .array((a[2].asArray ?? []) + (a[3].asArray ?? []))
                    let prev = try Self.make(a[0], a[1], a[2])
                    let next = try Self.make(a[0], a[1], both)
                    let delta = PCAIntentJit.deltaCells(prev, next)
                    var cells: JObject = [:]
                    for e in delta { cells[JKey(e.verb)] = Self.doubles(e.cells.map { Double($0) }) }
                    return .object(["cells": .object(cells), "predicates": .array(PCAIntentJit.deltaPredicates(next.omega, delta))])
                }
            case "requiredScenario":
                check(d, c) {
                    let om = try WalletOmega(a[0])
                    guard let vs = om.verb(a[1].asString ?? "") else { throw JSError("no such verb") }
                    let cell = try Self.ints(a[2])
                    let site = try Self.edKey(a[4])
                    let body = try PCAIntentJit.intentRequiredBody(a[3], vs, cell)
                    return .object(["signed": try PCAIntentJit.signedIntentRequired(a[3], vs, cell, "site-1", site), "body": body])
                }
            case "walletScenario":
                check(d, c) {
                    let om = try WalletOmega(a[0])
                    guard let vs = om.verb("stripe.refund") else { throw JSError("no such verb") }
                    let siteKey = try Ed25519Deterministic.key(seed: try Self.seedBytes(a[7]))
                    let signed = try PCAIntentJit.signedIntentRequired(a[1], vs, [1, 0], "site-1", PCASuiteKey.ed25519(siteKey))
                    let other: JSONValue = .string(Base64URLStrict.encode(Canonical.sha256(Array("other".utf8))))
                    var body: JSONValue? = IV.normalized(signed)
                    switch a[2].asString {
                    case "coords"?: body = Self.setting(body ?? .null, ["cell", "coords", "action.params.amount"], .array([.int(2), .int(2)]))
                    case "verb"?: body = Self.setting(body ?? .null, ["cell", "verb"], .string("gmail.send"))
                    case "sig"?:
                        let v: String = body?.get("sig")?.get("value")?.asString ?? ""
                        body = Self.setting(body ?? .null, ["sig", "value"], .string(String(v.dropLast(2)) + "AA"))
                    case "kid"?: body = Self.setting(body ?? .null, ["sig", "kid"], .string("other"))
                    case "session"?: body = Self.setting(body ?? .null, ["session"], other)
                    case "action"?: body = Self.setting(body ?? .null, ["action_digest"], other)
                    case "null"?: body = nil
                    default: break
                    }
                    let key: JSONValue = .object(["kid": .string("site-1"), "alg": .string("ed25519"), "pk": .string(siteKey.id)])
                    let now: Double = IV.num(a[3]) ?? .nan
                    let nowL: Int64 = (now != now.rounded(.down) || !now.isFinite || abs(now) > 9e15) ? Int64.min : Int64(now)
                    return PCAIntentJit.walletCheckIntentRequired(body, [key], nowL, a[5].asString ?? "", a[6].asString ?? "", om, a[4], a[1].get("pcactn") ?? .null)
                }
            case "mintScenario":
                check(d, c) {
                    let both: JSONValue = .array((a[2].asArray ?? []) + (a[3].asArray ?? []))
                    let prev = try Self.make(a[0], a[1], a[2])
                    let next = try Self.make(a[0], a[1], both)
                    return try PCAIntentJit.mintDelta(prev, next, a[4], try Self.edKey(a[5])) ?? .null
                }
            default: d.skip("\(c.fn): not mapped")
            }
        }
        print("intent jit: \(inexact) numbers not bit-identical (within \(Self.tol) relative)")
        d.finish(120)
    }

    // ---- trajectory ----

    static func omegaJSON(_ o: WalletOmega, _ approximate: JSONValue?) -> JSONValue {
        .object(["v": .int(1), "verbs": .array(o.verbs.map { PCAIntentJit.verbSpaceJSON($0) }), "approximate": approximate ?? .array([])])
    }

    func testTrajectoryAgainstTheReference() throws {
        let d = Base.Diffs()
        try Base.each("ref-intent-trajectory.json.gz") { c in
            let a = c.args
            func schema(_ i: Int) -> JSONValue? { a.count > i ? a[i] : nil }
            func tilde() throws -> WalletOmega { try PCAIntentTrajectory.augmentOmega(try WalletOmega(a[0]), a[1], a[2]) }
            switch c.fn {
            case "dimKindOf": check(d, c) { .string(PCAIntentTrajectory.dimKindOf(a[0].asString ?? "")) }
            case "accDimPath": check(d, c) { .string(PCAIntentTrajectory.accDimPath(a[0].asString ?? "")) }
            case "monDimPath": check(d, c) { .string(PCAIntentTrajectory.monDimPath(a[0].asString ?? "")) }
            case "trajectoryHarmRange": check(d, c) { .double(try PCAIntentTrajectory.trajectoryHarmRange(IV.num(a[0]) ?? .nan, IV.num(a[1]) ?? .nan)) }
            case "augment":
                check(d, c) { Self.omegaJSON(try PCAIntentTrajectory.augmentOmega(try WalletOmega(a[0]), a[1], schema(2)), a[0].get("approximate")) }
            case "liftScenario":
                check(d, c) {
                    let t = try tilde()
                    let lifted = try PCAIntentTrajectory.liftAction(t, a[1], a[3].asArray ?? [], a[4], schema(5))
                    let lc: PCAIntentTrajectory.LiftedCell? = lifted.flatMap { PCAIntentTrajectory.liftedCell(t, $0) }
                    return .object(["lifted": lifted ?? .null, "cell": lc.map { JSONValue.object(["verb": .string($0.vs.verb), "cell": Self.intsJSON($0.cell)]) } ?? .null])
                }
            case "stepScenario":
                check(d, c) {
                    let t = try tilde()
                    let g = a[5].asString
                    let grant: (String, [Int]) -> Bool = { _, cell in
                        switch g {
                        case "all"?: return true
                        case "none"?: return false
                        case "cell0"?: return cell.allSatisfy { $0 == 0 }
                        default: return cell[0] <= 1
                        }
                    }
                    let s = try PCAIntentTrajectory.stepTrajectory(t, a[1], a[3].asArray ?? [], a[4], grant, schema(6))
                    return .object(["admitted": .bool(s.admitted), "history": .array(s.history), "lifted": s.lifted ?? .null])
                }
            case "defaultAccumulators":
                check(d, c) {
                    let o = a[1]
                    return .array(try PCAIntentTrajectory.defaultAccumulators(a[0], IV.num(o.get("spendDomainMax")) ?? .nan, Self.opt(o.get("questionCap")).flatMap { IV.num($0) }, Self.opt(o.get("holder"))))
                }
            case "describeAccCell":
                check(d, c) {
                    var fmt: ((Double) -> String)? = nil
                    if a[4].asString == "bracket" { fmt = { (x: Double) -> String in "[" + Canonical.numberString(x) + "]" } }
                    return .string(try PCAIntentTrajectory.describeAccCell(try Self.dim(a[0]), Int(IV.num(a[1]) ?? -1), a[2].asString ?? "", Self.opt(a[3]).flatMap { IV.num($0) }, fmt))
                }
            default: d.skip("\(c.fn): not mapped")
            }
        }
        print("intent trajectory: \(inexact) numbers not bit-identical (within \(Self.tol) relative)")
        d.finish(250)
    }

    // ---- profiles ----

    func testProfileAgainstTheReference() throws {
        let d = Base.Diffs()
        try Base.each("ref-intent-profile.json.gz", seeds: true) { c in
            let a = c.args
            switch c.fn {
            case "signIntentProfile": check(d, c) { try PCAIntentProfile.signIntentProfile(a[0], key: try Self.edKey(a[1])) }
            case "intentProfileShapeError":
                check(d, c) {
                    let o: JSONValue? = a.count > 1 ? a[1] : nil
                    let signed = !(o?.asObject != nil && o?.get("signed") == .bool(false))
                    return PCAIntentProfile.intentProfileShapeError(a[0], signed).map { JSONValue.string($0) } ?? .null
                }
            case "verifyIntentProfile": check(d, c) { PCAIntentProfile.verifyIntentProfile(a[0]) }
            case "intentProfileDigest": check(d, c) { .string(PCAIntentProfile.intentProfileDigest(a[0])) }
            case "verifyProfileSuccession": check(d, c) { PCAIntentProfile.verifyProfileSuccession(a[0], a[1]) }
            case "profileApplies": check(d, c) { .bool(PCAIntentProfile.profileApplies(a[0], a[1])) }
            case "standingAdmits": check(d, c) { .bool(PCAIntentProfile.standingAdmits(a[0], a[1], a[2])) }
            case "standingPermits": check(d, c) { .bool(PCAIntentProfile.standingPermits(a[0], a[1], a[2])) }
            case "profileVetoCells": check(d, c) { .array(PCAIntentProfile.profileVetoCells(a[0], try WalletOmega(a[1]))) }
            case "profileCeiling": check(d, c) { .bool(PCAIntentProfile.profileCeiling(a[0], a[1])(try Self.verbSpace(a[2]), a[3])) }
            case "profileUsable": check(d, c) { PCAIntentProfile.profileUsable(a[0], a[1]) }
            default: d.skip("\(c.fn): not mapped")
            }
        }
        print("intent profile: \(inexact) numbers not bit-identical (within \(Self.tol) relative)")
        d.finish(1000)
    }

    // ---- suite signing ----

    func testSuiteSignedArtifactsAgainstTheReference() throws {
        let d = Base.Diffs()
        try Base.each("ref-intent-suite-sign-java.json.gz", seeds: true) { c in
            let a = c.args
            guard ["signStatement", "signObservation", "signProfile"].contains(c.fn) else { d.skip("\(c.fn): not mapped"); return }
            let alg = a[2].asString ?? "ed25519"
            if !MLDSA.available && alg != "ed25519" { d.skip("ML-DSA is not available on this OS"); return }
            check(d, c) {
                let ed = try Ed25519Deterministic.key(seed: try Self.seedBytes(a[1]))
                var key = PCASuiteKey.ed25519(ed)
                if alg != "ed25519" {
                    let level: PCAMLDSALevel = alg.hasSuffix("ml-dsa-87") ? .mlDsa87 : .mlDsa65
                    key = try PCASuiteKey(alg: alg, ed: ed, pq: try PCAPQKey.fromSeed(level, seed: try Self.seedBytes(a[3])))
                }
                switch c.fn {
                case "signStatement":
                    let s = try PCAIntentStatement.signIntent(a[0], key)
                    let who = s.get("principal")?.asString
                    return Self.signShape(s, PCAIntentStatement.verifyIntent(s, nil, Self.pinsOf(s, who)).get("ok") == .bool(true))
                case "signObservation":
                    let s = try PCAIntentObservation.signIntentObservation(try Self.obj(a[0]), key)
                    let who = s.get("signer")?.asString
                    return Self.signShape(s, PCAIntentObservation.verifyIntentObservation(s, nil, Self.pinsOf(s, who)).get("ok") == .bool(true))
                default:
                    let s = try PCAIntentProfile.signIntentProfile(a[0], key: key)
                    let who = s.get("owner")?.asString
                    return Self.signShape(s, PCAIntentProfile.verifyIntentProfile(s, .object(Self.pinsOf(s, who))).get("ok") == .bool(true))
                }
            }
        }
        d.finish(6)
    }
}
