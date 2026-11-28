import XCTest
import Foundation
@testable import AtlasPCAVerify

/// Differential replay of proof of progress against the reference (the corpus's potential kinds, registries, guards and sources are built by the helpers
/// here, from the specs in the corpus header).
final class RefProgressTests: XCTestCase {
    typealias PG = PCAProgress

    /// A potential of a corpus spec kind: the three built-ins, `const:N`, `v` (the state's `v` untouched) and the failing ones.
    static func kindFn(_ k: String) throws -> PG.PotentialFn {
        switch k {
        case "l1-feature-v1": return PG.l1FeaturePotential
        case "dag-remaining-v1": return PG.dagRemainingPotential
        case "dag-weighted-v1": return PG.dagWeightedPotential
        case "v": return { _, s in s?.get("v") }
        case "throws": return { _, _ in throw JSError("potential boom") }
        case "negative": return { _, _ in .int(-1) }
        case "frac": return { _, _ in .double(0.5) }
        case "nan": return { _, _ in .double(.nan) }
        case "big": return { _, _ in .double(9007199254740992) }
        default:
            if k.hasPrefix("const:"), let n = Int64(k.dropFirst(6)) { return { _, _ in .int(n) } }
            throw JSError("bad potential kind \(k)")
        }
    }

    private func registryOps(_ ops: [JSONValue]) -> JSONValue {
        var r = PG.PotentialRegistry()
        var out: [JSONValue] = []
        func fail(_ e: Error) -> JSONValue { .object(["$err": .string((e as? JSError)?.message ?? "\(e)")]) }
        for op in ops {
            let a = op.asArray ?? []
            do {
                switch a.first?.asString {
                case "new": r = PG.PotentialRegistry(); out.append(.null)
                case "defaults": r = PG.PotentialRegistry.defaults(); out.append(.null)
                case "default-frozen": r = PG.DEFAULT_POTENTIALS; out.append(.null)
                case "from":
                    let nr = PG.PotentialRegistry()
                    for (k, v) in JS.keyOrder(a[1].asObject ?? [:]).map({ ($0.s, a[1].asObject![$0]!) }) {
                        if let s = v.asString { try nr.register(.string(k), try Self.kindFn(s)) }
                        else { try nr.register(.string(k), try Self.kindFn(v.get("fn")?.asString ?? ""), embedder: v.get("embedder")) }
                    }
                    r = nr; out.append(.null)
                case "register": try r.register(a[1], try Self.kindFn(a[2].asString ?? ""), embedder: a.count > 3 ? a[3] : nil); out.append(.null)
                case "get": out.append(r.get(a[1].asString ?? "").map { .object(["embedder": .string($0.embedder)]) } ?? .null)
                case "has": out.append(.bool(r.has(a[1].asString ?? "")))
                case "ids": out.append(.array(r.ids().map { .string($0) }))
                case "freeze": r.freeze(); out.append(.null)
                default: throw JSError("bad op")
                }
            } catch { out.append(fail(error)) }
        }
        return .array(out)
    }

    /// The functions of the pure part of the module.
    static let pureFns: Set<String> = ["constants", "l1FeaturePotential", "dagRemainingPotential", "dagWeightedPotential", "registryOps", "goalDigest", "commitGoal",
                                       "verifyGoalCommitment", "stateDigest", "trajectoryHead", "progressStepDigest", "trajectoryAnchorCommit", "verifyTrajectoryAnchor"]

    func testPureFunctions() throws {
        let d = Base.Diffs()
        var seen = 0
        let n = try Base.each("ref-progress.json.gz", Self.pureFns) { c in
            seen += 1
            let a = c.args.map { RefAnalyzer.revive($0) }
            func arg(_ i: Int) -> JSONValue? { i < a.count ? a[i] : nil }
            let got = Base.run({ ($0 as? JSError)?.code }) { () -> JSONValue in
                switch c.fn {
                case "constants":
                    return .object(["PROGRESS_VERSION": .int(Int64(PG.PROGRESS_VERSION)), "PROGRESS_SIG_DOMAIN": .string(PG.PROGRESS_SIG_DOMAIN),
                                    "TRAJECTORY_ANCHOR_DOMAIN": .string(PG.TRAJECTORY_ANCHOR_DOMAIN), "STATE_ATTESTATION_DOMAIN": .string(PG.STATE_ATTESTATION_DOMAIN)])
                case "l1FeaturePotential": return try PG.l1FeaturePotential(arg(0), arg(1)) ?? .null
                case "dagRemainingPotential": return try PG.dagRemainingPotential(arg(0), arg(1)) ?? .null
                case "dagWeightedPotential": return try PG.dagWeightedPotential(arg(0), arg(1)) ?? .null
                case "registryOps": return self.registryOps(arg(0)?.asArray ?? [])
                case "goalDigest": return .string(try PG.goalDigest(arg(0)))
                case "commitGoal": return try PG.commitGoal(arg(0))
                case "verifyGoalCommitment": return .bool(PG.verifyGoalCommitment(arg(0), arg(1)))
                case "stateDigest": return .string(try PG.stateDigest(arg(0)))
                case "trajectoryHead": return try PG.trajectoryHead(arg(0))
                case "progressStepDigest": return try PG.progressStepDigest(arg(0))
                case "trajectoryAnchorCommit": return .string(try PG.trajectoryAnchorCommit(arg(0), arg(1)))
                case "verifyTrajectoryAnchor": return .bool(PG.verifyTrajectoryAnchor(arg(0), arg(1), arg(2)))
                default: XCTFail("unhandled fn \(c.fn)"); return .null
                }
            }
            if case let .value(v) = got { d.add(c, Base.diff(c, .value(RefAnalyzer.out(v)))) } else { d.add(c, Base.diff(c, got)) }
        }
        XCTAssertEqual(n, 270)
        XCTAssertEqual(seen, 270)
        d.finish(270)
    }

    // ---- host objects of the corpus specs ----

    /// A registry spec: nil / null is the default; `registry` mode builds it now, `record` mode when it is used (as the reference converts a plain record
    /// on use, so a bad id is a malformed check rather than a failed case).
    static func registrySpec(_ s: JSONValue?) throws -> (() throws -> PG.PotentialRegistry)? {
        guard let s = JS.present(s) else { return nil }
        let pots = s.get("potentials")?.asArray ?? []
        func entry(_ e: JSONValue) -> (id: JSONValue, kind: String, emb: JSONValue?) { (e.asArray?[0] ?? .null, e.asArray?[1].asString ?? "", (e.asArray?.count ?? 0) > 2 ? e.asArray?[2] : nil) }
        if s.get("mode") == .string("record") {
            return {
                let r = PG.PotentialRegistry()
                var order: [String] = [], last: [String: (kind: String, emb: JSONValue?)] = [:]
                for e in pots { let x = entry(e); let k = x.id.asString ?? ""; if last[k] == nil { order.append(k) }; last[k] = (x.kind, x.emb) }
                for k in order {
                    let v = last[k]!
                    if let emb = v.emb { try r.register(.string(k), try kindFn(v.kind), embedder: JS.present(emb) ?? .string("")) } else { try r.register(.string(k), try kindFn(v.kind)) }
                }
                return r
            }
        }
        let r = PG.PotentialRegistry()
        for e in pots { let x = entry(e); try r.register(x.id, try kindFn(x.kind), embedder: x.emb) }
        return { r }
    }

    static func guardSpec(_ g: JSONValue?) throws -> PG.StepGuard? {
        guard let g = JS.present(g)?.asString else { return nil }
        switch g {
        case "allow": return { _ in .bool(true) }
        case "deny": return { _ in .bool(false) }
        case "throws": return { _ in throw JSError("guard boom") }
        case "truthy": return { _ in .string("yes") }
        default:
            if g.hasPrefix("action:") { let d = String(g.dropFirst(7)); return { t in .bool(t.get("action_digest")?.asString != d) } }
            if g.hasPrefix("seq:"), let n = Int64(g.dropFirst(4)) { return { t in .bool(t.get("seq")?.safeInt != n) } }
            if g.hasPrefix("after-v:"), let n = Int64(g.dropFirst(8)) { return { t in .bool(t.get("after")?.get("v")?.safeInt != n) } }
            throw JSError("bad guard \(g)")
        }
    }

    static func attestationSpec(_ a: JSONValue?) -> PG.StateAttestationVerifier? {
        guard let a = JS.present(a) else { return nil }
        switch a.asString {
        case "allow"?: return { _ in .bool(true) }
        case "deny"?: return { _ in .bool(false) }
        case "throws"?: return { _ in throw JSError("att boom") }
        case "truthy"?: return { _ in .string("yes") }
        default:
            let f = PG.attestedStateVerifier(a.get("attested") ?? .null)
            return { step in .bool(f(step)) }
        }
    }

    static func stepOptions(_ o: JSONValue?) throws -> PG.VerifyStepOptions {
        var s = PG.VerifyStepOptions()
        s.expectedSeq = o?.get("expectedSeq")
        s.expectedPrev = o?.get("expectedPrev")
        s.expectedActionDigest = o?.get("expectedActionDigest")
        s.expectedBeforeDigest = o?.get("expectedBeforeDigest")
        s.expectedAfterDigest = o?.get("expectedAfterDigest")
        s.registry = try registrySpec(o?.get("registry"))
        s.guardFn = try guardSpec(o?.get("guard"))
        s.trustedStateSources = o?.get("trustedStateSources")?.asArray
        s.requireAttestedState = o?.get("requireAttestedState")
        s.attestation = attestationSpec(o?.get("attestation"))
        return s
    }

    static func trajectoryOptions(_ o: JSONValue?) throws -> PG.VerifyTrajectoryOptions {
        var t = PG.VerifyTrajectoryOptions()
        t.step = try stepOptions(o)
        t.initial = o?.get("initial")
        t.initialDigest = o?.get("initialDigest")
        t.expectedActionDigests = o?.get("expectedActionDigests")?.asArray
        return t
    }

    /// The verification functions of the module (the tracker, the sources and the ledger anchor are replayed by the second test).
    static let verifyFns: Set<String> = ["verifyProgressStep", "verifyTrajectory", "verifySignedProgressStep", "verifySignedTrajectory", "signProgressStep",
                                         "verifyStateAttestation", "attestedStateVerifier"]

    func testVerification() throws {
        let d = Base.Diffs()
        var seen: [String: Int] = [:]
        var unbound = 0
        let n = try Base.each("ref-progress.json.gz", Self.verifyFns) { c in
            seen[c.fn, default: 0] += 1
            let a = c.args.map { RefAnalyzer.revive($0) }
            func arg(_ i: Int) -> JSONValue? { i < a.count ? a[i] : nil }
            let got = Base.run({ ($0 as? JSError)?.code }) { () -> JSONValue in
                switch c.fn {
                case "verifyProgressStep": return PG.verifyProgressStep(arg(0), arg(1), arg(2), try Self.stepOptions(arg(3)))
                case "verifyTrajectory": return PG.verifyTrajectory(arg(0), arg(1), arg(2), try Self.trajectoryOptions(arg(3)))
                case "verifySignedProgressStep":
                    return PG.verifySignedProgressStep(arg(0), arg(1), arg(2), expectedHolder: arg(3)?.get("expectedHolder"), expectedActionDigest: arg(3)?.get("expectedActionDigest"),
                                                       try Self.stepOptions(arg(3)))
                case "verifySignedTrajectory":
                    return PG.verifySignedTrajectory(arg(0), arg(1), arg(2), expectedHolder: arg(3)?.get("expectedHolder"),
                                                     expectedActionDigests: arg(3)?.get("expectedActionDigests")?.asArray ?? [], try Self.trajectoryOptions(arg(3)))
                case "signProgressStep":
                    guard let label = arg(1)?.get("$bytes")?.get("$seed")?.asString, let holder = arg(2)?.asString else { throw JSError("bad signer") }
                    return try PG.signProgressStep(arg(0) ?? .null, key: try RefAnalyzer.key(label), holderPublicKey: holder)
                case "verifyStateAttestation": return .bool(PG.verifyStateAttestation(arg(0), arg(1), JS.present(arg(2))))
                case "attestedStateVerifier": return .bool(PG.attestedStateVerifier(arg(0) ?? .null)(arg(1) ?? .null))
                default: XCTFail("unhandled fn \(c.fn)"); return .null
                }
            }
            // allowUnboundPq is never ported (the reference keeps it as a legacy insecure opt-out): what it alone lets through is REFUSED here
            if c.fn == "verifyStateAttestation", arg(2)?.get("allowUnboundPq") == .bool(true), c.out == .bool(true), case .value(.bool(false)) = got {
                unbound += 1
                return
            }
            if case let .value(v) = got { d.add(c, Base.diff(c, .value(RefAnalyzer.out(v)))) } else { d.add(c, Base.diff(c, got)) }
        }
        XCTAssertEqual(n, 395)
        XCTAssertEqual(seen, ["verifyProgressStep": 147, "verifyTrajectory": 130, "verifySignedProgressStep": 26, "verifySignedTrajectory": 15, "signProgressStep": 7,
                              "verifyStateAttestation": 55, "attestedStateVerifier": 15])
        // the two post-quantum attestations the reference accepts only through allowUnboundPq (ruling: never ported): refused
        XCTAssertEqual(unbound, 2)
        d.finish(393)
    }

    // ---- state sources, the tracker and the ledger anchor ----

    /// A source of the corpus: the world it observes, and how it misbehaves (`liar-digest`, `liar-source`, `throws`, `null`).
    final class CorpusSource: PG.StateSource {
        let id: String
        let kind: String
        private var world: JSONValue
        private var mem: PG.InMemoryStateSource?
        private var att: PG.AttestedStateSource?
        var attestations: [JSONValue]? { att?.attestations }

        init(_ spec: JSONValue) throws {
            id = spec.get("id")?.asString ?? ""
            kind = spec.get("kind")?.asString ?? ""
            let initial = spec.get("initial") ?? .null
            world = initial
            if kind == "attested" {
                guard let label = spec.get("signerSecret")?.get("$seed")?.asString else { throw JSError("private key of length 32 expected, got 3") }
                if let alg = JS.present(spec.get("alg"))?.asString, alg != "ed25519" { throw JSError("AttestedStateSource: unknown signature alg '\(alg)'") }
                att = try PG.AttestedStateSource(id: id, key: try RefAnalyzer.key(label), observeState: { [unowned self] _ in self.world })
            } else {
                mem = try PG.InMemoryStateSource(initial: initial, id: id)
            }
        }

        func set(_ n: JSONValue) throws { world = n; try mem?.apply(n) }

        private func lie(_ req: JSONValue, _ key: String, _ value: JSONValue) throws -> JSONValue? {
            guard let ob = try mem?.observe(req) else { return nil }
            var o = ob.asObject ?? [:]
            o[JKey(key)] = value
            return .object(o)
        }

        func observe(_ req: JSONValue) throws -> JSONValue? {
            switch kind {
            case "attested": return try att?.observe(req)
            case "throws": throw JSError("source boom")
            case "null": return nil
            case "liar-digest": return try lie(req, "state_digest", .string(String(repeating: "x", count: 43)))
            case "liar-source": return try lie(req, "source", .string("someone-else"))
            default: return try mem?.observe(req)
            }
        }
    }

    static func fail(_ e: Error) -> JSONValue { .object(["$err": .string((e as? JSError)?.message ?? (e as? PG.ProgressError)?.message ?? "\(e)")]) }

    private func runTracker(_ a: [JSONValue]) throws -> JSONValue {
        func arg(_ i: Int) -> JSONValue? { i < a.count ? a[i] : nil }
        let srcs = try (arg(5)?.asArray ?? []).map { try CorpusSource($0) }
        let goal = arg(0) ?? .null
        let commitment: JSONValue = try JS.present(arg(1)) ?? .string(PG.goalDigest(goal))
        let t = try PG.ProgressTracker(goal: goal, commitment: commitment, initial: arg(2) ?? .null, registry: try Self.registrySpec(arg(3)), guardFn: try Self.guardSpec(arg(4)))
        var out: [JSONValue] = []
        for op in arg(6)?.asArray ?? [] {
            let o = op.asArray ?? []
            do {
                switch o.first?.asString {
                case "step": out.append(t.step(o[1], o[2]))
                case "stepObserved": out.append(t.stepObserved(srcs[Int(o[1].safeInt ?? 0)], o[2]))
                case "apply": try srcs[Int(o[1].safeInt ?? 0)].set(o[2]); out.append(.null)
                case "steps": out.append(.array(t.steps))
                case "state": out.append(t.state)
                case "currentStateDigest": out.append(.string(t.currentStateDigest))
                case "spent": out.append(.int(t.spent))
                case "remaining": out.append(.int(t.remaining))
                case "reached": out.append(.bool(try t.reached()))
                default: throw JSError("bad op")
                }
            } catch { out.append(Self.fail(error)) }
        }
        return .array(out)
    }

    static let proverFns: Set<String> = ["tracker", "attestedSource", "anchorTrajectoryHead"]

    func testTrackerSourcesAndAnchor() throws {
        let d = Base.Diffs()
        var seen: [String: Int] = [:]
        let n = try Base.each("ref-progress.json.gz", Self.proverFns) { c in
            seen[c.fn, default: 0] += 1
            let a = c.args.map { RefAnalyzer.revive($0) }
            func arg(_ i: Int) -> JSONValue? { i < a.count ? a[i] : nil }
            let got = Base.run({ ($0 as? PG.ProgressError)?.code ?? ($0 as? JSError)?.code }) { () -> JSONValue in
                switch c.fn {
                case "tracker": return try self.runTracker(a)
                case "attestedSource":
                    let src = try CorpusSource(arg(0) ?? .null)
                    var obs: [JSONValue] = []
                    for r in arg(1)?.asArray ?? [] { do { obs.append(try src.observe(r) ?? .null) } catch { obs.append(Self.fail(error)) } }
                    var o: JObject = ["observations": .array(obs)]
                    if let at = src.attestations { o["attestations"] = .array(at) } else if arg(0)?.get("kind")?.asString == "memory" { o["attestations"] = .null } // the in-memory source reports null
                    return .object(o)
                case "anchorTrajectoryHead":
                    let ledger = PCATransparencyLedger(principal: "p")
                    for p in arg(2)?.asArray ?? [] { try ledger.appendCommitment(p.asString ?? "") }
                    return try PG.anchorTrajectoryHead(ledger, arg(0), salt: arg(1)?.asString)
                default: XCTFail("unhandled fn \(c.fn)"); return .null
                }
            }
            if case let .value(v) = got { d.add(c, Base.diff(c, .value(RefAnalyzer.out(v)))) } else { d.add(c, Base.diff(c, got)) }
        }
        XCTAssertEqual(n, 58)
        XCTAssertEqual(seen, ["tracker": 40, "attestedSource": 8, "anchorTrajectoryHead": 10])
        d.finish(58)
    }
}
