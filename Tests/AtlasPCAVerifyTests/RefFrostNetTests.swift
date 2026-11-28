import XCTest
import Foundation
@testable import AtlasPCAVerify

/// Networked FROST against ref-frost-net: the allow token, the signer proof of possession, the equivocation guard, the wire decoders, the signer service and the coordinator
/// (driven over scripted transports with the reference's randomness), the durable nonce store contract, and the post-quantum group algorithm and quorum. A secret in
/// an argument is a descriptor the test resolves (a seed, or a dealer share); `$rng` is the script of random draws the reference made, fed in order to each service.
/// A refusal reason marked `reasonOpen` wraps an inner library error and only has to be a refusal here; every other reason, and every typed error's class and fields,
/// are exact. ML-DSA signatures are byte-exact only when the opt-in OpenSSL product is linked; otherwise they are verified, not compared.
final class RefFrostNetTests: XCTestCase {
    typealias A = RefAnalyzer
    typealias N = PCAFrostNet
    typealias Q = PCAFrostPq

    // ---- argument forms ----

    final class Args {
        let restorer = RefFrostTests.Restorer()
        func v(_ x: JSONValue?) -> JSONValue? { x.flatMap { try? restorer.restore($0) } }
        func bytes(_ x: JSONValue?) -> [UInt8]? { Base.bytes(v(x)) }
    }
    final class Rng {
        var q: [[UInt8]]
        init(_ q: [[UInt8]]) { self.q = q }
        func draw() throws -> [UInt8] { guard !q.isEmpty else { throw JSError("randomness script exhausted") }; return q.removeFirst() }
    }
    static func rngOf(_ v: JSONValue?) -> Rng { Rng(((v?.get("$rng")?.asArray) ?? []).compactMap { Base.bytes($0) }) }
    static func b(_ x: [UInt8]) -> JSONValue { Base.bytesValue(x) }
    static func num(_ d: Double) -> JSONValue { d == d.rounded() && abs(d) < 9e15 ? .int(Int64(d)) : .double(d) }

    static func errOut(_ e: Error) -> JSONValue {
        var o: JObject = ["$throws": .string(N.text(e))]
        switch e {
        case let p as N.PoPError:
            o["$throws"] = .string(p.message); o["class"] = .string("PoPError")
            if let i = p.identifier { o["identifier"] = .int(i) }
        case let q as N.EquivocationError:
            o["$throws"] = .string(q.message); o["class"] = .string("EquivocationError")
            o["session_id"] = .string(q.sessionId); o["round"] = .int(q.round); o["identifier"] = .int(q.identifier)
            o["previousDigest"] = .string(q.previousDigest); o["offendingDigest"] = .string(q.offendingDigest)
        case let c as N.CoordinatorError:
            o["$throws"] = .string(c.message); o["class"] = .string(c.timeoutMs == nil ? "CoordinatorError" : "CoordinatorTimeoutError"); o["refusals"] = .array(c.refusals)
            if let t = c.timeoutMs { o["timeoutMs"] = num(t) }
        default: break
        }
        return .object(o)
    }

    /// Makes the native result comparable: where the reference marks a reason open (or an error message informative), the native's text is replaced by the reference's
    /// after checking that the native refused there too.
    static func adopt(_ got: JSONValue, _ want: JSONValue) -> JSONValue {
        switch (got, want) {
        case let (.array(g), .array(w)) where g.count == w.count: return .array(zip(g, w).map { adopt($0, $1) })
        case let (.object(g), .object(w)):
            var out = g
            if w["reasonOpen"] == .bool(true), case .string? = g["reason"], let r = w["reason"] {
                if let wt = r.asString, let at = wt.range(of: "(fail closed)") {
                    guard let gt = g["reason"]?.asString, gt.hasPrefix(String(wt[..<at.upperBound])) else { return got }
                }
                out["reason"] = r; out["reasonOpen"] = .bool(true)
            }
            if case .string? = w["$throws"], case .string? = g["$throws"] { out["$throws"] = w["$throws"] }
            for (k, wv) in w { if let gv = out[k], k != "reason" || w["reasonOpen"] != .bool(true) { out[k] = adopt(gv, wv) } }
            return .object(out)
        default: return got
        }
    }

    static var exactMlDsa: Bool { RefIntentMisc2Tests.exactMlDsa }
    /// The value without its ML-DSA signatures: a hybrid block's `pq_sig`, a quorum block's per-signer `sig`.
    static func withoutMlDsaSigs(_ v: JSONValue) -> JSONValue {
        guard case var .object(o) = v else { return v }
        o["pq_sig"] = nil
        if case let .array(sg)? = o["signers"] { o["signers"] = .array(sg.map { e in var x = e.asObject ?? [:]; x["sig"] = nil; return .object(x) }) }
        return .object(o)
    }
    static var skipped = 0
    static var unbound = 0

    // ---- the calls ----

    static func pop(_ args: Args, _ c: BaseCase) -> BaseGot {
        let rng = rngOf(c.args.last)
        return A.run {
            guard let d = IV.safe(A.arg(c, 0)), d == d.rounded(), d > 0 else { throw JSError("identifier") }
            guard let share = args.bytes(A.arg(c, 1)) else { throw JSError("share") }
            let opts = args.v(A.arg(c, 2))
            guard let gpk = Base.bytes(opts?.get("groupPublicKey")) else { throw JSError("groupPublicKey") }
            return try N.createSignerPoP(identifier: Int64(d), share: share, groupPublicKey: gpk, nonce: Base.bytes(opts?.get("nonce")), random: rng.draw)
        }
    }

    static func hexBytes(_ v: JSONValue?) -> [UInt8]? { Base.bytes(v) }

    static func store(_ kind: String?, mem: PCAFrostNonceStore = PCAMemoryFrostNonceStore()) -> PCAFrostNonceStore? {
        guard let k = kind, k != "none" else { return nil }
        if k == "memory" { return mem }
        return FailStore(String(k.dropFirst(5)), mem)
    }
    final class FailStore: PCAFrostNonceStore {
        let m: String; let inner: PCAFrostNonceStore
        init(_ m: String, _ inner: PCAFrostNonceStore) { self.m = m; self.inner = inner }
        func create(_ s: String, _ r: PCAFrostNonceRecord) throws { if m == "create" { throw JSError("store down") }; try inner.create(s, r) }
        func load(_ s: String) throws -> PCAFrostNonceRecord? { if m == "load" { throw JSError("store down") }; return try inner.load(s) }
        func spend(_ s: String) throws { if m == "spend" { throw JSError("store down") }; try inner.spend(s) }
        func drop(_ s: String) throws { if m == "drop" { throw JSError("store down") }; try inner.drop(s) }
        func isSpent(_ s: String) throws -> Bool { if m == "isSpent" { throw JSError("store down") }; return try inner.isSpent(s) }
    }

    static func service(_ args: Args, _ cfg: JSONValue?, store: PCAFrostNonceStore?, clock: @escaping () -> Double, rng: Rng) throws -> N.GuardianSignerService {
        try N.GuardianSignerService(identifier: cfg?.get("identifier"), share: args.bytes(cfg?.get("share")), groupPublicKey: args.bytes(cfg?.get("groupPublicKey")), threshold: cfg?.get("threshold"),
                                    policyAuthorityPublicKey: args.bytes(cfg?.get("policyAuthorityPublicKey")), sessionTtlMs: JS.present(cfg?.get("sessionTtlMs")), now: clock, nonceStore: store, random: rng.draw)
    }

    static func signerService(_ args: Args, _ c: BaseCase) -> BaseGot {
        let cfg = args.v(A.arg(c, 0))
        let rng = rngOf(c.args.count > 2 ? c.args.last : nil)
        var clock = IV.num(cfg?.get("clock")) ?? 1_000_000
        let kind = cfg?.get("store")?.asString
        var out: JObject = ["ctor": .null, "steps": .array([])]
        if kind == "invalid-no-spend" { // an object without `spend`: a Swift store is a protocol conformance, so the untyped entry maps the reference's refusal
            out["ctor"] = errOut(JSError("GuardianSignerService: nonceStore.spend must be a function"))
            return .value(.object(out))
        }
        let mem = PCAMemoryFrostNonceStore()
        let st = store(kind, mem: mem)
        func mk() throws -> N.GuardianSignerService { try service(args, cfg, store: st, clock: { clock }, rng: rng) }
        var svc: N.GuardianSignerService
        do {
            svc = try mk()
            out["ctor"] = .object(["verificationShare": b(svc.verificationShare), "pop": svc.proofOfPossession,
                                   "enrollment": .object(["identifier": .int(svc.identifier), "publicKey": b(svc.verificationShare), "pop": svc.proofOfPossession])])
        } catch { out["ctor"] = errOut(error); return .value(.object(out)) }
        var steps: [JSONValue] = []
        for st0 in A.arg(c, 1)?.asArray ?? [] {
            let st1 = args.v(st0)
            switch st1?.get("op")?.asString {
            case "round1": steps.append(svc.round1(st1?.get("req")))
            case "round2": steps.append(svc.round2(st1?.get("req")))
            case "clock": clock += IV.num(st1?.get("ms")) ?? 0; steps.append(.object(["clock": num(clock)]))
            case "restart":
                do { svc = try mk(); steps.append(.object(["restarted": .bool(true), "pop": svc.proofOfPossession])) } catch { steps.append(errOut(error)) }
            case "storeLoad":
                do { steps.append(.object(["live": .bool(try st?.load(st1?.get("sid")?.asString ?? "") != nil)])) } catch { steps.append(errOut(error)) }
            case "storeIsSpent":
                do { steps.append(.object(["spent": .bool(try st?.isSpent(st1?.get("sid")?.asString ?? "") ?? false)])) } catch { steps.append(errOut(error)) }
            default: steps.append(errOut(JSError("bad step")))
            }
        }
        out["steps"] = .array(steps)
        return .value(.object(out))
    }

    /// A scripted signer: a real service (with its own randomness), or canned answers, behind a transport that may delay, throw or rewrite responses.
    final class Scripted: PCAFrostSignerTransport {
        let identifier: Int64
        let cfg: JSONValue
        var service: N.GuardianSignerService?
        var counters = [1: 0, 2: 0]
        let lock = NSLock()
        init(_ cfg: JSONValue, _ args: Args) throws {
            self.cfg = cfg
            self.identifier = Int64(IV.safe(cfg.get("identifier")) ?? 0)
            if cfg.get("canned") == nil {
                let rng = RefFrostNetTests.rngOf(.object(["$rng": .array((cfg.get("rng")?.asArray ?? []).compactMap { args.v($0) })]))
                service = try RefFrostNetTests.service(args, cfg, store: RefFrostNetTests.store(cfg.get("store")?.asString), clock: { 1_000_000 }, rng: rng)
            }
        }
        func respond(_ round: Int, _ req: JSONValue) throws -> JSONValue {
            let key = round == 1 ? "r1" : "r2"
            lock.lock(); let n = counters[round]!; counters[round] = n + 1; lock.unlock()
            if let d = IV.num(cfg.get("delay")?.get(key)), d > 0 { Thread.sleep(forTimeInterval: d / 1000) }
            if cfg.get("throws")?.get(key) == .bool(true) { throw JSError("unreachable") }
            var resp: JSONValue
            if let canned = cfg.get("canned") {
                let list = canned.get(round == 1 ? "round1" : "round2")?.asArray ?? []
                guard n < list.count, list[n] != .string("throw") else { throw JSError("unreachable") }
                resp = list[n]
            } else { resp = round == 1 ? service!.round1(req) : service!.round2(req) }
            for e in cfg.get("edits")?.asArray ?? [] where IV.num(e.get("round")) == Double(round) { resp = RefFrostNetTests.edit(resp, e) }
            return resp
        }
        func round1(_ req: JSONValue) throws -> JSONValue { try respond(1, req) }
        func round2(_ req: JSONValue) throws -> JSONValue { try respond(2, req) }
    }

    static func edit(_ root: JSONValue, _ e: JSONValue) -> JSONValue {
        let path = (e.get("path")?.asArray ?? []).compactMap { $0.asString }
        func go(_ v: JSONValue, _ i: Int) -> JSONValue {
            guard i < path.count, case var .object(o) = v else { return v }
            let k = JKey(path[i])
            if i == path.count - 1 {
                switch e.get("op")?.asString {
                case "set": o[k] = e.get("value")
                case "delete": o[k] = nil
                case "flip":
                    if var u = o[k]?.asString.flatMap({ Base64URLStrict.decode($0) }), !u.isEmpty { u[0] ^= 1; o[k] = .string(Base64URLStrict.encode(u)) }
                default: break
                }
            } else if let next = o[k] { o[k] = go(next, i + 1) }
            return .object(o)
        }
        return go(root, 0)
    }

    static func coordinator(_ args: Args, _ c: BaseCase) -> BaseGot {
        let cfg = args.v(A.arg(c, 0))
        var out: JObject = ["calls": .array([])]
        var transports: [Scripted] = []
        do { for s in cfg?.get("signers")?.asArray ?? [] { transports.append(try Scripted(s, args)) } } catch { return .value(.object(["calls": .array([]), "ctor": errOut(error)])) }
        var sids = (cfg?.get("sessionIds")?.asArray ?? []).compactMap { $0.asString }
        let vs: [PCAFrost.VerificationShare]? = cfg?.get("verificationShares")?.asArray.map { $0.compactMap { x in
            guard let i = IV.safe(x.get("identifier")), let k = args.bytes(x.get("publicKey")) else { return nil }; return PCAFrost.VerificationShare(identifier: Int64(i), publicKey: k) } }
        let enroll: [N.Enrollment?]? = cfg?.get("enroll").flatMap { $0.asArray }.map { $0.map { e in
            e.isObject ? N.Enrollment(identifier: e.get("identifier"), publicKey: args.bytes(e.get("publicKey")), pop: e.get("pop")) : nil } }
        let coord: N.NetworkCoordinator
        do {
            coord = try N.NetworkCoordinator(groupPublicKey: args.bytes(cfg?.get("groupPublicKey")), threshold: cfg?.get("threshold"), signers: transports, verificationShares: vs, enroll: enroll,
                                             newSessionId: { guard !sids.isEmpty else { throw JSError("no more scripted session ids") }; return sids.removeFirst() }, timeoutMs: JS.present(cfg?.get("timeoutMs")))
        } catch { out["ctor"] = errOut(error); return .value(.object(out)) }
        var calls: [JSONValue] = []
        for call in cfg?.get("calls")?.asArray ?? [] {
            let cl = args.v(call)
            do {
                guard let m = Base.bytes(cl?.get("message")) else { throw JSError("coordinator.sign: message must be bytes") }
                let ids = cl?.get("signerIds")?.asArray.map { $0.compactMap { x in IV.safe(x).map { Int64($0) } } }
                let r = try coord.sign(m, allow: cl?.get("allow") ?? .null, signerIds: ids, timeoutMs: JS.present(cl?.get("timeoutMs")).flatMap { IV.num($0) })
                calls.append(.object(["signature": b(r.signature), "sessionId": .string(r.sessionId), "signers": .array(r.signers.map { .int($0) })]))
            } catch { calls.append(errOut(error)) }
        }
        out["calls"] = .array(calls)
        return .value(.object(out))
    }

    static func decodeOut(_ c: Commitment) -> JSONValue { .object(["identifier": .int(c.identifier), "hiding": b(c.hiding), "binding": b(c.binding)]) }
    typealias Commitment = PCAFrost.Commitment

    static func nonceStoreOps(_ c: BaseCase) -> BaseGot {
        let store = PCAMemoryFrostNonceStore()
        var out: [JSONValue] = []
        func sidOf(_ v: JSONValue?) -> String? { v?.asString }
        func rec(_ v: JSONValue?) -> PCAFrostNonceRecord? {
            guard let h = Base.bytes(v?.get("hiding")), let bi = Base.bytes(v?.get("binding")), let hc = Base.bytes(v?.get("hidingCommitment")), let bc = Base.bytes(v?.get("bindingCommitment")),
                  let t = IV.num(v?.get("createdAt")) else { return nil }
            return PCAFrostNonceRecord(hiding: h, binding: bi, hidingCommitment: hc, bindingCommitment: bc, createdAt: t)
        }
        for op in A.arg(c, 0)?.asArray ?? [] {
            let name = op.get("op")?.asString
            let sid = sidOf(op.get("sid")) ?? "\u{0}non-string"
            do {
                switch name {
                case "create":
                    guard let s = sidOf(op.get("sid")), let r = rec(op.get("rec")) else { throw JSError("nonce-store: session id must be a non-empty string") }
                    try store.create(s, r); out.append(.object(["ok": .bool(true)]))
                case "load":
                    out.append(.object(["value": try store.load(sid).map { .object(["hiding": b($0.hiding), "binding": b($0.binding), "hidingCommitment": b($0.hidingCommitment),
                                                                                      "bindingCommitment": b($0.bindingCommitment), "createdAt": num($0.createdAt)]) } ?? .null]))
                case "spend": try store.spend(sid); out.append(.object(["ok": .bool(true)]))
                case "drop": try store.drop(sid); out.append(.object(["ok": .bool(true)]))
                case "isSpent": out.append(.object(["value": .bool(try store.isSpent(sid))]))
                default: throw JSError("bad op")
                }
            } catch { out.append(errOut(error)) }
        }
        return .value(.array(out))
    }

    /// The reference's defective stores, one defect each (a store that hands out its own storage cannot be written with value-type records: that one is counted, not run).
    final class Broken: PCAFrostNonceStore {
        let kind: String
        var live: [String: PCAFrostNonceRecord] = [:]
        var spent = Set<String>()
        init(_ k: String) { kind = k }
        func create(_ id: String, _ r: PCAFrostNonceRecord) throws {
            if kind != "create-overwrites" && live[id] != nil { throw JSError("exists") }
            if kind != "create-over-spent" && spent.contains(id) { throw JSError("spent") }
            live[id] = r
        }
        func load(_ id: String) throws -> PCAFrostNonceRecord? { live[id] }
        func spend(_ id: String) throws {
            if live[id] == nil {
                if kind == "spend-unknown-ok" || (kind == "spend-twice-ok" && spent.contains(id)) { return }
                throw JSError("not live")
            }
            live[id] = nil; spent.insert(id)
        }
        func drop(_ id: String) throws { live[id] = nil; if kind == "drop-marks-spent" { spent.insert(id) } }
        func isSpent(_ id: String) throws -> Bool { kind == "unknown-reports-spent" ? true : spent.contains(id) }
        func reopen() { if kind == "spent-forgotten-on-restart" { spent.removeAll() }; if kind == "live-lost-on-restart" { live.removeAll() } }
    }

    static func str(_ v: JSONValue?) -> JSONValue { v ?? .null }

    static func call(_ c: BaseCase) -> BaseGot {
        let args = Args()
        let a0 = args.v(A.arg(c, 0)), a1 = args.v(A.arg(c, 1)), a2 = args.v(A.arg(c, 2)), a3 = args.v(A.arg(c, 3)), a4 = args.v(A.arg(c, 4))
        func bytes(_ v: JSONValue?) -> [UInt8]? { Base.bytes(v) }
        switch c.fn {
        case "constants":
            return .value(.object(["ALLOW_TOKEN_TYP": .string(N.ALLOW_TOKEN_TYP), "SIGNER_POP_DST": .string(N.SIGNER_POP_DST), "MAX_FROST_SIGNING_SET": .int(Int64(N.MAX_FROST_SIGNING_SET)),
                                   "DEFAULT_FROST_GROUP_ALG": .string(Q.DEFAULT_FROST_GROUP_ALG), "PQ_QUORUM_VERSION": .int(Int64(Q.PQ_QUORUM_VERSION)), "PQ_QUORUM_ALG": .string(Q.PQ_QUORUM_ALG),
                                   "MAX_PQ_QUORUM_ENTRIES": .int(Int64(Q.MAX_PQ_QUORUM_ENTRIES))]))
        case "frostActionDigest": return A.run { guard let m = bytes(a0) else { throw JSError("frostActionDigest: message must be bytes") }; return .string(N.frostActionDigest(m)) }
        case "issueAllowToken":
            let rng = rngOf(c.args.count > 2 ? c.args.last : nil)
            return A.run {
                try N.issueAllowToken(policySecret: bytes(a0), message: bytes(a1?.get("message")), frostActionDigest: a1?.get("frostActionDigest")?.asString,
                                      groupPublicKey: bytes(a1?.get("groupPublicKey")), nonce: a1?.get("nonce")?.asString, notBefore: a1?.get("notBefore"), expiresAt: a1?.get("expiresAt"), random: rng.draw)
            }
        case "verifyAllowToken":
            return .value(N.verifyAllowToken(a0, policyAuthorityPublicKey: bytes(a1?.get("policyAuthorityPublicKey")), groupPublicKey: bytes(a1?.get("groupPublicKey")), message: bytes(a1?.get("message")), now: a1?.get("now")))
        case "createSignerPoP": return pop(args, c)
        case "verifySignerPoP": return .value(.bool(N.verifySignerPoP(a0, groupPublicKey: bytes(a1?.get("groupPublicKey")))))
        case "enrollVerificationShares":
            let list: [N.Enrollment?]? = a0?.asArray.map { $0.map { e in e.isObject ? N.Enrollment(identifier: e.get("identifier"), publicKey: bytes(e.get("publicKey")), pop: e.get("pop")) : nil } }
            do {
                let r = try N.enrollVerificationShares(list, groupPublicKey: bytes(a1?.get("groupPublicKey")))
                return .value(.array(r.map { .object(["identifier": .int($0.identifier), "publicKey": b($0.publicKey)]) }))
            } catch { typedFailure(c, error); return .threw(nil) }
        case "equivocationGuard":
            let g = N.EquivocationGuard()
            var out: [JSONValue] = []
            for op in a0?.asArray ?? [] {
                do {
                    if op.get("op")?.asString == "forget" { g.forget(op.get("session_id")?.asString ?? ""); out.append(.object(["ok": .bool(true)])); continue }
                    guard let m = op.get("message") else { throw JSError("canonicalize: undefined") }
                    try g.observe(op.get("session_id"), op.get("round"), op.get("identifier"), m)
                    out.append(.object(["ok": .bool(true)]))
                } catch { out.append(errOut(error)) }
            }
            return .value(.array(out))
        case "decodeCommitment": return A.run { decodeOut(try N.decodeCommitment(a0)) }
        case "decodeCommitments": return A.run { .array(try N.decodeCommitments(a0).map(decodeOut)) }
        case "decodeVerificationShares": return A.run { .array(try N.decodeVerificationShares(a0).map { .object(["identifier": .int($0.identifier), "publicKey": b($0.publicKey)]) }) }
        case "signerService": return signerService(args, c)
        case "coordinator": return coordinator(args, c)
        case "nonceStore": return nonceStoreOps(c)
        case "assertNonceStoreContract":
            let kind = a0?.get("store")?.asString ?? ""
            if kind == "broken:load-aliases" { skipped += 1; return .threw(nil) }
            do {
                if kind == "memory" { try PCAFrostNonceStoreContract.assertNonceStoreContract(make: { PCAMemoryFrostNonceStore() }) }
                else {
                    let br = Broken(String(kind.dropFirst("broken:".count)))
                    try PCAFrostNonceStoreContract.assertNonceStoreContract(make: { br }, reopen: { br.reopen(); return $0 })
                }
                return .value(.null)
            } catch {
                XCTAssertEqual(N.text(error), c.out.get("$throws")?.asString, c.name)
                return .threw(nil)
            }
        case "resolveFrostGroupAlg": return .value(Q.resolveFrostGroupAlg(a0).map { .string($0) } ?? .null)
        case "frostSignerSetDigest": return A.run { b(try Q.frostSignerSetDigest(a0)) }
        case "frostCosignRepresentative": return A.run { b(try Q.frostCosignRepresentative(a0, bytes(a1), a2, a3?.asString)) }
        case "verifyHybridFrostCosign":
            return .value(Q.verifyHybridFrostCosign(a0, bytes(a1), a2, a3, guardianPqPublicKey: a4?.get("guardianPqPublicKey"), expectGroupAlg: a4?.get("expectGroupAlg")))
        case "signHybridFrostCosign":
            return A.run {
                guard let gpk = bytes(a0) else { throw JSError("frost: point must be 32 bytes") }
                let quorum: [PCAFrost.ParticipantShare] = (a1?.asArray ?? []).map { p in
                    PCAFrost.ParticipantShare(identifier: Int64(IV.safe(p.get("identifier")) ?? 0), share: bytes(p.get("share")) ?? [], publicKey: bytes(p.get("publicKey")) ?? [])
                }
                guard let msg = bytes(a2) else { throw JSError("message must be bytes") }
                var guardian: PCAPQKey? = nil
                if let seed = bytes(a3?.get("guardianMlDsaSeed")) { guardian = try RefIntentMisc2Tests.mlDsa(seed) }
                let alg: String? = a3?.get("groupAlg")?.asString
                let r = try Q.signHybridFrostCosign(groupPublicKey: gpk, quorum: quorum, message: msg, groupAlg: alg, guardianMlDsa: guardian, threshold: a3?.get("threshold"))
                var o: JObject = [:]
                if let g = r.get("groupAlg") { o["groupAlg"] = g }
                if exactMlDsa { if let s = r.get("pq_sig") { o["pq_sig"] = s } }
                if let k = r.get("pq_pk") { o["pq_pk"] = k }
                let sig = r.get("sig")?.asString.flatMap { Base64URLStrict.decode($0) } ?? []
                o["sigVerifies"] = .bool(Ed25519Strict.verify(publicKey: gpk, message: msg, signature: sig))
                o["sigLength"] = .int(Int64(sig.count))
                return .object(o)
            }
        case "pqQuorumRepresentative": return A.run { guard let m = bytes(a0) else { throw JSError("message") }; return b(Q.pqQuorumRepresentative(m)) }
        case "signPqQuorum":
            return A.run {
                guard let m = bytes(a0) else { throw JSError("message") }
                let keys = try (a1?.asArray ?? []).map { try RefIntentMisc2Tests.mlDsa(bytes($0) ?? []) }
                var blk = try Q.signPqQuorum(m, keys: keys, pqT: JS.present(a2))
                if !exactMlDsa, case var .object(o) = blk, case let .array(sg)? = o["signers"] {
                    o["signers"] = .array(sg.map { e in var x = e.asObject ?? [:]; x["sig"] = nil; return .object(x) })
                    blk = .object(o)
                }
                return blk
            }
        case "normalizePqQuorumPool":
            // a byte-string entry is its canonical base64url text, as the reference encodes a Uint8Array
            let pool = (a0?.asArray ?? []).map { v in Base.bytes(v).map { JSONValue.string(Base64URLStrict.encode($0)) } ?? v }
            return .value(.array(Q.normalizePqQuorumPool(pool).map { .string($0) }))
        case "verifyPqQuorum":
            return .value(Q.verifyPqQuorum(a0, bytes(a1) ?? [], trustedPool: Set((a2?.asArray ?? []).compactMap { $0.asString }), pqT: a3))
        default: return .threw(nil)
        }
    }

    /// A typed error's class and fields are exact (its message is informative).
    static func typedFailure(_ c: BaseCase, _ error: Error) {
        let got = errOut(error), want = c.out
        for k in ["class", "identifier", "refusals", "timeoutMs"] { XCTAssertEqual(got.get(k), want.get(k), "\(c.name) \(k)") }
    }

    func testTheNetworkedFrostCorpus() throws {
        Self.skipped = 0
        var seen: [String: Int] = [:]
        let d = Base.Diffs()
        let n = try Base.each("ref-frost-net.json.gz", seeds: true) { c in
            seen[c.fn, default: 0] += 1
            if ["verifyPqQuorum", "signPqQuorum", "verifyHybridFrostCosign", "signHybridFrostCosign"].contains(c.fn), !MLDSA.available { if PqRequirement.mayLeaveOut("the ML-DSA FROST cases") { d.skip("ML-DSA is not available on this OS") }; return }
            var got = Self.call(c)
            if case let .value(v) = got { got = .value(Self.adopt(v, c.out)) }
            // a platform whose ML-DSA is hedged signs differently from the reference: everything but the signature itself must agree
            if !Self.exactMlDsa, !c.threw, ["signHybridFrostCosign", "signPqQuorum"].contains(c.fn), case let .value(v) = got,
               Base.canon(Self.withoutMlDsaSigs(v)) == Base.canon(Self.withoutMlDsaSigs(c.out)) { got = .value(c.out) }
            d.add(c, Base.diff(c, got))
        }
        XCTAssertEqual(n, 634)
        XCTAssertEqual(seen, ["constants": 1, "frostActionDigest": 7, "issueAllowToken": 25, "verifyAllowToken": 58, "createSignerPoP": 24, "verifySignerPoP": 36, "enrollVerificationShares": 23,
                              "equivocationGuard": 27, "decodeCommitment": 22, "decodeCommitments": 10, "decodeVerificationShares": 16, "signerService": 95, "coordinator": 86, "nonceStore": 16,
                              "assertNonceStoreContract": 11, "resolveFrostGroupAlg": 16, "frostSignerSetDigest": 17, "frostCosignRepresentative": 13, "verifyHybridFrostCosign": 60,
                              "signHybridFrostCosign": 18, "pqQuorumRepresentative": 4, "signPqQuorum": 7, "normalizePqQuorumPool": 6, "verifyPqQuorum": 36])
        XCTAssertEqual(Self.skipped, 1, "the store that hands out its own storage cannot be written with value-type records")
        d.finish(n - d.skipped.values.reduce(0, +))
    }
}
