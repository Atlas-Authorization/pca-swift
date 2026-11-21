import XCTest
import Foundation
@testable import AtlasPCAVerify

/// Differential replay of the wallet side of the Intent Layer v2 (PCAWallet, PCAWalletCard, PCAWalletPricing, PCAWalletPopulation,
/// PCAWalletDelivery, WalletTrustedChannel: signed answers, friction tiers, cell coordinates, noise numerics, canaries, approval
/// fatigue, risk-priced escalation, the trusted card, clarification, population priors, question delivery and the whole question
/// channel) against the TypeScript reference (@atlasauth/pca-wallet). A reference throw requires a native refusal.
///
/// Numbers: doubles computed through the platform libm (lnGamma, betaInc, the noise estimates, the Gaussian mechanism, the cell
/// statistics, ...) are compared bit for bit first; a result that differs in the last bits is accepted within 1e-12 relative and counted
/// ("not bit-identical", printed per function) because the reference's fdlibm and the platform libm may round a transcendental
/// differently. Everything else is compared as canonical JSON.
///
/// Not replayed: the learner-side corpora of other lanes (learnerView, priorAdmittedPpm need the intent learner, which this SDK does not
/// carry). A webhook delivery's JSON text is compared as parsed JSON (a parsed object has no member order). Cases carrying a lone
/// surrogate are skipped by the harness (a Swift String cannot hold one).
final class RefWalletTests: XCTestCase {
    static let file = "ref-wallet.json.gz"
    static let tol = 1e-12

    // ---- value helpers ----

    static func num(_ v: JSONValue?) throws -> Double {
        guard let d = IV.num(v) else { throw JSError("not a number") }
        return d
    }

    static func ints(_ v: JSONValue?) throws -> [Int] {
        guard let a = v?.asArray else { throw JSError("not an array") }
        return try a.map { guard let i = IV.safe($0) else { throw JSError("not an integer") }; return Int(i) }
    }

    static func ints2(_ v: JSONValue?) throws -> [[Int]] {
        guard let a = v?.asArray else { throw JSError("not an array") }
        return try a.map { try ints($0) }
    }

    static func cells(_ v: JSONValue?) throws -> [(verb: String, idx: [Int])] {
        guard let a = v?.asArray else { throw JSError("not an array") }
        return try a.map { guard let verb = $0.get("verb")?.asString else { throw JSError("no verb") }; return (verb, try ints($0.get("idx"))) }
    }

    static func seq(_ xs: JSONValue?) -> () throws -> Double {
        let list = (xs?.asArray ?? []).map { IV.num($0) ?? .nan }
        var i = 0
        return {
            if i >= list.count { throw JSError("rand exhausted") }
            i += 1
            return list[i - 1]
        }
    }

    static func seed(_ v: JSONValue?) throws -> [UInt8] {
        guard let l = v?.get("$seed")?.asString else { throw JSError("no key in the case") }
        return RefKeys.seed(l)
    }

    var om: [String: JSONValue] = [:]

    /// The corpus's `{"$omega": id}` placeholders -> the outcome space; everything else is kept.
    func sub(_ v: JSONValue?) -> JSONValue? {
        switch v {
        case let .object(o)?:
            if o.count == 1, let id = o["$omega"]?.asString { return om[id] }
            return .object(o.mapValues { sub($0) ?? .null })
        case let .array(a)?: return .array(a.map { sub($0) ?? .null })
        default: return v
        }
    }

    func omega(_ id: JSONValue?) throws -> WalletOmega {
        guard let k = id?.asString, let o = om[k] else { throw JSError("no such outcome space") }
        return try WalletOmega(o)
    }

    func verbOf(_ id: JSONValue?, _ verb: JSONValue?) throws -> WalletVerb {
        guard let v = verb?.asString, let vs = try omega(id).verb(v) else { throw JSError("no such verb") }
        return vs
    }

    // ---- comparison ----

    var inexact: [String: Int] = [:]

    /// Numbers within 1e-12 relative (counting the ones that are not bit-identical); everything else as canonical JSON.
    func close(_ a: JSONValue?, _ b: JSONValue?, _ fn: String) -> Bool {
        switch (a, b) {
        case let (.object(x)?, .object(y)?):
            return Set(x.keys) == Set(y.keys) && x.allSatisfy { close($0.value, y[$0.key], fn) }
        case let (.array(x)?, .array(y)?):
            return x.count == y.count && zip(x, y).allSatisfy { close($0, $1, fn) }
        default:
            if let p = IV.num(a), let q = IV.num(b) {
                if p == q || (p.isNaN && q.isNaN) { return true }
                inexact[fn, default: 0] += 1
                return abs(p - q) <= Self.tol * max(abs(p), abs(q)) + 1e-15
            }
            return Base.canon(a) == Base.canon(b)
        }
    }

    func check(_ d: Base.Diffs, _ c: BaseCase, _ got: BaseGot, approx: Bool = false, norm: ((JSONValue) -> JSONValue)? = nil) {
        guard case let .value(v) = got, !c.threw else { d.add(c, Base.diff(c, got)); return }
        let want = norm.map { $0(c.out) } ?? c.out
        let have = norm.map { $0(v) } ?? v
        if approx ? close(want, have, c.fn) : Base.canon(want) == Base.canon(have) { d.add(c, nil) }
        else { d.add(c, "\(c.name): want \(Base.firstDiff(want, have, "@")) || want \(Base.canon(want).prefix(300)) got \(Base.canon(have).prefix(300))") }
    }

    // ---- scenario helpers ----

    static func sliding(_ window: JSONValue?, _ ops: JSONValue?) throws -> JSONValue {
        let c: PCAWallet.SlidingWindowCounter
        if window == nil || window == .null { c = try PCAWallet.SlidingWindowCounter() } else { c = try PCAWallet.SlidingWindowCounter(windowMs: num(window)) }
        return .array((ops?.asArray ?? []).map { op -> JSONValue in
            do {
                let a = op.asArray ?? []
                let now = try num(a.count > 1 ? a[1] : nil)
                if a.first?.asString == "count" { return WJ.obj([("v", WJ.i(c.count(now)))]) }
                return WJ.obj([("v", .bool(try c.tryAdd(now, num(a.count > 2 ? a[2] : nil))))])
            } catch { return WJ.obj([("err", .bool(true))]) }
        })
    }

    /// Webhook bodies are JSON text: parsed before comparison.
    static func normCalls(_ v: JSONValue) -> JSONValue {
        guard case var .object(o) = v, let calls = o["calls"]?.asArray else { return v }
        o["calls"] = .array(calls.map { call in
            guard case var .object(c) = call, let b = c["body"]?.asString else { return call }
            c["body"] = K042.parse(b)
            return .object(c)
        })
        return .object(o)
    }

    static func step(_ script: [JSONValue], _ i: inout Int) -> JSONValue? {
        defer { i += 1 }
        return i < script.count ? script[i] : nil
    }

    func hook(_ cfg: JSONValue?, _ script: JSONValue?, _ notices: JSONValue?) -> JSONValue {
        let steps = script?.asArray ?? []
        var idx = 0
        var calls: [JSONValue] = []
        let fetch: PCAWalletDelivery.FetchLike = { url, initV in
            calls.append(WJ.obj([("url", .string(url)), ("method", initV.get("method") ?? .null), ("headers", initV.get("headers") ?? .null), ("body", initV.get("body") ?? .null)]))
            let st = Self.step(steps, &idx) ?? WJ.obj([("ok", .bool(true)), ("status", WJ.i(200))])
            if let t = st.get("throw") { throw JSError(t.asString ?? "") }
            return (st.get("ok") == .bool(true), st.get("status") ?? .null)
        }
        let headers = cfg?.get("headers")
        let ch = PCAWalletDelivery.questionWebhookChannel(url: cfg?.get("url")?.asString, headers: (headers.map { JS.truthy($0) } ?? false) ? headers?.asObject : nil, fetch: fetch)
        let deliveries = (notices?.asArray ?? []).map { ch.notify($0) }
        return WJ.obj([("kind", .string(ch.kind)), ("enabled", .bool(ch.enabled)), ("deliveries", .array(deliveries)), ("calls", .array(calls))])
    }

    func tchan(_ kind: JSONValue?, _ name: JSONValue?, _ script: JSONValue?, _ notices: JSONValue?) -> JSONValue {
        let steps = script?.asArray ?? []
        var idx = 0
        var sent: [JSONValue] = []
        var send: ((JSONValue) throws -> Void)?
        if script != nil && script != .null {
            send = { body in
                sent.append(body)
                if let st = Self.step(steps, &idx), let t = st.get("throw") { throw JSError(t.asString ?? "") }
            }
        }
        let ch = PCAWalletDelivery.questionTextChannel(kind: kind?.asString ?? "", siteName: name, send: send)
        let deliveries = (notices?.asArray ?? []).map { ch.notify($0) }
        return WJ.obj([("kind", .string(ch.kind)), ("enabled", .bool(ch.enabled)), ("deliveries", .array(deliveries)), ("sent", .array(sent))])
    }

    func dispatch(_ cfgs: JSONValue?, _ notice: JSONValue?) -> JSONValue {
        var chans: [PCAWalletDelivery.QuestionChannel] = []
        for c in cfgs?.asArray ?? [] {
            if c.get("type")?.asString == "webhook" {
                chans.append(PCAWalletDelivery.questionWebhookChannel(url: c.get("url")?.asString, fetch: { _, _ in (true, WJ.i(200)) }))
            } else {
                var send: ((JSONValue) throws -> Void)?
                if JS.truthy(c.get("enabled")) { send = { _ in } }
                chans.append(PCAWalletDelivery.questionTextChannel(kind: c.get("type")?.asString ?? "", siteName: .string("S"), send: send))
            }
        }
        return WJ.obj([("n", WJ.i(chans.count)), ("deliveries", .array(PCAWalletDelivery.notifyAll(chans, notice ?? .null)))])
    }

    func aggregate(_ a: [JSONValue?]) throws -> JSONValue {
        let agg = try PCAWalletPopulation.Aggregator(schemaDigest: a[0], period: a[1] ?? .null, maxCellsPerPrincipal: a[2]?.get("maxCellsPerPrincipal"), rand: Self.seq(a[5]))
        let votes = (a[3]?.asArray ?? []).map { agg.contribute($0) }
        let release: JSONValue
        do { release = try agg.release(a[4]) } catch { release = WJ.obj([("err", .bool(true))]) }
        return WJ.obj([("votes", .array(votes)), ("release", release)])
    }

    func prior(_ a: [JSONValue?]) throws -> JSONValue {
        let beta = try Self.num(a[1])
        let p = try PCAWalletPopulation.populationPrior(a[0], beta)
        let contained = Set(try Self.ints(a[4]))
        let w = try p.weight(try verbOf(a[2], a[3])) { contained.contains($0) }
        return WJ.obj([("beta", .double(p.beta)), ("weight", .double(w))])
    }

    func pick(_ ctx0: JSONValue?) throws -> JSONValue {
        guard let ctx = sub(ctx0) else { throw JSError("no ctx") }
        let knownNo = ctx.get("knownNo")
        let c = try PCAWallet.pickCanary(omega: try WalletOmega(ctx.get("omega")), confirmed: try Self.cells(ctx.get("confirmed")),
                                         knownNo: { verb, idx in knownNo?.get(PCAWallet.cellKey(verb, idx))?.asString },
                                         knownYes: try Self.cells(ctx.get("knownYes")), exclude: Set((ctx.get("exclude")?.asArray ?? []).compactMap { $0.asString }),
                                         rand: Self.seq(ctx.get("rands")), rho: ctx.get("rho").map { IV.num($0) ?? .nan }, lowHarmSession: JS.truthy(ctx.get("lowHarmSession")),
                                         canariesSoFar: try Self.num(ctx.get("canariesSoFar")))
        return c?.json ?? .null
    }

    func viewOf(_ v: JSONValue?) -> PCAWalletCard.View {
        let p = v?.get("p"), vetoed = Set((v?.get("vetoed")?.asArray ?? []).compactMap { $0.asString }), ceiling = Set((v?.get("ceiling")?.asArray ?? []).compactMap { $0.asString })
        return PCAWalletCard.View(p: { verb, idx in IV.num(p?.get(PCAWallet.cellKey(verb, idx))) ?? 0 },
                                  vetoed: { vetoed.contains(PCAWallet.cellKey($0, $1)) }, outsideCeiling: { ceiling.contains(PCAWallet.cellKey($0, $1)) },
                                  confirmed: { ((try? Self.cells(v?.get("confirmed"))) ?? []) })
    }

    func plan(_ x0: JSONValue?) throws -> JSONValue {
        guard let x = sub(x0) else { throw JSError("no input") }
        let p = try PCAWalletCard.planClarification(omega: try WalletOmega(x.get("omega")), view: viewOf(x.get("view")), candidates: x.get("candidates")?.asArray ?? [],
                                                    asked: Set((x.get("asked")?.asArray ?? []).compactMap { $0.asString }), etaPos: try Self.num(x.get("etaPos")),
                                                    etaNeg: try Self.num(x.get("etaNeg")))
        return p.json
    }

    func render(_ x: JSONValue?) throws -> JSONValue {
        guard case var .object(o)? = x, let id = o["omegaId"]?.asString, let space = om[id] else { throw JSError("no omega") }
        o["omegaId"] = nil
        switch try PCAWalletCard.renderCard(try WalletOmega(space), .object(o)) {
        case let .success(card): return WJ.obj([("ok", .bool(true)), ("card", card)])
        case let .failure(f): return WJ.obj([("ok", .bool(false)), ("reason", .string(f.reason))])
        }
    }

    func resolve(_ a: [JSONValue?]) throws -> JSONValue {
        switch try PCAWallet.resolveCoords(try WalletOmega(sub(a[0])), a[1], a[2]) {
        case let .success(r): return WJ.obj([("ok", .bool(true)), ("verb", .string(r.vs.verb)), ("box", .array(r.box.map { WJ.arr($0) }))])
        case let .failure(f): return WJ.obj([("ok", .bool(false)), ("reason", .string(f.reason))])
        }
    }

    /// One session of the question channel (see the generator for the spec); a step that throws records {"$err": true}.
    func channel(_ spec0: JSONValue?) throws -> JSONValue {
        guard let spec = sub(spec0), let session = spec.get("session") else { throw JSError("no spec") }
        let omegaV = try WalletOmega(spec.get("omega"))
        var t = IV.num(spec.get("t0")) ?? 0
        var counts = spec.get("noise") ?? .null
        let hourly: PCAWallet.SlidingWindowCounter
        if spec.get("windowMs") != nil { hourly = try PCAWallet.SlidingWindowCounter(windowMs: try Self.num(spec.get("windowMs"))) } else { hourly = try PCAWallet.SlidingWindowCounter() }
        for ts in spec.get("hourlyPre")?.asArray ?? [] { _ = try hourly.tryAdd(try Self.num(ts), 9007199254740991) }
        let v = spec.get("view")
        let mapDigest = spec.get("mapDigest") ?? .null
        let lift = spec.get("lift")?.get("add"), liftCand = spec.get("liftCand")
        var opts = WalletChannelOptions(omega: omegaV, session: session, mapDigest: { mapDigest }, principalSeed: RefKeys.seed(spec.get("principal")?.asString ?? ""),
                                        site: spec.get("site") ?? .null, view: viewOf(v), hourly: hourly, noise: { counts }, onNoise: { counts = $0 },
                                        rand: Self.seq(spec.get("rands")), now: { t })
        func truthy(_ k: String) -> JSONValue? { spec.get(k).flatMap { JS.truthy($0) ? $0 : nil } }
        if let s = spec.get("statementText") { opts.statementText = s }
        if let u = truthy("units") { opts.units = u }
        if let s = truthy("sensitivity") { opts.sensitivity = s }
        if let p = truthy("identityPaths") { opts.identityPaths = (p.asArray ?? []).compactMap { $0.asString } }
        if let c = truthy("caps") { opts.caps = (IV.num(c.get("perSession")), IV.num(c.get("perHour"))) }
        if let r = spec.get("rho") { opts.rho = IV.num(r) }
        if let f = truthy("fatigue") { opts.fatigue = f }
        if let m = spec.get("maxPerScreen") { opts.maxPerScreen = IV.num(m) }
        if let m = spec.get("maxBoxCells") { opts.maxBoxCells = IV.num(m) }
        if let dv = truthy("device") {
            var sc: [String: Double]?
            if case let .object(o)? = dv.get("signCounts") { sc = [:]; for (k, x) in o { sc![k.s] = IV.num(x) ?? 0 } }
            opts.device = WalletDeviceState(rpId: dv.get("rpId")?.asString ?? "", origins: (dv.get("origins")?.asArray ?? []).compactMap { $0.asString },
                                            credentials: dv.get("credentials") ?? .object([:]), signCounts: sc)
        }
        if let l = truthy("lift") {
            _ = l
            opts.lift = { a in
                guard case var .object(o) = try PCAWallet.actionValuesOf(a), case var .object(vals)? = o["values"] else { throw JSError("lift") }
                for (k, x) in lift?.asObject ?? [:] { vals[k] = x }
                o["values"] = .object(vals)
                return .object(o)
            }
        }
        if let l = truthy("liftCand") {
            _ = l
            opts.liftCandidate = { a in
                guard case var .object(o) = a, case var .object(vals)? = o["values"] else { throw JSError("liftCandidate") }
                for (k, x) in liftCand?.asObject ?? [:] { vals[k] = x }
                o["values"] = .object(vals)
                return WJ.obj([("verb", o["verb"] ?? .null), ("values", .object(vals))])
            }
        }
        let ch = WalletTrustedChannel(opts)
        var seen: [String] = []
        var steps: [JSONValue] = []
        let sid = session.asString ?? ""
        let resolver: (String) -> WalletTrustedChannel? = { $0 == sid ? ch : nil }
        for st in spec.get("steps")?.asArray ?? [] {
            let op = st.get("op")?.asString ?? ""
            var r: JSONValue
            do {
                var qid: String?
                if let q = st.get("q") { if let i = IV.safe(q), i >= 0, Int(i) < seen.count { qid = seen[Int(i)] } } else { qid = st.get("qid")?.asString }
                switch op {
                case "time": t = try Self.num(st.get("t")); r = WJ.obj([("t", .double(t))])
                case "receive": r = try ch.receive(st.get("ir") ?? .null, action: st.get("action") ?? .null)
                case "next":
                    r = ch.nextScreen()
                    for x in r.get("questions")?.asArray ?? [] { if let id = x.get("questionId")?.asString { seen.append(id) } }
                case "answer": r = try ch.answer(qid, st.get("response"))
                case "clarify": r = try ch.clarify(st.get("body"))
                case "hQuestion": r = try PCAWalletHandlers.questionHandler(resolver)(st.get("sid")?.asString ?? sid, st.get("body"))
                case "hClarify": r = try PCAWalletHandlers.clarifyHandler(resolver)(st.get("sid")?.asString ?? sid, st.get("body"))
                case "summary": r = try ch.summary()
                case "state": r = WJ.obj([("digest", .string(try ch.stateDigest())), ("asked", WJ.i(ch.questionsAsked()))])
                case "noise": r = WJ.obj([("noise", try ch.noise()), ("admission", try ch.admission())])
                case "challenge": r = try ch.deviceChallengeFor(qid)
                default: throw JSError("bad op " + op)
                }
            } catch { r = WJ.obj([("$err", .bool(true))]) }
            steps.append(WJ.obj([("op", .string(op)), ("r", r)]))
        }
        var signCounts: JSONValue = .null
        if let dev = opts.device, let sc = dev.signCounts { signCounts = .object(Dictionary(uniqueKeysWithValues: sc.map { (JKey($0.key), JSONValue.double($0.value)) })) }
        return WJ.obj([("steps", .array(steps)), ("noise", counts), ("signCounts", signCounts)])
    }

    static func constants() -> JSONValue {
        let strs = { (xs: [String]) in JSONValue.array(xs.map { .string($0) }) }
        return WJ.obj([
            ("FRICTION_ORDER", strs(PCAWallet.FRICTION_ORDER)), ("INTENT_ANSWER_SIG_DOMAIN", .string(PCAWallet.INTENT_ANSWER_SIG_DOMAIN)),
            ("INTENT_ANSWER_REF_DOMAIN", .string(PCAWallet.INTENT_ANSWER_REF_DOMAIN)), ("INTENT_TYPED_DOMAIN", .string(PCAWallet.INTENT_TYPED_DOMAIN)),
            ("INTENT_DEVICE_CHALLENGE_DOMAIN", .string(PCAWallet.INTENT_DEVICE_CHALLENGE_DOMAIN)), ("MIN_HOLD_MS", WJ.i(PCAWallet.MIN_HOLD_MS)),
            ("PROVENANCE_ORDER", strs(PCAWallet.PROVENANCE_ORDER)), ("DEFAULT_FRICTION_THRESHOLDS", WJ.obj([("hTap", WJ.i(5)), ("hDevice", WJ.i(100_000))])),
            ("CARD_DOMAIN", .string(PCAWalletCard.CARD_DOMAIN)), ("CLARIFY_REASONS", strs(PCAWalletCard.CLARIFY_REASONS)),
            ("REASON_LABELS", .object(Dictionary(uniqueKeysWithValues: PCAWalletCard.REASON_LABELS.map { (JKey($0.key), JSONValue.string($0.value)) }))),
            ("MAX_CANDIDATES", WJ.i(PCAWalletCard.MAX_CANDIDATES)), ("EMPTY_NOISE", PCAWallet.EMPTY_NOISE), ("NOISE_PRIOR", PCAWallet.NOISE_PRIOR),
            ("DEFAULT_FATIGUE", PCAWallet.DEFAULT_FATIGUE), ("PPM", WJ.i(PCAWalletPricing.PPM)), ("MAX_MULTIPLIER_PPM", WJ.i(PCAWalletPricing.MAX_MULTIPLIER_PPM)),
            ("POPULATION_VOTE_DOMAIN", .string(PCAWalletPopulation.POPULATION_VOTE_DOMAIN)), ("BETA_MAX", .double(PCAWalletPopulation.BETA_MAX)),
        ])
    }

    // ---- the replay ----

    func testWallet() throws {
        try K042.requireCovers(["Wallet", "JSInterop"])
        let d = Base.Diffs()
        let normReason: (JSONValue) -> JSONValue = { v in
            // "malformed answer: <engine message>" is compared as the prefix only
            if case var .object(o) = v, let r = o["reason"]?.asString, r.hasPrefix("malformed answer:") { o["reason"] = .string("malformed answer"); return .object(o) }
            return v
        }
        try Base.each(Self.file) { c in
            let a = (0..<6).map { c.arg($0) }
            let a0 = a[0], a1 = a[1], a2 = a[2]
            func n(_ i: Int) throws -> Double { try Self.num(a[i]) }
            var approx = false
            let got: BaseGot
            switch c.fn {
            case "omegas":
                if let o = c.out.asObject { for (k, v) in o { om[k.s] = v } }
                return
            case "constants":
                let want = c.out.asObject ?? [:]
                let have = Self.constants().asObject ?? [:]
                for (k, v) in want { d.add(c, Base.canon(v) == Base.canon(have[k]) ? nil : "\(c.name): constant \(k.s) differs") }
                return
            case "isFrictionTier": got = .value(.bool(PCAWallet.isFrictionTier(a0)))
            case "frictionRank": got = .value(WJ.i(PCAWallet.frictionRank(a0)))
            case "maxFriction": got = .value(PCAWallet.maxFriction(c.args))
            case "satisfiesTier": got = .value(.bool(PCAWallet.satisfiesTier(a0, a1)))
            case "isProvenanceLevel": got = .value(.bool(PCAWallet.isProvenanceLevel(a0)))
            case "worstProvenance": got = Ref.v { .string(try PCAWallet.worstProvenance(a0)) }
            case "frictionFor": got = Ref.v { try PCAWallet.frictionFor(a0, a1) }
            case "pcaActionDigest": got = Ref.v { .string(try PCAWallet.pcaActionDigest(a0)) }
            case "actionValuesOf": got = Ref.v { try PCAWallet.actionValuesOf(a0) }
            case "isB64u32": got = .value(.bool(PCAWallet.isB64u32(a0)))
            case "isObj": got = .value(.bool(PCAWallet.isObj(a0)))
            case "coordsError": got = .value(Base.opt(PCAWallet.coordsError(a0)))
            case "answerShapeError": got = .value(Base.opt(PCAWallet.answerShapeError(a0)))
            case "signIntentAnswer": got = Ref.v { try PCAWallet.signIntentAnswer(a0, seed: try Self.seed(a1)) }
            case "verifyIntentAnswer": got = .value(PCAWallet.verifyIntentAnswer(a0, a1))
            case "answerRef": got = Ref.v { .string(try PCAWallet.answerRef(a0)) }
            case "typedDigest":
                guard let q = a0?.asString, let v = a1?.asString else { d.skip("typedDigest: non-string argument"); return }
                got = Ref.v { .string(try PCAWallet.typedDigest(q, v)) }
            case "deviceChallenge":
                got = Ref.v { .string(try PCAWallet.deviceChallenge(questionId: a0?.get("questionId"), renderedDigest: a0?.get("renderedDigest"), y: a0?.get("y"), actionDigest: a0?.get("actionDigest"))) }
            case "lnGamma": approx = true; got = Ref.v { .double(WalletStats.lnGamma(try n(0))) }
            case "betacf": approx = true; got = Ref.v { .double(WalletStats.betacf(try n(0), try n(1), try n(2))) }
            case "betaInc": approx = true; got = Ref.v { .double(try WalletStats.betaInc(try n(0), try n(1), try n(2))) }
            case "betaQuantile": approx = true; got = Ref.v { .double(try WalletStats.betaQuantile(try n(0), try n(1), try n(2))) }
            case "clopperPearsonUpper": approx = true; got = Ref.v { .double(try WalletOmegaMath.clopperPearsonUpper(a0, a1, a2)) }
            case "binEnt": approx = true; got = Ref.v { .double(WalletStats.binEnt(try n(0))) }
            case "recordCanary": got = Ref.v { try PCAWallet.recordCanary(a0, expected: a1, y: a2) }
            case "estimateNoise": approx = true; got = Ref.v { var dc = 0.05; if a1 != nil { dc = try n(1) }; return try PCAWallet.estimateNoise(a0, deltaC: dc) }
            case "cellKey": got = Ref.v { .string(PCAWallet.cellKey(a0?.asString ?? "", try Self.ints(a1))) }
            case "boundaryNeighbours":
                got = Ref.v {
                    let r = PCAWallet.boundaryNeighbours(try WalletOmega(sub(a0)), try Self.cells(a1))
                    return .array(r.map { WJ.obj([("verb", .string($0.verb)), ("idx", WJ.arr($0.idx))]) })
                }
            case "pickCanary": got = Ref.v { try pick(a0) }
            case "etaUnderLoad": approx = true; got = Ref.v { .double(try PCAWallet.etaUnderLoad(try n(0), try n(1), try n(2))) }
            case "noiseState": approx = true; got = Ref.v { try PCAWallet.noiseState(a0, try n(1), a2) }
            case "admissionPolicy": approx = true; got = Ref.v { try PCAWallet.admissionPolicy(a0, a1) }
            case "doubleConfirmed":
                got = Ref.v {
                    guard let recs = a0?.asArray else { throw JSError("not an array") }
                    return .bool(PCAWallet.doubleConfirmed(try recs.map { (try Self.num($0.get("screen")), $0.get("tier")?.asString ?? "") }))
                }
            case "slidingWindow": got = Ref.v { try Self.sliding(a0, a1) }
            case "signPricingConfig": got = Ref.v { try PCAWalletPricing.signPricingConfig(a0, seed: try Self.seed(a1)) }
            case "pricingConfigError": got = .value(Base.opt(PCAWalletPricing.pricingConfigError(a0)))
            case "freshCalibration": got = .value(PCAWalletPricing.freshCalibration())
            case "decideEscalation": got = .value(PCAWalletPricing.decideEscalation(a0, a1, a2))
            case "signAnswer": got = Ref.v { try PCAWalletPricing.signAnswer(a0, seed: try Self.seed(a1)) }
            case "updateCalibration": got = Ref.v { try PCAWalletPricing.updateCalibration(a0, a1, a2, a[3]) }
            case "signAutonomyRaise": got = Ref.v { try PCAWalletPricing.signAutonomyRaise(a0, seed: try Self.seed(a1)) }
            case "applyAutonomyRaise": got = Ref.v { try PCAWalletPricing.applyAutonomyRaise(a0, a1, seed: try Self.seed(a2)) }
            case "omega.verbCellCount": got = Ref.v { WJ.i(WalletOmegaMath.verbCellCount(try verbOf(a0, a1))) }
            case "omega.cellCount": got = Ref.v { WJ.i(WalletOmegaMath.cellCount(try verbOf(a0, a1).dims[Int(try n(2))])) }
            case "omega.numCells":
                got = Ref.v { .array(WalletOmegaMath.numCells(try verbOf(a0, a1).dims[Int(try n(2))]).map { WJ.obj([("lo", WJ.i($0.lo)), ("hi", WJ.i($0.hi))]) }) }
            case "omega.labelOf": got = .value(.string(WalletOmegaMath.labelOf(a0?.asString ?? "")))
            case "omega.decodeCell": got = Ref.v { WJ.arr(WalletOmegaMath.decodeCell(try verbOf(a0, a1), Int(try n(2)))) }
            case "omega.cellStats":
                approx = true
                got = Ref.v { let s = WalletOmegaMath.cellStats(try verbOf(a0, a1), try Self.ints(a2)); return WJ.obj([("mass", .double(s.mass)), ("harm", .double(s.harm))]) }
            case "omega.cellRep": got = Ref.v { WalletOmegaMath.cellRep(try verbOf(a0, a1), try Self.ints(a2)) }
            case "omega.cellOf":
                got = Ref.v { WalletOmegaMath.cellOf(try verbOf(a0, a1), values: a2?.get("values")).map { WJ.arr($0) } ?? .null }
            case "coordKeyOf": got = .value(.string(PCAWallet.coordKeyOf(a0?.asString ?? "")))
            case "resolveCoords": got = Ref.v { try resolve(a) }
            case "coordsOfBox": got = Ref.v { try PCAWallet.coordsOfBox(try verbOf(a0, a1), try Self.ints2(a2)) }
            case "coordsOfCell": got = Ref.v { try PCAWallet.coordsOfCell(try verbOf(a0, a1), try Self.ints(a2)) }
            case "cellInBox": got = Ref.v { .bool(PCAWallet.cellInBox(try Self.ints2(a0), try Self.ints(a1))) }
            case "boxCells": got = Ref.v { .array(PCAWallet.boxCells(try Self.ints2(a0)).map { WJ.arr($0) }) }
            case "boxSize": got = Ref.v { WJ.i(PCAWallet.boxSize(try Self.ints2(a0))) }
            case "cellOfAction":
                got = Ref.v {
                    guard let r = try PCAWallet.cellOfAction(try omega(a0), a1) else { return .null }
                    return WJ.obj([("verb", .string(r.vs.verb)), ("idx", WJ.arr(r.idx))])
                }
            case "flatIndex": got = Ref.v { WJ.i(PCAWallet.flatIndex(try verbOf(a0, a1), try Self.ints(a2))) }
            case "cleanText": got = Ref.v { .string(try PCAWalletCard.cleanText(a0, Int(try n(1)))) }
            case "last4":
                guard let s = a0?.asString else { d.skip("last4: non-string"); return }
                got = .value(.string(PCAWalletCard.last4(s)))
            case "formatNumber": got = Ref.v { .string(try PCAWalletCard.formatNumber(a0, a1)) }
            case "renderCard": got = Ref.v { try render(a0) }
            case "cardDigest": got = Ref.v { .string(try PCAWalletCard.cardDigest(a0)) }
            case "cardDigestMatches": got = Ref.v { .bool(try PCAWalletCard.cardDigestMatches(a0)) }
            case "cardText": got = Ref.v { .string(try PCAWalletCard.cardText(a0)) }
            case "partialError": got = Ref.v { Base.opt(try PCAWalletCard.partialError(a0, a1)) }
            case "normalizeTyped": got = Ref.v { Base.opt(try PCAWalletCard.normalizeTyped(a0, a1, a2)) }
            case "expectedTyped": got = Ref.v { Base.opt(try PCAWalletCard.expectedTyped(a0, a1)) }
            case "parseClarifyRequest": got = .value(PCAWalletCard.parseClarifyRequest(a0))
            case "informationGain": approx = true; got = Ref.v { .double(PCAWalletCard.informationGain(try n(0), try n(1), try n(2))) }
            case "planClarification": approx = true; got = Ref.v { try plan(a0) }
            case "gaussianSigma": approx = true; got = Ref.v { .double(try PCAWalletPopulation.gaussianSigma(try n(0), try n(1), try n(2))) }
            case "gaussian": approx = true; got = Ref.v { .double(try PCAWalletPopulation.gaussian(Self.seq(a0))) }
            case "rrKeepProbability": approx = true; got = Ref.v { .double(try PCAWalletPopulation.rrKeepProbability(a0)) }
            case "randomizedResponse":
                got = Ref.v { let r = try n(2); return try PCAWalletPopulation.randomizedResponse(a0, a1, { r }) }
            case "debiasRandomizedResponse": approx = true; got = Ref.v { .double(try PCAWalletPopulation.debiasRandomizedResponse(a0, a1, a2)) }
            case "populationCellKey":
                got = Ref.v { .string(try PCAWalletPopulation.populationCellKey(a0?.asString ?? "", try verbOf(a1, a2), try Self.ints(a[3]))) }
            case "aggregate": approx = true; got = Ref.v { try aggregate(a) }
            case "populationPrior": approx = true; got = Ref.v { try prior(a) }
            case "siteQuestionNotice":
                got = Ref.v { try PCAWalletDelivery.siteQuestionNotice(a0, keys: a1, site: a2, now: a[3], inboxUrl: a[4]) }
            case "clarificationNotice": got = .value(PCAWalletDelivery.clarificationNotice(session: a0, questionId: a1, inboxUrl: a2))
            case "questionText": got = Ref.v { try PCAWalletDelivery.questionText(a0, siteName: a1) }
            case "webhookChannel": got = .value(hook(a0, a1, a2)); check(d, c, got, norm: Self.normCalls); return
            case "textChannel": got = .value(tchan(a0, a1, a2, a[3]))
            case "dispatcher": got = .value(dispatch(a0, a1))
            case "channel": approx = true; got = Ref.v { try channel(a0) }
            default:
                d.skip("\(c.fn): not mapped"); return
            }
            check(d, c, got, approx: approx, norm: c.fn == "verifyIntentAnswer" ? normReason : nil)
        }
        for (fn, k) in inexact.sorted(by: { $0.key < $1.key }) { print("wallet: \(k) numbers of \(fn) not bit-identical to the reference (within \(Self.tol) relative)") }
        d.finish(6500)
    }
}
