import Foundation

/// The device-tier (WebAuthn) state of a channel: the relying party, the origin allowlist, the principal's credentials (public JWKs by
/// credential id) and the stored signature counters (updated on every verified assertion).
public final class WalletDeviceState {
    public let rpId: String
    public let origins: [String]
    public let credentials: JSONValue
    public var signCounts: [String: Double]?

    public init(rpId: String, origins: [String], credentials: JSONValue, signCounts: [String: Double]?) {
        self.rpId = rpId; self.origins = origins; self.credentials = credentials; self.signCounts = signCounts
    }
}

/// Everything a `WalletTrustedChannel` is configured with (the reference's TrustedChannelOptions).
public struct WalletChannelOptions {
    public var omega: WalletOmega
    public var session: JSONValue
    public var mapDigest: () -> JSONValue
    public var principalSeed: [UInt8]
    /// {origin, name, keys}: the verified site identity and its discovery keys.
    public var site: JSONValue
    public var view: PCAWalletCard.View
    public var hourly: PCAWallet.SlidingWindowCounter
    public var noise: () -> JSONValue
    public var onNoise: (JSONValue) -> Void
    public var rand: () throws -> Double
    public var now: () -> Double
    public var statementText: JSONValue?
    public var units: JSONValue?
    public var sensitivity: JSONValue?
    public var identityPaths: [String] = []
    public var caps: (perSession: Double?, perHour: Double?) = (nil, nil)
    public var rho: Double?
    public var fatigue: JSONValue?
    public var friction: JSONValue?
    public var maxPerScreen: Double?
    public var maxBoxCells: Double?
    public var device: WalletDeviceState?
    public var lift: ((JSONValue) throws -> JSONValue)?
    public var liftCandidate: ((JSONValue) throws -> JSONValue)?
    public var reversibility: ((WalletVerb, [[Int]]) -> String)?

    public init(omega: WalletOmega, session: JSONValue, mapDigest: @escaping () -> JSONValue, principalSeed: [UInt8], site: JSONValue, view: PCAWalletCard.View,
                hourly: PCAWallet.SlidingWindowCounter, noise: @escaping () -> JSONValue, onNoise: @escaping (JSONValue) -> Void, rand: @escaping () throws -> Double,
                now: @escaping () -> Double) {
        self.omega = omega; self.session = session; self.mapDigest = mapDigest; self.principalSeed = principalSeed; self.site = site; self.view = view
        self.hourly = hourly; self.noise = noise; self.onNoise = onNoise; self.rand = rand; self.now = now
    }
}

/// The trusted question channel of the wallet (PCA Intent Layer v2, 3.4 and 3.14): one instance per session. SELECTION belongs to the
/// verifier (questions enter only as a site-signed `intent_required`, re-derived by the wallet, or as a structured agent clarification
/// whose cell the wallet picks itself); RENDERING and ORDERING belong to the wallet; friction scales with harm; canaries are inserted
/// with probability rho and update only the noise counts; caps and a freeze on the estimated false-yes rate bound the questions; a cell
/// is asked at most once per session; under estimated noise an irreversible cell needs two confirmations. Native port of the
/// TypeScript reference (@atlasauth/pca-wallet, channel.ts). Items and results are `JSONValue`s with the reference's member names.
public final class WalletTrustedChannel {
    static let B64U = Array("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_")

    final class Item {
        var id: String
        var kind: String
        var source: String
        var verb: String
        var box: [[Int]]
        var coords: JSONValue
        var card: JSONValue
        var action: JSONValue?
        var actionDigest: String?
        var irreversible: Bool
        var expected: Int?
        var weight: Double
        var jit: Bool
        var expiresAt: Double?
        var shownOn: Int?
        var notBefore: Int?
        var first: JSONValue?
        var flat = 0
        var vs: WalletVerb

        init(id: String, kind: String, source: String, verb: String, box: [[Int]], coords: JSONValue, card: JSONValue, action: JSONValue?, actionDigest: String? = nil,
             irreversible: Bool, expected: Int? = nil, weight: Double, jit: Bool, expiresAt: Double? = nil, vs: WalletVerb) {
            self.id = id; self.kind = kind; self.source = source; self.verb = verb; self.box = box; self.coords = coords; self.card = card; self.action = action
            self.actionDigest = actionDigest; self.irreversible = irreversible; self.expected = expected; self.weight = weight; self.jit = jit
            self.expiresAt = expiresAt; self.vs = vs
        }

        func copy() -> Item {
            let c = Item(id: id, kind: kind, source: source, verb: verb, box: box, coords: coords, card: card, action: action, actionDigest: actionDigest,
                         irreversible: irreversible, expected: expected, weight: weight, jit: jit, expiresAt: expiresAt, vs: vs)
            c.shownOn = shownOn; c.notBefore = notBefore; c.first = first; c.flat = flat
            return c
        }

        var tier: JSONValue { card.get("friction") ?? .null }
        var rank: Int { PCAWallet.frictionRank(card.get("friction")) }
        var renderedDigest: JSONValue { card.get("rendered_digest") ?? .null }
    }

    let o: WalletChannelOptions
    private var pending: [String: Item] = [:]
    private var asked = Set<String>()
    private var canaryUsed = Set<String>()
    private var knownYes: [(verb: String, idx: [Int])] = []
    private var confirmations: [String: [(screen: Double, tier: String)]] = [:]
    private var refusedWhileFrozen: [JSONValue] = []
    private var sessionQuestions = 0
    private var canaries = 0
    private var screenNo = 0

    public init(_ options: WalletChannelOptions) { o = options }

    // ---- options ----

    var perSession: Double { o.caps.perSession ?? 6 }
    var perHour: Double { o.caps.perHour ?? 12 }
    var fatigue: JSONValue { o.fatigue ?? PCAWallet.DEFAULT_FATIGUE }
    var harm: WalletOmegaMath.HarmModel { WalletOmegaMath.DEFAULT_HARM }

    /// The current noise state (eta+ under load, frozen?).
    public func noise() throws -> JSONValue { try PCAWallet.noiseState(o.noise(), Double(o.hourly.count(o.now())), fatigue) }

    /// The admission policy the learner should use now (tau, eta+, eta-; double confirmation).
    public func admission() throws -> JSONValue { try PCAWallet.admissionPolicy(try noise(), fatigue) }

    public func questionsAsked() -> Int { sessionQuestions }

    func newId() throws -> String {
        var s = "q_"
        for _ in 0..<10 { s.append(Self.B64U[Int((try o.rand() * 64).rounded(.down)) % 64]) }
        if pending[s] != nil { return try newId() }
        return s
    }

    func boxStats(_ vs: WalletVerb, _ box: [[Int]]) -> (weight: Double, meanHarm: Double)? {
        let cells = PCAWallet.boxCells(box)
        if Double(cells.count) > (o.maxBoxCells ?? 4096) { return nil }
        var m = 0.0, mh = 0.0
        for idx in cells {
            let s = WalletOmegaMath.cellStats(vs, idx, harm)
            m += s.mass
            mh += s.mass * s.harm
        }
        return (mh, m > 0 ? mh / m : 0)
    }

    func revOf(_ vs: WalletVerb, _ box: [[Int]]) -> String { o.reversibility?(vs, box) ?? vs.reversibility }

    func frictionOf(_ vs: WalletVerb, _ box: [[Int]], _ meanHarm: Double, _ siteMin: JSONValue?, _ irreversible: Bool) throws -> JSONValue {
        var provenance: [JSONValue] = []
        var widens = false
        for (k, d) in vs.dims.enumerated() {
            if IV.startsWith(d.path, "env.prov.") && !d.isNum {
                let param = IV.dropPrefix(d.path, 9)
                var levels: [JSONValue] = []
                for i in box[k] {
                    let v = d.values[i]
                    let text = v.kind == "prefix" ? v.value + "*" : v.value
                    levels.append(contentsOf: text.unicodeScalars.split(omittingEmptySubsequences: false, whereSeparator: { $0 == "|" || $0 == "," }).map { .string(IV.text($0)) })
                }
                var sens: JSONValue = .string("material")
                if let s = o.sensitivity?.get(param), JS.truthy(s) { sens = s }
                provenance.append(WJ.obj([("path", .string(param)), ("sensitivity", sens), ("levels", .array(levels))]))
            }
            if !d.isNum && o.identityPaths.contains(where: { IV.same($0, d.path) }) {
                if box[k].contains(where: { d.values[$0].kind != "exact" }) { widens = true }
            }
        }
        var inp: JObject = ["reversibility": .string(revOf(vs, box)), "expectedHarm": .double(meanHarm), "provenance": .array(provenance),
                            "widensCriticalIdentity": .bool(widens)]
        if let m = siteMin, JS.truthy(m) { inp["siteMin"] = m }
        var tier = try PCAWallet.frictionFor(.object(inp), o.friction).get("tier") ?? .string("device")
        if irreversible, try admission().get("doubleConfirmIrreversible") == .bool(true) { tier = PCAWallet.maxFriction([tier, .string("typed")]) }
        return tier
    }

    func render(_ kind: String, _ verb: String, _ coords: JSONValue, _ friction: JSONValue, _ action: JSONValue?, _ vs: WalletVerb, _ box: [[Int]],
                reason: String? = nil) throws -> (card: JSONValue, friction: JSONValue)? {
        var base: JObject = ["verb": .string(verb), "coords": coords,
                             "site": WJ.obj([("origin", o.site.get("origin") ?? .null), ("name", o.site.get("name") ?? .null)])]
        if let t = o.statementText { base["statementText"] = t }
        base["reversibility"] = .string(revOf(vs, box))
        if let u = o.units, JS.truthy(u) { base["units"] = u }
        if let a = action { base["action"] = a }
        base["kind"] = .string(kind)
        if let r = reason, !r.isEmpty { base["reason"] = .string(r) }
        var withFriction = base
        withFriction["friction"] = friction
        var r = try PCAWalletCard.renderCard(o.omega, .object(withFriction))
        // a typed question needs a value to type; with none on the card, the only stronger tier is the device
        if case let .success(card) = r, PCAWallet.frictionRank(friction) == PCAWallet.frictionRank(.string("typed")), card.get("typed") == nil {
            withFriction["friction"] = .string("device")
            r = try PCAWalletCard.renderCard(o.omega, .object(withFriction))
        }
        guard case let .success(card) = r else { return nil }
        return (card, card.get("friction") ?? .null)
    }

    func refusal(_ code: String, _ reason: String) -> JSONValue { WJ.obj([("ok", .bool(false)), ("code", .string(code)), ("reason", .string(reason))]) }

    /// nil when a question may be asked now, else the refusal.
    func gate() throws -> JSONValue? {
        if try noise().get("frozen") == .bool(true) { return refusal("frozen", "the estimated false-yes rate is above \u{3B7}_stop: no more questions this session") }
        if !(Double(sessionQuestions) < perSession) { return refusal("cap_session", "at most \(JS.number(perSession)) questions per session") }
        if !(o.now().isFinite && Double(o.hourly.count(o.now())) < perHour) { return refusal("cap_hour", "at most \(JS.number(perHour)) questions per hour") }
        return nil
    }

    func enqueue(_ it: Item) {
        it.flat = PCAWallet.boxCells(it.box).map { PCAWallet.flatIndex(it.vs, $0) }.min() ?? 0
        pending[it.id] = it
    }

    func countQuestion() throws {
        sessionQuestions += 1
        if !(try o.hourly.tryAdd(o.now(), 9007199254740991)) { throw JSError("unreachable") }
    }

    /// Insert a canary with probability rho (rendered and ordered like a real question).
    func maybeCanary() throws {
        var exclude = canaryUsed
        for p in pending.values { for idx in PCAWallet.boxCells(p.box) { exclude.insert(PCAWallet.cellKey(p.verb, idx)) } }
        let lowHarm = pending.values.allSatisfy { $0.kind != "real" || $0.rank <= PCAWallet.frictionRank(.string("hold")) }
        let view = o.view
        guard let c = try PCAWallet.pickCanary(omega: o.omega, confirmed: view.confirmed(),
                                               knownNo: { verb, idx in view.outsideCeiling(verb, idx) ? "ceiling" : (view.vetoed(verb, idx) ? "veto" : nil) },
                                               knownYes: knownYes, exclude: exclude, rand: o.rand, rho: o.rho, lowHarmSession: lowHarm, canariesSoFar: Double(canaries)) else { return }
        guard let vs = o.omega.verb(c.verb) else { throw JSError("no such verb") }
        let box = c.idx.map { [$0] }
        guard let st = boxStats(vs, box) else { return }
        let coords = try PCAWallet.coordsOfCell(vs, c.idx)
        let action = WJ.obj([("verb", .string(c.verb)), ("values", WalletOmegaMath.cellRep(vs, c.idx).get("values") ?? .null)])
        let friction = try frictionOf(vs, box, st.meanHarm, nil, false)
        guard let r = try render("question", c.verb, coords, friction, action, vs, box) else { return }
        canaries += 1
        canaryUsed.insert(PCAWallet.cellKey(c.verb, c.idx))
        enqueue(Item(id: try newId(), kind: "canary", source: "elicitation", verb: c.verb, box: box, coords: coords, card: r.card, action: action, irreversible: false,
                     expected: c.expected, weight: st.weight, jit: false, vs: vs))
    }

    /// Receive a site-signed intent_required (delivered directly, or relayed unchanged by the agent) together with the action the agent
    /// attempted. Every check fails closed. `action` is {verb, resource, params, reversibility_class}.
    public func receive(_ ir: JSONValue, action: JSONValue) throws -> JSONValue {
        let now = o.now()
        let v = PCAWalletDelivery.verifyIntentRequired(ir, o.site.get("keys"), .double(now))
        if v.get("ok") != .bool(true) { return refusal("bad_site_signature", v.get("reason")?.asString ?? "") }
        guard let cell = ir.get("cell"), let verb = cell.get("verb") else { throw JSError("malformed intent_required") }
        if !WJ.sameStr(ir.get("session"), o.session) { return refusal("wrong_session", "the question is for another session") }
        if !WJ.sameStr(ir.get("map_digest"), o.mapDigest()) { return refusal("stale_map", "the question names another map version") }
        if !WJ.sameStr(action.get("verb"), verb) { return refusal("action_mismatch", "the action does not match the signed action digest") }
        let actionDigest = try PCAWallet.pcaActionDigest(action)
        if !WJ.sameStr(.string(actionDigest), ir.get("action_digest")) { return refusal("action_mismatch", "the action does not match the signed action digest") }
        let lifted = try o.lift?(action) ?? PCAWallet.actionValuesOf(action)
        let r: PCAWallet.Resolved
        switch try PCAWallet.resolveCoords(o.omega, verb, cell.get("coords")) {
        case let .failure(f): return refusal("cell_mismatch", f.reason)
        case let .success(x): r = x
        }
        guard let at = try PCAWallet.cellOfAction(o.omega, lifted), PCAWallet.cellInBox(r.box, at.idx) else {
            return refusal("cell_mismatch", "the action's cell (re-derived by the wallet) is not the cell the site names")
        }
        guard let st = boxStats(r.vs, r.box) else { return refusal("cell_too_large", "the question covers too many cells") }
        let cells = PCAWallet.boxCells(r.box)
        let view = o.view
        let vname = r.vs.verb
        for idx in cells {
            if view.outsideCeiling(vname, idx) { return refusal("not_uncertain", "the cell is outside a ceiling: the principal cannot widen it") }
            if view.vetoed(vname, idx) { return refusal("not_uncertain", "the cell was vetoed") }
        }
        let pa = view.p(vname, at.idx)
        if !(pa > 0 && pa < 1) { return refusal("not_uncertain", pa <= 0 ? "the cell is denied" : "the cell is already in the grant") }
        if cells.contains(where: { asked.contains(PCAWallet.cellKey(vname, $0)) }) { return refusal("already_asked", "a cell is asked at most once per session") }
        if let g = try gate() {
            if g.get("code") == .string("frozen") { refusedWhileFrozen.append(WJ.obj([("verb", .string(vname)), ("coords", cell.get("coords") ?? .null)])) }
            return g
        }
        let irreversible = revOf(r.vs, r.box) == "irreversible"
        let friction = try frictionOf(r.vs, r.box, st.meanHarm, ir.get("friction"), irreversible)
        guard let rendered = try render("question", verb.asString ?? "", cell.get("coords") ?? .null, friction, lifted, r.vs, r.box) else {
            return refusal("render_failed", "the card could not be rendered")
        }
        let qid = ir.get("question_id")?.asString ?? ""
        if pending[qid] != nil { return refusal("already_asked", "duplicate question id") }
        for idx in cells { asked.insert(PCAWallet.cellKey(vname, idx)) }
        try countQuestion()
        let it = Item(id: qid, kind: "real", source: "elicitation", verb: verb.asString ?? "", box: r.box, coords: cell.get("coords") ?? .null, card: rendered.card, action: lifted,
                      actionDigest: ir.get("action_digest")?.asString, irreversible: irreversible, weight: st.weight, jit: true, expiresAt: IV.num(ir.get("expires_at")), vs: r.vs)
        enqueue(it)
        try maybeCanary()
        return WJ.obj([("ok", .bool(true)), ("questionId", .string(qid)), ("friction", rendered.friction)])
    }

    /// An agent clarification (3.14): {candidates: [<= 8 structured actions], reason}, no text. Certain cells are answered at once (dry
    /// run); among the uncertain ones the wallet picks the most informative and asks it.
    public func clarify(_ body: JSONValue?) throws -> JSONValue {
        let parsed = PCAWalletCard.parseClarifyRequest(body)
        if parsed.get("ok") != .bool(true) {
            return WJ.obj([("status", WJ.i(400)), ("verdicts", .array([])), ("error", parsed.get("error") ?? .null)])
        }
        let st = try noise()
        let request = parsed.get("request") ?? .null
        let candidates = request.get("candidates")?.asArray ?? []
        let plan = try PCAWalletCard.planClarification(omega: o.omega, view: o.view, candidates: candidates, lift: o.liftCandidate, asked: asked,
                                                       etaPos: min(0.5 - 1e-9, IV.num(st.get("etaPosBar")) ?? .nan), etaNeg: min(0.5 - 1e-9, IV.num(st.get("etaNegBar")) ?? .nan),
                                                       harm: harm)
        guard let ask = plan.ask else { return WJ.obj([("status", WJ.i(200)), ("verdicts", plan.verdictsJSON)]) }
        if let g = try gate() {
            let frozen = g.get("code") == .string("frozen")
            return WJ.obj([("status", WJ.i(frozen ? 200 : 429)), ("verdicts", plan.verdictsJSON), ("refused", g.get("code") ?? .null)])
        }
        guard let vs = o.omega.verb(ask.verb) else { throw JSError("no such verb") }
        let box = ask.idx.map { [$0] }
        guard let stats = boxStats(vs, box) else { throw JSError("cell too large") }
        let coords = try PCAWallet.coordsOfCell(vs, ask.idx)
        let raw = candidates[ask.index]
        let action = try o.liftCandidate?(raw) ?? raw
        let irreversible = revOf(vs, box) == "irreversible"
        let friction = try frictionOf(vs, box, stats.meanHarm, nil, irreversible)
        guard let rendered = try render("clarification", vs.verb, coords, friction, action, vs, box, reason: request.get("reason")?.asString) else {
            return WJ.obj([("status", WJ.i(200)), ("verdicts", plan.verdictsJSON), ("refused", .string("render_failed"))])
        }
        let qid = try newId()
        asked.insert(PCAWallet.cellKey(vs.verb, ask.idx))
        try countQuestion()
        enqueue(Item(id: qid, kind: "real", source: "clarification", verb: vs.verb, box: box, coords: coords, card: rendered.card, action: action, irreversible: irreversible,
                     weight: stats.weight, jit: false, vs: vs))
        try maybeCanary()
        return WJ.obj([("status", WJ.i(200)), ("verdicts", plan.verdictsJSON), ("questionId", .string(qid))])
    }

    /// Pending items in display order: friction desc, E[h|c]*mu(c) desc, cell index asc, id asc.
    func ordered() -> [Item] {
        pending.values.sorted { a, b in
            if a.rank != b.rank { return a.rank > b.rank }
            if a.weight != b.weight { return a.weight > b.weight }
            if a.flat != b.flat { return a.flat < b.flat }
            return WJ.u16Less(a.id, b.id)
        }
    }

    /// The next screen (nil when nothing is waiting). A typed or device question is always alone; tap/hold questions share up to
    /// maxPerScreen.
    public func nextScreen() -> JSONValue {
        let now = o.now()
        for (qid, it) in pending { if let e = it.expiresAt, !(now.isFinite && now <= e) { pending[qid] = nil } }
        let items = ordered().filter { $0.shownOn == nil }
        if items.isEmpty { return .null }
        let nxt = screenNo + 1
        let eligible = items.filter { $0.notBefore == nil || nxt >= $0.notBefore! }
        screenNo = nxt
        if eligible.isEmpty { return WJ.obj([("screen", WJ.i(nxt)), ("kind", .string("interstitial")), ("questions", .array([]))]) }
        let first = eligible[0]
        var picked = [first]
        if first.rank <= PCAWallet.frictionRank(.string("hold")) {
            let mx = o.maxPerScreen ?? 3
            for it in eligible.dropFirst() {
                if Double(picked.count) >= mx { break }
                if it.rank <= PCAWallet.frictionRank(.string("hold")) { picked.append(it) }
            }
        }
        for it in picked { it.shownOn = nxt }
        return WJ.obj([("screen", WJ.i(nxt)), ("kind", .string("questions")),
                       ("questions", .array(picked.map { WJ.obj([("questionId", .string($0.id)), ("card", $0.card)]) }))])
    }

    /// The principal's response to a shown question.
    public func answer(_ questionId: String?, _ response: JSONValue?) throws -> JSONValue {
        guard let qid = questionId, let it = pending[qid] else { return refusal("unknown_question", "no such pending question") }
        if it.shownOn == nil { return refusal("not_shown", "the question was never shown") }
        let now = o.now()
        if let e = it.expiresAt, !(now.isFinite && now <= e) {
            pending[qid] = nil
            return refusal("expired", "the question expired")
        }
        var partial: JSONValue?
        let ans = response?.get("answer")
        let y: Int
        if WJ.isStr(ans, "no") { y = 0 }
        else if WJ.isStr(ans, "partly") {
            if let e = try PCAWalletCard.partialError(it.card, response?.get("partial")) { return refusal("bad_response", e) }
            y = 1
            partial = response?.get("partial")
        } else { y = 1 }
        var ux: JObject = ["tier": it.tier, "rendered_digest": it.renderedDigest, "canary": .bool(it.kind == "canary")]
        if y == 1 {
            let ev = try tierEvidence(it, response, qid)
            if ev.get("ok") != .bool(true) { return ev }
            for (k, v) in ev.get("ux")?.asObject ?? [:] { ux[k] = v }
        }
        let plainYes = y == 1 && !(partial.map { JS.truthy($0) } ?? false)
        if it.kind != "canary", it.jit, it.irreversible, plainYes, let ad = it.actionDigest, !ad.isEmpty, it.rank >= PCAWallet.frictionRank(.string("typed")) {
            ux["action_digest"] = .string(ad)
            ux["consent_for_action"] = .bool(true)
        }
        var body: JObject = ["map_digest": o.mapDigest(), "session": o.session, "question_id": .string(qid), "verb": .string(it.verb), "cell": it.coords, "y": WJ.i(y)]
        if let p = partial, JS.truthy(p) { body["partial"] = p }
        body["source"] = .string(it.source)
        body["observed_at"] = .double(now)
        body["ux"] = .object(ux)
        let signed = try PCAWallet.signIntentAnswer(.object(body), seed: o.principalSeed)
        pending[qid] = nil
        if it.kind == "canary" {
            o.onNoise(try PCAWallet.recordCanary(o.noise(), expected: it.expected.map { WJ.i($0) }, y: WJ.i(y)))
            return WJ.obj([("ok", .bool(true)), ("kind", .string("canary")), ("answer", signed)])
        }
        if y == 0 { return WJ.obj([("ok", .bool(true)), ("kind", .string("veto")), ("answer", signed)]) }
        if plainYes && it.rank >= PCAWallet.frictionRank(.string("typed")) && it.box.allSatisfy({ $0.count == 1 }) {
            // a verified high-friction yes: a source of known-yes canaries
            knownYes.append((it.verb, it.box.map { $0[0] }))
        }
        if plainYes && it.irreversible, try admission().get("doubleConfirmIrreversible") == .bool(true) {
            let key = "\(it.verb)|\(JS.stringify(it.coords))"
            var recs = confirmations[key] ?? []
            recs.append((Double(it.shownOn ?? 0), it.tier.asString ?? ""))
            confirmations[key] = recs
            if it.kind == "confirmation", let first = it.first, PCAWallet.doubleConfirmed(recs) {
                return WJ.obj([("ok", .bool(true)), ("kind", .string("confirmed")), ("answers", .array([first, signed]))])
            }
            if it.kind == "confirmation" { return WJ.obj([("ok", .bool(true)), ("kind", .string("pending_confirmation")), ("answer", signed)]) }
            // schedule the second, independent confirmation: at least one other screen in between
            let second = it.copy()
            second.id = try newId()
            second.kind = "confirmation"
            second.first = signed
            second.notBefore = (it.shownOn ?? 0) + 2
            second.shownOn = nil
            pending[second.id] = second
            return WJ.obj([("ok", .bool(true)), ("kind", .string("pending_confirmation")), ("answer", signed)])
        }
        return WJ.obj([("ok", .bool(true)), ("kind", .string("answer")), ("answer", signed)])
    }

    func evidenceFail(_ code: String, _ reason: String) -> JSONValue { refusal(code, reason) }

    func tierEvidence(_ it: Item, _ response: JSONValue?, _ questionId: String) throws -> JSONValue {
        let r: JSONValue? = WJ.isStr(response?.get("answer"), "no") ? WJ.obj([]) : response
        let tier = it.tier.asString ?? ""
        func ok(_ ux: JSONValue) -> JSONValue { WJ.obj([("ok", .bool(true)), ("ux", ux)]) }
        switch tier {
        case "tap": return ok(WJ.obj([]))
        case "hold":
            guard let hm = IV.num(r?.get("holdMs")), hm.isFinite, hm == hm.rounded(.down), hm >= Double(PCAWallet.MIN_HOLD_MS) else {
                return evidenceFail("tier_evidence", "hold for at least \(PCAWallet.MIN_HOLD_MS) ms")
            }
            return ok(WJ.obj([("hold_ms", r!.get("holdMs")!)]))
        case "typed":
            guard let t = it.card.get("typed"), JS.truthy(t), let act = it.action, let typedText = r?.get("typed")?.asString else {
                return evidenceFail("tier_evidence", "type the value shown on the card")
            }
            let want = try PCAWalletCard.expectedTyped(it.card, act)
            let unit = o.units?.get(t.get("path")?.asString ?? "")
            let got = try PCAWalletCard.normalizeTyped(.string(typedText), t.get("mode"), unit)
            guard let w = want, let g = got, w == g else { return evidenceFail("typed_mismatch", "the typed value does not match the card") }
            return ok(WJ.obj([("typed_digest", .string(try PCAWallet.typedDigest(questionId, g)))]))
        case "device":
            guard let wa = r?.get("webauthn"), JS.truthy(wa), let dev = o.device else { return evidenceFail("tier_evidence", "a security-key assertion is required") }
            let cred = wa.get("credential_id")?.asString
            let pk = cred.flatMap { dev.credentials.get($0) }
            let ad = wa.get("authenticator_data")?.asString.flatMap { Base64URLStrict.decode($0) }
            let cd = wa.get("client_data_json")?.asString.flatMap { Base64URLStrict.decode($0) }
            let sg = wa.get("signature")?.asString.flatMap { Base64URLStrict.decode($0) }
            guard let c = cred, let key = pk, JS.truthy(key), let adb = ad, let cdb = cd, let sgb = sg else {
                return evidenceFail("tier_evidence", "unknown credential or malformed assertion")
            }
            let challenge = try PCAWallet.deviceChallenge(questionId: .string(questionId), renderedDigest: it.renderedDigest, y: WJ.i(1),
                                                          actionDigest: (it.jit && it.irreversible && !(it.actionDigest ?? "").isEmpty) ? it.actionDigest.map { .string($0) } : nil)
            var exp = PCAWebauthn.Expectations(expectedChallenge: .b64u(challenge), rpId: dev.rpId, origins: dev.origins, storedSignCount: dev.signCounts?[c] ?? 0)
            exp.requireUV = true
            let res = PCAWebauthn.verifyAssertion(PCAWebauthn.Assertion(authenticatorData: adb, clientDataJSON: cdb, signature: sgb, publicKey: .jwk(key)), exp)
            if !res.ok { return evidenceFail("tier_evidence", "security key: \(res.reason)") }
            if dev.signCounts != nil { dev.signCounts![c] = Double(res.signCount) }
            return ok(WJ.obj([("webauthn", wa)]))
        default:
            throw JSError("unknown friction tier")
        }
    }

    /// The WebAuthn challenge the wallet UI passes to navigator.credentials.get for a shown device-tier question.
    public func deviceChallengeFor(_ questionId: String?) throws -> JSONValue {
        guard let qid = questionId, let it = pending[qid], it.shownOn != nil, WJ.isStr(it.tier, "device") else { return .null }
        return .string(try PCAWallet.deviceChallenge(questionId: .string(qid), renderedDigest: it.renderedDigest, y: WJ.i(1),
                                                     actionDigest: (it.jit && it.irreversible && !(it.actionDigest ?? "").isEmpty) ? it.actionDigest.map { .string($0) } : nil))
    }

    /// The end-of-session summary shown instead of questions once the session froze.
    public func summary() throws -> JSONValue {
        WJ.obj([("frozen", try noise().get("frozen") ?? .bool(false)), ("refused", .array(refusedWhileFrozen)), ("asked", WJ.i(sessionQuestions)), ("canaries", WJ.i(canaries))])
    }

    /// A stable digest of the channel's pending state (for tests and audit logs).
    public func stateDigest() throws -> String {
        try WJ.hash(WJ.obj([("d", .string("atlas-pca/wallet-channel-state/v1")),
                            ("p", .array(ordered().map { WJ.obj([("id", .string($0.id)), ("k", .string($0.kind)), ("d", $0.renderedDigest)]) })),
                            ("a", .array(asked.sorted(by: WJ.u16Less).map { .string($0) })), ("n", WJ.i(sessionQuestions))]))
    }
}

extension WJ {
    /// `a === b` over two strings that may be absent.
    static func sameStr(_ a: JSONValue?, _ b: JSONValue?) -> Bool { IV.same(a?.asString, b?.asString) }
}

/// Framework-neutral handlers for the two wallet endpoints named in the session root (3.3 item 3, 3.14): the question endpoint (a site
/// delivers, or an agent relays unchanged, a site-signed intent_required plus the raw action) and the clarification endpoint. The HTTP
/// routes live with the session store of the host; these functions are what such a route calls, so the wire behaviour is fixed here.
/// Neither response carries p or any map content. Native port of the TypeScript reference (@atlasauth/pca-wallet, handlers.ts).
public enum PCAWalletHandlers {
    static let STATUS_OF_REFUSAL: [String: Int] = [
        "bad_site_signature": 401, "wrong_session": 409, "stale_map": 409, "action_mismatch": 422, "cell_mismatch": 422, "not_uncertain": 409,
        "already_asked": 409, "frozen": 429, "cap_session": 429, "cap_hour": 429, "cell_too_large": 422, "bad_request": 400, "render_failed": 422,
    ]
    static let ACTION_KEYS = ["verb", "resource", "params", "reversibility_class"]

    static func actionOf(_ v: JSONValue?) -> JSONValue? {
        guard case let .object(o)? = v, o["verb"]?.asString != nil, o["resource"]?.asString != nil, o["reversibility_class"]?.asString != nil, o["params"]?.isObject == true else { return nil }
        for k in PCAWallet.keysOf(o) where !ACTION_KEYS.contains(k) { return nil }
        return .object(["verb": o["verb"]!, "resource": o["resource"]!, "params": o["params"]!, "reversibility_class": o["reversibility_class"]!])
    }

    static func reply(_ status: Int, _ body: JSONValue) -> JSONValue { WJ.obj([("status", WJ.i(status)), ("body", body)]) }

    /// The question endpoint: `resolve(sessionId)` -> the session's channel or nil.
    public static func questionHandler(_ resolve: @escaping (String) -> WalletTrustedChannel?) -> (String, JSONValue?) throws -> JSONValue {
        { sessionId, body in
            guard let ch = resolve(sessionId) else { return reply(404, WJ.obj([("error", .string("unknown_session"))])) }
            guard case let .object(b)? = body else { return reply(400, WJ.obj([("error", .string("bad_request"))])) }
            for k in PCAWallet.keysOf(b) where k != "intent_required" && k != "action" {
                return reply(400, WJ.obj([("error", .string("bad_request")), ("detail", .string("unknown member \"\(k)\""))]))
            }
            guard let action = actionOf(b["action"]), let ir = b["intent_required"], ir.isObject else { return reply(400, WJ.obj([("error", .string("bad_request"))])) }
            let r = try ch.receive(ir, action: action)
            if r.get("ok") == .bool(true) {
                return reply(202, WJ.obj([("question_id", r.get("questionId") ?? .null), ("friction", r.get("friction") ?? .null)]))
            }
            return reply(STATUS_OF_REFUSAL[r.get("code")?.asString ?? ""] ?? 400, WJ.obj([("error", r.get("code") ?? .null)]))
        }
    }

    /// The clarification endpoint (3.14).
    public static func clarifyHandler(_ resolve: @escaping (String) -> WalletTrustedChannel?) -> (String, JSONValue?) throws -> JSONValue {
        { sessionId, body in
            guard let ch = resolve(sessionId) else { return reply(404, WJ.obj([("error", .string("unknown_session"))])) }
            let r = try ch.clarify(body)
            if let e = r.get("error"), e != .null { return reply(400, WJ.obj([("error", .string("bad_request")), ("detail", e)])) }
            var out: JObject = ["verdicts": r.get("verdicts") ?? .array([])]
            if let q = r.get("questionId"), q != .null { out["question_id"] = q }
            if let f = r.get("refused"), f != .null { out["refused"] = f }
            return reply(Int(IV.num(r.get("status")) ?? 400), .object(out))
        }
    }
}
