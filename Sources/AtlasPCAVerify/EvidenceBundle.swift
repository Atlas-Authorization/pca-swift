import Foundation

/// A verdict a supplied verifier port returns for one artifact (`{ok, reason?}`).
public struct EvidenceVerdict {
    public var ok: Bool
    public var reason: String
    public init(ok: Bool, reason: String = "") { self.ok = ok; self.reason = reason }
}

/// A verifier for one artifact of an evidence bundle: it OVERRIDES the core default for artifacts that have one and is the only check
/// for artifacts that have none. A port that throws refutes the artifact (`verifier threw: <message>`).
public typealias EvidencePort = (_ artifact: JSONValue, _ bundle: JSONValue) throws -> EvidenceVerdict

public struct EvidencePorts {
    public var sessionRoot: EvidencePort?
    public var schema: EvidencePort?
    public var receipt: EvidencePort?
    public var fact: EvidencePort?
    public var classifier: EvidencePort?
    public var offerSet: EvidencePort?
    public var labels: EvidencePort?
    public var effect: EvidencePort?
    public var verdict: EvidencePort?
    public var settlement: EvidencePort?
    public init() {}
}

/// The findings of a replay (`Findings` in `verify.ts`), text from fixed templates.
final class EvFindings {
    struct Finding { let code: String; let status: String; let text: String; let refs: [String] }

    static let templates: [String: String] = [
        "shape": "The bundle is well formed (pca-intent-evidence v1, closed members)",
        "principal.pinned": "Every session-root key that signs in this bundle is a principal key pinned by the reader (attribution)",
        "trust.principals": "The pinned principal keys (trust.principals) are well formed",
        "statement.commit": "The session root commits to the intent statement the bundle names",
        "statement.opening": "The opened statement is signed by a principal and hashes to the committed ref",
        "session_root.signature": "The session root is signed by one of its principal keys",
        "schema.signature": "The action schema is signed by a site key",
        "schema.digest": "The session root binds this action schema",
        "schema.anchor": "The action schema is anchored in a transparency log",
        "map.replay": "The task map replays to its committed digest",
        "root_grant": "The root intent grant G_0 is principal-signed and bound to the session",
        "delta.signature": "The delta grant is a root capability signed by a principal of the session",
        "delta.chain": "The delta grant chains to the session (session, seq, prev, root)",
        "delta.backed": "Every delta grant is backed by a principal \"yes\" answer",
        "answer.signature": "The answer is signed by a principal of the session, for this session",
        "answer.map": "The answer refers to a map version in the bundle",
        "answer.tier": "The answer meets the site minimum friction tier for the verb",
        "answer.typed": "The typed-tier value re-derives the signed typed digest",
        "answer.device": "The device-tier WebAuthn assertion verifies with user verification",
        "canaries.summary": "The canary summary equals the one recomputed from the signed canary answers",
        "pcactn.verify": "The PCActn verifies (signature, chain, audience, validity at its issue time)",
        "pcactn.root": "The PCActn's root capability is G_0 or a bundled delta grant",
        "pcactn.session": "The PCActn's signed intent_session member matches the session, its root grant and the accumulator events",
        "subject.present": "The subject PCActn is in the bundle",
        "jit.consent": "The irreversible subject action carries a principal JIT consent bound to its exact action digest",
        "accumulator.declared": "The accumulator is declared in the session root",
        "accumulator.arithmetic": "The accumulator posts are the running values of the counted events",
        "accumulator.cap": "Every accumulator post is within the admitting grant's cap",
        "accumulator.receipts": "The sequencer reservation receipt verifies and is consistent",
        "acc.keysets.equivocation": "No two different sequencer key sets share one root and version",
        "acc.keysets": "The sequencer key set is signed by the session's pinned sequencer root and its version never rolls back",
        "trust.acc": "The verifier freshness configuration (trust.acc) is well formed",
        "effect.binding": "The effect record is bound to the PCActn's signed params",
        "effect.charged": "The charged amount is within the confirmed value",
        "effect.frame": "No monitored state outside the write set changed",
        "effect.signature": "The effect record is signed by the site",
        "verdict.signature": "The site verdict record verifies",
        "fact.signature": "The oracle fact verifies under a pinned oracle key",
        "classifier.signature": "The classifier verdict verifies under a pinned judge key",
        "offer_set.signature": "The offer set is signed by a site key, for this session",
        "labels.signature": "The label receipt is signed by a pinned site key, for this session",
        "settlement.signature": "The settlement record verifies",
        "revocation.history": "The bundled revocation epoch extends its predecessor (one append-only chain by the session revocation authority)",
        "revocation.epoch": "A fresh revocation epoch shows the session, its maps and its deltas unrevoked at the action time",
        "anchor.inclusion": "The anchored artifact is included under a guardian-signed head of the intent log",
    ]
    static let statusText = ["pass": "verified", "fail": "REFUTED", "unverified": "not verified here"]

    var list: [Finding] = []

    func add(_ code: String, _ status: String, _ refs: [String] = [], _ detail: String? = nil) {
        let d = (detail?.isEmpty ?? true) ? "" : " (\(detail!))"
        list.append(Finding(code: code, status: status, text: "\(EvFindings.templates[code]!): \(EvFindings.statusText[status]!)\(d).", refs: refs))
    }

    func verdict(_ code: String, _ v: EvidenceVerdict, _ refs: [String] = []) {
        if v.ok { add(code, "pass", refs) } else { add(code, "fail", refs, v.reason) }
    }

    /// Run `port` if supplied, else the core default; with neither (or a core default that returns nil) the artifact stays unverified.
    func check(_ code: String, _ port: EvidencePort?, _ core: (() throws -> EvidenceVerdict?)?, _ artifact: JSONValue, _ bundle: JSONValue, _ refs: [String], _ what: String) {
        var v: EvidenceVerdict?
        do {
            if let p = port { v = try p(artifact, bundle) } else if let c = core { v = try c() } else { v = nil }
        } catch {
            v = EvidenceVerdict(ok: false, reason: "verifier threw: \(EvidenceReplay.message(error))")
        }
        if let v = v { verdict(code, v, refs) } else { add(code, "unverified", refs, "no verifier for \(what)") }
    }
}

/// The deterministic replay of one dispute evidence bundle (`replay` in `verify.ts`).
final class EvidenceReplay {
    typealias G = (id: JSONValue?, cap: JSONValue, seq: Int)

    let b: JSONValue
    let digest: String
    let trust: JSONValue
    let ports: EvidencePorts
    let f: EvFindings

    // summary
    var admittedUnder: String?
    var principalKeys: [String] = []
    var answersSummary: JObject = ["total": .int(0), "yes": .int(0), "no": .int(0), "partial": .int(0), "canaries": .int(0)]
    var refusals: [String] = []
    var consent: JSONValue = .null
    var charged: JSONValue = .null
    var canaryAccuracy: JObject = ["correct": .int(0), "asked": .int(0)]
    var attributionPinned = false
    var keysToCheck: [String] = []
    var proven: [String] = []

    // shared state
    var S: JSONValue = .null
    var session = ""
    var principals: [String] = []
    var sRef: JSONValue = .null
    var pqPins: [String: String] = [:]
    var siteKeys: JSONValue?
    var schemaDoc: JSONValue?
    var schemaDigest = ""
    var mapCommits = Set<JKey>()
    var grants: [G] = []
    var g0: JSONValue = .null
    var verified: [JSONValue] = []
    var real: [JSONValue] = []
    var rootHolderOrder: [String] = []
    var rootHolders: [String: JObject] = [:]
    var acceptedKeySets: [JSONValue] = []
    var verifiedKeySets: [JSONValue] = []
    var equivocated = Set<String>()
    var byDigestOrder: [String] = []
    var byDigest: [String: JSONValue] = [:]
    var rootSeq: [String: Int] = [:]
    var history: [JSONValue] = []
    var decls: [String: JObject] = [:]

    init(_ b: JSONValue, _ digest: String, _ trust: JSONValue, _ ports: EvidencePorts, _ f: EvFindings) {
        self.b = b; self.digest = digest; self.trust = trust; self.ports = ports; self.f = f
    }

    // ---- small JS helpers ----

    static func message(_ e: Error) -> String { (e as? JSError)?.message ?? "\(e)" }
    func g(_ o: JSONValue?, _ k: String) -> JSONValue? { JSLoose.get(o, k) }
    func rd(_ o: JSONValue?, _ k: String) throws -> JSONValue? { try JSLoose.rd(o, k) }
    func s(_ v: JSONValue?) -> String { JS.toString(v) }
    func str(_ v: JSONValue?) -> String? { v?.asString }
    func bk(_ k: String) -> JSONValue? { g(b, k) }
    func arr(_ v: JSONValue?) -> [JSONValue] { v?.asArray ?? [] }
    func tr(_ k: String) -> JSONValue? { g(trust, k) }
    func le(_ a: JSONValue?, _ x: Double) -> Bool { IV.num(a).map { $0 <= x } ?? false }
    func isNum(_ v: JSONValue?) -> Bool { IV.num(v).map { $0.isFinite } ?? false }
    func same(_ a: JSONValue?, _ b: String) -> Bool { IV.same(a?.asString, b) }
    func hash(_ v: JSONValue) throws -> String {
        guard let h = IV.strictHash(v) else { throw JSError("canonicalize: \(IV.strictCanonError(v) ?? "value out of profile")") }
        return h
    }
    /// `[...].sort()` of strings (UTF-16 code unit order).
    static func sorted(_ xs: [String]) -> [String] { xs.sorted { $0.utf16.lexicographicallyPrecedes($1.utf16) } }
    func int(_ n: Int) -> JSONValue { .int(Int64(n)) }
    func mapKey(_ v: JSONValue?) -> String { v?.asString ?? "\u{0}undefined" }

    func setGrant(_ e: G) {
        if let i = grants.firstIndex(where: { mapKey($0.id) == mapKey(e.id) }) { grants[i] = e } else { grants.append(e) }
    }
    func setByDigest(_ d: String, _ p: JSONValue) {
        if byDigest[d] == nil { byDigestOrder.append(d) }
        byDigest[d] = p
    }
    func effectOf(_ d: String) -> JSONValue? { arr(bk("effects")).first { g($0, "pcactn_digest") == .string(d) } }
    func digestOf(_ p: JSONValue) -> String? { IV.strictHash(p) }
    func paramsOf(_ d: String) -> JSONValue? { let p = g(effectOf(d), "params"); return JS.truthy(p) ? p : nil }

    // ---- the replay ----

    func run() throws {
        S = bk("session_root") ?? .null
        let subject = bk("subject")
        session = str(g(subject, "session")) ?? ""
        // Consistency is checked against the keys the session root names; ATTRIBUTION (below) against the reader's pins.
        guard case let .array(plist)? = g(S, "principals") else { throw JSError("S.principals.map is not a function") }
        principals = EvidenceReplay.sorted(plist.compactMap { str(g($0, "key")) })
        principalKeys = principals
        if let o = tr("sessionRootDigest"), o != .null {
            guard o.asString != nil else { throw JSError("trust.sessionRootDigest must be a string") }
            sRef = o
        } else {
            guard let d = IntentSession.rootDigest(S) else { throw JSError("canonicalize: value out of profile") }
            sRef = .string(d)
        }
        // The reader's PQ pins (trust.principals[].pq_pk, out of band; NEVER the bundle's own S.principals).
        for p in arr(tr("principals")) { if let k = str(g(p, "key")), let pq = str(g(p, "pq_pk")) { pqPins[k] = pq } }
        siteKeys = tr("siteKeys")
        schemaDoc = g(bk("schema"), "doc")

        try sessionRootSection()
        statementSection()
        try schemaSection()
        try mapsSection()
        try grantsSection()
        try answersSection()
        try keySetsSection()
        try pcactnSection()
        try effectsSection()
        try jitSection()
        try accumulatorSection()
        try artifactsSection()
        try revocationSection()
        try anchorsSection()
        try attributionSection()
        provenSection()
    }

    var pqPinsJSON: JSONValue { .object(Dictionary(uniqueKeysWithValues: pqPins.map { (JKey($0.key), JSONValue.string($0.value)) })) }

    func sessionRootSection() throws {
        if !same(g(S, "session"), session) {
            f.add("session_root.signature", "fail", ["session_root"], "session root is for another session")
        } else {
            f.check("session_root.signature", ports.sessionRoot, {
                let r = IntentSession.verifyRoot(self.S, pqPins: self.pqPinsJSON)
                return EvidenceVerdict(ok: r.ok, reason: r.reason)
            }, S, b, ["session_root"], "the session root")
        }
    }

    func statementSection() {
        let st = bk("statement")
        f.add("statement.commit", g(S, "intent_ref") == g(st, "commit") ? "pass" : "fail", ["statement"])
        guard let opening = g(st, "opening") else {
            f.add("statement.opening", "unverified", ["statement"], "the statement was not opened (it stays a commitment)")
            return
        }
        let v = PCAIntentStatement.verify(opening)
        if !v.ok { f.add("statement.opening", "fail", ["statement"], v.reason); return }
        if (try? PCAIntentStatement.ref(opening)).map({ JSONValue.string($0) }) != g(st, "commit") {
            f.add("statement.opening", "fail", ["statement"], "the opening does not hash to the commitment")
        } else if !principals.contains(where: { IV.same($0, str(g(opening, "principal")) ?? "\u{0}") }) {
            f.add("statement.opening", "fail", ["statement"], "signed by a key that is not a principal of the session")
        } else {
            f.add("statement.opening", "pass", ["statement"])
        }
    }

    func schemaSection() throws {
        let doc = schemaDoc ?? .null
        var core: (() throws -> EvidenceVerdict?)?
        if JS.truthy(siteKeys) {
            core = {
                let r = ActionSchema.verify(doc, keys: self.siteKeys)
                return EvidenceVerdict(ok: r.ok, reason: r.reason)
            }
        }
        f.check("schema.signature", ports.schema, core, doc, b, ["schema"], "the action schema (no site keys supplied)")
        guard let d = ActionSchema.digest(doc) else { throw JSError("canonicalize: value out of profile") }
        schemaDigest = d
        let ss = try rd(S, "schema")
        let okDigest = try rd(ss, "digest") == .string(d) && rd(ss, "aud") == g(bk("subject"), "aud")
        f.add("schema.digest", okDigest ? "pass" : "fail", ["schema"])
    }

    func mapsSection() throws {
        for m in arr(bk("maps")) { if let c = str(g(m, "commit")) { mapCommits.insert(JKey(c)) } }
        for m in arr(bk("maps")) {
            let ref = ["map:\(s(g(m, "seq")))"]
            let mv = g(m, "map")
            if !JS.truthy(mv) { f.add("map.replay", "unverified", ref, "committed map not revealed"); continue }
            let r = PCAIntentMap.verify(mv)
            if !r.ok {
                f.add("map.replay", "fail", ref, r.problems.prefix(3).joined(separator: "; "))
            } else if try PCAIntentMap.digest(mv!) != str(g(m, "commit")) {
                f.add("map.replay", "fail", ref, "the revealed map does not hash to its commit")
            } else {
                f.add("map.replay", "pass", ref)
            }
        }
    }

    /// `grantSessionCaveat` + the chain check shared by G_0 and every delta.
    func chainError(_ cap: JSONValue) -> String? {
        Capability.verifyChain([cap], expectedRootIssuer: str(g(cap, "issuer")), pqPins: pqPins)
    }

    func grantsSection() throws {
        g0 = bk("root_grant") ?? .null
        let g0id = try rd(g0, "id")
        do {
            let cv = IntentSession.grantCaveat(g0)
            let chain = chainError(g0)
            if let c = chain {
                f.add("root_grant", "fail", ["G_0"], c)
            } else if !principals.contains(where: { IV.same($0, str(g(g0, "issuer")) ?? "\u{0}") }) {
                f.add("root_grant", "fail", ["G_0"], "not signed by a principal of the session")
            } else if cv == nil || IntentSession.caveatError(cv) != nil {
                f.add("root_grant", "fail", ["G_0"], cv != nil ? (IntentSession.caveatError(cv) ?? "") : "no intent_session caveat")
            } else if g(cv, "session") != .string(session) || IV.num(g(cv, "seq")) != 0 || g(cv, "root") != sRef {
                f.add("root_grant", "fail", ["G_0"], "intent_session caveat does not bind seq 0 of this session root")
            } else {
                f.add("root_grant", "pass", ["G_0"])
                setGrant((id: g0id, cap: g0, seq: 0))
            }
        }
        var prevId: JSONValue? = g0id
        for (i, d) in arr(bk("deltas")).enumerated() {
            let want = i + 1
            let ref = ["D_\(want)"]
            let issuer = try rd(d, "issuer")
            let chain = chainError(d)
            let isPrincipal = principals.contains(where: { IV.same($0, str(issuer) ?? "\u{0}") })
            if chain != nil || !isPrincipal || g(d, "parent") != nil {
                f.add("delta.signature", "fail", ref, chain ?? "not a principal-signed root capability")
                continue
            }
            f.add("delta.signature", "pass", ref)
            let cv = IntentSession.grantCaveat(d)
            let nCv = arr(g(d, "caveats")).filter { g($0, "type") == .string("intent_session") }.count
            var why: String?
            if cv == nil || nCv != 1 { why = "no single intent_session caveat" }
            else if let e = IntentSession.caveatError(cv) { why = e }
            else if g(cv, "session") != .string(session) { why = "bound to another session" }
            else if g(cv, "root") != sRef { why = "bound to another session root" }
            else if IV.num(g(cv, "seq")) != Double(want) { why = "seq \(s(g(cv, "seq"))) where \(want) was expected (gap, duplicate or reorder)" }
            else if g(cv, "prev") != prevId { why = "prev does not name the previous grant" }
            if let w = why {
                f.add("delta.chain", "fail", ref, w)
            } else {
                f.add("delta.chain", "pass", ref)
                setGrant((id: g(d, "id"), cap: d, seq: want))
            }
            prevId = g(d, "id")
        }
    }

    func answersSection() throws {
        let principalsJSON: JSONValue = .array(principals.map { .string($0) })
        for a in arr(bk("answers")) {
            let ref = ["answer:\(s(g(a, "question_id")))"]
            let v = PCAWallet.verifyIntentAnswer(a, principalsJSON)
            if v.get("ok") != .bool(true) { f.add("answer.signature", "fail", ref, str(v.get("reason")) ?? ""); continue }
            if g(a, "session") != .string(session) { f.add("answer.signature", "fail", ref, "answer for another session"); continue }
            f.add("answer.signature", "pass", ref)
            verified.append(a)
            let mapKnown = str(g(a, "map_digest")).map { mapCommits.contains(JKey($0)) } ?? false
            f.add("answer.map", mapKnown ? "pass" : "fail", ref)
            let ux = g(a, "ux")
            if JS.truthy(g(ux, "canary")) || IV.num(g(a, "y")) != 1 { continue }
            if let min = minTierOf(a) {
                f.add("answer.tier", PCAWallet.frictionRank(g(ux, "tier")) >= PCAWallet.frictionRank(min) ? "pass" : "fail", ref, "\(s(g(ux, "tier"))) vs minimum \(s(min))")
            }
            if g(ux, "tier") == .string("typed") {
                let qid = str(g(a, "question_id")) ?? ""
                if let tv = typedValueOf(qid) {
                    let ok = (try? PCAWallet.typedDigest(qid, tv)).map { JSONValue.string($0) } == g(ux, "typed_digest")
                    f.add("answer.typed", ok ? "pass" : "fail", ref)
                } else {
                    f.add("answer.typed", "unverified", ref, "the typed value is not known to this verifier")
                }
            }
            if g(ux, "tier") == .string("device") { try deviceSection(a, ux, ref) }
        }
        real = verified.filter { !JS.truthy(g(g($0, "ux"), "canary")) }
        let canaries = verified.filter { JS.truthy(g(g($0, "ux"), "canary")) }
        answersSummary = ["total": int(real.count),
                          "yes": int(real.filter { IV.num(g($0, "y")) == 1 && g($0, "partial") == nil }.count),
                          "no": int(real.filter { IV.num(g($0, "y")) == 0 }.count),
                          "partial": int(real.filter { g($0, "partial") != nil }.count),
                          "canaries": int(canaries.count)]
        refusals = EvidenceReplay.sorted(real.filter { IV.num(g($0, "y")) == 0 }.map { s(g($0, "question_id")) })
        let yesCount = real.filter { IV.num(g($0, "y")) == 1 }.count
        let nd = arr(bk("deltas")).count
        f.add("delta.backed", yesCount >= nd ? "pass" : "fail", [], "\(nd) delta(s), \(yesCount) principal yes answer(s)")
        try canariesSection(canaries)
    }

    func minTierOf(_ a: JSONValue) -> JSONValue? {
        guard case let .object(mt)? = tr("minTier"), let verb = str(g(a, "verb")) else { return nil }
        return mt[JKey(verb)]
    }

    func typedValueOf(_ qid: String) -> String? {
        guard case let .object(tv)? = tr("typedValues") else { return nil }
        return tv[JKey(qid)]?.asString
    }

    func deviceSection(_ a: JSONValue, _ ux: JSONValue?, _ ref: [String]) throws {
        let wa = g(ux, "webauthn")
        var cred: JSONValue?
        if JS.truthy(wa), case let .object(cs)? = tr("credentials"), let cid = str(g(wa, "credential_id")) { cred = cs[JKey(cid)] }
        guard JS.truthy(wa), JS.truthy(cred) else { f.add("answer.device", "unverified", ref, "unknown authenticator"); return }
        func bytes(_ k: String) throws -> [UInt8] {
            guard let t = str(g(wa, k)), let d = Base64URLStrict.decode(t) else { throw JSError("invalid base64url") }
            return d
        }
        let challenge = try PCAWallet.deviceChallenge(questionId: g(a, "question_id"), renderedDigest: g(ux, "rendered_digest"), y: g(a, "y"), actionDigest: g(ux, "action_digest"))
        guard let pub = g(cred, "publicKey") else { f.add("answer.device", "fail", ref, "no public key"); return }
        let origins = arr(g(cred, "origins")).compactMap { $0.asString }
        var e = PCAWebauthn.Expectations(expectedChallenge: .b64u(challenge), rpId: str(g(cred, "rpId")) ?? "", origins: origins,
                                         storedSignCount: IV.num(g(cred, "signCount")) ?? 0)
        e.requireUV = true
        let r = PCAWebauthn.verifyAssertion(PCAWebauthn.Assertion(authenticatorData: try bytes("authenticator_data"), clientDataJSON: try bytes("client_data_json"),
                                                                 signature: try bytes("signature"), publicKey: .jwk(pub)), e)
        f.add("answer.device", r.ok ? "pass" : "fail", ref, r.ok ? nil : r.reason)
    }

    func canariesSection(_ canaries: [JSONValue]) throws {
        var labels: [String: JSONValue] = [:]
        for c in arr(bk("canary_labels")) { if let q = str(g(c, "question_id")) { labels[q] = g(c, "label") } }
        var falseYes = 0, falseNo = 0, missing = 0
        for a in canaries {
            let q = str(g(a, "question_id")) ?? ""
            var label = labels[q]
            if case let .object(tl)? = tr("canaryLabels"), let t = tl[JKey(q)], t != .null { label = t }
            if label == nil || label == .null { missing += 1 }
            else if IV.num(label) == 0 && IV.num(g(a, "y")) == 1 { falseYes += 1 }
            else if IV.num(label) == 1 && IV.num(g(a, "y")) == 0 { falseNo += 1 }
        }
        canaryAccuracy = ["correct": int(canaries.count - missing - falseYes - falseNo), "asked": int(canaries.count)]
        let c = bk("canaries")
        if missing > 0 {
            f.add("canaries.summary", "fail", [], "\(missing) canary answer(s) without a known label")
        } else if IV.num(g(c, "asked")) != Double(canaries.count) || IV.num(g(c, "false_yes")) != Double(falseYes) || IV.num(g(c, "false_no")) != Double(falseNo) {
            f.add("canaries.summary", "fail", [], "claimed \(s(g(c, "asked")))/\(s(g(c, "false_yes")))/\(s(g(c, "false_no"))), recomputed \(canaries.count)/\(falseYes)/\(falseNo)")
        } else {
            f.add("canaries.summary", "pass", [], "\(canaries.count) asked, \(falseYes) false yes, \(falseNo) false no")
        }
    }

    // ---- sequencer key sets (rule 15) ----

    struct KeySetsAt { var sets: [JSONValue]; var minV: Double?; var tracked: IntentAcc.TrackedKeySet? }

    func slot(_ root: String, _ version: JSONValue?) -> String { "\(root)#\(s(version))" }

    func keySetsSection() throws {
        guard case let .array(accs)? = g(S, "accumulators") else { throw JSError("S.accumulators is not iterable") }
        for a in accs {
            let h = try rd(a, "holder")
            if g(h, "kind") == .string("sequenced"), case let .object(ho)? = h, let root = str(ho["root"]) {
                if rootHolders[root] == nil { rootHolderOrder.append(root) }
                rootHolders[root] = ho
            }
        }
        let raw = arr(g(bk("accumulator"), "sequencer_keys"))
        func nz(_ v: JSONValue?) -> Double { let n = JS.toNumber(v); return n.isNaN ? 0 : n }
        let sets = try JSLoose.sort(raw) { x, y in
            try JSLoose.or(nz(self.g(x, "issued_at")) - nz(self.g(y, "issued_at"))) {
                try JSLoose.or(nz(self.g(x, "version")) - nz(self.g(y, "version"))) {
                    let hx = try self.hash(x), hy = try self.hash(y)
                    return hx.utf16.lexicographicallyPrecedes(hy.utf16) ? -1 : hy.utf16.lexicographicallyPrecedes(hx.utf16) ? 1 : 0
                }
            }
        }
        var tracked: [String: Double] = [:]
        var byVersion: [String: (digest: String, ref: String)] = [:]
        for (i, k) in sets.enumerated() {
            let isO = k.isObject
            let ref = "keyset#\(i):\(isO ? s(g(k, "version")) : "?")"
            guard isO, let seq = str(g(k, "sequencer")), let holder = rootHolders[seq], let root = str(holder["root"]) else {
                f.add("acc.keysets", "fail", [ref], "not signed by a sequencer root the session root pins"); continue
            }
            if IntentAcc.verifyKeySet(k, root: root, rootPqPk: holder["root_pq_pk"]) != .valid {
                f.add("acc.keysets", "fail", [ref], "the key set does not verify under its pinned root"); continue
            }
            let version = IV.num(g(k, "version")) ?? .nan
            let prev = tracked[root]
            if let p = prev, version < p { f.add("acc.keysets", "fail", [ref], "version \(s(g(k, "version"))) rolls back the tracked version \(JS.number(p))"); continue }
            // Equivocation (rule 15, tracked {version, digest}): two DIFFERENT sets under one root and version are both refused.
            let sl = slot(root, g(k, "version"))
            guard let dg = IntentAcc.keySetDigest(k) else { throw JSError("canonicalize: value out of profile") }
            let seen = byVersion[sl]
            if let sn = seen, sn.digest != dg {
                equivocated.insert(sl)
                verifiedKeySets.append(k)
                f.add("acc.keysets.equivocation", "fail", [sn.ref, ref], "two different key sets under version \(s(g(k, "version"))) of one sequencer root")
                continue
            }
            if seen == nil { byVersion[sl] = (dg, ref) }
            verifiedKeySets.append(k)
            tracked[root] = max(prev ?? 0, version)
            acceptedKeySets.append(k)
            f.add("acc.keysets", "pass", [ref])
        }
        acceptedKeySets.removeAll { equivocated.contains(slot(str(g($0, "sequencer")) ?? "", g($0, "version"))) }
    }

    /// In force = accepted sets of the holder's root issued by admission (+ the core skew); the tracked state is the newest VERIFIED set
    /// issued at or before admission, equivocating ones included.
    func keySetsAt(_ root: String, _ t: Double) -> KeySetsAt {
        let own = acceptedKeySets.filter { str(g($0, "sequencer")) == root }
        var newest: JSONValue?
        for k in verifiedKeySets where str(g(k, "sequencer")) == root && le(g(k, "issued_at"), t) {
            if newest == nil || (IV.num(g(k, "version")) ?? .nan) > (IV.num(g(newest, "version")) ?? .nan) { newest = k }
        }
        let poisoned = newest.map { equivocated.contains(slot(root, g($0, "version"))) } ?? false
        let nv = newest.flatMap { IV.num(g($0, "version")) }
        var trackedState: IntentAcc.TrackedKeySet?
        if let n = newest, !poisoned, let v = IV.int(g(n, "version")), let d = IntentAcc.keySetDigest(n) { trackedState = IntentAcc.TrackedKeySet(version: v, digest: d) }
        return KeySetsAt(sets: own.filter { le(g($0, "issued_at"), t + IntentAcc.RECEIPT_SKEW_MS) && (IV.num(g($0, "version")) ?? .nan) >= (nv ?? 0) },
                         minV: nv, tracked: trackedState)
    }

    func freshness(_ ks: KeySetsAt) -> IntentAcc.Freshness {
        var fr = IntentAcc.Freshness()
        let acc = tr("acc")
        if let m = IV.num(g(acc, "max_receipt_age_s")) { fr.maxReceiptAgeMs = m * 1000 }
        if let m = IV.num(g(acc, "max_keyset_age_s")) { fr.maxKeySetAgeMs = m * 1000 }
        if let t = ks.tracked { fr.tracked = t } else if let v = ks.minV { fr.minKeySetVersion = v }
        return fr
    }

    // ---- PCActns ----

    func epochIdxAt(_ t: Double) -> Int {
        var idx = -1
        for (i, r) in arr(bk("revocation_epochs")).enumerated() where le(g(g(r, "epoch"), "issued_at"), t) { idx = i }
        return idx
    }

    func v2Context(_ p: JSONValue, _ d: String, _ seq: Int?) throws -> JSONValue? {
        guard let params = paramsOf(d), let seq = seq, case let .object(po) = params else { return nil }
        let iat = IV.num(g(p, "iat")) ?? .nan
        let before: [JSONValue]
        if let idx = history.firstIndex(where: { g($0, "id") == .string(d) }) { before = Array(history[..<idx]) } else { before = history.filter { le(g($0, "t"), iat) } }
        let verbs = g(schemaDoc, "verbs")
        let schemaView: JSONValue = .object(verbs.map { ["verbs": $0] } ?? [:])
        let acc = try IntentHistory.accContextFor(S, before, params: po, t: g(p, "iat"), schema: schemaView)
        let ri = epochIdxAt(iat)
        let epochs = arr(bk("revocation_epochs"))
        let sorted = grants.sorted { $0.seq < $1.seq }.map { $0.cap }
        var sess: JObject = ["root": S, "grants": .array(Array(sorted.prefix(seq))), "pq_pins": pqPinsJSON]
        if ri >= 0 { sess["revocation"] = epochs[ri] }
        if ri > 0 { sess["revocation_last"] = epochs[ri - 1] }
        var sequencerKeys: [JSONValue] = []
        var versions: JObject = [:]
        for root in rootHolderOrder {
            let ks = keySetsAt(root, iat)
            sequencerKeys += ks.sets
            if let t = ks.tracked { versions[JKey(root)] = .object(["version": .int(t.version), "digest": .string(t.digest)]) }
        }
        let accObj: JObject = ["state": .object(acc.state), "monitors": .object(acc.monitors),
                               "receipts": .array(arr(g(bk("accumulator"), "receipts"))), "sequencer_keys": .array(sequencerKeys),
                               "keyset_versions": .object(versions)]
        var ctx: JObject = ["params": params, "schema": .object(["docs": .array(schemaDoc.map { [$0] } ?? []), "keys": JS.truthy(siteKeys) ? siteKeys! : .array([])]),
                            "session": .object(sess), "acc": .object(accObj)]
        if JS.truthy(tr("acc")) { ctx["policy"] = .object(["acc": tr("acc")!]) }
        return .object(ctx)
    }

    func pcactnSection() throws {
        // the admitted history, as the site's store held it: one event per accumulator-bearing PCActn, in event order
        let pcs = arr(bk("pcactns"))
        for ev in arr(g(bk("accumulator"), "events")) {
            guard let evd = str(g(ev, "pcactn_digest")) else { continue }
            if history.contains(where: { g($0, "id") == .string(evd) }) { continue }
            let p = pcs.first { digestOf($0) == evd }
            guard let pp = p, let params = paramsOf(evd) else { continue }
            let action = try rd(pp, "action")
            var h: JObject = ["id": .string(evd), "params": params, "status": g(ev, "status") ?? .string("committed")]
            if let v = try rd(action, "verb") { h["verb"] = v }
            if let r = try rd(action, "resource") { h["resource"] = r }
            if let t = try rd(pp, "iat") { h["t"] = t }
            history.append(.object(h))
        }
        let v2Checks = ["schema", "intent_session", "accumulators"]
        for p in pcs {
            guard let d = digestOf(p) else { f.add("pcactn.verify", "fail", ["pcactn:?"], "not canonicalizable"); continue }
            setByDigest(d, p)
            let ref = ["pcactn:\(d)"]
            let chain = try rd(p, "cap_chain")
            guard let root = chain?.asArray?.first, JS.truthy(root) else { f.add("pcactn.verify", "fail", ref, "empty capability chain"); continue }
            let gEntry = grants.first { mapKey($0.id) == mapKey(g(root, "id")) }
            var sameRoot = false
            if let ge = gEntry { sameRoot = try hash(ge.cap) == hash(root) }
            let isess = g(p, "intent_session")
            var ctx: JSONValue?
            if isess != nil && sameRoot { ctx = try v2Context(p, d, gEntry?.seq) }
            // pca-unsafe-root: allow offline replay: the root's authority is pcactn.root (byte-equal to G_0 / a verified delta) plus
            // principal.pinned (trust.principals); a non-Ed25519 root verifies only under the reader's pqPins, else it is refused.
            let r = PCA.verify(pcactn: p, grant: root, now: IV.int(g(p, "iat")) ?? 0, audience: .id(str(g(bk("subject"), "aud")) ?? ""),
                               intentV2: ctx.map { IntentV2Context($0) }, insecureSkipPlanRootCheck: true, pqPins: pqPins, grantFromArtifact: true)
            // the reference names the capability-chain check `cap_chain`
            let failed = EvidenceReplay.sorted(r.checks.filter { !$0.value }.map { $0.key == "chain" ? "cap_chain" : $0.key })
            let v1f = failed.filter { !v2Checks.contains($0) }
            let v2f = failed.filter { v2Checks.contains($0) }
            f.add("pcactn.verify", v1f.isEmpty ? "pass" : "fail", ref, v1f.isEmpty ? nil : "\(v1f.joined(separator: ", ")): \(r.reason)")
            if sameRoot, let ge = gEntry {
                f.add("pcactn.root", "pass", ref, ge.seq == 0 ? "G_0" : "D_\(ge.seq)")
                rootSeq[d] = ge.seq
            } else {
                f.add("pcactn.root", "fail", ref, "rooted at a grant that is not G_0 or a verified delta of this session")
            }
            guard let isv = isess else { continue }
            var why: String?
            if g(isv, "session") != .string(session) { why = "another session" }
            else if g(isv, "root") != sRef { why = "another session root" }
            else if g(isv, "schema") != .string(schemaDigest) { why = "another schema" }
            else if let ge = gEntry, IV.num(g(isv, "seq")) != Double(ge.seq) { why = "seq \(s(g(isv, "seq"))) but rooted at seq \(ge.seq)" }
            else {
                let accClaims: [JSONValue]
                switch g(isv, "acc") {
                case nil, .null?: accClaims = []
                case let .array(a)?: accClaims = a
                default: throw JSError("is.acc is not iterable")
                }
                for c in accClaims {
                    let ev = arr(g(bk("accumulator"), "events")).first { g($0, "pcactn_digest") == .string(d) && g($0, "acc") == g(c, "id") }
                    if ev == nil || g(ev, "post") != g(c, "post") {
                        why = "the signed claim \(s(g(c, "id"))).post = \(s(g(c, "post"))) has no matching accumulator event"
                    }
                }
            }
            if why == nil && !v2f.isEmpty { why = "core v2 checks failed: \(v2f.joined(separator: ", "))" }
            if let w = why { f.add("pcactn.session", "fail", ref, w) }
            else if ctx == nil { f.add("pcactn.session", "unverified", ref, "the core v2 checks need the plaintext params of the effect record") }
            else { f.add("pcactn.session", "pass", ref) }
        }
        let sd = str(g(bk("subject"), "pcactn_digest")) ?? ""
        f.add("subject.present", byDigest[sd] != nil ? "pass" : "fail", ["pcactn:\(s(g(bk("subject"), "pcactn_digest")))"])
        if let sSeq = rootSeq[sd] { admittedUnder = sSeq == 0 ? "G_0" : "D_\(sSeq)" }
    }

    var subjectPcactn: JSONValue? { str(g(bk("subject"), "pcactn_digest")).flatMap { byDigest[$0] } }

    func effectsSection() throws {
        for e in arr(bk("effects")) {
            let ed = s(g(e, "pcactn_digest"))
            let ref = ["effect:\(ed)"]
            guard let p = byDigest[ed] else { f.add("effect.binding", "fail", ref, "no such PCActn in the bundle"); continue }
            let params = g(e, "params")
            if params == nil {
                f.add("effect.binding", "unverified", ref, "no raw params to bind")
            } else {
                let pd = try hash(params == .null ? .object([:]) : params!)
                f.add("effect.binding", g(try rd(p, "action"), "params_digest") == .string(pd) ? "pass" : "fail", ref)
            }
            if let ch = g(e, "charged"), JS.truthy(ch) {
                guard let cref = str(g(ch, "ref")) else { throw JSError("e.charged.ref.startsWith is not a function") }
                let name = IV.startsWith(cref, "action.params.") ? IV.dropPrefix(cref, 14) : nil
                let bound = (name != nil && JS.truthy(params)) ? g(params, name!) : nil
                if !isNum(bound) || !isNum(g(ch, "amount")) {
                    f.add("effect.charged", "unverified", ref, "no numeric \(cref) to compare")
                } else {
                    let amount = IV.num(g(ch, "amount"))!, bd = IV.num(bound)!
                    f.add("effect.charged", amount <= bd ? "pass" : "fail", ref, "\(JS.number(amount)) vs \(JS.number(bd))")
                    if ed == str(g(bk("subject"), "pcactn_digest")) { charged = .object(["amount": g(ch, "amount")!, "bound": bound!]) }
                }
            }
            if let fv = g(e, "frame_violations") {
                guard case let .array(vs) = fv else { throw JSError("frame_violations.length") }
                f.add("effect.frame", vs.isEmpty ? "pass" : "fail", ref, vs.isEmpty ? nil : EvidenceReplay.sorted(vs.map { s($0) }).joined(separator: ", "))
            }
            f.check("effect.signature", ports.effect, nil, e, b, ref, "effect records (no core format yet)")
        }
    }

    func jitSection() throws {
        guard let subject = subjectPcactn, g(try rd(subject, "action"), "reversibility_class") == .string("irreversible") else { return }
        let ref = ["pcactn:\(s(g(bk("subject"), "pcactn_digest")))"]
        let ad = try PCAIntentStatement.actionDigest(g(subject, "action"))
        let need: JSONValue = JS.present(tr("jitTier")) ?? .string("typed")
        let c = real.first { a in
            IV.num(g(a, "y")) == 1 && g(g(a, "ux"), "consent_for_action") == .bool(true) && g(g(a, "ux"), "action_digest") == .string(ad)
                && PCAWallet.frictionRank(g(g(a, "ux"), "tier")) >= PCAWallet.frictionRank(need)
        }
        if let c = c {
            f.add("jit.consent", "pass", ref, "question \(s(g(c, "question_id"))), \(s(g(g(c, "ux"), "tier"))) tier")
            consent = .object(["question_id": g(c, "question_id") ?? .null, "tier": g(g(c, "ux"), "tier") ?? .null, "signer": g(c, "signer") ?? .null])
        } else {
            f.add("jit.consent", "fail", ref, "no principal yes at \(s(need)) tier or above bound to this action digest")
        }
    }

    // ---- accumulators ----

    func valueOf(_ decl: JObject, _ d: String) throws -> Double? {
        guard let p = byDigest[d], case let .object(params)? = paramsOf(d) else { return nil }
        let action = try rd(p, "action")
        let verbs = g(schemaDoc, "verbs")
        let r = IntentAcc.valueOfChecked(decl, str(g(action, "verb")) ?? "", params, .object(verbs.map { ["verbs": $0] } ?? [:]))
        return r.value?.val
    }

    func accumulatorSection() throws {
        guard case let .array(accs)? = g(S, "accumulators") else { throw JSError("S.accumulators is not iterable") }
        for a in accs { if case let .object(o) = a, let id = str(o["id"]) { decls[id] = o } }
        var running: [String: Double] = [:]
        for (i, ev) in arr(g(bk("accumulator"), "events")).enumerated() {
            let accId = s(g(ev, "acc"))
            let ref = ["acc:\(accId)#\(i)"]
            guard let decl = decls[accId] else { f.add("accumulator.declared", "fail", ref); continue }
            let evd = s(g(ev, "pcactn_digest"))
            let p = byDigest[evd]
            let status = str(g(ev, "status"))
            let counted = status != "released" && status != "reverted"
            let prev = running[accId] ?? 0
            let post = IV.num(g(ev, "post")) ?? .nan
            var expected: Double?
            let agg = str(decl["agg"])
            if !counted { expected = prev }
            else if agg == "count" { expected = prev + 1 }
            else if agg == "sum" || agg == "max" {
                if let val = try valueOf(decl, evd) { expected = agg == "sum" ? prev + val : max(prev, val) }
            }
            if p == nil {
                f.add("accumulator.arithmetic", "fail", ref, "event names a PCActn that is not in the bundle")
            } else if let ex = expected {
                f.add("accumulator.arithmetic", post == ex ? "pass" : "fail", ref, post == ex ? nil : "post \(JS.number(post)), recomputed \(JS.number(ex))")
            } else {
                f.add("accumulator.arithmetic", post >= prev ? "unverified" : "fail", ref, post >= prev ? "contribution not recomputable" : "post decreased")
            }
            running[accId] = counted ? post : prev
            if !counted { continue }
            let seq: Int? = p != nil ? rootSeq[evd] : nil
            let delta = IV.num(g(ev, "delta"))
            if let dl = delta, let sq = seq, dl != Double(sq) {
                f.add("accumulator.cap", "fail", ref, "the event names a different admitting grant from the PCActn root")
                continue
            }
            let want: Double? = seq.map { Double($0) } ?? delta
            let grant = want.flatMap { w in grants.first { Double($0.seq) == w } }
            var caps: [Double] = []
            if let gr = grant, let pp = p, let c = IV.num(try PCAEvidence.capOf(gr.cap, g(ev, "acc"), g(try rd(pp, "action"), "verb"))) { caps.append(c) }
            if isNum(decl["domain_max"]) { caps.append(IV.num(decl["domain_max"])!) }
            if isNum(decl["cap"]) { caps.append(IV.num(decl["cap"])!) }
            if caps.isEmpty { f.add("accumulator.cap", "unverified", ref, "no cap stated for this accumulator") }
            else {
                let cap = caps.min()!
                f.add("accumulator.cap", post.isFinite && post <= cap ? "pass" : "fail", ref, "post \(JS.number(post)), cap \(JS.number(cap))")
            }
        }
        let receipts = arr(g(bk("accumulator"), "receipts"))
        if g(bk("accumulator"), "holder") == .string("sequenced") && receipts.isEmpty {
            f.add("accumulator.receipts", "fail", ["accumulator"], "a sequenced accumulator without receipts")
        }
        for (i, r) in receipts.enumerated() {
            // nil = the signature and freshness held but the contribution cannot be recomputed (params withheld): unverified.
            let core: () throws -> EvidenceVerdict? = {
                guard let decl = self.decls[self.s(self.g(r, "acc"))], case let .object(holder)? = decl["holder"], self.same(holder["kind"], "sequenced") else {
                    return EvidenceVerdict(ok: false, reason: "the receipt names an accumulator that is not sequenced in the session root")
                }
                if self.g(r, "session") != .string(self.session) || self.g(r, "aud") != self.g(self.bk("subject"), "aud") {
                    return EvidenceVerdict(ok: false, reason: "receipt for another session or audience")
                }
                var d: String?
                for k in self.byDigestOrder where d == nil {
                    guard case let .object(po)? = self.byDigest[k] else { continue }
                    guard let rdg = IntentAcc.reservationDigest(po) else { throw JSError("canonicalize: value out of profile") }
                    if self.g(r, "pcactn_digest") == .string(rdg) { d = k }
                }
                guard let dd = d else { return EvidenceVerdict(ok: false, reason: "the receipt reserves for a PCActn that is not in the bundle") }
                // Rule 15 freshness is judged at ADMISSION time (the reserved PCActn's iat), never at bundle-verification time.
                let admittedAt = IV.num(self.g(self.byDigest[dd], "iat")) ?? .nan
                let ks = self.keySetsAt(self.str(holder["root"]) ?? "", admittedAt)
                if IntentAcc.verifyAgainstHolder(r, holder: holder, keySets: .array(ks.sets), now: admittedAt, fresh: self.freshness(ks)) != .valid {
                    return EvidenceVerdict(ok: false, reason: "not signed by a key the pinned sequencer root listed, or not fresh, at admission time")
                }
                if !(admittedAt.isFinite && (IV.num(self.g(r, "expires_at")) ?? .nan).isFinite && admittedAt <= (IV.num(self.g(r, "expires_at")) ?? .nan)) { return EvidenceVerdict(ok: false, reason: "the receipt had expired when the action was admitted") }
                guard let val = try self.valueOf(decl, dd) else { return nil }
                if !IntentAcc.receiptArithmeticOk(self.str(decl["agg"]) ?? "", r, val) { return EvidenceVerdict(ok: false, reason: "pre + delta does not give post for the reserved value") }
                return EvidenceVerdict(ok: true)
            }
            let seqRef = g(r, "seq").map { s($0) } ?? String(i)
            f.check("accumulator.receipts", ports.receipt, core, r, b, ["receipt:\(s(g(r, "acc")))#\(seqRef)"], "the reserved contribution (the effect params were withheld)")
        }
    }

    // ---- W-B artifacts ----

    func artifactsSection() throws {
        for (i, x) in arr(bk("facts")).enumerated() {
            var pk: JSONValue?
            if x.isObject, let o = str(g(x, "oracle")), case let .object(ok)? = tr("oracleKeys") { pk = ok[JKey(o)] }
            var core: (() throws -> EvidenceVerdict?)?
            if !(pk == nil) {
                core = {
                if let w = IntentWB.factWireError(x) { return EvidenceVerdict(ok: false, reason: w) }
                guard case let .object(xo) = x, let k = pk?.asString, IntentWB.verifyArtifactSig(IntentWB.FACT_DOMAIN, xo, k) else { return EvidenceVerdict(ok: false, reason: "bad oracle signature") }
                return EvidenceVerdict(ok: true)
                }
            }
            f.check("fact.signature", ports.fact, core, x, b, ["fact:\(i)"], "this fact (oracle key not pinned)")
        }
        let judges = arr(tr("judges"))
        for (i, x) in arr(bk("classifier")).enumerated() {
            let judge = x.isObject ? str(g(x, "judge")) : nil
            var core: (() throws -> EvidenceVerdict?)?
            if !((judge == nil || !judges.contains(.string(judge!)))) {
                core = {
                if let w = IntentWB.verdictWireError(x) { return EvidenceVerdict(ok: false, reason: w) }
                if self.g(x, "session") != .string(self.session) { return EvidenceVerdict(ok: false, reason: "verdict for another session") }
                guard case let .object(xo) = x, IntentWB.verifyArtifactSig(IntentWB.CLASSIFIER_DOMAIN, xo, judge!) else { return EvidenceVerdict(ok: false, reason: "bad judge signature") }
                return EvidenceVerdict(ok: true)
                }
            }
            f.check("classifier.signature", ports.classifier, core, x, b, ["classifier:\(i)"], "this classifier verdict (judge not pinned)")
        }
        for (i, x) in arr(bk("offer_sets")).enumerated() {
            let key: JSONValue? = x.isObject ? arr(siteKeys).first { g($0, "kid") == g(x, "kid") && g($0, "alg") == .string("ed25519") } : nil
            var core: (() throws -> EvidenceVerdict?)?
            if !(key == nil) {
                core = {
                if let w = IntentWB.offerSetWireError(x) { return EvidenceVerdict(ok: false, reason: w) }
                if self.g(x, "session") != .string(self.session) { return EvidenceVerdict(ok: false, reason: "offer set for another session") }
                guard case let .object(xo) = x, let pk = self.str(self.g(key, "pk")), IntentWB.verifyArtifactSig(IntentWB.OFFER_SET_DOMAIN, xo, pk) else {
                    return EvidenceVerdict(ok: false, reason: "bad site signature")
                }
                return EvidenceVerdict(ok: true)
                }
            }
            f.check("offer_set.signature", ports.offerSet, core, x, b, ["offer_set:\(i)"], "this offer set (site key not pinned)")
        }
        let labelKeys: JSONValue
        if let t = JS.present(tr("labelKeys")) { labelKeys = t }
        else {
            let site = try rd(try rd(bk("schema"), "doc"), "site")
            labelKeys = .array(arr(siteKeys).filter { g($0, "alg") == .string("ed25519") }.map { k in
                var o: JObject = [:]
                if let site = site { o["site"] = site }
                if let kid = g(k, "kid") { o["kid"] = kid }
                if let pk = g(k, "pk") { o["pk"] = pk }
                return .object(o)
            })
        }
        for (i, x) in arr(bk("labels")).enumerated() {
            var core: (() throws -> EvidenceVerdict?)?
            if !(labelKeys.asArray?.isEmpty == true) {
                core = {
                let e = IntentWB.verifyLabels(x, labelKeys)
                if e == nil && self.g(x, "session") != .string(self.session) { return EvidenceVerdict(ok: false, reason: "label receipt for another session") }
                return e == nil ? EvidenceVerdict(ok: true) : EvidenceVerdict(ok: false, reason: e!)
                }
            }
            f.check("labels.signature", ports.labels, core, x, b, ["labels:\(i)"], "this label receipt (no site keys)")
        }
        // ported artifacts with no core format
        for v in arr(bk("verdicts")) {
            let vd = try rd(v, "pcactn_digest")
            f.check("verdict.signature", ports.verdict, nil, v, b, ["verdict:\(s(vd))"], "site verdicts (no core format yet)")
        }
        for (i, x) in arr(bk("settlements")).enumerated() {
            f.check("settlement.signature", ports.settlement, nil, x, b, ["settlement:\(i)"], "settlement records (no core format yet)")
        }
    }

    // ---- revocation (rule 13 step 7) ----

    func revocationSection() throws {
        let epochs = arr(bk("revocation_epochs"))
        if epochs.isEmpty { f.add("revocation.epoch", "unverified", [], "no revocation epoch in the bundle"); return }
        let rev = g(S, "revocation")
        guard JS.truthy(rev) else { f.add("revocation.epoch", "fail", [], "the session root names no revocation authority"); return }
        let authorityV = g(rev, "key")
        let maxAgeMs = (IV.num(JS.present(g(rev, "max_age_s"))) ?? 300) * 1000
        var pins: [String: String] = [:]
        if let a = str(authorityV), let pq = str(g(rev, "pq_pk")) { pins[a] = pq }
        func check(_ ev: JSONValue, _ ids: [String], _ now: Double, _ last: JSONValue?) -> EvidenceVerdict {
            guard let authority = str(authorityV) else { return EvidenceVerdict(ok: false, reason: "ids must be an array and the authority a key") }
            let r = IntentRevocation.check(ev, session: session, authority: authority, ids: ids, now: now, maxAgeMs: maxAgeMs, pqPins: pins, last: last)
            return EvidenceVerdict(ok: r.0, reason: r.1)
        }
        var historyOk = true
        for (i, ev) in epochs.enumerated() {
            let v = check(ev, [], IV.num(g(g(ev, "epoch"), "issued_at")) ?? .nan, i > 0 ? epochs[i - 1] : nil)
            if !v.ok { historyOk = false }
            f.verdict("revocation.history", v, ["epoch#\(i):\(s(g(g(ev, "epoch"), "epoch")))"])
        }
        guard let subject = subjectPcactn else { f.add("revocation.epoch", "unverified", [], "no subject action time"); return }
        var ids = [IntentRevocation.sessionId(session)]
        ids += arr(bk("maps")).map { IntentRevocation.mapId(s(g($0, "commit"))) }
        ids += arr(bk("deltas")).map { IntentRevocation.deltaId(s(g($0, "id"))) }
        let iat = IV.num(try rd(subject, "iat")) ?? .nan
        let idx = epochIdxAt(iat)
        if idx < 0 { f.add("revocation.epoch", "fail", [], "every epoch was issued after the action"); return }
        let ev = epochs[idx]
        let ref = ["epoch:\(s(g(g(ev, "epoch"), "epoch")))"]
        if !historyOk { f.add("revocation.epoch", "fail", ref, "the bundled epochs are not one append-only chain"); return }
        f.verdict("revocation.epoch", check(ev, ids, iat, idx > 0 ? epochs[idx - 1] : nil), ref)
    }

    // ---- anchors ----

    func anchorsSection() throws {
        if JS.truthy(g(bk("schema"), "anchor")) { f.add("schema.anchor", "unverified", ["schema"], "the anchor names a log position without an inclusion proof") }
        let anchors = arr(bk("anchors"))
        func anchorable(_ kind: JSONValue?, _ d: JSONValue?) throws -> Bool {
            switch str(kind) {
            case "evidence"?: return d == .string(digest)
            case "statement"?: return d == g(bk("statement"), "commit")
            case "map"?: return d?.asString.map { mapCommits.contains(JKey($0)) } ?? false
            case "schema"?: return d == .string(schemaDigest)
            case "observation"?: return try verified.contains { try PCAWallet.answerRef($0) == d?.asString }
            default: return false
            }
        }
        if !anchors.contains(where: { g($0, "kind") == .string("evidence") }) { f.add("anchor.inclusion", "unverified", ["anchor:evidence"], "the bundle is not anchored") }
        for a in anchors {
            let ref = ["anchor:\(s(g(a, "kind"))):\(s(g(a, "index")))"]
            if !(try anchorable(g(a, "kind"), g(a, "digest"))) { f.add("anchor.inclusion", "fail", ref, "the anchor names an artifact that is not this one"); continue }
            let gd = tr("anchorGuardian")
            guard JS.truthy(gd) else { f.add("anchor.inclusion", "unverified", ref, "no anchor-log guardian key supplied"); continue }
            let h = g(a, "signed_tree_head")
            _ = try rd(h, "principal")
            var ok = g(h, "principal") == .string(PCAEvidence.INTENT_ANCHOR_LOG) && g(h, "instance_id") == g(gd, "instance")
            if ok, let pub = str(g(gd, "public")) { ok = Ledger.verifyTreeHead(h, pub, nil) } else { ok = false }
            if ok { ok = g(g(a, "proof"), "index") == g(a, "index") && g(g(a, "proof"), "size") == g(h, "size") }
            if ok, let root = str(g(h, "root")) {
                let leaf = try PCAEvidence.anchorCommit(g(a, "kind"), g(a, "digest"))
                ok = Ledger.verifyInclusion(root, g(a, "proof"), .string(leaf))
            } else { ok = false }
            f.add("anchor.inclusion", ok ? "pass" : "fail", ref)
        }
    }

    // ---- attribution ----

    func attributionSection() throws {
        var signing = Set<String>()
        if let x = str(g(S, "signer")) { signing.insert(x) }
        if let x = str(try rd(g0, "issuer")) { signing.insert(x) }
        for d in arr(bk("deltas")) { if let x = str(try rd(d, "issuer")) { signing.insert(x) } }
        for a in arr(bk("answers")) { if let x = str(try rd(a, "signer")) { signing.insert(x) } }
        if let o = g(g(bk("statement"), "opening"), "principal"), let x = str(o) { signing.insert(x) }
        let keys = EvidenceReplay.sorted(Array(signing))
        keysToCheck = keys
        guard let tp = tr("principals") else {
            f.add("principal.pinned", "unverified", keys, "no pinned principal keys: the bundle names its own principals; verify these keys out of band")
            return
        }
        var pins: [String: JSONValue] = [:]
        for p in tp.asArray ?? [] { if let k = str(g(p, "key")) { pins[k] = p } }
        let unpinned = keys.filter { pins[$0] == nil }
        let pqMismatch = keys.filter { k in
            guard let pin = pins[k] else { return false }
            let sp = arr(g(S, "principals")).first { str(g($0, "key")) == k }
            func norm(_ v: JSONValue?) -> JSONValue { v ?? .null }
            return norm(g(pin, "pq_pk")) != norm(g(sp, "pq_pk"))
        }
        if !unpinned.isEmpty { f.add("principal.pinned", "fail", unpinned, "signing keys that are not pinned principals") }
        else if !pqMismatch.isEmpty { f.add("principal.pinned", "fail", pqMismatch, "the session root binds a different PQ key than the pin") }
        else { f.add("principal.pinned", "pass", keys); attributionPinned = true }
    }

    // ---- plain-language facts (only what passed) ----

    func provenSection() {
        func passed(_ code: String) -> Bool { f.list.contains { $0.code == code && $0.status == "pass" } && !f.list.contains { $0.code == code && $0.status == "fail" } }
        if let au = admittedUnder, passed("pcactn.verify") {
            proven.append("The subject action was signed by the agent under \(au), a grant signed by the session principal\(attributionPinned ? " (pinned)" : " (NOT pinned)").")
        }
        func who(_ k: String) -> String { attributionPinned ? "Pinned principal key \(k)" : "Session-root key \(k) (NOT pinned: not attributed to a known principal)" }
        if consent != .null {
            proven.append("\(who(s(g(consent, "signer")))) signed a \(s(g(consent, "tier")))-tier \"yes\" bound to this exact action (question \(s(g(consent, "question_id")))).")
        }
        if charged != .null, let a = IV.num(g(charged, "amount")), let bd = IV.num(g(charged, "bound")), a <= bd {
            proven.append("The charged amount \(JS.number(a)) is within the confirmed value \(JS.number(bd)).")
        }
        if !refusals.isEmpty { proven.append("The principal refused \(refusals.count) question(s): \(refusals.joined(separator: ", ")).") }
        if let asked = IV.num(canaryAccuracy["asked"]), asked != 0 { proven.append("Canary accuracy \(s(canaryAccuracy["correct"]))/\(s(canaryAccuracy["asked"])).") }
        if passed("accumulator.cap") { proven.append("Every accumulator post is within the cap of the grant that admitted it.") }
        if passed("effect.frame") { proven.append("The site reports no change to monitored state outside the write set.") }
    }
}

extension PCAEvidence {
    static let NOT_PROVEN = [
        "That the principal understood the question: the bundle proves only that a deterministic card with the recorded digest was shown and answered at the recorded friction tier.",
        "That the site's signed schema describes what its endpoints really do (SCH).",
        "That the site's effect records and any oracle facts are true (EFF, ORC).",
        "Acceptance of this bundle by any card network, court or regulator.",
    ]
    public static let INTENT_ANCHOR_LOG = "pca-intent:v1"

    private static func utf16Less(_ a: String, _ b: String) -> Bool { a.utf16.lexicographicallyPrecedes(b.utf16) }

    private static func finish(_ f: EvFindings, _ digest: String?, _ r: EvidenceReplay?) throws -> JSONValue {
        let findings = f.list.enumerated().sorted { x, y in
            let a = x.element, b = y.element
            for (p, q) in [(a.code, b.code), (a.refs.joined(separator: ","), b.refs.joined(separator: ",")), (a.status, b.status), (a.text, b.text)] where p != q {
                return utf16Less(p, q)
            }
            return x.offset < y.offset
        }.map { $0.element }
        let consistent = !findings.isEmpty && !findings.contains { $0.status == "fail" }
        let attributed = findings.contains { $0.code == "principal.pinned" && $0.status == "pass" } && !findings.contains { $0.code == "principal.pinned" && $0.status != "pass" }
        let ok = consistent && attributed
        let complete = !findings.contains { $0.status == "unverified" }
        var notProven = NOT_PROVEN
        let keys = r?.keysToCheck ?? []
        if consistent && !attributed && !keys.isEmpty {
            notProven.insert("The bundle is internally consistent but NOT attributed to any known principal: verify these session-root keys out of band: \(keys.joined(separator: ", ")).", at: 0)
        }
        let unverifiedCodes = EvidenceReplay.sorted(Array(Set(findings.filter { $0.status == "unverified" }.map { $0.code })))
        if !unverifiedCodes.isEmpty { notProven.append("Checked only through a supplied verifier, or not at all: \(unverifiedCodes.joined(separator: ", ")).") }
        func arr(_ xs: [String]) -> JSONValue { .array(xs.map { .string($0) }) }
        let summary: JSONValue = .object([
            "admitted_under": r?.admittedUnder.map { .string($0) } ?? .null,
            "principal_keys": arr(r?.principalKeys ?? []),
            "answers": .object(r?.answersSummary ?? ["total": .int(0), "yes": .int(0), "no": .int(0), "partial": .int(0), "canaries": .int(0)]),
            "refusals": arr(r?.refusals ?? []),
            "consent": r?.consent ?? .null,
            "charged": r?.charged ?? .null,
            "canary_accuracy": .object(r?.canaryAccuracy ?? ["correct": .int(0), "asked": .int(0)]),
            "attribution": .object(["pinned": .bool(r?.attributionPinned ?? false), "keys_to_check": arr(keys)]),
            "proven": arr(r?.proven ?? []),
            "not_proven": arr(notProven),
        ])
        let fj: JSONValue = .array(findings.map { .object(["code": .string($0.code), "status": .string($0.status), "text": .string($0.text), "refs": arr($0.refs)]) })
        var body: JObject = ["ok": .bool(ok), "consistent": .bool(consistent), "attributed": .bool(attributed), "complete": .bool(complete),
                             "digest": digest.map { .string($0) } ?? .null, "findings": fj, "summary": summary]
        guard let rd = IV.strictHash(.object(["d": .string(EVIDENCE_REPORT_DOMAIN), "r": .object(body)])) else { throw JSError("canonicalize: value out of profile") }
        body["report_digest"] = .string(rd)
        return .object(body)
    }

    /// Replay a bundle (spec section 3.11): every finding is RECOMPUTED from the signed artifacts; nothing the bundle claims about itself is
    /// taken on trust. A malformed bundle is a report with a failed `shape` finding. `trust` is the reference's `EvidenceTrust` as JSON
    /// (everything but `verifiers`, which are the typed `ports`); absent (nil) = no trust inputs.
    public static func verifyEvidenceBundle(_ input: JSONValue?, trust trustIn: JSONValue? = nil, ports: EvidencePorts = EvidencePorts()) throws -> JSONValue {
        let f = EvFindings()
        var trust = trustIn ?? .object([:])
        if trust == .null { trust = .object([:]) }
        guard trust.isObject else { throw JSError("trust is not an object") }
        if let te = accTrustError(trust.get("acc")) { f.add("trust.acc", "fail", [], te); return try finish(f, nil, nil) }
        if let pe = principalsTrustError(trust.get("principals")) { f.add("trust.principals", "fail", [], pe); return try finish(f, nil, nil) }
        if let bad = bundleShapeError(input) { f.add("shape", "fail", [], bad); return try finish(f, nil, nil) }
        let b: JSONValue, digest: String
        do {
            b = try normalizeBundle(input)
            digest = try evidenceDigest(b)
        } catch {
            f.add("shape", "fail", [], "not canonicalizable: \(EvidenceReplay.message(error))")
            return try finish(f, nil, nil)
        }
        f.add("shape", "pass")
        let r = EvidenceReplay(b, digest, trust, ports, f)
        do { try r.run() } catch { f.add("shape", "fail", [], "replay aborted: \(EvidenceReplay.message(error))") }
        return try finish(f, digest, r)
    }

    /// A COSE Signed Statement over the bundle reference, ready to register with a SCITT transparency service.
    public static func evidenceSignedStatement(_ bundle: JSONValue?, signer: PCAScitt.CoseSigner, issuer: String, subject: String? = nil) throws -> [UInt8] {
        let ref = try evidenceRef(bundle)
        let sub = subject ?? JSLoose.get(JSLoose.get(ref, "subject"), "pcactn_digest")?.asString
        return try PCAScitt.signStatement(ref, signer: signer, issuer: issuer, subject: sub, contentType: EVIDENCE_CONTENT_TYPE)
    }
}
