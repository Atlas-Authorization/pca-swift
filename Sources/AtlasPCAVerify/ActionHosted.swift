import Foundation

/// The hosted action registry of one instance: the publish gate (what a new version of a namespace may change without a reviewer) and the verifier's view
/// of the active versions (provenance facts, trait floors for rule 22, undo eligibility, the server reversibility class, compiled business rules). Pure:
/// storage, keys and time are the caller's. Fail closed everywhere: an action the view does not know, one that is not confirmed by a reviewer key the
/// instance pins, or a deprecated one gets the top of the trait registry (every floor) and no provenance facts, is irreversible, and is never undoable.
public enum ActionHosted {
    public static let RULES_DOC_KIND = "pca-action-rules"
    public static let HOSTED_VERSION_DOMAIN = "atlas-pca/hosted-action-version/v1"
    private static let SEMVER = "[0-9]+\\.[0-9]+\\.[0-9]+"
    private static let EFFECTIVE_DIMS = ["confirmation", "effective.traits", "effective.profile"]
    private static let CAVEAT_KINDS = ["amount_cap", "count_cap", "window", "resource_scope", "recipient_scope", "approval_ref", "short_expiry", "rate_cap"]
    private static let SERVER_CLASS = ["reversible": "reversible", "rate_limited": "costly", "irreversible": "irreversible"]

    private static func messageOf(_ e: Error) -> String { (e as? ActionKitError)?.message ?? (e as? JSError)?.message ?? "\(e)" }

    private static func truthy(_ v: JSONValue?) -> Bool { JS.truthy(v) }

    private static func fail(_ code: String, _ reason: String?, _ verbs: [String]? = nil) -> JObject {
        var m: JObject = [JKey("ok"): .bool(false), JKey("code"): .string(code), JKey("reason"): reason.map { .string($0) } ?? .null]
        if let v = verbs { m[JKey("verbs")] = AK.strs(v) }
        return m
    }

    /// The trait registry of a version: core plus its custom traits. Throws for custom traits that do not extend their implies.
    public static func registryOfTraits(_ traits: [JSONValue]) throws -> TraitRegistry { traits.isEmpty ? Actions.coreRegistry : try Actions.extendRegistry(Actions.coreRegistry, traits) }

    /// The attestation check the instance pins give (nil without pins: nothing is confirmed).
    public static func reviewOptsOf(_ pins: JSONValue?, _ reg: TraitRegistry) -> ((JObject) -> Bool)? {
        guard let p = pins, p != .null else { return nil }
        return ActionUndoEngine.attestationVerifier(p, reg)
    }

    /// Nil iff `x` is a rules document for `ns` whose every verb is in `defs` and whose rules lint without errors.
    public static func rulesDocError(_ x: JSONValue?, _ ns: String, _ defs: [JSONValue]) -> String? {
        guard case let .object(r)? = x else { return "rules must be a pca-action-rules document" }
        for k in JS.keyOrder(r) where !["v", "kind", "ns", "rules", "reviews"].contains(k.s) { return "rules: unknown member '\(k.s)'" }
        if IV.num(r["v"]) != 1 || r["kind"] != .string(RULES_DOC_KIND) { return "rules: not a \(RULES_DOC_KIND) v1 document" }
        if r["ns"] != .string(ns) { return "rules: ns '" + (r["ns"] != nil ? JS.toString(r["ns"]) : "undefined") + "' is not the pack's '" + ns + "'" }
        guard case let .object(blocks)? = r["rules"] else { return "rules.rules must map verbs to rules blocks" }
        if let rv = r["reviews"], rv.asObject == nil { return "rules.reviews must map verbs to rules reviews" }
        var byVerb: [JKey: JObject] = [:]
        for d in defs { if let v = d.get("verb")?.asString { byVerb[JKey(v)] = AK.o(d) } }
        for k in JS.keyOrder(blocks) {
            guard let d = byVerb[k] else { return "rules: '\(k.s)' is not an action of the pack" }
            var errs: [String] = []
            for f in (try? ActionBusinessRules.lintBusinessRules(d, blocks[k])) ?? [] where f.get("severity") == .string("error") { errs.append(JS.toString(f.get("message"))) }
            if !errs.isEmpty { return "rules for '\(k.s)': " + errs.joined(separator: "; ") }
        }
        if let rv = r["reviews"]?.asObject { for k in JS.keyOrder(rv) where byVerb[k] == nil { return "rules.reviews: '\(k.s)' is not an action of the pack" } }
        return nil
    }

    /// The content address of a version: the digest of `{pack, rules, traits, deprecated}`.
    public static func hostedVersionDigest(_ v: JObject) throws -> String {
        let dep = AK.arr(v["deprecated"]).map { $0.asString ?? "" }.sorted(by: ActionBusinessRules.u16less)
        guard let h = IV.strictHash(AK.obj(["d": .string(HOSTED_VERSION_DOMAIN), "pack": v["pack"] ?? .null, "rules": v["rules"] ?? .null, "traits": v["traits"] ?? .null, "deprecated": AK.strs(dep)])) else {
            throw JSError("the version is outside the strict JSON profile")
        }
        return h
    }

    /// diffDefs, but each side under its own registry and review (a trait registry change shows up in the effective dimensions).
    private static func diffDefsAcross(_ o: JObject, _ n: JObject, _ oReg: TraitRegistry, _ nReg: TraitRegistry, _ same: Bool, _ oRev: ((JObject) -> Bool)?, _ nRev: ((JObject) -> Bool)?) throws -> JObject {
        let base = AK.o(try ActionDiff.diffDefs(o, n, nReg, nRev))
        if same { return base }
        let eo = try ActionEffective.effective(o, oReg, oRev)["eff"] ?? .null, en = try ActionEffective.effective(n, nReg, nRev)["eff"] ?? .null
        let rel: String? = try ActionEffective.leq(eo, en) ? (try ActionEffective.leq(en, eo) ? nil : "narrow") : (try ActionEffective.leq(en, eo) ? "widen" : "incomparable")
        guard let rl = rel else { return base }
        var reasons = AK.arr(base["reasons"]).map { JS.toString($0) }.filter { !$0.hasPrefix("effective.profile") }
        reasons.append("effective.profile: \(rl)")
        reasons.sort(by: ActionBusinessRules.u16less)
        let bc = base["class"]
        let inc = rl == "incomparable" || bc == .string("incomparable") || (rl == "widen" && bc == .string("narrow")) || (rl == "narrow" && bc == .string("widen"))
        return [JKey("class"): .string(inc ? "incomparable" : (rl == "widen" || bc == .string("widen")) ? "widen" : "narrow"), JKey("reasons"): AK.strs(reasons)]
    }

    private static func tierOf(_ v: JSONValue?, _ d: Int64) -> Int64 { if let i = IV.int(v), i >= 0, i <= 3 { return i }; return d }

    /// Decide whether a version may become the active one of its namespace, and compute what it changes. `i`: `{current?, pack, rules?, traits?,
    /// publisherKeys, pins?, pin?}`. Returns `{ok:true, version}` or `{ok:false, code, reason, verbs?, changes?}` where code is one of
    /// bad_pack, bad_rules, bad_traits, bad_version, ns_mismatch, not_newer, widen_unreviewed.
    public static func publishGate(_ i: JObject) throws -> JObject {
        var traits: [JSONValue] = []
        if own(i, "traits") {
            guard case let .array(t)? = i["traits"] else { return fail("bad_traits", "traits must be a list of trait definitions") }
            traits = t
        }
        let reg: TraitRegistry
        do { reg = try registryOfTraits(traits) } catch { return fail("bad_traits", messageOf(error)) }
        let pv = AK.o(ActionBuild.verifyPack(i["pack"], i["publisherKeys"], reg))
        if pv["ok"] != .bool(true) { return fail("bad_pack", pv["reason"]?.asString) }
        let pack = AK.o(i["pack"])
        let packVersion = JS.toString(pack["version"]), packNs = JS.toString(pack["ns"])
        if !Actions.fullMatch(SEMVER, packVersion) { return fail("bad_version", "version '\(packVersion)' must be MAJOR.MINOR.PATCH") }
        let cur: JObject? = i["current"]?.asObject
        if let c = cur, .string(packNs) != c["ns"] { return fail("ns_mismatch", "the active namespace is '\(JS.toString(c["ns"]))', the pack is '\(packNs)'") }
        if let c = cur, !truthy(i["pin"]), (Actions.compareVersions(packVersion, JS.toString(c["version"])) ?? 0) <= 0 {
            return fail("not_newer", "version \(packVersion) is not above the active \(JS.toString(c["version"]))")
        }
        let rulesIn: JSONValue = own(i, "rules") ? (i["rules"] ?? .null)
            : AK.obj(["v": .int(1), "kind": .string(RULES_DOC_KIND), "ns": .string(packNs), "rules": .object([:])])
        let packDefs = AK.arr(pack["defs"])
        if let re = rulesDocError(rulesIn, packNs, packDefs) { return fail("bad_rules", re) }
        let rules = AK.o(rulesIn)
        let ruleBlocks = AK.o(rules["rules"])

        let review = reviewOptsOf(i["pins"], reg)
        var prevReg = reg
        var same = traits.isEmpty
        if let c = cur {
            let ct = AK.arr(c["traits"])
            if let p = try? registryOfTraits(ct) { prevReg = p; same = ct.isEmpty && traits.isEmpty } else { same = true }
        }
        let prevReview = reviewOptsOf(i["pins"], prevReg)
        var changes: [JObject] = []
        var blocked: [String] = [], reasons: [String] = []
        var oldDefs: [JKey: JObject] = [:], oldOrder: [JKey] = []
        if let c = cur { for d in AK.arr(c["pack"]?.get("defs")) { if let v = d.get("verb")?.asString { if oldDefs[JKey(v)] == nil { oldOrder.append(JKey(v)) }; oldDefs[JKey(v)] = AK.o(d) } } }
        let oldDep = Set((cur.map { AK.arr($0["deprecated"]) } ?? []).compactMap { $0.asString }.map { JKey($0) })
        var newVerbs = Set<JKey>()
        for d in packDefs { if let v = d.get("verb")?.asString { newVerbs.insert(JKey(v)) } }
        for n0 in packDefs {
            let n = AK.o(n0)
            let verb = JS.toString(n["verb"])
            let o = oldDefs[JKey(verb)]
            let hasNewRules = ruleBlocks[JKey(verb)] != nil
            let newRules = ruleBlocks[JKey(verb)]
            let confirmed = ActionEffective.isConfirmed(n, review)
            var change: JObject
            if o == nil || oldDep.contains(JKey(verb)) {
                change = [JKey("verb"): .string(verb), JKey("class"): .string("added"), JKey("reasons"): .array([])]
                if confirmed { change[JKey("reviewed")] = .bool(true) }
            } else {
                let d = try diffDefsAcross(o!, n, prevReg, reg, same, prevReview, review)
                change = [JKey("verb"): .string(verb), JKey("class"): d["class"] ?? .null, JKey("reasons"): d["reasons"] ?? .null]
                var effWidens = false
                for r in AK.arr(d["reasons"]).map({ JS.toString($0) }) { for dim in EFFECTIVE_DIMS where r.hasPrefix("\(dim): widen") || r.hasPrefix("\(dim): incomparable") { effWidens = true } }
                if effWidens {
                    if confirmed { change[JKey("reviewed")] = .bool(true) }
                    else { blocked.append(verb); reasons.append("\(verb): its effective authority widens without a valid confirmation of the new definition") }
                }
            }
            let oldRules: JSONValue? = (o != nil && !oldDep.contains(JKey(verb))) ? JS.present(cur?["rules"]?.get("rules")?.get(verb)) : nil
            if oldRules != nil || hasNewRules {
                var rd: JObject
                do {
                    rd = try ActionBusinessRules.diffBusinessRules(n, oldRules.map { AK.o($0) }, JS.present(newRules).map { AK.o($0) })
                } catch { rd = [JKey("class"): .string("incomparable"), JKey("reasons"): AK.strs(["rules: " + messageOf(error)])] }
                // rules apply to confirmed and unconfirmed actions alike, so any widening of them needs a reviewer, whatever the state of the definition
                if rd["class"] != .string("equal") { change[JKey("rules")] = .object(rd) }
                if rd["class"] == .string("widen") || rd["class"] == .string("incomparable") {
                    // removing every rule is reviewed as the empty block
                    let err = ActionBusinessRules.rulesReviewError(rules["reviews"]?.get(verb), n, JS.present(newRules).map { AK.o($0) } ?? [:], i["pins"])
                    if err == nil { change[JKey("reviewed")] = .bool(true) }
                    else {
                        blocked.append(verb)
                        reasons.append("\(verb): its business rules widen (" + AK.arr(rd["reasons"]).map { JS.toString($0) }.joined(separator: ", ") + ") without a valid rules review: " + err!)
                    }
                }
            }
            if change["class"] != .string("equal") || change[JKey("rules")] != nil { changes.append(change) }
        }
        var deprecated = Set<String>()
        for v in oldDep where !newVerbs.contains(v) { deprecated.insert(v.s) }
        for v in oldOrder {
            if newVerbs.contains(v) || oldDep.contains(v) { continue }
            deprecated.insert(v.s)
            changes.append([JKey("verb"): .string(v.s), JKey("class"): .string("deprecated"), JKey("reasons"): AK.strs(["removed from the namespace: treated as unknown"])])
        }
        changes = changes.enumerated().sorted { a, b in
            let x = JS.toString(a.element["verb"]), y = JS.toString(b.element["verb"])
            return x == y ? a.offset < b.offset : ActionBusinessRules.u16less(x, y)
        }.map { $0.element }
        if !blocked.isEmpty {
            var out = fail("widen_unreviewed", reasons.joined(separator: "\n"), Set(blocked).sorted(by: ActionBusinessRules.u16less))
            out[JKey("changes")] = .array(changes.map { .object($0) })
            return out
        }
        let depList = AK.strs(deprecated.sorted(by: ActionBusinessRules.u16less))
        var body: JObject = [JKey("pack"): .object(pack), JKey("rules"): .object(rules), JKey("traits"): .array(traits), JKey("deprecated"): depList]
        var version: JObject = [JKey("ns"): .string(packNs), JKey("version"): .string(packVersion), JKey("digest"): .string(try hostedVersionDigest(body)),
                                JKey("prev"): JS.present(cur?["digest"]) ?? .null]
        for (k, v) in body { version[k] = v }
        body = [:]
        version[JKey("changes")] = .array(changes.map { .object($0) })
        return [JKey("ok"): .bool(true), JKey("version"): .object(version)]
    }

    private static func own(_ o: JObject, _ k: String) -> Bool { o[JKey(k)] != nil }

    // ---- the verifier's view ----

    /// A rules block that no longer compiles denies every call of its action (its tightening must not silently disappear).
    private static func brokenRules(_ verb: String) -> JSONValue {
        AK.obj(["v": .int(1), "verb": .string(verb), "rules_digest": .string(""), "def_digest": .string(""),
                "tighten": .array([AK.obj(["id": .string("rules_broken"), "when": AK.obj(["field": .string("action.verb"), "op": .string("eq"), "value": .string(verb)]),
                                           "signal": .string("deny"), "reason": .string("the business rules of this action no longer compile")])]),
                "accumulators": .array([])])
    }

    private struct Entry { let def: JObject; let reg: TraitRegistry; let regKey: Int; let review: ((JObject) -> Bool)?; let rules: JObject? }

    /// The verifier's view of the active versions of an instance.
    public final class View {
        public private(set) var versions: [String] = []
        private var byVerb: [JKey: Entry] = [:]
        private var deprecated = Set<JKey>()
        private var broken: [JKey] = []
        private var prov: [JKey: JSONValue] = [:]
        private var cache: [JKey: JObject] = [:]
        private var undoByReg: [Int: ActionUndoEngine] = [:]
        private let top: Profile
        private let topTraitIds: [String]

        fileprivate init(_ vs: [JSONValue], _ pins: JSONValue?) {
            var regs: [TraitRegistry] = []
            for (vi, v) in vs.enumerated() {
                versions.append("\(JS.toString(v.get("ns")))@\(JS.toString(v.get("version")))")
                let traits = AK.arr(v.get("traits"))
                let reg: TraitRegistry
                do { reg = try ActionHosted.registryOfTraits(traits) } catch {
                    if case let .array(defs)? = v.get("pack")?.get("defs") { for d in defs { if let s = d.get("verb")?.asString, !broken.contains(JKey(s)) { broken.append(JKey(s)) } } }
                    continue
                }
                regs.append(reg)
                let regKey = traits.isEmpty ? -1 : vi
                let review = ActionHosted.reviewOptsOf(pins, reg)
                let blocks = v.get("rules")?.get("rules")?.asObject
                for d in AK.arr(v.get("pack")?.get("defs")) {
                    let verb = JS.toString(d.get("verb"))
                    if byVerb[JKey(verb)] != nil { continue }
                    byVerb[JKey(verb)] = Entry(def: AK.o(d), reg: reg, regKey: regKey, review: review, rules: blocks?[JKey(verb)]?.asObject)
                }
                for x in AK.arr(v.get("deprecated")) { if let s = x.asString { deprecated.insert(JKey(s)) } }
            }
            for x in deprecated { byVerb[x] = nil }
            for x in broken { byVerb[x] = nil }
            // the strictest profile any active registry has (an unknown verb could be anything)
            var t: Profile? = nil
            let used = regs.isEmpty ? [Actions.coreRegistry] : regs
            for r in used {
                let p = (try? Actions.floorOf(r, Actions.topTraits(r))) ?? Profile()
                if let cur = t { t = Actions.leq(cur, p) ? p : Actions.leq(p, cur) ? cur : Actions.join(cur, p) } else { t = p }
            }
            top = t ?? Profile()
            var ids = Set<String>()
            for r in used { for x in Actions.topTraits(r) { ids.insert(x) } }
            topTraitIds = ids.sorted(by: ActionBusinessRules.u16less)
            // the reference computes this inside try / catch: a def that cannot be read has no facts (unknown: the gate treats it as sensitive)
            for (k, e) in byVerb where ActionEffective.isConfirmed(e.def, e.review) { if let info = try? ActionProvenance.provenanceInfoOf(e.def, e.reg, e.review) { prov[k] = info } }
            var groups: [Int: [JSONValue]] = [:], order: [Int] = [], regOf: [Int: TraitRegistry] = [:]
            for k in byVerb.keys.sorted(by: { $0.s < $1.s }) {
                let e = byVerb[k]!
                if !Actions.normalizable(e.def) { continue }
                if groups[e.regKey] == nil { order.append(e.regKey); regOf[e.regKey] = e.reg }
                groups[e.regKey, default: []].append(.object(e.def))
            }
            for r in order { undoByReg[r] = ActionUndoEngine.undoEngine(defs: groups[r]!, pins: pins, registry: regOf[r]!) }
        }

        /// What the view knows of a verb: `{verb, confirmed, known, deprecated, def_digest?, idempotency_param?, profile, traits, serverClass, rules?}`.
        public func lookup(_ verb: String) -> JObject {
            if let hit = cache[JKey(verb)] { return hit }
            let e = byVerb[JKey(verb)]
            var out: JObject = [JKey("verb"): .string(verb), JKey("confirmed"): .bool(false), JKey("known"): .bool(e != nil), JKey("deprecated"): .bool(deprecated.contains(JKey(verb))),
                                JKey("profile"): top.json, JKey("traits"): AK.strs(topTraitIds), JKey("serverClass"): .string("irreversible")]
            if e == nil, broken.contains(JKey(verb)), !deprecated.contains(JKey(verb)) { out[JKey("known")] = .bool(true); out[JKey("rules")] = ActionHosted.brokenRules(verb) }
            if let e = e {
                do {
                    let eff = try ActionEffective.effective(e.def, e.reg, e.review)
                    let confirmed = eff["confirmed"] == .bool(true)
                    let idem = JS.present(e.def["idempotency"])
                    let idemParam: JSONValue? = (idem?.get("mode") == .string("key_param")) ? JS.present(idem?.get("param")) : nil
                    out[JKey("def_digest")] = .string(try Actions.defDigest(e.def))
                    if let ip = idemParam { out[JKey("idempotency_param")] = ip }
                    out[JKey("confirmed")] = .bool(confirmed)
                    if confirmed {
                        out[JKey("profile")] = eff["eff"] ?? .null
                        out[JKey("traits")] = eff["traits"] ?? .null
                        out[JKey("serverClass")] = SERVER_CLASS[JS.toString(eff["eff"]?.get("rev"))].map { .string($0) } ?? .null
                    }
                    // rules apply whether or not the action is confirmed: they only tighten
                    if let r = e.rules { out[JKey("rules")] = .object(try ActionBusinessRules.compileBusinessRules(e.def, r)) }
                } catch {
                    // a def or rules block that no longer compiles: unknown-strict, and its rules cannot be dropped silently
                    out[JKey("confirmed")] = .bool(false)
                    out[JKey("profile")] = top.json
                    out[JKey("traits")] = AK.strs(topTraitIds)
                    out[JKey("serverClass")] = .string("irreversible")
                    out[JKey("rules")] = ActionHosted.brokenRules(verb)
                }
            }
            cache[JKey(verb)] = out
            return out
        }

        /// The provenance facts of a confirmed, non-deprecated exact verb; nil otherwise (sensitive).
        public func provenance(_ verb: String) -> JSONValue? { prov[JKey(verb)] }

        /// Undo eligibility from confirmed definitions (exact verb; a deprecated action never): the plan or nil.
        public func undoPlan(_ op: JObject) -> JSONValue? {
            guard let v = op["verb"]?.asString, let e = byVerb[JKey(v)] else { return nil }
            return undoByReg[e.regKey]?.plan(op)
        }

        /// Rule 22: the floor decision for this action under what the grant provides (`{caveats, max_esc, preauth_esc}`) and the call context the server observed.
        public func floor(_ verb: String, _ grant: JObject, _ callContext: [JSONValue]) -> String {
            let kinds = AK.arr(grant["caveats"]).filter { $0.asString.map { CAVEAT_KINDS.contains($0) } ?? false }
            guard let maxEsc = IV.int(grant["max_esc"]), maxEsc >= 0, let pre = IV.int(grant["preauth_esc"]), pre >= 0 else { return "deny" }
            let rho = AK.o(lookup(verb)[JKey("profile")])
            guard let esc = IV.num(rho["esc"]) else { return "deny" }
            if esc > Double(maxEsc) { return "deny" }
            if !AK.arr(rho["caveats"]).allSatisfy({ kinds.contains($0) }) || !AK.arr(rho["context"]).allSatisfy({ callContext.contains($0) }) || esc > Double(pre) { return "escalate" }
            return "allow"
        }
    }

    /// Build the verifier's view from the active versions of an instance (`pins` may be nil).
    public static func hostedView(_ versions: [JSONValue], _ pins: JSONValue?) -> View { View(versions, pins) }

    /// Grant facts for rule 22 from a stored grant: envelope caveat types plus the pin block's caveats and escalation tiers.
    public static func grantFactsOf(_ grant: JSONValue?) -> JObject {
        let env = PCA.readEnvelope(grant ?? .null)
        let a = env?.get("actions")
        var caveats: [JSONValue] = []
        for c in AK.arr(env?.get("caveats")) { if let t = c.get("type")?.asString { caveats.append(.string(t)) } }
        for t in AK.arr(a?.get("caveats")) { if case .string = t { caveats.append(t) } }
        return [JKey("caveats"): .array(caveats), JKey("max_esc"): .int(tierOf(a?.get("max_esc"), 3)), JKey("preauth_esc"): .int(tierOf(a?.get("preauth_esc"), 0))]
    }

    /// The context keys the hosted server itself establishes for a call: it always checks revocation fresh; an idempotency key present.
    public static func hostedCallContext(_ lookup: JObject?, _ params: JObject?) -> [JSONValue] {
        var out: [JSONValue] = [.string("fresh_revocation")]
        if let k = lookup?["idempotency_param"]?.asString, let p = params?[JKey(k)]?.asString, !p.isEmpty { out.append(.string("idempotency")) }
        return out
    }

    /// `hostedCallContext` over JSON values: a `null` parameter bag is dereferenced by the reference once the lookup names an idempotency parameter
    /// (a TypeError), where an absent one is skipped. The typed entry above stays strict.
    public static func hostedCallContext(lookup: JSONValue?, params: JSONValue?) throws -> [JSONValue] {
        var out: [JSONValue] = [.string("fresh_revocation")]
        guard let k = lookup?.get("idempotency_param") else { return out }
        guard let p = params else { return out }
        if p.isNull { throw JSError("Cannot read properties of null (reading '\(JS.toString(k))')") }
        if let v = p.get(JS.toString(k))?.asString, !v.isEmpty { out.append(.string("idempotency")) }
        return out
    }

    private static func msNum(_ v: Double) -> JSONValue { v == v.rounded() && abs(v) < 9.007e15 ? .int(Int64(v)) : .double(v) }

    /// The event keys of a rules block's rate limits: `[{id, ms, key?}]`. A key names the verb, the window and the scope id (never a rule index or the
    /// rules digest), so editing or reordering the rules never resets a count. `who`: `{principal?, org?}`.
    public static func rateKeysOf(_ c: JObject, _ who: JObject) -> [JSONValue] {
        var out: [JSONValue] = []
        for a in AK.arr(c["accumulators"]) {
            let scope = a.get("scope") == .string("org") ? "org" : "principal"
            let id = who[JKey(scope)]?.asString
            let win = a.get("win")
            let ms: Double = win?.get("kind") == .string("task") ? 0 : (IV.num(win?.get("ms")) ?? 0)
            var r: JObject = [JKey("id"): a.get("id") ?? .null, JKey("ms"): msNum(ms)]
            if let id = id, !id.isEmpty, ms > 0 { r[JKey("key")] = .string("\(JS.toString(c["verb"]))|\(JS.number(ms))|\(scope):\(id)") }
            out.append(.object(r))
        }
        return out
    }
}
