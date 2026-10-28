import Foundation

/// Action-kit registry layer (native port): signed evolution records, principal re-approvals, the grant pin decision, signed packs
/// (with shards), the rollback tracker and rule 22 over a whole v2 document. Natives verify signatures, digests and pins; they do not
/// recompute the semantic diff. Pure and total: malformed input is a refusal.
public struct PinDecision: Equatable {
    public var ok: Bool
    public var via: String?
    public var code: String?
    public var escalate: Bool
    public var reason: String
    public var needsReapproval: String?
}

public struct PackVerdict {
    public var ok: Bool
    public var reason: String
    public var digest: String
    public var defs: [JSONValue]
}

extension Actions {
    static let EVOLUTION_CLASSES = ["equal", "narrow", "widen", "incomparable", "added", "removed"]
    static let EVOLUTION_RECORD_KIND = "pca-evolution-record"
    static let REAPPROVAL_KIND = "pca-reapproval"
    static let EVOLUTION_DOMAIN = "atlas-pca/action-evolution/v1\u{0}"
    static let EVOLUTION_DIFF_DOMAIN = "atlas-pca/action-evolution-diff/v1"
    static let REAPPROVAL_DOMAIN = "atlas-pca/action-reapproval/v1\u{0}"
    static let PACK_SIG_DOMAIN = "atlas-pca/action-pack/v1\u{0}"
    static let PACK_REF_DOMAIN = "atlas-pca/action-pack-ref/v1"
    static let PACK_SHARD_DOMAIN = "atlas-pca/action-pack-shard/v1"
    static let RULES_DIGEST_DOMAIN = "atlas-pca/action-rules/v1"
    static let PACK_SHARD_KIND = "pca-action-pack-shard"
    static let MAX_EVOLUTION_STEPS = 32

    // ---- helpers ------------------------------------------------------------------------------------------------------------

    private static func fullMatch(_ pattern: String, _ s: String) -> Bool {
        guard let re = try? NSRegularExpression(pattern: "^(?:\(pattern))$") else { return false }
        let n = s.utf16.count
        guard let m = re.firstMatch(in: s, options: [.anchored], range: NSRange(location: 0, length: n)) else { return false }
        return m.range.length == n
    }
    private static func isSha(_ v: JSONValue?) -> Bool { v?.asString.map { fullMatch("[A-Za-z0-9_-]{43}", $0) } ?? false }
    private static func isNs(_ v: JSONValue?) -> Bool { v?.asString.map { fullMatch("[a-z0-9_]+(?:\\.[a-z0-9_]+){0,5}", $0) } ?? false }
    private static func isVerbName(_ s: String) -> Bool { fullMatch("[a-z0-9_]+(?:\\.[a-z0-9_]+){1,5}", s) }
    private static func isOne(_ v: JSONValue?) -> Bool { if case .int(1)? = v { return true } else { return false } }
    private static func closedKeys(_ o: JObject, _ allowed: [String]) -> String? {
        for k in o.keys where !IV.contains(allowed, k.s) { return "unknown member '\(k.s)'" }
        return nil
    }
    private static func tier(_ v: JSONValue?) -> Bool { if case let .int(i)? = v { return i >= 0 && i <= 3 } else { return false } }
    private static func sigMessage(_ domain: String, _ body: JObject) -> [UInt8]? { IV.message(domain, .object(body)) }
    private static func without(_ o: JObject, _ k: String) -> JObject { var b = o; b[JKey(k)] = nil; return b }
    private static func utf16Less(_ a: String, _ b: String) -> Bool { Array(a.utf16).lexicographicallyPrecedes(Array(b.utf16)) }

    // ---- evolution records --------------------------------------------------------------------------------------------------

    public static func evolutionRecordError(_ xv: JSONValue?, signed: Bool = true) -> String? {
        guard case let .object(x)? = xv else { return "evolution record must be an object" }
        if let u = closedKeys(x, ["v", "kind", "ns", "verb", "from", "to", "class", "reasons"] + (signed ? ["sig"] : [])) { return "evolution record: \(u)" }
        if !isOne(x["v"]) || x["kind"]?.asString.map({ IV.same($0, EVOLUTION_RECORD_KIND) }) != true { return "evolution record: bad v/kind" }
        if !isNs(x["ns"]) { return "evolution record: bad ns" }
        if !(x["verb"]?.asString.map(isVerbName) ?? false) { return "evolution record: bad verb" }
        if x["from"]?.isNull != true && !isSha(x["from"]) { return "evolution record: bad from" }
        if x["to"]?.isNull != true && !isSha(x["to"]) { return "evolution record: bad to" }
        guard let c = x["class"]?.asString, IV.contains(EVOLUTION_CLASSES, c) else { return "evolution record: bad class" }
        if (c == "added") != (x["from"]?.isNull == true) || (c == "removed") != (x["to"]?.isNull == true) { return "evolution record: endpoints do not match the class" }
        guard case let .array(r)? = x["reasons"], r.count <= 64, r.allSatisfy({ $0.asString.map { IV.u16($0) <= 512 } ?? false }) else { return "evolution record: bad reasons" }
        if signed {
            guard case let .object(s)? = x["sig"], closedKeys(s, ["alg", "kid", "value", "pq_value"]) == nil else { return "evolution record: bad sig" }
            guard let kid = s["kid"]?.asString, IV.u16(kid) > 0, IV.u16(kid) <= 128, s["value"]?.asString != nil, s["alg"]?.asString != nil else { return "evolution record: bad sig" }
            if let pq = s["pq_value"], pq.asString == nil { return "evolution record: bad sig" }
        }
        if let e = IV.strictCanonError(.object(without(x, "sig"))) { return "evolution record: \(e)" }
        return nil
    }

    /// Digest of ONE record's diff; nil where the reference throws (a member is absent or out of profile).
    public static func evolutionDiffDigest(_ rv: JSONValue?) -> String? {
        guard case let .object(r)? = rv, let ns = r["ns"], let verb = r["verb"], let from = r["from"], let to = r["to"], let cl = r["class"], let rs = r["reasons"] else { return nil }
        return IV.strictHash(.object(["d": .string(EVOLUTION_DIFF_DOMAIN), "ns": ns, "verb": verb, "from": from, "to": to, "class": cl, "reasons": rs]))
    }

    /// Verify a registry-signed body under `domain` against the pinned registry keys (the suite comes from the KEY entry). Total.
    public static func verifyRegistrySig(_ domain: String, _ body: JObject, _ sig: JObject, _ keys: JSONValue?) -> Bool {
        guard case let .array(ks)? = keys else { return false }
        var key: JObject?
        for k in ks { if case let .object(o) = k, IV.same(o["kid"]?.asString, sig["kid"]?.asString) { key = o; break } }
        guard let k = key else { return false }
        if let pq = k["pq_pk"], pq.asString == nil { return false }
        guard let pk = k["pk"]?.asString, Base64URLStrict.isValid(pk, length: 32) else { return false }
        guard let ka = IV.sigAlg(k["alg"]), PQ.resolve(ka) != nil, ka == IV.sigAlg(sig["alg"]) else { return false }
        guard let msg = sigMessage(domain, body) else { return false }
        let pin = k["pq_pk"].map { $0.asString ?? "" }
        return IV.verifyPinned(alg: .string(ka), identity: pk, artifactPqPk: k["pq_pk"], msg: msg, sig: sig["value"], pqSig: sig["pq_value"], pin: pin) == .valid
    }

    public static func verifyEvolutionRecord(_ rv: JSONValue?, _ keys: JSONValue?) -> Bool {
        if evolutionRecordError(rv) != nil { return false }
        guard case let .object(r)? = rv, case let .object(s)? = r["sig"] else { return false }
        return verifyRegistrySig(EVOLUTION_DOMAIN, without(r, "sig"), s, keys)
    }

    public static func reapprovalValid(_ rv: JSONValue?, grantId: String, issuer: String, verb: String, diff: String) -> Bool {
        guard case let .object(r)? = rv, closedKeys(r, ["v", "kind", "grant", "verb", "diff", "sig"]) == nil else { return false }
        guard isOne(r["v"]), IV.same(r["kind"]?.asString, REAPPROVAL_KIND), IV.same(r["grant"]?.asString, grantId),
              IV.same(r["verb"]?.asString, verb), IV.same(r["diff"]?.asString, diff) else { return false }
        guard case let .object(s)? = r["sig"], closedKeys(s, ["alg", "value"]) == nil, IV.same(s["alg"]?.asString, "ed25519"), s["value"]?.asString != nil,
              let msg = sigMessage(REAPPROVAL_DOMAIN, without(r, "sig")) else { return false }
        return IV.verifyPinned(alg: .string("ed25519"), identity: issuer, artifactPqPk: nil, msg: msg, sig: s["value"], pqSig: nil, pin: nil) == .valid
    }

    // ---- the pin --------------------------------------------------------------------------------------------------------------

    public static func actionPinError(_ xv: JSONValue?) -> String? {
        guard case let .object(x)? = xv else { return "actions must be an object" }
        if let u = closedKeys(x, ["pack", "defs", "on_new_action", "max_esc", "preauth_esc", "caveats"]) { return "actions: \(u)" }
        guard case let .object(p)? = x["pack"], closedKeys(p, ["ns", "root"]) == nil else { return "actions.pack must be {ns, root}" }
        if !isNs(p["ns"]) { return "actions.pack.ns is not a namespace" }
        if !isSha(p["root"]) { return "actions.pack.root must be a base64url digest" }
        guard let on = x["on_new_action"]?.asString, on == "deny" || on == "escalate" else { return "actions.on_new_action must be 'deny' or 'escalate'" }
        if x["max_esc"] != nil && !tier(x["max_esc"]) { return "actions.max_esc must be an integer tier 0..3" }
        if x["preauth_esc"] != nil && !tier(x["preauth_esc"]) { return "actions.preauth_esc must be an integer tier 0..3" }
        if tier(x["max_esc"]), tier(x["preauth_esc"]), case let .int(a)? = x["preauth_esc"], case let .int(b)? = x["max_esc"], a > b { return "actions.preauth_esc exceeds actions.max_esc" }
        if let c = x["caveats"] {
            guard let cs = strings(c), cs.allSatisfy({ IV.contains(ActionSchema.V2_CAVEATS, $0) }), Set(cs.map { JKey($0) }).count == cs.count else { return "actions.caveats must be distinct caveat kinds" }
        }
        if let d = x["defs"] {
            guard case let .object(dm) = d else { return "actions.defs must be an object" }
            for (k, v) in dm {
                if !isVerbName(k.s) { return "actions.defs: '\(k.s)' is not a verb" }
                if !isSha(v) { return "actions.defs.\(k.s) must be a base64url digest" }
            }
        }
        return nil
    }

    private static func deny(_ code: String, _ reason: String, escalate: Bool = false, needs: String? = nil) -> PinDecision {
        PinDecision(ok: false, via: nil, code: code, escalate: escalate, reason: reason, needsReapproval: needs)
    }

    public static func decidePin(pin pinV: JSONValue?, doc: JSONValue?, verb: String, records: [JSONValue], keys: JSONValue?, reapprovals: [JSONValue], grantId: String, issuer: String) -> PinDecision {
        if let pe = actionPinError(pinV) { return deny("bad_pin", pe) }
        guard case let .object(pin)? = pinV, case let .object(pp)? = pin["pack"], let pns = pp["ns"]?.asString, let proot = pp["root"]?.asString else { return deny("bad_pin", "malformed") }
        let verbs = doc?.get("verbs")?.asArray
        guard verbs?.contains(where: { $0.asObject != nil && IV.same($0.get("verb")?.asString, verb) }) == true,
              let v = verbs?.first(where: { $0.asObject != nil && IV.same($0.get("verb")?.asString, verb) }) else { return deny("unknown_verb", "the accepted schema does not declare '\(verb)'") }
        guard case let .object(pk)? = doc?.get("pack"), IV.same(pk["ns"]?.asString, pns) else { return deny("pack_mismatch", "the schema does not come from the pinned pack '\(pns)'") }
        let onNew = pin["on_new_action"]?.asString ?? "deny"
        guard case let .object(defs)? = pin["defs"] else {
            return IV.same(pk["root"]?.asString, proot) ? PinDecision(ok: true, via: "pack", code: nil, escalate: false, reason: "", needsReapproval: nil)
                : deny("pack_mismatch", "the pack root differs from the pinned root (the grant pins the pack as a whole)")
        }
        guard let pinned = defs[JKey(verb)]?.asString else { return deny("new_action", "the grant does not name '\(verb)' (on_new_action: \(onNew))", escalate: onNew == "escalate") }
        guard let presented = v.get("def")?.asString else { return deny("def_changed", "the schema verb carries no definition digest") }
        if IV.same(presented, pinned) { return PinDecision(ok: true, via: "exact", code: nil, escalate: false, reason: "", needsReapproval: nil) }
        var edges: [String: [(to: String, blocked: String?)]] = [:]
        for r in records {
            guard verifyEvolutionRecord(r, keys), let ns = r.get("ns")?.asString, IV.same(ns, pns), IV.same(r.get("verb")?.asString, verb),
                  let from = r.get("from")?.asString, let to = r.get("to")?.asString, let cls = r.get("class")?.asString, let diff = evolutionDiffDigest(r) else { continue }
            let free = cls == "equal" || cls == "narrow"
            let approved = free || reapprovals.contains { reapprovalValid($0, grantId: grantId, issuer: issuer, verb: verb, diff: diff) }
            edges[from, default: []].append((to, approved ? nil : diff))
        }
        func search(_ usableOnly: Bool) -> [String: (from: String, blocked: String?)] {
            var parent: [String: (from: String, blocked: String?)] = [:]
            var seen: Set<String> = [pinned]
            var frontier = [pinned]
            var step = 0
            while step < MAX_EVOLUTION_STEPS && !frontier.isEmpty && parent[presented] == nil {
                var next: [String] = []
                for f in frontier {
                    for e in edges[f] ?? [] {
                        if seen.contains(e.to) || (usableOnly && e.blocked != nil) { continue }
                        seen.insert(e.to)
                        parent[e.to] = (f, e.blocked)
                        next.append(e.to)
                    }
                }
                frontier = next
                step += 1
            }
            return parent
        }
        if search(true)[presented] != nil { return PinDecision(ok: true, via: "chain", code: nil, escalate: false, reason: "", needsReapproval: nil) }
        let all = search(false)
        if all[presented] != nil {
            var first: String?
            var cur = presented
            while cur != pinned {
                let p = all[cur]!
                if let b = p.blocked { first = b }
                cur = p.from
            }
            return deny("def_changed", "the definition widened (or changed incomparably) since the grant pinned it: the principal must re-approve", needs: first)
        }
        return deny("def_changed", "the definition differs from the pinned digest and no signed evolution record chains to it")
    }

    // ---- signed packs ---------------------------------------------------------------------------------------------------------

    /// `<0, 0, >0`; nil when either is not MAJOR.MINOR.PATCH.
    public static func compareVersions(_ a: String, _ b: String) -> Int? {
        func parse(_ s: String) -> [Int]? {
            guard fullMatch("(0|[1-9][0-9]{0,8})\\.(0|[1-9][0-9]{0,8})\\.(0|[1-9][0-9]{0,8})", s) else { return nil }
            return s.split(separator: ".").compactMap { Int($0) }
        }
        guard let pa = parse(a), let pb = parse(b) else { return nil }
        for i in 0..<3 where pa[i] != pb[i] { return pa[i] - pb[i] }
        return 0
    }

    public static func rulesDigest() -> String {
        IV.strictHash(.object(["d": .string(RULES_DIGEST_DOMAIN), "prules": .array(PARAM_RULE_IDS.map { .string($0) }),
                               "caveats": .array(CAVEAT_KINDS.map { .string($0) }), "context": .array(CONTEXT_KEYS.map { .string($0) })]))!
    }
    static func packDigest(_ p: JObject) -> String? { IV.strictHash(.object(["d": .string(PACK_REF_DOMAIN), "p": .object(p)])) }
    static func shardDigest(_ s: JSONValue) -> String? { IV.strictHash(.object(["d": .string(PACK_SHARD_DOMAIN), "s": s])) }

    private static func sortedUniqueDefsError(_ defs: [JSONValue]) -> String? {
        for (i, d) in defs.enumerated() {
            if let e = validateDef(d) { return "def \(i): \(e)" }
            if i > 0, !utf16Less(defs[i - 1].get("verb")?.asString ?? "", d.get("verb")?.asString ?? "") {
                return "defs must be sorted by verb and unique (at '\(d.get("verb")?.asString ?? "")')"
            }
        }
        return nil
    }

    public static func packShapeError(_ xv: JSONValue?) -> String? {
        guard case let .object(x)? = xv else { return "pack must be an object" }
        if let e = closedKeys(x, ["v", "kind", "ns", "version", "stability", "traits_digest", "roles_digest", "rules_digest", "root", "defs", "source", "prev", "evolution", "sig"]) { return "pack: \(e)" }
        if !isOne(x["v"]) || !IV.same(x["kind"]?.asString, "pca-action-pack") { return "pack: bad v/kind" }
        if !isNs(x["ns"]) { return "pack: bad ns" }
        if !(x["version"]?.asString.map { compareVersions($0, $0) != nil } ?? false) { return "pack: version must be MAJOR.MINOR.PATCH" }
        if !inList(["draft", "beta", "stable"], x["stability"]) { return "pack: bad stability" }
        for k in ["traits_digest", "roles_digest", "rules_digest", "root"] where !isSha(x[JKey(k)]) { return "pack: \(k) must be a base64url digest" }
        if x["prev"]?.isNull != true && !isSha(x["prev"]) { return "pack: bad prev" }
        guard case let .object(s)? = x["source"], closedKeys(s, ["kind", "uri", "spec_digest", "licence", "licence_notes"]) == nil else { return "pack: source must be {kind, uri, spec_digest, licence, licence_notes}" }
        for k in ["kind", "uri", "spec_digest", "licence", "licence_notes"] {
            guard let v = s[JKey(k)]?.asString, !(k != "licence_notes" && v.isEmpty), IV.u16(v) <= 2048 else { return "pack: source.\(k) is not a string of 1..2048 characters" }
        }
        if case let .array(d)? = x["defs"] {
            if d.isEmpty || d.count > 4096 { return "pack: inline defs must number 1..4096 (larger packs are sharded)" }
            if let de = sortedUniqueDefsError(d) { return "pack: \(de)" }
        } else {
            guard case let .object(d)? = x["defs"], closedKeys(d, ["shards"]) == nil, case let .array(sh)? = d["shards"], !sh.isEmpty, sh.count <= 4096 else { return "pack: defs must be a list of defs or {shards}" }
            var names: [String] = []
            for r in sh {
                guard case let .object(ro) = r, closedKeys(ro, ["name", "digest", "uri"]) == nil else { return "pack: bad shard ref" }
                guard let n = ro["name"]?.asString, fullMatch("[a-z0-9_]+(?:[.-][a-z0-9_]+){0,7}", n), !names.contains(where: { IV.same($0, n) }) else { return "pack: shard names must be distinct simple names" }
                names.append(n)
                guard isSha(ro["digest"]), let u = ro["uri"]?.asString, !u.isEmpty, IV.u16(u) <= 2048 else { return "pack: bad shard digest or uri" }
            }
        }
        guard case let .array(ev)? = x["evolution"], ev.count <= 65536 else { return "pack: evolution must be a list of records" }
        for r in ev { if let e = evolutionRecordError(r) { return "pack: \(e)" } }
        guard case let .object(g)? = x["sig"], closedKeys(g, ["alg", "kid", "value", "pq_value"]) == nil, g["kid"]?.asString != nil, g["value"]?.asString != nil, g["alg"]?.asString != nil else { return "pack: bad sig" }
        if let e = IV.strictCanonError(.object(without(x, "sig"))) { return "pack: \(e)" }
        return nil
    }

    static func packDefs(_ p: JObject, _ shards: JObject) throws -> [JSONValue] {
        if case let .array(d)? = p["defs"] { return d }
        var all: [JSONValue] = []
        for r in p["defs"]?.get("shards")?.asArray ?? [] {
            let name = r.get("name")?.asString ?? ""
            guard let s = shards[JKey(name)] else { throw ActionKitError(code: "missing_shard", message: "shard '\(name)' was not supplied") }
            if shardDigest(s) != r.get("digest")?.asString { throw ActionKitError(code: "shard_digest_mismatch", message: "shard '\(name)' does not match its digest") }
            guard isOne(s.get("v")), IV.same(s.get("kind")?.asString, PACK_SHARD_KIND), IV.same(s.get("ns")?.asString, p["ns"]?.asString), IV.same(s.get("version")?.asString, p["version"]?.asString),
                  IV.same(s.get("name")?.asString, name), let defs = s.get("defs")?.asArray else { throw ActionKitError(code: "bad_shard", message: "shard '\(name)' is not a shard of this pack") }
            all.append(contentsOf: defs)
        }
        return all.sorted { utf16Less($0.get("verb")?.asString ?? "", $1.get("verb")?.asString ?? "") }
    }

    private static func failedPack(_ r: String) -> PackVerdict { PackVerdict(ok: false, reason: r, digest: "", defs: []) }

    public static func verifyPack(_ pv: JSONValue?, keys: JSONValue?, shards: JObject = [:]) -> PackVerdict {
        if let se = packShapeError(pv) { return failedPack(se) }
        guard case let .object(p)? = pv, case let .object(sig)? = p["sig"] else { return failedPack("malformed") }
        if !verifyRegistrySig(PACK_SIG_DOMAIN, without(p, "sig"), sig, keys) { return failedPack("pack signature: invalid") }
        if !IV.same(p["traits_digest"]?.asString, traitsDigest(coreRegistry)) { return failedPack("traits_digest does not match the trait registry") }
        if !IV.same(p["roles_digest"]?.asString, tablesDigest()) { return failedPack("roles_digest does not match the vocabulary tables") }
        if !IV.same(p["rules_digest"]?.asString, rulesDigest()) { return failedPack("rules_digest does not match the rule tables") }
        let defs: [JSONValue]
        do { defs = try packDefs(p, shards) } catch let e as ActionKitError { return failedPack(e.message) } catch { return failedPack("\(error)") }
        if let de = sortedUniqueDefsError(defs) { return failedPack(de) }
        if defs.isEmpty || defs.count > 1_000_000 { return failedPack("the pack lists no defs or too many") }
        let digests = defs.map { defDigest($0.asObject ?? [:]) }
        guard let root = try? packRoot(digests), IV.same(root, p["root"]?.asString) else { return failedPack("the Merkle root does not match the defs") }
        for r in p["evolution"]?.asArray ?? [] {
            if !verifyEvolutionRecord(r, keys) { return failedPack("evolution record: invalid") }
            if !IV.same(r.get("ns")?.asString, p["ns"]?.asString) { return failedPack("evolution record of another namespace") }
            if let to = r.get("to")?.asString, !digests.contains(where: { IV.same($0, to) }) { return failedPack("evolution record names a definition that is not in the pack") }
        }
        guard let d = packDigest(p) else { return failedPack("pack digest") }
        return PackVerdict(ok: true, reason: "", digest: d, defs: defs)
    }

    /// The verifier's view of a registry: refuses rollback, fork and chain gap. The semantic diff of an upgrade is not recomputed natively.
    public final class PackTracker {
        let keys: JSONValue?
        var seen: [String: (version: String, digest: String)] = [:]
        public init(keys: JSONValue?) { self.keys = keys }

        /// `status` on success, else the refusal code.
        public func accept(_ pack: JSONValue, shards: JObject = [:]) -> (ok: Bool, value: String) {
            let v = Actions.verifyPack(pack, keys: keys, shards: shards)
            if !v.ok { return (false, "bad_pack") }
            let ns = pack.get("ns")?.asString ?? "", version = pack.get("version")?.asString ?? ""
            guard let cur = seen[ns] else { seen[ns] = (version, v.digest); return (true, "first") }
            if cur.digest == v.digest { return (true, "same") }
            let c = Actions.compareVersions(version, cur.version) ?? 0
            if c < 0 { return (false, "rollback") }
            if c == 0 { return (false, "fork") }
            if pack.get("prev")?.asString != cur.digest { return (false, "chain_gap") }
            seen[ns] = (version, v.digest)
            return (true, "upgrade")
        }
    }

    // ---- rule 22 over a whole document ------------------------------------------------------------------------------------------

    private static let rule22Codes = ["schema_floor_forged", "schema_traits_forged", "unknown_trait", "traits_digest_mismatch", "bad_registry"]
    public static func rule22Code(_ e: String?) -> String? {
        guard let e = e else { return nil }
        return rule22Codes.first { e.contains($0) } ?? "unknown"
    }

    public static func rule22Decide(doc: JSONValue, verb: String, grantCaveats: [String], maxEsc: Int, preauthEsc: Int, context: [String]) -> String {
        guard let v = doc.get("verbs")?.asArray?.first(where: { IV.same($0.get("verb")?.asString, verb) }),
              profileError(v.get("floors")) == nil, let rho = Profile(json: v.get("floors")) else { return "deny" }
        return floorDecision(grantCaveats: grantCaveats.filter { IV.contains(CAVEAT_KINDS, $0) }, maxEsc: maxEsc, preauthEsc: preauthEsc,
                             callContext: context.filter { isContextKey($0) }, rho: rho)
    }
}
