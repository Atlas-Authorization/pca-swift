import Foundation

/// Least privilege from observed behaviour: a narrower replacement for a grant proposed from what its holder really did, plus the
/// unused-permission findings, ranked by blast radius and reversibility. It is a REVIEW artefact, never applied:
///
///  - It only narrows. The proposal is built as "the original predicate AND extra conditions" and is then PROVEN subsumed by the
///    original with the analyzer; if that proof is not exact the proposal is withheld.
///  - Only observations from the principal's own ledger (`source: "ledger"`) count; an action the agent merely CLAIMS is `rejected`.
///  - A denied attempt never loosens a grant: it becomes an access request for a human to read.
///
/// Policies, observations and results are plain JSON trees (`JSONValue`); `nil` is JavaScript `undefined`.
fileprivate enum NrH {
    typealias V = JSONValue
    typealias A = PCAAnalyzer

    static let catalog = PCACatalog.default

    static func revWeight(_ r: String) -> Double {
        Double((A.REVERSIBILITY_ORDER.firstIndex { IV.same($0, r) } ?? -1) + 1)
    }

    /// The spec of a catalogued verb, else the fail-closed spec (irreversible, maximum blast radius). A custom catalog is a JSON value
    /// without a `get`, which is a TypeError at first use; a verb that is not a string is a TypeError in the uncatalogued spec.
    static func spec(_ verb: V?, _ custom: V?) throws -> (blast: Double, rev: String) {
        if custom != nil { throw JSError("catalog.get is not a function") }
        guard case let .string(s)? = verb else { throw JSError("verb.split is not a function") }
        if let a = catalog.get(s) { return (a.blastRadius, a.reversibility) }
        return (1, "irreversible")
    }

    static func sortedUnique(_ xs: [String]) -> [String] { PCADataflow.jsSorted(PCADataflow.distinct(xs)) }

    static func str(_ v: V?) throws -> String {
        guard case let .string(s)? = v else { throw JSError("not a string") }
        return s
    }

    /// The longest common leading run of the resources, cut after its last "/".
    static func commonPrefix(_ rs: [String]) -> String {
        var p = Array((rs.first ?? "").utf16)
        for r in rs {
            let u = Array(r.utf16)
            var i = 0
            while i < p.count && i < u.count && p[i] == u[i] { i += 1 }
            p = Array(p[..<i])
        }
        guard let cut = p.lastIndex(of: 0x2f) else { return "" }
        return String(decoding: p[...cut], as: UTF16.self)
    }

    /// `[...(x ?? [])]` for a `for ... of`.
    static func each(_ v: V?) throws -> [V] { try JS.spread(JS.present(v) ?? .array([])) }

    static func upperBoundOf(_ where_: V?, _ path: String) throws -> Double {
        var ub = Double.infinity
        for c in try each(where_) {
            guard c.isObject || c.isArray, A.inObj(c, "field"), IV.same(A.mem(c, "field")?.asString, path), let op = A.mem(c, "op")?.asString,
                  IV.same(op, "lte") || IV.same(op, "lt"), let v = A.mem(c, "value"), v.isNumber else { continue }
            ub = min(ub, JS.toNumber(v))
        }
        return ub
    }

    static func paramsOf(_ a: V?) -> V { JS.present(A.mem(a, "params")) ?? .object([:]) }

    static func ctxOf(_ a: V?) -> V {
        .object(["action": A.obj([("verb", A.mem(a, "verb")), ("resource", A.mem(a, "resource")), ("params", paramsOf(a))])])
    }

    static func matches(_ p: V, _ a: V) -> Bool { Predicates.predicateMatches(p, ctxOf(a), SafeRegex.Budget()) }

    static func finding(_ kind: String, _ i: Int, _ s: (blast: Double, rev: String), _ extra: [(String, V?)]) -> V {
        var items: [(String, V?)] = [("kind", .string(kind)), ("predicate", .int(Int64(i)))]
        items += extra
        items.append(("blastRadius", A.num(s.blast)))
        items.append(("reversibility", .string(s.rev)))
        items.append(("rank", A.num(s.blast * revWeight(s.rev))))
        return A.obj(items)
    }

    /// `verbs.join(', ')` (a null / undefined member joins as "").
    static func joined(_ vs: [V]) -> String { vs.map { $0 == .null ? "" : JS.toString($0) }.joined(separator: ", ") }

    static let ACCESS_REQUEST_SIG_DOMAIN = "atlas-pca/access-request/v1\u{0}"

    /// `utf8(domain) || sha256(utf8(hashCanonical(r)))`.
    static func requestMessage(_ r: V) throws -> [UInt8] {
        guard let h = IV.strictHash(r) else { throw JSError(IV.strictCanonError(r) ?? "canonicalize: outside the strict profile") }
        return Canonical.utf8(ACCESS_REQUEST_SIG_DOMAIN) + Canonical.sha256(Canonical.utf8(h))
    }
}

extension PCAAnalyzer {
    /// Propose a narrower grant from what the holder did (`observed`: ledger entries {verb, resource, params, source, outcome?}), and list what
    /// was never used. Never applies anything. A custom `catalog`, a non-numeric `margin`, and a `decay` that is not two numbers are refused
    /// (the reference would coerce or fail on them).
    public static func suggestNarrowing(_ policy: JSONValue?, _ observed: JSONValue?, _ o: JSONValue? = nil) throws -> JSONValue {
        let oo: V = o ?? .object([:])
        let marginV: V = JS.present(try rd(oo, "margin")) ?? .double(0.1)
        guard marginV.isNumber else { throw JSError("margin must be a number") }
        let margin = JS.toNumber(marginV)
        let minSamples = JS.toNumber(JS.present(try rd(oo, "minSamples")) ?? .int(5))
        let enumLimit = JS.toNumber(JS.present(try rd(oo, "enumLimit")) ?? .int(8))
        let custom = JS.present(try rd(oo, "catalog"))
        let model = try toModel(policy)
        let digest = try policyDigestOf(model)

        guard case let .array(obs)? = observed else { throw JSError("observed.filter is not a function") }
        var trusted: [V] = [], refused: [V] = []
        var rejected = 0
        for x in obs {
            let src = try rd(x, "source")
            let ledger = IV.same(src?.asString, "ledger")
            let denied = IV.same(try rd(x, "outcome")?.asString, "denied")
            if ledger && !denied { trusted.append(x) }
            if !ledger { rejected += 1 }
            if ledger && denied { refused.append(x) }
        }
        var findings: [(V, Double, Int)] = []
        let basev = try rd(policy, "predicates")
        let base: [V] = basev?.asArray ?? []

        func build(_ narrow: Bool) throws -> [V] {
            var out: [V] = []
            for p in base {
                let hits = trusted.filter { NrH.matches(p, $0) }
                if hits.isEmpty { continue }
                let verbs = NrH.sortedUnique(try hits.map { try NrH.str(mem($0, "verb")) })
                let resources = NrH.sortedUnique(try hits.map { try NrH.str(mem($0, "resource")) })
                var next: JObject = ["verb": verbs.count == 1 ? .string(verbs[0]) : strs(verbs)]
                let pres = try rd(p, "resource")
                if narrow {
                    if resources.count == 1 { next["resource"] = .string(resources[0]) }
                    else {
                        let pre = NrH.commonPrefix(resources)
                        if IV.u16(pre) > 1 { next["resource"] = .string(pre + "*") }
                        else if let r = pres { next["resource"] = r }
                    }
                } else if let r = pres { next["resource"] = r }
                var where_: [V] = try NrH.each(try rd(p, "where"))
                var names: [String] = []
                for h in hits { names += JSLoose.keys(NrH.paramsOf(h)) }
                for name in NrH.sortedUnique(names) {
                    let path = "action.params.\(name)"
                    let vals = hits.map { JSLoose.get(NrH.paramsOf($0), name) }
                    if Double(vals.count) < minSamples || vals.contains(where: { $0 == nil }) { continue }
                    if vals.allSatisfy({ fin($0) != nil }) {
                        let nums = vals.map { fin($0)! }
                        let v = nums.max()! * (1 + margin)
                        let ceil = nums.allSatisfy({ $0 == $0.rounded() }) ? v.rounded(.up) : v
                        let ub = try NrH.upperBoundOf(try rd(p, "where"), path)
                        if ceil < ub {
                            where_.append(.object(["field": .string(path), "op": .string("lte"), "value": num(ceil)]))
                        }
                    } else if vals.allSatisfy({ $0?.asString != nil }) {
                        let set = NrH.sortedUnique(vals.map { $0!.asString! })
                        if Double(set.count) <= enumLimit { where_.append(.object(["field": .string(path), "op": .string("in"), "value": strs(set)])) }
                    }
                }
                if !where_.isEmpty { next["where"] = .array(where_) }
                out.append(.object(next))
            }
            return out
        }

        for (i, p) in base.enumerated() {
            let hit = trusted.contains { NrH.matches(p, $0) }
            let pv = try rd(p, "verb")
            let verbs: [V] = pv?.asString != nil ? [pv!] : (pv?.asArray ?? [])
            if !hit {
                let v: V = JS.present(verbs.first) ?? .string("*")
                let s = try NrH.spec(IV.same(v.asString, "*") ? .string("unknown.any") : v, custom)
                let list = NrH.joined(verbs)
                findings.append((NrH.finding("unused-predicate", i, s, [("verb", v), ("detail", .string("no observed action used predicate \(i) (\(list.isEmpty ? "*" : list))"))]),
                                 s.blast * NrH.revWeight(s.rev), i))
                continue
            }
            for v in verbs {
                if IV.same(v.asString, "*") { continue }
                if !trusted.contains(where: { nrSame(mem($0, "verb"), v) && NrH.matches(p, $0) }) {
                    let s = try NrH.spec(v, custom)
                    findings.append((NrH.finding("unused-verb", i, s, [("verb", v), ("detail", .string("verb \(JS.toString(v)) is granted by predicate \(i) but never used"))]),
                                     s.blast * NrH.revWeight(s.rev), i))
                }
            }
            for c in try NrH.each(try rd(p, "where")) {
                guard c.isObject, let field = mem(c, "field")?.asString, let op = mem(c, "op")?.asString, IV.same(op, "lte") || IV.same(op, "lt"),
                      let cv = mem(c, "value"), cv.isNumber, IV.startsWith(field, "action.params.") else { continue }
                let name = IV.dropPrefix(field, 14)
                let vals: [Double] = trusted.filter { NrH.matches(p, $0) }.compactMap { (a: V) -> Double? in
                    let x = JSLoose.get(NrH.paramsOf(a), name)
                    return (x?.isNumber ?? false) ? JS.toNumber(x) : nil
                }
                let top = vals.max() ?? -.infinity
                if Double(vals.count) >= minSamples && top < JS.toNumber(cv) / 2 {
                    let s = try NrH.spec(JS.present(verbs.first) ?? .string("unknown.any"), custom)
                    findings.append((NrH.finding("unreached-cap", i, s, [("verb", JS.truthy(verbs.first) ? verbs.first : nil),
                                                                       ("detail", .string("\(name) <= \(JS.toString(cv)) but the largest observed value is \(JS.toString(.double(top)))"))]),
                                     s.blast * NrH.revWeight(s.rev), i))
                }
            }
        }
        // rank descending, then predicate ascending; a stable sort
        let findingsSorted = findings.indices.sorted { a, b in
            let x = findings[a], y = findings[b]
            if x.1 != y.1 { return x.1 > y.1 }
            if x.2 != y.2 { return x.2 < y.2 }
            return a < b
        }.map { findings[$0].0 }

        var order: [JKey] = []
        var groups: [JKey: JObject] = [:]
        var counts: [JKey: Int] = [:]
        let taskBinding = try rd(oo, "taskBinding")
        for a in refused {
            let k = JKey(JS.toString(mem(a, "verb")) + "\u{0}" + JS.toString(mem(a, "resource")))
            if counts[k] != nil { counts[k]! += 1; continue }
            var g: [(String, V?)] = [("v", .int(1)), ("kind", .string("pca-access-request")), ("verb", mem(a, "verb")), ("resource", mem(a, "resource")),
                                     ("example_params", .object(JSLoose.spread(NrH.paramsOf(a)))), ("policy_digest", .string(digest))]
            if let tb = taskBinding, JS.truthy(tb) { g.append(("task_binding", tb)) }
            groups[k] = obj(g).asObject!
            counts[k] = 1
            order.append(k)
        }
        // denied_count descending, then verb ascending (equal verbs keep their order)
        let accessRequests: [V] = order.indices.sorted { a, b in
            let ca = counts[order[a]]!, cb = counts[order[b]]!
            if ca != cb { return ca > cb }
            let va = groups[order[a]]!["verb"], vb = groups[order[b]]!["verb"]
            if JSLoose.lt(va, vb) { return true }
            if JSLoose.lt(vb, va) { return false }
            return a < b
        }.map { (i: Int) -> V in
            var g = groups[order[i]]!
            g["denied_count"] = .int(Int64(counts[order[i]]!))
            return .object(g)
        }

        var res: JObject = ["used": .int(Int64(trusted.count)), "rejected": .int(Int64(rejected)), "denied": .int(Int64(refused.count)),
                            "coversObserved": .bool(false), "findings": .array(findingsSorted), "accessRequests": .array(accessRequests)]
        if let tb = taskBinding, JS.truthy(tb) { res["taskBinding"] = tb }

        var caveats = model.caveats
        if let decay = try rd(oo, "decay"), JS.truthy(decay) {
            guard let now = mem(decay, "nowSec"), now.isNumber, let ex = mem(decay, "expiresInSecs"), ex.isNumber else { throw JSError("decay.nowSec and decay.expiresInSecs must be numbers") }
            caveats.append(.object(["type": .string("expires"), "at": num(JS.toNumber(now) + JS.toNumber(ex))]))
        }
        for narrow in [true, false] {
            let preds = try build(narrow)
            let proposal: V = .object(["predicates": .array(preds), "caveats": .array(caveats), "vetoes": .array(model.vetoes), "tighten": .array(model.tighten)])
            if preds.isEmpty {
                res["reason"] = .string("no ledger observation matches any predicate")
                return .object(res)
            }
            let proof = try subsumes(policy, proposal)
            if mem(proof, "subsumes") != .bool(true) || mem(proof, "approximate") == .bool(true) {
                res["reason"] = JS.present(mem(proof, "reason")) ?? .string("the proposal could not be proven narrower than the original")
                continue
            }
            res["reason"] = nil
            res["proposal"] = proposal
            var covers = true
            for a in trusted {
                let act = obj([("verb", mem(a, "verb")), ("resource", mem(a, "resource")), ("params", NrH.paramsOf(a))])
                if !(try admitsConcrete(proposal, act)) { covers = false; break }
            }
            res["coversObserved"] = .bool(covers)
            res["diff"] = try diffPolicies(policy, proposal, nil)
            return .object(res)
        }
        return .object(res)
    }

    // ---- access requests ----

    /// The holder's signed ask (a request for a human to read; nothing here turns it into authority): {request, signer, sig}.
    public static func signAccessRequest(_ r: JSONValue, key: PCAEdKey) throws -> JSONValue {
        let sig = try key.sign(try NrH.requestMessage(r))
        return .object(["request": r, "signer": .string(key.id), "sig": .string(Base64URLStrict.encode(sig))])
    }

    /// Verify a signed access request, optionally against an expected signer public key; anything malformed is false.
    public static func verifyAccessRequest(_ s: JSONValue?, _ expectedSigner: JSONValue? = nil) -> Bool {
        guard let sv = s, sv.isObject, let req = mem(sv, "request"), req.isObject, IV.same(mem(req, "kind")?.asString, "pca-access-request"),
              IV.num(mem(req, "v")) == 1 else { return false }
        if let e = expectedSigner, !IV.same(mem(sv, "signer")?.asString, e.asString) { return false }
        guard let sig = mem(sv, "sig")?.asString, let signer = mem(sv, "signer")?.asString, let msg = try? NrH.requestMessage(req) else { return false }
        return Ed25519Strict.verifyB64u(signer, msg, sig)
    }
}

/// `a === b` for the strings an observation / policy verb is.
fileprivate func nrSame(_ a: JSONValue?, _ b: JSONValue?) -> Bool {
    if case let .string(x)? = a, case let .string(y)? = b { return IV.same(x, y) }
    return false
}
