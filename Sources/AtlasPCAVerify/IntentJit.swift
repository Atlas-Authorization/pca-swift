import Foundation

/// Lazy just-in-time elicitation: the ordered decision for a visited cell (schema violation, ceiling, intent denied, admit, intent
/// required), the cell coordinates of an `intent_required` question, the wallet's check of one, and the delta grant minted from an
/// answer. Outcomes are `{verb, values}` values; the verb space is the learner's own (`WalletVerb`).
public enum PCAIntentJit {
    public static let INTENT_ACTION_DOMAIN = "atlas-pca/intent-action/v1"

    /// A ceiling: does the verb space's grant ceiling admit the lifted outcome?
    public typealias Ceiling = (WalletVerb, JSONValue) throws -> Bool

    private static func ints(_ a: [Int]) -> JSONValue { .array(a.map { JSONValue.int(Int64($0)) }) }

    /// ECMAScript `String(x)` of an optional member (`undefined` when absent).
    private static func jsStr(_ v: JSONValue?) -> String {
        guard let v = v else { return "undefined" }
        return IntentV2.jsString(v)
    }

    /// The verb space as JSON (the dimensions in order).
    static func dimJSON(_ d: WalletDim) -> JSONValue {
        var m: JObject = ["kind": .string(d.kind), "path": .string(d.path)]
        if d.isNum {
            m["lo"] = .int(Int64(d.lo))
            m["hi"] = .int(Int64(d.hi))
            m["cuts"] = .array(d.cuts.map { JSONValue.int(Int64($0)) })
            m["dist"] = d.dist.map { JSONValue.string($0) } ?? .null
        } else {
            m["values"] = .array(d.values.map { JSONValue.object(["kind": .string($0.kind), "value": .string($0.value)]) })
        }
        return .object(m)
    }

    static func verbSpaceJSON(_ vs: WalletVerb) -> JSONValue {
        .object(["verb": .string(vs.verb), "reversibility": .string(vs.reversibility), "weight": .double(vs.weight), "dims": .array(vs.dims.map { dimJSON($0) })])
    }

    /// The ordered decision of a visit. `conform`: `{ok, code?, reason?}` (the schema conformance of the plaintext action); `ceilings`:
    /// each must admit the lifted outcome (a deny anywhere wins); `inEffective`: is the cell in the effective grant. Returns `{kind, ...}`.
    public static func decideVisit(_ learner: PCAIntentLearner, _ lifted: JSONValue, _ conform: JSONValue, _ ceilings: [Ceiling]?, _ inEffective: Bool) throws -> JSONValue {
        var r: JObject = [:]
        if conform.get("ok") != .bool(true) {
            r["kind"] = .string("schema_violation")
            r["reason"] = .string(jsStr(conform.get("code")) + ": " + jsStr(conform.get("reason")))
            return .object(r)
        }
        guard let verb = lifted.get("verb")?.asString, let vs = learner.omega.verb(verb), let cell = WalletOmegaMath.cellOf(vs, values: lifted.get("values")) else {
            r["kind"] = .string("schema_violation")
            r["reason"] = .string("the lifted action lies outside \u{03A9}\u{0303}")
            return .object(r)
        }
        if let cs = ceilings {
            for c in cs {
                if !(try c(vs, lifted)) { r["kind"] = .string("ceiling"); return .object(r) }
            }
        }
        let vetoed = learner.isVetoed(lifted)
        let p = learner.acceptance(lifted)
        if vetoed || p <= 0 {
            r["kind"] = .string("intent_denied"); r["vetoed"] = .bool(vetoed)
            return .object(r)
        }
        if inEffective { r["kind"] = .string("admit"); r["cell"] = ints(cell); return .object(r) }
        r["kind"] = .string("intent_required")
        r["cell"] = ints(cell)
        r["p"] = .double(p)
        return .object(r)
    }

    /// The coordinates of one cell (numeric: [i, i]; categorical: the cell's value).
    public static func cellCoords(_ vs: WalletVerb, _ cell: [Int]) throws -> JSONValue {
        var out: JObject = [:]
        for k in 0..<vs.dims.count {
            let d = vs.dims[k]
            guard k < cell.count else { throw JSError("cellCoords: the cell has too few coordinates") }
            if d.isNum {
                out[JKey(d.path)] = .array([.int(Int64(cell[k])), .int(Int64(cell[k]))])
            } else {
                guard cell[k] >= 0 && cell[k] < d.values.count else { throw JSError("cellCoords: no such value") }
                out[JKey(d.path)] = .array([.string(d.values[cell[k]].value)])
            }
        }
        return .object(out)
    }

    /// Coordinates to per-dimension cell indices (the inverse of `cellCoords` for one cell), or nil.
    public static func cellFromCoords(_ vs: WalletVerb, _ coords: JSONValue?) -> [Double]? {
        guard let m = coords?.asObject, m.count == vs.dims.count else { return nil }
        var out: [Double] = []
        for d in vs.dims {
            guard let c = m[JKey(d.path)]?.asArray else { return nil }
            if d.isNum {
                guard c.count >= 2, let a = IV.num(c[0]), let b = IV.num(c[1]), a == b else { return nil }
                out.append(a)
            } else {
                guard c.count == 1, let s = c[0].asString, let i = d.values.firstIndex(where: { IV.same($0.value, s) }) else { return nil }
                out.append(Double(i))
            }
        }
        return out
    }

    /// `intentActionDigest`: the content address of the action an intent_required question is about.
    public static func intentActionDigest(_ action: JSONValue?) throws -> String {
        guard let a = action?.asObject else { throw JSError("intentActionDigest: the action must be an object") }
        var act: JObject = [:]
        for k in ["verb", "resource", "params_digest", "reversibility_class"] { act[JKey(k)] = a[JKey(k)] ?? .null }
        return Canonical.hashCanonical(IV.normalized(.object(["d": .string(INTENT_ACTION_DOMAIN), "action": .object(act)])))
    }

    /// The site's `pca-intent-required` body for a visited uncertain cell. `inp`: session, mapDigest, schemaDigest, pcactn (JSON),
    /// questionId, friction, deliveredTo, expiresAt; `vs` and `cell` locate the cell.
    public static func intentRequiredBody(_ inp: JSONValue, _ vs: WalletVerb, _ cell: [Int]) throws -> JSONValue {
        guard let pcactn = inp.get("pcactn")?.asObject else { throw JSError("intentRequiredBody: pcactn must be an object") }
        var b: JObject = [:]
        b["v"] = .int(1)
        b["kind"] = .string("pca-intent-required")
        b["session"] = inp.get("session") ?? .null
        b["map_digest"] = inp.get("mapDigest") ?? .null
        b["schema"] = inp.get("schemaDigest") ?? .null
        b["pcactn_digest"] = .string(Canonical.hashCanonical(IV.normalized(.object(pcactn))))
        b["action_digest"] = .string(try intentActionDigest(pcactn["action"]))
        b["cell"] = .object(["verb": .string(vs.verb), "coords": try cellCoords(vs, cell)])
        b["reason"] = .string("uncertain")
        b["question_id"] = inp.get("questionId") ?? .null
        b["friction"] = inp.get("friction") ?? .null
        b["delivered_to"] = inp.get("deliveredTo") ?? .null
        b["expires_at"] = inp.get("expiresAt") ?? .null
        return .object(b)
    }

    public static func signedIntentRequired(_ inp: JSONValue, _ vs: WalletVerb, _ cell: [Int], _ kid: String, _ site: PCASuiteKey) throws -> JSONValue {
        try PCASigners.signIntentRequired(try intentRequiredBody(inp, vs, cell), kid: kid, site: site)
    }

    private static func fail(_ reason: String) -> JSONValue { .object(["ok": .bool(false), "reason": .string(reason)]) }

    /// The wallet's check of an `intent_required`: the site signature under its discovery keys, the expiry, the session and map, and the
    /// CELL, re-derived from the wallet's own space and the lifted action. Returns `{ok: true, vs, cell}` or `{ok: false, reason}`.
    public static func walletCheckIntentRequired(_ body: JSONValue?, _ keys: [JSONValue], _ now: Int64, _ session: String, _ mapDigest: String, _ omegaTilde: WalletOmega,
                                                 _ lifted: JSONValue, _ pcactn: JSONValue) -> JSONValue {
        let v: JSONValue = PCAWalletDelivery.verifyIntentRequired(body, .array(keys), .int(now))
        if v.get("ok") != .bool(true) { return fail(v.get("reason")?.asString ?? "malformed intent_required") }
        guard let b = body?.asObject else { return fail("not an object") }
        if !IV.same(b["session"]?.asString, session) || !IV.same(b["map_digest"]?.asString, mapDigest) { return fail("the question is for another session or map") }
        let digest: String = Canonical.hashCanonical(IV.normalized(pcactn))
        let actionDigest: String? = try? intentActionDigest(pcactn.get("action"))
        if !IV.same(b["pcactn_digest"]?.asString, digest) || actionDigest == nil || !IV.same(b["action_digest"]?.asString, actionDigest) {
            return fail("the question is about another action")
        }
        let bc: JSONValue? = b["cell"]
        guard let verb = lifted.get("verb")?.asString, let vs = omegaTilde.verb(verb), let mine = WalletOmegaMath.cellOf(vs, values: lifted.get("values")),
              IV.same(vs.verb, bc?.get("verb")?.asString) else { return fail("the wallet cannot place the action in \u{03A9}\u{0303}") }
        guard let theirs = cellFromCoords(vs, bc?.get("coords")), theirs.count == mine.count else { return fail("the site cell differs from the cell the wallet derives") }
        for k in 0..<theirs.count where theirs[k] != Double(mine[k]) { return fail("the site cell differs from the cell the wallet derives") }
        return .object(["ok": .bool(true), "vs": verbSpaceJSON(vs), "cell": ints(mine)])
    }

    // ---- delta grants ----

    private static func join(_ a: [Int]) -> String { a.map { String($0) }.joined(separator: ",") }

    /// Per verb, the cells the next learner's grant adds over the previous one's (both over the same space); verbs with no new cell are absent.
    public static func deltaCells(_ prev: PCAIntentLearner, _ next: PCAIntentLearner) -> [(verb: String, cells: [UInt8])] {
        var out: [(verb: String, cells: [UInt8])] = []
        var prevIn = Set<JKey>()
        for c in prev.cells() where c.inGrant { prevIn.insert(JKey(c.verb + "|" + join(c.cell))) }
        let nextCells = next.cells()
        for vs in next.omega.verbs {
            var a = [UInt8](repeating: 0, count: WalletOmegaMath.verbCellCount(vs))
            var anyNew = false
            for c in nextCells {
                if !IV.same(c.verb, vs.verb) || !c.inGrant || prevIn.contains(JKey(c.verb + "|" + join(c.cell))) { continue }
                a[PCAIntentLearner.encode(vs, c.cell)] = 1
                anyNew = true
            }
            if anyNew { out.append((vs.verb, a)) }
        }
        return out
    }

    /// The predicates of a delta (one maximal box per covered region, per verb).
    public static func deltaPredicates(_ omegaTilde: WalletOmega, _ delta: [(verb: String, cells: [UInt8])]) -> [JSONValue] {
        var out: [JSONValue] = []
        for vs in omegaTilde.verbs {
            guard let d = delta.first(where: { IV.same($0.verb, vs.verb) }) else { continue }
            out.append(contentsOf: PCAIntentLearner.boxesToPredicates(vs, d.cells))
        }
        return out
    }

    /// Mint D_k from the k-th answer: nil when the answer added no cell. `a`: holder, holderPq?, session, seq, prev?, root, mapDigest,
    /// mapForm?, caveats?, agentBinding?, riskPolicy?, salt?, and `prevGrant` (the previous session grant, JSON). Returns `{grant, goalSalt, cells}`.
    public static func mintDelta(_ prev: PCAIntentLearner, _ next: PCAIntentLearner, _ a: JSONValue, _ principal: PCASuiteKey) throws -> JSONValue? {
        let delta = deltaCells(prev, next)
        var cells: Int64 = 0
        for v in delta { for x in v.cells { cells += Int64(x) } }
        if cells == 0 { return nil }
        guard let prevGrant = a.get("prevGrant")?.asObject else { throw JSError("mintDelta: prevGrant must be an object") }
        if let p = a.get("prev"), !p.isNull, p != (prevGrant["id"] ?? .null) { throw JSError("mintDelta: prev must be the id of the previous session grant") }
        let preds: [JSONValue] = deltaPredicates(next.omega, delta)
        guard let holder = a.get("holder")?.asString, let session = a.get("session")?.asString, let root = a.get("root")?.asString,
              let mapDigest = a.get("mapDigest")?.asString, let seqD = IV.num(a.get("seq")), seqD.isFinite, abs(seqD) < 9e18 else {
            throw JSError("mintDelta: holder, session, seq, root and mapDigest are required")
        }
        let caveats: [JSONValue] = a.get("caveats")?.asArray ?? []
        let binding: JObject = a.get("agentBinding")?.asObject ?? [:]
        let risk: JObject? = a.get("riskPolicy")?.asObject
        let g = try PCASigners.mintSessionGrant(principal: principal, holder: holder, session: session, seq: Int64(seqD), root: root, mapDigest: mapDigest, predicates: preds,
                                                prev: prevGrant["id"]?.asString, mapForm: a.get("mapForm")?.asString, caveats: caveats, agentBinding: binding, riskPolicy: risk,
                                                salt: a.get("salt")?.asString, holderPqPk: a.get("holderPq")?.asString)
        return .object(["grant": g.grant, "goalSalt": .string(g.goalSalt), "cells": .double(Double(cells))])
    }
}
