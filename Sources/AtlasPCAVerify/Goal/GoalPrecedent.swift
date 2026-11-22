import Foundation

private func str(_ v: JSONValue?) -> String? { v?.asString }

/// `===` between two JSON values: strings by code point, numbers by value, booleans, null; objects and arrays are never identical.
private func strictEq(_ a: JSONValue?, _ b: JSONValue?) -> Bool {
    switch (a, b) {
    case (nil, nil): return true
    case let (.string(x)?, .string(y)?): return IV.same(x, y)
    case let (x?, y?):
        if let p = IV.num(x), let q = IV.num(y) { return p == q }
        if case .bool(let p) = x, case .bool(let q) = y { return p == q }
        if case .null = x, case .null = y { return true }
        return false
    default: return false
    }
}

private func ok(_ entry: JSONValue) -> JSONValue { GV.obj([("ok", .bool(true)), ("entry", entry)]) }
private func no(_ reason: String) -> JSONValue { GV.obj([("ok", .bool(false)), ("reason", .string(reason))]) }


/// Progressive authorization. Widening is only by an escalation request answered by a principal-signed answer; a verified answer
/// becomes an append-only hash-chained precedent bound to (policy digest, decision cell, the answered action's exact quantities
/// as a ceiling). A recorded cell decision is never flipped except by a principal-signed revocation; a deny is never turned into
/// an allow (precedents act only on escalate). Entries, answers and answered cases are parsed-JSON objects.
public enum PCAGoalPrecedent {
    private static func unitKey(_ q: JSONValue) throws -> String {
        guard let u = q.get("u"), u.asObject != nil else { throw JSError("a quantity needs a unit") }
        return JS.toString(u.get("k")) == "money" ? "money:" + JS.toString(u.get("ccy")) : JS.toString(u.get("k"))
    }

    /// Ceilings are keyed by parameter AND unit (kind + currency): a EUR answer never covers a GBP action.
    public static func ceilingsOf(_ params: JSONValue) throws -> JSONValue {
        guard let p = params.asObject else { throw JSError("params must be an object") }
        var out = JObject()
        for (k, v) in p where v.get("k")?.asString == "q" {
            guard let q = v.get("q"), q.asObject != nil else { throw JSError("a quantity value needs q") }
            if let n = q.get("n") { out[JKey(k.s + "|" + (try unitKey(q)))] = n }
        }
        return .object(out)
    }

    private static func caseOf(_ a: JSONValue) throws -> JSONValue {
        guard let act = a.get("pcactn")?.get("action"), act.asObject != nil else { throw JSError("answered case needs a pcactn action") }
        return GV.obj([("act", try PCAGoalExamples.mkAct(str(act.get("verb")), str(act.get("resource")), a.get("params"))), ("rels", a.get("rels") ?? .null)])
    }

    public static func signRevocation(_ p: JSONValue, _ seed: [UInt8]) throws -> JSONValue { try PCAGoalSign.signPayload("precedent-revocation", p, seed) }

    /// The answer body for a request: bound to the request's exact (policy, action, history head). Sign it with the escalation signer.
    public static func answerBodyFor(_ req: JSONValue, _ principal: String, _ decision: String, _ iat: JSONValue?, _ expiresAt: JSONValue?, _ nonce: String) -> JSONValue {
        var o = JObject()
        o["v"] = .int(1)
        o["kind"] = .string("pca-escalation-answer")
        o["principal"] = .string(principal)
        for k in ["policy_digest", "action_digest", "history_head"] { if let x = req.get(k) { o[JKey(k)] = x } }
        o["decision"] = .string(decision)
        if let x = iat { o["iat"] = x }
        if let x = expiresAt { o["expires_at"] = x }
        o["nonce"] = .string(nonce)
        return .object(o)
    }

    private static let GENESIS = String(repeating: "0", count: 64)

    private static func entryDigest(_ e: JObject) throws -> String {
        var answeredOut: JSONValue = .null
        if let answered = e["answered"], GV.truthy(answered) {
            guard var a = answered.asObject else { throw JSError("answered must be an object") }
            if a["lastCounter"] == nil { a["lastCounter"] = .null }
            answeredOut = .object(a)
        }
        var o = JObject()
        o["d"] = .string("atlas-pca/goal-precedent-entry/v1")
        for k in ["seq", "prev", "kind"] { if let x = e[JKey(k)] { o[JKey(k)] = x } }
        for k in ["answer", "cell", "ceilings", "revocation"] { o[JKey(k)] = e[JKey(k)] ?? .null }
        o["answered"] = answeredOut
        return Canonical.hashCanonical(.object(o))
    }


    /// The append-only precedent log of one verifier, which pins the principals allowed to answer and revoke
    /// (an array of base64url keys or {pk, pq_pk} objects).
    public final class Log {
        private let principals: JSONValue
        /// The entries in order (a test may tamper with one).
        public var entries: [JObject] = []

        public init(_ principals: JSONValue) { self.principals = principals }

        private func headValue() -> JSONValue { entries.last?["digest"] ?? (entries.isEmpty ? .string(PCAGoalPrecedent.GENESIS) : .null) }

        public func head() -> String { headValue().asString ?? "" }

        private func pinFor(_ pk: String) -> JSONValue? {
            for p in principals.asArray ?? [] {
                let key: JSONValue? = p.asString != nil ? p : p.get("pk")
                if let k = key?.asString, IV.same(k, pk) { return p }
            }
            return nil
        }

        private func escPrincipals() -> [PinnedSigner] {
            var out: [PinnedSigner] = []
            for p in principals.asArray ?? [] {
                if let s = p.asString { out.append(PinnedSigner(s)) }
                else if let pk = p.get("pk")?.asString { out.append(PinnedSigner(pk, pqPk: p.get("pq_pk")?.asString)) }
            }
            return out
        }

        /// Everything about an answer that does not depend on the clock. nil = sound.
        private func answerFault(_ answer: JSONValue, _ answered: JSONValue) throws -> String? {
            if PCA.escalationAnswerShapeError(answer) != nil { return "malformed answer" }
            guard let principal = str(answer.get("principal")), let pin = pinFor(principal), try PCAGoalSign.verifyArtifactSig(PCA.ESCALATION_ANSWER_DOMAIN, answer, pin) else { return "bad signature" }
            guard let pcactn = answered.get("pcactn"), let action = pcactn.get("action"), action.asObject != nil else { throw JSError("answered case needs a pcactn action") }
            if !strictEq(answer.get("action_digest"), PCA.escalationActionDigest(pcactn: pcactn).map { JSONValue.string($0) }) { return "answer is bound to another action" }
            var lc: Int64? = nil
            if let l = PCAGoalPrecedent.present(answered.get("lastCounter")) {
                guard let i = GV.safeInt(l) else { return "answer is bound to another history state" }
                lc = i
            }
            if !strictEq(answer.get("history_head"), PCA.escalationHistoryHead(lastCounter: lc).map { JSONValue.string($0) }) { return "answer is bound to another history state" }
            if !strictEq(.string(Merkle.paramsDigest(answered.get("params"))), action.get("params_digest")) { return "params do not match the signed action" }
            return nil
        }

        /// Recompute the whole chain, every signature and binding, and every derived cell and ceiling under `space`.
        public func verifyChain(_ space: PCAGoalExamples.Space) -> Bool {
            do {
                var prev = PCAGoalPrecedent.GENESIS
                for i in 0..<entries.count {
                    let e = entries[i]
                    guard IV.num(e["seq"]) == Double(i), strictEq(e["prev"], .string(prev)), strictEq(.string(try PCAGoalPrecedent.entryDigest(e)), e["digest"]) else { return false }
                    if strictEq(e["kind"], .string("answer")) {
                        guard let answer = e["answer"], answer.asObject != nil, let answered = e["answered"], answered.asObject != nil else { return false }
                        if try answerFault(answer, answered) != nil { return false }
                        let want = try PCAGoalExamples.cellKey(space, try PCAGoalPrecedent.caseOf(answered))
                        guard strictEq(e["cell"], .string(want)) else { return false }
                        let ceil = try PCAGoalPrecedent.ceilingsOf(answered.get("params") ?? .null)
                        if GV.stable(e["ceilings"]) != GV.stable(ceil) { return false }
                    } else {
                        guard let rev = e["revocation"], GV.truthy(rev), try PCAGoalSign.verifyPayload(rev, "precedent-revocation", principals) else { return false }
                    }
                    guard let d = e["digest"]?.asString else { return false }
                    prev = d
                }
                return true
            } catch {
                return false
            }
        }

        private func live(_ policy: JSONValue, _ cell: JSONValue, _ now: Double) throws -> JObject? {
            var revoked = Set<String>()
            for e in entries where strictEq(e["kind"], .string("revocation")) {
                guard let t = e["revocation"]?.get("payload")?.get("target_entry") else { throw JSError("revocation without a payload") }
                revoked.insert(GV.stable(t))
            }
            for e in entries.reversed() {
                guard strictEq(e["kind"], .string("answer")), let a = e["answer"] else { continue }
                guard let digest = e["digest"] else { continue }
                if strictEq(a.get("policy_digest"), policy) && strictEq(e["cell"], cell) && GV.toNum(a.get("expires_at")) > now && !revoked.contains(GV.stable(digest)) { return e }
            }
            return nil
        }

        /// Verify the answer (pinned signer, bound to this grant's policy digest, this exact action and history, unexpired) and record it: {ok, entry | reason}.
        public func append(_ answer: JSONValue, _ answered: JSONValue, _ grant: JSONValue, _ space: PCAGoalExamples.Space, _ now: Int64) throws -> JSONValue {
            let pcactn: JSONValue = answered.get("pcactn") ?? .null
            var lc: Int64? = nil
            if let l = PCAGoalPrecedent.present(answered.get("lastCounter")) {
                guard let i = GV.safeInt(l) else { throw JSError("lastCounter must be a safe integer") }
                lc = i
            }
            guard let pd = PCA.escalationPolicyDigest(grant: grant), let ad = PCA.escalationActionDigest(pcactn: pcactn), let hh = PCA.escalationHistoryHead(lastCounter: lc) else { throw JSError("a digest cannot be computed") }
            let v = PCA.verifyEscalationAnswer(answer, principals: escPrincipals(), bind: EscalationBinding(policyDigest: pd, actionDigest: ad, historyHead: hh), now: now)
            if !v.ok { return no(v.reason) }
            if let fault = try answerFault(answer, answered) { return no(fault) }
            let cell = try PCAGoalExamples.cellKey(space, try PCAGoalPrecedent.caseOf(answered))
            if let existing = try live(answer.get("policy_digest") ?? .null, .string(cell), Double(now)), !strictEq(existing["answer"]?.get("decision"), answer.get("decision")) {
                return no("conflicts with a recorded decision; revoke it first")
            }
            var f = JObject()
            f["kind"] = .string("answer")
            f["answer"] = answer
            f["answered"] = answered
            f["cell"] = .string(cell)
            f["ceilings"] = try PCAGoalPrecedent.ceilingsOf(answered.get("params") ?? .null)
            return ok(try push(f))
        }

        public func revoke(_ rev: JSONValue) throws -> JSONValue {
            if !(try PCAGoalSign.verifyPayload(rev, "precedent-revocation", principals)) { return no("bad signature") }
            guard let p = rev.get("payload"), p.asObject != nil else { throw JSError("revocation without a payload") }
            var found = false
            for e in entries where strictEq(e["kind"], .string("answer")) && strictEq(e["digest"], p.get("target_entry")) && strictEq(e["answer"]?.get("policy_digest"), p.get("policy_digest")) && strictEq(e["cell"], p.get("cell")) {
                found = true
            }
            if !found { return no("no such precedent") }
            var f = JObject()
            f["kind"] = .string("revocation")
            f["revocation"] = rev
            return ok(try push(f))
        }

        private func push(_ fields: JObject) throws -> JSONValue {
            var base = JObject()
            base["seq"] = .int(Int64(entries.count))
            base["prev"] = headValue()
            for (k, v) in fields { base[k] = v }
            var entry = base
            entry["digest"] = .string(try PCAGoalPrecedent.entryDigest(base))
            entries.append(entry)
            return .object(entry)
        }

        /// The recorded decision covering this case under this policy, or nil: {decision, entry}.
        public func lookup(_ policyDigest: String, _ space: PCAGoalExamples.Space, _ c: JSONValue, _ now: Double) throws -> JSONValue? {
            guard let e = try live(.string(policyDigest), .string(try PCAGoalExamples.cellKey(space, c)), now) else { return nil }
            guard let ceil = e["ceilings"]?.asObject, let params = c.get("act")?.get("params") else { throw JSError("a precedent needs ceilings and the case params") }
            let now2 = try PCAGoalPrecedent.ceilingsOf(params).asObject ?? [:]
            for (k, value) in now2 {
                let limit: Double = ceil[k].map { JS.toNumber($0) } ?? -Double.infinity
                if JS.toNumber(value) > limit { return nil }
            }
            for k in ceil.keys where now2[k] == nil { return nil }
            return GV.obj([("decision", e["answer"]?.get("decision") ?? .null), ("entry", .object(e))])
        }
    }

    private static func present(_ v: JSONValue?) -> JSONValue? { (v == nil || v == .null) ? nil : v }

    /// Policy decision refined by precedents: {decision, via, precedent?}. Precedents act only on escalate; a recorded deny also tightens.
    public static func authorizeWithPrecedents(_ goal: JSONValue, _ ont: JSONValue, _ policyDigest: String, _ log: Log, _ c: JSONValue, _ now: Double) throws -> JSONValue {
        guard let base = try PCAGoalExamples.decideCase(goal, ont, c).get("decision")?.asString else { throw JSError("decideCase gave no decision") }
        if base != "escalate" { return GV.obj([("decision", .string(base)), ("via", .string("policy"))]) }
        let space = try PCAGoalExamples.buildSpace([goal], [])
        if !log.verifyChain(space) { return GV.obj([("decision", .string("escalate")), ("via", .string("policy"))]) }
        guard let hit = try log.lookup(policyDigest, space, c, now) else { return GV.obj([("decision", .string("escalate")), ("via", .string("policy"))]) }
        return GV.obj([("decision", .string(hit.get("decision")?.asString == "allow" ? "allow" : "deny")), ("via", .string("precedent")), ("precedent", hit.get("entry") ?? .null)])
    }
}
