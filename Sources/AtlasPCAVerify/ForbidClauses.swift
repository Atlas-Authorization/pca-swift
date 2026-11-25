import Foundation

// Forbid-wins clause decisions and certificates: a port of `decideClauses`, `certify`, `clausesError` and `checkForbidCertificate` of
// `forbid-certificate.ts` (the TypeScript is authoritative). The certificate table check itself is `PCA.forbidCertificateConsistent`.
//
// A policy is a list of clauses `{id, kind: permit|forbid|escalate, signer?, when}`. Any matched forbid denies (the most authoritative signer's is
// named, ties by id), otherwise no matched permit denies, otherwise a matched escalate escalates, otherwise allow. A forbid / escalate clause is
// read with veto polarity (`Prohibitions.whenMatches`): a clause that cannot be decided still counts as matched (`unknown`).

/// The decision a clause list forces.
public struct ClauseDecision: Sendable {
    /// `allow`, `escalate` or `deny`.
    public let decision: String
    /// `permit`, `forbid`, `escalate`, `none` or `malformed`.
    public let winnerKind: String
    public let winnerId: String?
    /// Ids of every other clause that also matched.
    public let shadowed: [String]
    /// Per clause, in policy order: `{id, kind, value: true|false|unknown}`.
    public let values: [JSONValue]

    var winner: JSONValue { .object(["kind": .string(winnerKind), "id": winnerId.map { .string($0) } ?? .null]) }
    public var json: JSONValue {
        .object(["decision": .string(decision), "winner": winner, "shadowed": PD.strs(shadowed), "values": .array(values)])
    }
}

public enum ForbidClauses {
    /// Most clauses one policy may carry.
    public static let MAX_CLAUSES = 512
    static let KINDS = ["permit", "forbid", "escalate"]

    /// nil = the clause list is well formed (distinct ids, known kinds, a predicate for each).
    public static func clausesError(_ clauses: JSONValue?) -> String? {
        guard case let .array(a)? = clauses else { return "clauses must be an array" }
        if a.count > MAX_CLAUSES { return "more than \(MAX_CLAUSES) clauses" }
        var seen = Set<JKey>()
        for (i, cv) in a.enumerated() {
            guard case let .object(c) = cv else { return "clauses[\(i)] must be an object" }
            guard case let .string(id)? = c["id"], !id.isEmpty, IV.u16(id) <= 128 else { return "clauses[\(i)].id must be a string of 1..128 characters" }
            if seen.contains(JKey(id)) { return "clauses[\(i)].id '\(id)' is a duplicate" }
            seen.insert(JKey(id))
            guard case let .string(kind)? = c["kind"], KINDS.contains(where: { IV.same($0, kind) }) else { return "clauses[\(i)].kind must be permit, forbid or escalate" }
            if let s = c["signer"] {
                guard case let .string(ss) = s, IV.u16(ss) <= 256 else { return "clauses[\(i)].signer must be a string of at most 256 characters" }
            }
            if !PD.isObj(c["when"]) { return "clauses[\(i)].when must be a predicate object" }
        }
        return nil
    }

    static func valueOf(_ c: JObject, _ ctx: JSONValue) -> String {
        let when = c["when"] ?? .null
        if c["kind"]?.asString == "permit" { return Predicates.predicateMatches(when, ctx, SafeRegex.Budget()) ? "true" : "false" }
        // veto polarity: a clean match is true; cannot-decide-but-the-veto-applies is unknown; a clean miss is false
        if !Prohibitions.whenMatches(when, ctx) { return "false" }
        return Predicates.predicateMatches(when, ctx, SafeRegex.Budget()) ? "true" : "unknown"
    }

    static func rank(_ signer: String?, _ precedence: [String]) -> Int {
        guard let s = signer, let i = precedence.firstIndex(where: { IV.same($0, s) }) else { return precedence.count } // an unlisted signer ranks last
        return i
    }

    static func malformed() -> ClauseDecision { ClauseDecision(decision: "deny", winnerKind: "malformed", winnerId: nil, shadowed: [], values: []) }

    static func utf16Less(_ a: String, _ b: String) -> Bool { a.utf16.lexicographicallyPrecedes(b.utf16) }

    /// Decide a clause list against an action context `{action, subject?, env?}`. Order-independent for the decision; the named winner is
    /// deterministic. `permitSigners`, when given, drops permits from any other signer. Total: a malformed policy or action is a deny naming
    /// `malformed`.
    public static func decideClauses(_ clauses: JSONValue?, _ ctx: JSONValue?, precedence: [String] = [], permitSigners: [String]? = nil) -> ClauseDecision {
        if clausesError(clauses) != nil { return malformed() }
        guard case let .array(list)? = clauses, let c = ctx, let a = c.get("action"), a.get("verb")?.asString != nil, a.get("resource")?.asString != nil else { return malformed() }
        let objs: [JObject] = list.map { $0.asObject ?? [:] }
        var values: [JSONValue] = []
        var vals: [String] = []
        for o in objs {
            let isPermit = o["kind"]?.asString == "permit"
            var signerOk = false
            if let s = o["signer"]?.asString, let ps = permitSigners { signerOk = ps.contains { IV.same($0, s) } }
            let active = !isPermit || permitSigners == nil || signerOk
            let v = active ? valueOf(o, c) : "false"
            vals.append(v)
            values.append(.object(["id": o["id"] ?? .null, "kind": o["kind"] ?? .null, "value": .string(v)]))
        }
        func hit(_ k: String) -> [Int] { objs.indices.filter { objs[$0]["kind"]?.asString == k && vals[$0] != "false" } }
        func id(_ i: Int) -> String { objs[i]["id"]?.asString ?? "" }
        let forbids = hit("forbid").sorted { x, y in
            let rx = rank(objs[x]["signer"]?.asString, precedence), ry = rank(objs[y]["signer"]?.asString, precedence)
            return rx != ry ? rx < ry : utf16Less(id(x), id(y))
        }
        let permits = hit("permit"), escalates = hit("escalate")
        func others(_ win: Int?) -> [String] { (forbids + permits + escalates).filter { $0 != win }.map(id) }
        if let w = forbids.first { return ClauseDecision(decision: "deny", winnerKind: "forbid", winnerId: id(w), shadowed: others(w), values: values) }
        if permits.isEmpty { return ClauseDecision(decision: "deny", winnerKind: "none", winnerId: nil, shadowed: others(nil), values: values) }
        if let w = escalates.first { return ClauseDecision(decision: "escalate", winnerKind: "escalate", winnerId: id(w), shadowed: others(w), values: values) }
        let w = permits[0]
        return ClauseDecision(decision: "allow", winnerKind: "permit", winnerId: id(w), shadowed: others(w), values: values)
    }

    /// The canonical certificate for a decision. Throws where the reference throws (an action context outside the strict profile).
    public static func certify(_ clauses: JSONValue?, _ ctx: JSONValue?, precedence: [String] = [], permitSigners: [String]? = nil) throws -> JSONValue {
        let d = decideClauses(clauses, ctx, precedence: precedence, permitSigners: permitSigners)
        guard let cl = clauses, case let .array(list) = cl, let cx = ctx else { throw PDFail(what: "clauses") }
        var byId: [JKey: JObject] = [:]
        for c in list { if let o = c.asObject, let id = o["id"]?.asString { byId[JKey(id)] = o } }
        let rows: [JSONValue] = d.values.map { v in
            var row: JObject = ["id": v.get("id") ?? .null, "kind": v.get("kind") ?? .null]
            if let id = v.get("id")?.asString, let s = byId[JKey(id)]?["signer"] { row["signer"] = s }
            row["value"] = v.get("value") ?? .null
            return .object(row)
        }
        return .object(["v": .int(1), "kind": .string("forbid-wins"), "policy": .string(try PD.hash(cl)), "action": .string(try PD.hash(cx)), "decision": .string(d.decision),
                        "winner": d.winner, "shadowed": PD.strs(d.shadowed), "clauses": .array(rows)])
    }

    /// Recompute the certificate from the clauses and the action; it must match byte for byte (canonical form).
    public static func checkForbidCertificate(_ cert: JSONValue?, _ clauses: JSONValue?, _ ctx: JSONValue?, precedence: [String] = [], permitSigners: [String]? = nil) -> ProhibitionVerdict {
        if clausesError(clauses) != nil { return .no("malformed clauses") }
        if !PCA.forbidCertificateConsistent(cert ?? .null, precedence: precedence) { return .no("certificate table does not entail its decision") }
        do {
            let again = try certify(clauses, ctx, precedence: precedence, permitSigners: permitSigners)
            guard let c = cert, try PD.hash(again) == PD.hash(c) else { return .no("certificate does not match the recomputed decision") }
            return .pass
        } catch {
            return .no("certificate check error (fail closed)")
        }
    }
}
