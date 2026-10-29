import Foundation

// PROVENANCE BY DEFAULT (0.5): an agent cannot be steered by injected content into choosing who, where or how much. A port of
// the TypeScript reference (`arg-provenance.ts`); the decision, its codes and its escalate reasons are shared through
// conformance/arg-provenance-vectors.json.
//
// A MEDIATOR (the agent harness, a gateway, an MCP client: whatever sees bytes enter the model's context and holds a key the model
// cannot reach) appends one signed receipt per context segment to a per-session hash chain: the principal's own message
// (`principal`), a tool result (`tool`), a retrieved document (`retrieval`), a fetched page (`web`), and finally the action the
// model chose (`action`, bound to the exact operation digest). The verifier re-derives every label from that chain; nothing the
// agent writes can lower one. An action is SENSITIVE unless its facts say it only reads; a sensitive action whose choice or any
// sink argument does not derive from the principal is `escalate`. A forged or malformed chain is `deny`.
//
// Not to be confused with the K9 build-provenance gate (`ProvenanceGate.swift`) or Intent v2 rule 17 (check `provenance`): this is
// check `provenance_flow`. Every function here is pure and total; malformed input fails closed.

/// The outcome of `PCA.decideArgProvenance`.
public struct ArgProvenanceDecision: Equatable, Sendable {
    /// `pass`, `escalate` (the principal must confirm) or `deny` (forged or malformed provenance).
    public var outcome: String
    public var code: String?
    public var reason: String?
    public var sensitive: Bool
    /// True when a bundle verified under a pinned mediator.
    public var verified: Bool
    /// The label of the action choice.
    public var control: String
    /// The label of every top-level parameter (name -> level).
    public var labels: JObject
    /// Sink parameters whose label is above their floor (UTF-8 order).
    public var tainted: [String]
    /// Where untrusted content came from: `origin:source`, plus `unlabelled` without a verified chain (UTF-8 order).
    public var path: [String]

    /// The decision as the reference serialises it (absent `code` / `reason` are omitted).
    public var json: JSONValue {
        var o: JObject = ["outcome": .string(outcome), "sensitive": .bool(sensitive), "verified": .bool(verified), "control": .string(control),
                          "labels": .object(labels), "tainted": .array(tainted.map { .string($0) }), "path": .array(path.map { .string($0) })]
        if let c = code { o["code"] = .string(c) }
        if let r = reason { o["reason"] = .string(r) }
        return .object(o)
    }
}

/// The inputs of `PCA.decideArgProvenance`, as JSON values so malformed input is judged, never a build error.
public struct ArgProvenanceInput {
    /// The presented bundle; nil or JSON null = none.
    public var bundle: JSONValue?
    /// `{verb, resource, params}`: the operation about to run.
    public var operation: JSONValue
    /// Pinned mediator keys, a list of `{mediator, kid, pk, pq_pk?}`.
    public var mediators: JSONValue
    /// The action's facts `{effects?, traits?, params?}`; nil = unknown action (sensitive).
    public var action: JSONValue?
    /// The principal authorized this exact operation (a node of an executable, principal-authorized plan).
    public var principalPlan: Bool
    /// The principal committed to this step (an admitted workflow step): the CHOICE is trusted, the values are not.
    public var principalControl: Bool
    /// Untrusted content the SERVER saw reach this agent's context, a list of `{origin: tool|retrieval|web, source}` (raise only).
    public var observed: JSONValue?

    public init(bundle: JSONValue?, operation: JSONValue, mediators: JSONValue, action: JSONValue? = nil, principalPlan: Bool = false,
                principalControl: Bool = false, observed: JSONValue? = nil) {
        self.bundle = bundle
        self.operation = operation
        self.mediators = mediators
        self.action = action
        self.principalPlan = principalPlan
        self.principalControl = principalControl
        self.observed = observed
    }
}

/// The provenance gate's configuration in `PCA.authorize` (the gate itself is always on; the grant's signed envelope member
/// `provenance: {mode: "insecure_off"}` is the only opt-out).
public struct ArgProvenanceOptions {
    /// Pinned mediator keys `{mediator, kid, pk, pq_pk?}` (the grant envelope's `provenance.mediators` are added to them).
    public var mediators: [JSONValue]
    /// The facts `{effects?, traits?, params?}` of the action about to run, from YOUR action definitions; nil = unknown (sensitive).
    public var actions: ((PCA.Operation) -> JSONValue?)?
    /// Untrusted content THIS server saw reach the agent's context: `(pcactn, operation, bundle session) -> [{origin, source}]`.
    public var observed: ((JSONValue, PCA.Operation, String?) -> [JSONValue])?

    public init(mediators: [JSONValue] = [], actions: ((PCA.Operation) -> JSONValue?)? = nil,
                observed: ((JSONValue, PCA.Operation, String?) -> [JSONValue])? = nil) {
        self.mediators = mediators
        self.actions = actions
        self.observed = observed
    }
}

extension PCA {
    public static let PROV_RECEIPT_DOMAIN = "atlas-pca/prov-receipt/v1\u{0}"
    public static let PROV_RECEIPT_REF_DOMAIN = "atlas-pca/prov-receipt-ref/v1"
    public static let PROV_ACTION_DOMAIN = "atlas-pca/prov-action/v1"
    /// Request header carrying a bundle (base64url of its JSON). The body member is `pca_provenance`.
    public static let PROV_HEADER = "PCA-Provenance"
    public static let MAX_PROV_RECEIPTS = 256
    /// Largest principal message a bundle may carry (UTF-8 bytes).
    public static let MAX_PROV_CONTENT_BYTES = 65_536
    /// Leaves examined per parameter; a larger value is not examined and keeps the context label.
    public static let MAX_PROV_LEAVES = 4096
    static let MAX_PROV_DEPTH = 32
    public static let PROV_ORIGINS = ["principal", "tool", "retrieval", "web", "action"]
    /// Traits a read-only action may carry and still be non-sensitive.
    public static let READ_SAFE_TRAITS = ["pca.financial_data_read", "pca.pii_access", "pca.regulated_data"]
    static let PROV_FLOORS = ["first_party", "tool", "agent"]

    // the label lattice is the taint lattice of rule 17: trusted < first_party < tool < web < agent
    static func provJoin(_ a: String, _ b: String) -> String { IntentWB.rank(a) >= IntentWB.rank(b) ? a : b }
    static func originLevel(_ o: String) -> String {
        switch o {
        case "principal": return "trusted"
        case "tool", "retrieval": return "tool"
        case "web": return "web"
        default: return "agent"
        }
    }
    static func sortU(_ xs: [String]) -> [String] {
        var seen = Set<JKey>()
        return xs.filter { seen.insert(JKey($0)).inserted }.sorted(by: IV.utf8Less)
    }

    /// The digest an `action` receipt binds: the exact operation (verb, resource, params). nil outside the strict JSON profile.
    public static func provActionDigest(verb: String, resource: String, params: JSONValue) -> String? {
        IV.strictHash(.object(["d": .string(PROV_ACTION_DOMAIN), "verb": .string(verb), "resource": .string(resource), "params": params]))
    }

    /// Content address of a receipt (signature included).
    public static func provReceiptRef(_ r: JSONValue) -> String? { IntentWB.artifactRef(PROV_RECEIPT_REF_DOMAIN, "r", r) }

    /// Is `k` a well-formed mediator pin `{mediator, kid, pk, pq_pk?}`?
    public static func isProvMediatorPin(_ k: JSONValue) -> Bool {
        guard case let .object(o) = k, IntentWB.closedMembers(o, ["mediator", "kid", "pk"], ["pq_pk"]) else { return false }
        return IV.bounded(o["mediator"], 256) != nil && IV.bounded(o["kid"], 64) != nil && IV.digest(o["pk"]) != nil && IntentWB.pinPqOk(o["pq_pk"])
    }

    /// Wire validation of one receipt. nil = well-formed.
    public static func provReceiptWireError(_ rv: JSONValue) -> String? {
        guard case let .object(r) = rv else { return "a receipt must be an object" }
        if let m = IntentWB.closedMembersError(r, ["v", "kind", "mediator", "kid", "session", "seq", "prev", "origin", "source", "content_digest", "issued_at", "sig"],
                                               IntentWB.SUITE_MEMBERS, "receipt") { return m }
        if IV.num(r["v"]) != 1 || !IV.same(r["kind"]?.asString, "pca-prov") { return "a receipt must be {v: 1, kind: \"pca-prov\"}" }
        if IV.bounded(r["mediator"], 256) == nil { return "'mediator' must be a non-empty string (<= 256 bytes)" }
        if IV.bounded(r["kid"], 64) == nil { return "'kid' must be a non-empty string (<= 64 bytes)" }
        if IV.digest(r["session"]) == nil { return "'session' must be canonical base64url (32 bytes)" }
        if IV.nonNeg(r["seq"]) == nil { return "'seq' must be a non-negative safe integer" }
        if r["prev"] != .null && IV.digest(r["prev"]) == nil { return "'prev' must be null or canonical base64url (32 bytes)" }
        guard let origin = r["origin"]?.asString, IV.contains(PROV_ORIGINS, origin) else { return "'origin' must be one of \(PROV_ORIGINS.joined(separator: ", "))" }
        if IV.bounded(r["source"], 256) == nil { return "'source' must be a non-empty string (<= 256 bytes)" }
        if IV.digest(r["content_digest"]) == nil { return "'content_digest' must be canonical base64url (32 bytes)" }
        if IV.nonNeg(r["issued_at"]) == nil { return "'issued_at' must be a non-negative safe integer" }
        if r["sig"]?.asString == nil { return "'sig' must be a string" }
        return IntentWB.artifactSuiteError(r)
    }

    /// Validate action facts `{effects?, traits?, params?}`. nil = well-formed.
    public static func provActionInfoError(_ av: JSONValue) -> String? {
        guard case let .object(a) = av else { return "action info must be an object" }
        if let m = IntentWB.closedMembersError(a, [], ["effects", "traits", "params"], "action info") { return m }
        for k in ["effects", "traits"] {
            guard let v = a[JKey(k)] else { continue }
            guard case let .array(xs) = v, xs.count <= 64, xs.allSatisfy({ IV.bounded($0, 128) != nil }) else { return "action info '\(k)' must be a list of strings" }
        }
        if let pv = a["params"] {
            guard case let .object(ps) = pv else { return "action info 'params' must be an object" }
            for k in ps.keys.sorted() where IV.bounded(.string(k.s), 128) == nil || !(ps[k]?.asString.map { IV.contains(PROV_FLOORS, $0) } ?? false) {
                return "action info param '\(k.s)' must map to first_party | tool | agent"
            }
        }
        return nil
    }

    /// Is an action with these facts non-sensitive (it only reads)? Unknown (nil or JSON null) facts are sensitive.
    public static func isReadOnlyAction(_ av: JSONValue?) -> Bool {
        guard case let .object(a)? = av, case let .array(effects)? = a["effects"], !effects.isEmpty else { return false }
        if !effects.allSatisfy({ IV.same($0.asString, "read") }) { return false }
        guard let tv = a["traits"] else { return true }
        guard case let .array(traits) = tv else { return false }
        return traits.allSatisfy { t in t.asString.map { IV.contains(READ_SAFE_TRAITS, $0) } ?? false }
    }

    // ---- tokens ----

    /// Word characters for token boundaries: ASCII letters, digits, `_`, and every non-ASCII code unit (fail closed: fewer matches).
    static func isWordUnit(_ c: UInt16) -> Bool { (c >= 48 && c <= 57) || (c >= 65 && c <= 90) || (c >= 97 && c <= 122) || c == 95 || c >= 0x80 }

    /// Does `needle` occur in `text` as a whole token? Exact, case-sensitive, scanned over UTF-16 code units like the reference (no
    /// normalization): an occurrence counts when the unit before it is not a word character (or the needle starts with a non-word
    /// character), and likewise after it. An empty needle never occurs.
    public static func occursAsToken(_ text: String, _ needle: String) -> Bool {
        let t = Array(text.utf16), n = Array(needle.utf16)
        guard !n.isEmpty, n.count <= t.count else { return false }
        let headWord = isWordUnit(n[0]), tailWord = isWordUnit(n[n.count - 1])
        for i in 0...(t.count - n.count) where t[i] == n[0] && t[i..<(i + n.count)].elementsEqual(n) {
            let end = i + n.count
            let okB = !headWord || i == 0 || !isWordUnit(t[i - 1])
            let okA = !tailWord || end == t.count || !isWordUnit(t[end])
            if okB && okA { return true }
        }
        return false
    }

    /// The text of every leaf of a value (strings as is, other scalars in strict canonical form, object keys included); nil when
    /// deeper than 32, over 4096 leaves, or not strict-canonical. Object members are walked in UTF-8 key order (a parsed object keeps
    /// no member order here; the decision only reads membership).
    public static func provLeaves(_ v: JSONValue) -> [String]? {
        var out: [String] = []
        func walk(_ x: JSONValue, _ depth: Int) -> Bool {
            if depth > MAX_PROV_DEPTH || out.count > MAX_PROV_LEAVES { return false }
            switch x {
            case let .string(s): out.append(s)
            case let .array(a):
                for y in a where !walk(y, depth + 1) { return false }
            case let .object(o):
                for k in o.keys.sorted() {
                    out.append(k.s)
                    if !walk(o[k] ?? .null, depth + 1) { return false }
                }
            default:
                guard let c = IV.strictCanon(x) else { return false }
                out.append(c)
            }
            return out.count <= MAX_PROV_LEAVES
        }
        return walk(v, 0) ? out : nil
    }

    // ---- the decision ----

    struct ProvChain {
        var verified: Bool
        var context: String
        var path: [String]
        var principalTexts: [String]
        static let unverified = ProvChain(verified: false, context: "agent", path: ["unlabelled"], principalTexts: [])
    }

    static let CONTENT_KEY_MAX_DIGITS = 9

    /// `^(0|[1-9][0-9]{0,8})$` as an index.
    static func contentIndex(_ k: String) -> Int? {
        let u = Array(k.utf8)
        guard !u.isEmpty, u.count <= CONTENT_KEY_MAX_DIGITS, u.allSatisfy({ $0 >= 48 && $0 <= 57 }), u.count == 1 || u[0] != 48 else { return nil }
        return Int(k)
    }

    /// Verify a bundle against the pins and the operation: the chain, or a deny `(code, reason)`.
    static func verifyProvChain(_ bundle: JSONValue?, verb: String, resource: String, params: JSONValue, pins: [JObject]) -> Swift.Result<ProvChain, ProvDeny> {
        guard let bv = bundle, bv != .null else { return .success(.unverified) }
        func bad(_ code: String, _ reason: String) -> Swift.Result<ProvChain, ProvDeny> { .failure(ProvDeny(code: code, reason: reason)) }
        guard case let .object(b) = bv else { return bad("malformed_bundle", "the bundle must be an object") }
        if let m = IntentWB.closedMembersError(b, ["v", "kind", "receipts"], ["contents"], "bundle") { return bad("malformed_bundle", m) }
        if IV.num(b["v"]) != 1 || !IV.same(b["kind"]?.asString, "pca-provenance") { return bad("malformed_bundle", "the bundle must be {v: 1, kind: \"pca-provenance\"}") }
        guard case let .array(rs)? = b["receipts"], !rs.isEmpty, rs.count <= MAX_PROV_RECEIPTS else {
            return bad("malformed_bundle", "the bundle must hold 1..\(MAX_PROV_RECEIPTS) receipts")
        }
        for (i, r) in rs.enumerated() { if let e = provReceiptWireError(r) { return bad("malformed_bundle", "receipt \(i): \(e)") } }
        var contents: JObject = [:]
        if let cv = b["contents"] {
            guard case let .object(c) = cv else { return bad("malformed_bundle", "'contents' must be an object") }
            contents = c
        }
        let receipts = rs.compactMap { $0.asObject }
        let first = receipts[0]
        for (i, r) in receipts.enumerated() {
            if IV.num(r["seq"]) != Double(i) { return bad("broken_chain", "receipt \(i) has seq \(IntentWB.jsOpt(r["seq"]))") }
            if !IV.same(r["session"]?.asString, first["session"]?.asString) || !IV.same(r["mediator"]?.asString, first["mediator"]?.asString)
                || !IV.same(r["kid"]?.asString, first["kid"]?.asString) {
                return bad("broken_chain", "receipt \(i) belongs to another session or mediator")
            }
            if i == 0 {
                if r["prev"] != .null { return bad("broken_chain", "receipt \(i) does not link to its predecessor") }
            } else {
                guard let ref = provReceiptRef(rs[i - 1]) else { return bad("malformed_config", "evaluation error (fail closed): a receipt is outside the strict JSON profile") }
                if !IV.same(r["prev"]?.asString, ref) { return bad("broken_chain", "receipt \(i) does not link to its predecessor") }
                if (IV.num(r["issued_at"]) ?? -1) < (IV.num(receipts[i - 1]["issued_at"]) ?? -1) { return bad("broken_chain", "receipt \(i) is older than its predecessor") }
            }
        }
        let last = receipts[receipts.count - 1]
        guard let opDigest = provActionDigest(verb: verb, resource: resource, params: params) else {
            return bad("malformed_config", "evaluation error (fail closed): the operation is outside the strict JSON profile")
        }
        if !IV.same(last["origin"]?.asString, "action") || !IV.same(last["source"]?.asString, verb) || !IV.same(last["content_digest"]?.asString, opDigest) {
            return bad("unbound_action", "the last receipt is not the action receipt of this operation")
        }
        for k in contents.keys.sorted() {
            let idx = contentIndex(k.s)
            guard let i = idx, i < receipts.count, IV.same(receipts[i]["origin"]?.asString, "principal") else {
                return bad("malformed_bundle", "contents '\(k.s)' does not name a principal receipt")
            }
            guard let text = contents[k]?.asString, IV.u8(text) <= MAX_PROV_CONTENT_BYTES else {
                return bad("malformed_bundle", "contents '\(k.s)' must be a string of at most \(MAX_PROV_CONTENT_BYTES) bytes")
            }
            guard let d = IV.strictHash(.string(text)) else { return bad("content_mismatch", "contents '\(k.s)' is not canonical text") }
            if !IV.same(d, receipts[i]["content_digest"]?.asString ?? "") { return bad("content_mismatch", "contents '\(k.s)' does not hash to its receipt") }
        }
        // a chain from a mediator this verifier does not pin vouches for nothing: every value stays at the top (escalate, never allow)
        guard let pin = pins.first(where: { IV.same($0["mediator"]?.asString, first["mediator"]?.asString) && IV.same($0["kid"]?.asString, first["kid"]?.asString) }),
              let pk = pin["pk"]?.asString else { return .success(.unverified) }
        for (i, r) in receipts.enumerated() where !IntentWB.verifyArtifactSig(PROV_RECEIPT_DOMAIN, r, pk, pqPin: pin["pq_pk"]?.asString) {
            return bad("bad_signature", "receipt \(i) does not verify under the pinned mediator key")
        }
        let before = receipts.dropLast().filter { !IV.same($0["origin"]?.asString, "action") }
        var context = before.isEmpty ? "agent" : "trusted"
        var path: [String] = []
        for r in before {
            let origin = r["origin"]?.asString ?? ""
            context = provJoin(context, originLevel(origin))
            if !IV.same(origin, "principal") { path.append("\(origin):\(r["source"]?.asString ?? "")") }
        }
        if before.isEmpty { path.append("unlabelled") }
        return .success(ProvChain(verified: true, context: context, path: sortU(path), principalTexts: contents.values.compactMap { $0.asString }))
    }

    struct ProvDeny: Error {
        let code: String
        let reason: String
    }

    /// The provenance decision for one operation. Steps, first failure wins:
    ///   0. inputs: pins, operation and action facts well-formed, else `deny` (malformed_config / malformed_operation / malformed_action);
    ///   1. the bundle (when present): wire, chain (contiguous seq, prev links, one session and mediator, non-decreasing issued_at),
    ///      the last receipt is the `action` receipt of this operation, every principal content hashes to its receipt, every
    ///      signature verifies under the pinned (mediator, kid). A failure is `deny`; an unpinned mediator is ignored (no trust);
    ///   2. server observations join into the context (raise only);
    ///   3. control = `trusted` with principalPlan or principalControl, else the context;
    ///   4. each top-level parameter: `trusted` with principalPlan; else the join over its leaves (a leaf is `trusted` when the
    ///      context is, or when it occurs as a token in a verified principal content); no leaves = `trusted`; too large = the context;
    ///   5. floors: the facts' `params[p]`, else `first_party` for a sensitive action and `agent` otherwise; above the floor = tainted;
    ///   6. a sensitive action whose control is not `trusted`, or any tainted parameter, is `escalate`; otherwise `pass`.
    public static func decideArgProvenance(_ input: ArgProvenanceInput) -> ArgProvenanceDecision {
        var base = ArgProvenanceDecision(outcome: "deny", code: nil, reason: nil, sensitive: true, verified: false, control: "agent", labels: [:], tainted: [], path: [])
        func deny(_ code: String, _ reason: String) -> ArgProvenanceDecision {
            var d = base
            d.outcome = "deny"
            d.code = code
            d.reason = reason
            return d
        }
        guard case let .array(pinList) = input.mediators, pinList.allSatisfy(isProvMediatorPin) else {
            return deny("malformed_config", "mediator pins must be a list of {mediator, kid, pk, pq_pk?}")
        }
        guard case let .object(op) = input.operation, let verb = IV.bounded(op["verb"], 256), let resource = op["resource"]?.asString,
              let params = op["params"], case let .object(po) = params else {
            return deny("malformed_operation", "the operation needs a verb, a resource and a params object")
        }
        if let a = input.action, let e = provActionInfoError(a) { return deny("malformed_action", e) }
        var obs: [JObject] = []
        if let ov = input.observed {
            guard case let .array(list) = ov else { return deny("malformed_config", "observations must be a list of {origin, source}") }
            for o in list {
                guard case let .object(x) = o, let origin = x["origin"]?.asString, IV.contains(["tool", "retrieval", "web"], origin),
                      IV.bounded(x["source"], 256) != nil else { return deny("malformed_config", "observations must be a list of {origin, source}") }
                obs.append(x)
            }
        }
        let sensitive = !isReadOnlyAction(input.action)
        base.sensitive = sensitive
        let ch: ProvChain
        switch verifyProvChain(input.bundle, verb: verb, resource: resource, params: params, pins: pinList.compactMap { $0.asObject }) {
        case let .failure(d): return deny(d.code, d.reason)
        case let .success(c): ch = c
        }
        base.verified = ch.verified
        var context = ch.context
        var path = ch.path
        for o in obs {
            let origin = o["origin"]?.asString ?? ""
            context = provJoin(context, originLevel(origin))
            path.append("\(origin):\(o["source"]?.asString ?? "")")
        }
        base.path = sortU(path)
        let plan = input.principalPlan
        let control = plan || input.principalControl ? "trusted" : context
        base.control = control
        var labels: [(String, String)] = []
        for k in po.keys.sorted() {
            if plan {
                labels.append((k.s, "trusted"))
                continue
            }
            guard let leaves = provLeaves(po[k] ?? .null) else {
                labels.append((k.s, context))
                continue
            }
            var l = "trusted"
            for leaf in leaves {
                // a leaf the principal typed verbatim is the principal's choice whatever else the context held
                let lv = context == "trusted" || ch.principalTexts.contains(where: { occursAsToken($0, leaf) }) ? "trusted" : context
                l = provJoin(l, lv)
            }
            labels.append((k.s, l))
        }
        var lo: JObject = [:]
        for (k, l) in labels { lo[JKey(k)] = .string(l) }
        base.labels = lo
        let floors = input.action?.get("params")?.asObject ?? [:]
        var tainted: [String] = []
        for (p, l) in labels {
            let f = floors[JKey(p)]?.asString ?? (sensitive ? "first_party" : "agent")
            if IntentWB.rank(l) > IntentWB.rank(f) { tainted.append(p) }
        }
        base.tainted = sortU(tainted)
        // no segment origin maps to first_party, so a control label is trusted or untrusted
        let badControl = sensitive && control != "trusted"
        if !badControl && base.tainted.isEmpty {
            base.outcome = "pass"
            return base
        }
        let where_ = base.path.isEmpty ? "" : " [\(base.path.joined(separator: ", "))]"
        base.code = badControl && !base.tainted.isEmpty ? "untrusted_control_and_args" : badControl ? "untrusted_control" : "untrusted_args"
        var parts: [String] = []
        if badControl { parts.append("the choice of \(verb) derives from untrusted content") }
        if !base.tainted.isEmpty { parts.append("\(base.tainted.joined(separator: ", ")) \(base.tainted.count == 1 ? "derives" : "derive") from untrusted content") }
        base.outcome = "escalate"
        base.reason = "\(parts.joined(separator: "; "))\(where_): the principal must confirm (prompt-injection path)"
        return base
    }

    // ---- the grant envelope member ----

    /// The grant envelope member `provenance` `{mode?: "enforce" | "insecure_off", mediators?: [pin] (<= 16)}`: nil when well-formed.
    /// `insecure_off` is the documented DANGEROUS opt-out (injected content can then steer the grant's sensitive actions).
    public static func provEnvelopeError(_ pv: JSONValue) -> String? {
        guard case let .object(p) = pv else { return "provenance must be an object" }
        if let m = IntentWB.closedMembersError(p, [], ["mode", "mediators"], "provenance") { return m }
        if let m = p["mode"], !(IV.same(m.asString, "enforce") || IV.same(m.asString, "insecure_off")) { return "provenance.mode must be 'enforce' or 'insecure_off'" }
        if let ms = p["mediators"] {
            guard case let .array(list) = ms, list.count <= 16, list.allSatisfy(isProvMediatorPin) else { return "provenance.mediators must be at most 16 {mediator, kid, pk, pq_pk?}" }
        }
        return nil
    }

    /// The `provenance_flow` check of `authorize` (always on): `(status, reason)`; the escalate reasons carry the `escalate:` prefix so
    /// the ternary decision reads them as escalate-class, a deny code keeps the refusal a deny.
    static func provenanceFlowCheck(_ input: AuthorizeInput, pcactn: JSONValue, grant: JSONValue, op: Operation, principalPlan: Bool,
                                    principalControl: Bool) -> (status: CheckStatus, reason: String?) {
        let pe = readEnvelope(grant)?.get("provenance")
        if let p = pe, let e = provEnvelopeError(p) { return (.fail, "the grant's provenance member is malformed: \(e)") }
        // the principal's signed, documented-dangerous opt-out
        if IV.same(pe?.get("mode")?.asString, "insecure_off") { return (.notEnforced, nil) }
        var bundle: JSONValue? = input.provenance
        if bundle == nil, let h = input.provenanceHeader, !h.isEmpty {
            guard let text = PcaGuard.decodeHeader(h), let v = try? StrictJSON.parse(text) else { return (.fail, "the provenance bundle is unreadable (fail closed)") }
            bundle = v
        }
        let pins = input.argProvenance.mediators + (pe?.get("mediators")?.asArray ?? [])
        let session = bundle?.get("receipts")?.asArray?.first?.get("session")?.asString
        let observed = input.argProvenance.observed?(pcactn, op, session) ?? []
        let d = decideArgProvenance(ArgProvenanceInput(
            bundle: bundle, operation: .object(["verb": .string(op.verb), "resource": .string(op.resource), "params": op.params]), mediators: .array(pins),
            action: input.argProvenance.actions?(op), principalPlan: principalPlan, principalControl: principalControl, observed: .array(observed)))
        if d.outcome == "pass" { return (.pass, nil) }
        return (.fail, d.outcome == "escalate" ? "escalate: \(d.reason ?? "")" : "\(d.code ?? "deny"): \(d.reason ?? "")")
    }

    /// The bundle for an operation that came straight from the principal (the application's own UI acting on the user's explicit
    /// input, no model in between): one principal segment holding the operation, then the action.
    public static func principalDirectProvenance(_ recorder: ProvenanceRecorder, _ op: Operation) throws -> JSONValue {
        guard let text = IV.strictCanon(.object(["verb": .string(op.verb), "resource": .string(op.resource), "params": op.params])) else {
            throw PCAProducerError("principalDirectProvenance: the operation is outside the strict JSON profile")
        }
        try recorder.principal(text)
        return try recorder.forAction(op)
    }
}

/// The mediator side (the client half): one recorder per agent session. Run it where the bytes enter the model's context (the
/// harness that builds the prompt, a gateway, an MCP client), with a key the model cannot reach; present `forAction`'s bundle with
/// the call (`PCA-Provenance` header, base64url of its JSON, or the body member `pca_provenance`). Safe for concurrent use.
public final class ProvenanceRecorder: @unchecked Sendable {
    public let session: String
    /// The pin a verifier (or the principal's grant envelope `provenance.mediators`) must carry for this recorder.
    public let pin: JSONValue
    private let mediator: String
    private let kid: String
    private let signer: PCASuiteKey
    private let now: () -> Int64
    private var chain: [JSONValue] = []
    private var contents: JObject = [:]
    private let lock = NSLock()

    /// `signer` must carry an Ed25519 key (the pin's `pk`); a hybrid suite adds the pin's `pq_pk`. `session`: canonical base64url of 32
    /// bytes (random when nil). `now`: epoch milliseconds (default the wall clock).
    public init(mediator: String, kid: String, signer: PCASuiteKey, session: String? = nil, now: (() -> Int64)? = nil) throws {
        guard IV.bounded(.string(mediator), 256) != nil, IV.bounded(.string(kid), 64) != nil else {
            throw PCAProducerError("ProvenanceRecorder: mediator (<= 256 bytes) and kid (<= 64 bytes) are required")
        }
        guard let pk = signer.ed?.id else { throw PCAProducerError("ProvenanceRecorder: the signer needs an Ed25519 key (the pin's pk)") }
        let s = session ?? Base64URLStrict.encode((0..<32).map { _ in UInt8.random(in: 0...255) })
        guard IV.digest(.string(s)) != nil else { throw PCAProducerError("ProvenanceRecorder: session must be canonical base64url of 32 bytes") }
        var p: JObject = ["mediator": .string(mediator), "kid": .string(kid), "pk": .string(pk)]
        if let q = signer.pqPk { p["pq_pk"] = .string(q) }
        self.mediator = mediator
        self.kid = kid
        self.signer = signer
        self.session = s
        self.pin = .object(p)
        self.now = now ?? { Int64(Date().timeIntervalSince1970 * 1000) }
    }

    /// An Ed25519 recorder from a 32-byte secret seed (a random key when nil: then pin `recorder.pin`).
    public convenience init(mediator: String, kid: String, secretKey: [UInt8]? = nil, session: String? = nil, now: (() -> Int64)? = nil) throws {
        let ed = try secretKey.map { try PCAEdKey(seed: $0) } ?? PCAEdKey.generate()
        try self.init(mediator: mediator, kid: kid, signer: .ed25519(ed), session: session, now: now)
    }

    /// A source of at most 256 UTF-8 bytes, `-` when empty: halved by UTF-16 code units until it fits, exactly as the reference
    /// (`s.slice(0, max(1, floor(s.length / 2)))`). A cut that leaves half of a surrogate pair cannot be canonicalized, so recording
    /// throws (the reference's canonicalizer throws there too).
    static func clip(_ s: String) throws -> String {
        var u = Array(s.utf16)
        func utf8Len(_ u: [UInt16]) -> Int {
            var n = 0, i = 0
            while i < u.count {
                let c = u[i]
                if (0xD800...0xDBFF).contains(c), i + 1 < u.count, (0xDC00...0xDFFF).contains(u[i + 1]) { n += 4; i += 2; continue }
                n += c < 0x80 ? 1 : c < 0x800 ? 2 : 3 // a lone surrogate counts 3, as in the reference
                i += 1
            }
            return n
        }
        while utf8Len(u) > 256 { u = Array(u.prefix(max(1, u.count / 2))) }
        if u.isEmpty { return "-" }
        // a prefix can only split a pair at its end
        if let last = u.last, (0xD800...0xDBFF).contains(last) {
            throw PCAProducerError("ProvenanceRecorder: the clipped source splits a surrogate pair (not canonical text)")
        }
        return String(decoding: u, as: UTF16.self)
    }

    private func append(_ origin: String, _ source: String, _ digest: String) throws -> JSONValue {
        var prev: JSONValue = .null
        var issued = now()
        if let p = chain.last {
            guard let ref = PCA.provReceiptRef(p) else { throw PCAProducerError("ProvenanceRecorder: a receipt is outside the strict JSON profile") }
            prev = .string(ref)
            issued = max(issued, p.get("issued_at")?.safeInt ?? 0)
        }
        let body: JObject = ["v": .int(1), "kind": .string("pca-prov"), "mediator": .string(mediator), "kid": .string(kid), "session": .string(session),
                             "seq": .int(Int64(chain.count)), "prev": prev, "origin": .string(origin), "source": .string(try ProvenanceRecorder.clip(source)),
                             "content_digest": .string(digest), "issued_at": .int(max(0, issued))]
        let r = JSONValue.object(try PCAIssue.signArtifact(domain: PCA.PROV_RECEIPT_DOMAIN, body: .object(body), signer: signer))
        chain.append(r)
        return r
    }

    private func segment(_ origin: String, _ source: String, _ text: String) throws -> JSONValue {
        lock.lock()
        defer { lock.unlock() }
        guard let d = IV.strictHash(.string(text)) else { throw PCAProducerError("ProvenanceRecorder: the content is not canonical text") }
        let r = try append(origin, source, d)
        if origin == "principal" && IV.u8(text) <= PCA.MAX_PROV_CONTENT_BYTES { contents[JKey(String(chain.count - 1))] = .string(text) }
        return r
    }

    /// The principal's own message (TRUSTED).
    @discardableResult public func principal(_ text: String) throws -> JSONValue { try segment("principal", "user", text) }
    /// A tool result (UNTRUSTED).
    @discardableResult public func tool(_ name: String, _ output: String) throws -> JSONValue { try segment("tool", name, output) }
    /// A retrieved document (UNTRUSTED).
    @discardableResult public func retrieval(_ source: String, _ content: String) throws -> JSONValue { try segment("retrieval", source, content) }
    /// A fetched web page or HTTP response (UNTRUSTED).
    @discardableResult public func web(_ url: String, _ content: String) throws -> JSONValue { try segment("web", url, content) }

    /// Record the chosen action and return the bundle to present with it.
    public func forAction(_ op: PCA.Operation) throws -> JSONValue {
        lock.lock()
        defer { lock.unlock() }
        if chain.count >= PCA.MAX_PROV_RECEIPTS {
            throw PCAProducerError("provenance: the session holds \(PCA.MAX_PROV_RECEIPTS) receipts; start a new session with the principal's message")
        }
        guard let d = PCA.provActionDigest(verb: op.verb, resource: op.resource, params: op.params) else {
            throw PCAProducerError("ProvenanceRecorder: the operation is outside the strict JSON profile")
        }
        _ = try append("action", op.verb, d)
        var b: JObject = ["v": .int(1), "kind": .string("pca-provenance"), "receipts": .array(chain)]
        if !contents.isEmpty { b["contents"] = .object(contents) }
        return .object(b)
    }

    /// Every receipt so far.
    public func receipts() -> [JSONValue] {
        lock.lock()
        defer { lock.unlock() }
        return chain
    }

    /// The `PCA-Provenance` header value of a bundle: base64url of its canonical JSON.
    public static func header(_ bundle: JSONValue) -> String { Base64URLStrict.encode(Canonical.utf8(Canonical.canonicalize(bundle))) }
}
