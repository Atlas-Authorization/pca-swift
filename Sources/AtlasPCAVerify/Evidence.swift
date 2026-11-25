import Foundation

/// The dispute evidence bundle `pca-intent-evidence` v1 (Intent Layer v2): closed-member shape validation, the deterministic normal
/// form, the commitments-only form and the digest that commits to it, the bundle reference and its anchor-log leaf, the accumulator
/// cap reader, and the validators of the verifier's trust inputs.
///
/// Inputs are JSON values; the reference's JavaScript semantics over hostile input (property reads on any value, `Object.keys`
/// order, relational comparison, the `||` chain of the sort comparators, JSON round-trip copy) are reproduced, so a malformed bundle
/// gives the same shape error, the same order or the same refusal (a thrown error) as the reference.
///
/// Not ported: the full replay (`verifyEvidenceBundle`), the COSE signed statement over the bundle reference and the command line.
public enum PCAEvidence {
    public static let EVIDENCE_DOMAIN = "atlas-pca/intent-evidence/v1"
    public static let EVIDENCE_REPORT_DOMAIN = "atlas-pca/intent-evidence-report/v1"
    public static let EVIDENCE_CONTENT_TYPE = "application/pca-intent-evidence+json"
    public static let INTENT_ANCHOR_DOMAIN = "atlas-pca/intent-anchor/v1"
    static let MAX_SAFE = Double(Canonical.MAX_SAFE)

    static let TOP_KEYS = ["v", "kind", "subject", "statement", "session_root", "schema", "root_grant", "maps", "answers", "canary_labels",
                           "canaries", "deltas", "pcactns", "verdicts", "accumulator", "facts", "classifier", "offer_sets", "labels",
                           "effects", "settlements", "revocation_epochs", "anchors"]

    private static func g(_ o: JSONValue?, _ k: String) -> JSONValue? { JSLoose.get(o, k) }
    private static func isStr(_ v: JSONValue?) -> Bool { v?.asString != nil }
    private static func isArr(_ v: JSONValue?) -> Bool { v?.isArray ?? false }
    private static func nonNeg(_ v: JSONValue?) -> Bool { JSLoose.isInt(v) && (IV.num(v) ?? -1) >= 0 }

    // ---- shape ----

    static func closed(_ o: JSONValue?, _ keys: [String], _ where_: String) -> String? {
        guard JSLoose.isObj(o) else { return "\(where_) must be an object" }
        for k in JSLoose.keys(o) where !keys.contains(k) { return "\(where_): unknown member \"\(k)\"" }
        return nil
    }

    /// Closed-member shape validation (unknown members are refused at every level the bundle owns). nil when well formed.
    public static func bundleShapeError(_ b: JSONValue?) -> String? {
        if let e = closed(b, TOP_KEYS, "bundle") { return e }
        let x = b
        if !JSLoose.isOne(g(x, "v")) || g(x, "kind") != .string("pca-intent-evidence") { return "not a pca-intent-evidence v1 bundle" }
        if let e = closed(g(x, "subject"), ["pcactn_digest", "aud", "session"], "subject") { return e }
        let s = g(x, "subject")
        if !["pcactn_digest", "aud", "session"].allSatisfy({ isStr(g(s, $0)) }) { return "subject members must be strings" }
        if let e = closed(g(x, "statement"), ["commit", "opening"], "statement") { return e }
        if !isStr(g(g(x, "statement"), "commit")) { return "statement.commit must be a string" }
        let sr = g(x, "session_root")
        if !JSLoose.isObj(sr) || !JSLoose.isOne(g(sr, "v")) || g(sr, "kind") != .string("pca-intent-session") { return "session_root is not a pca-intent-session v1" }
        if !isStr(g(sr, "session")) || !isStr(g(sr, "intent_ref")) || !JSLoose.isInt(g(sr, "expires_at")) {
            return "session_root is missing session / intent_ref / expires_at"
        }
        guard case let .array(pr)? = g(sr, "principals"), !pr.isEmpty, pr.allSatisfy({ JSLoose.isObj($0) && isStr(g($0, "key")) }) else {
            return "session_root.principals must be a non-empty key list"
        }
        if let e = closed(g(x, "schema"), ["doc", "anchor"], "schema") { return e }
        let doc = g(g(x, "schema"), "doc")
        if !JSLoose.isObj(doc) || g(doc, "kind") != .string("pca-action-schema") || !JSLoose.isObj(g(doc, "sig")) {
            return "schema.doc is not a signed pca-action-schema"
        }
        if !JSLoose.isObj(g(x, "root_grant")) { return "root_grant must be a capability" }
        for k in ["maps", "answers", "canary_labels", "deltas", "pcactns", "verdicts", "effects", "revocation_epochs", "anchors"] where !isArr(g(x, k)) {
            return "\(k) must be an array"
        }
        for k in ["facts", "classifier", "offer_sets", "labels", "settlements"] {
            if let v = g(x, k), !v.isArray { return "\(k) must be an array" }
        }
        for (i, m) in (g(x, "maps")?.asArray ?? []).enumerated() {
            if let e = closed(m, ["seq", "commit", "map", "disclosed"], "maps[\(i)]") { return e }
            if !nonNeg(g(m, "seq")) || !isStr(g(m, "commit")) { return "maps[\(i)] needs an integer seq and a commit" }
        }
        for (i, c) in (g(x, "canary_labels")?.asArray ?? []).enumerated() {
            if let e = closed(c, ["question_id", "label"], "canary_labels[\(i)]") { return e }
            let lab = IV.num(g(c, "label"))
            if !isStr(g(c, "question_id")) || !(lab == 0 || lab == 1) { return "canary_labels[\(i)] is malformed" }
        }
        if let e = closed(g(x, "canaries"), ["asked", "false_yes", "false_no"], "canaries") { return e }
        if !["asked", "false_yes", "false_no"].allSatisfy({ nonNeg(g(g(x, "canaries"), $0)) }) { return "canaries counts must be non-negative integers" }
        if let e = closed(g(x, "accumulator"), ["holder", "events", "receipts", "sequencer_keys"], "accumulator") { return e }
        let acc = g(x, "accumulator")
        if g(acc, "holder") != .string("site_local") && g(acc, "holder") != .string("sequenced") { return "accumulator.holder must be site_local or sequenced" }
        guard case let .array(events)? = g(acc, "events") else { return "accumulator.events must be an array" }
        for (i, ev) in events.enumerated() {
            if let e = closed(ev, ["acc", "post", "pcactn_digest", "delta", "status"], "accumulator.events[\(i)]") { return e }
            if !isStr(g(ev, "acc")) || !nonNeg(g(ev, "post")) || !isStr(g(ev, "pcactn_digest")) { return "accumulator.events[\(i)] is malformed" }
            if let d = g(ev, "delta"), !nonNeg(d) { return "accumulator.events[\(i)].delta must be a non-negative integer" }
        }
        if let v = g(acc, "receipts"), !v.isArray { return "accumulator.receipts must be an array" }
        if let v = g(acc, "sequencer_keys"), !v.isArray { return "accumulator.sequencer_keys must be an array" }
        for (i, r) in (g(x, "revocation_epochs")?.asArray ?? []).enumerated() {
            if let e = closed(r, ["epoch", "revoked"], "revocation_epochs[\(i)]") { return e }
            if !JSLoose.isObj(g(r, "epoch")) || !isArr(g(r, "revoked")) { return "revocation_epochs[\(i)] needs an epoch and its revoked list" }
        }
        for (i, a) in (g(x, "anchors")?.asArray ?? []).enumerated() {
            if let e = closed(a, ["kind", "digest", "index", "proof", "signed_tree_head"], "anchors[\(i)]") { return e }
        }
        for (i, ef) in (g(x, "effects")?.asArray ?? []).enumerated() where !JSLoose.isObj(ef) || !isStr(g(ef, "pcactn_digest")) {
            return "effects[\(i)] needs a pcactn_digest"
        }
        return nil
    }

    // ---- normal form ----

    /// hashCanonical (strict) of a value as the string the comparators order by; throws where the reference throws.
    private static func key(_ v: JSONValue) throws -> JSONValue {
        guard let h = IV.strictHash(v) else { throw JSError("canonicalize: value out of profile") }
        return .string(h)
    }

    private static func seqOf(_ c: JSONValue) throws -> Double {
        guard case let .array(cvs)? = try JSLoose.rd(c, "caveats") else { throw JSError("find is not a function") }
        for k in cvs where try JSLoose.rd(k, "type") == .string("intent_session") {
            let s = g(k, "seq")
            return JSLoose.isInt(s) ? IV.num(s)! : MAX_SAFE
        }
        return MAX_SAFE
    }

    private static func effectKey(_ e: JSONValue) throws -> JSONValue { try key(.object(try JSLoose.rest(e, without: "params"))) }

    /// Deterministic normal form: the members that are sets (answers, deltas, PCActns, verdicts, effects, epochs, anchors, maps, canary
    /// labels, ...) are sorted by a content key; `accumulator.events` is a sequence and is never reordered. Throws on a bundle that
    /// cannot be put in order (the reference's thrown error).
    public static func normalizeBundle(_ b: JSONValue?) throws -> JSONValue {
        guard let b = b else { throw JSError("undefined is not valid JSON") }
        var x = JSLoose.plain(b)
        func r(_ o: JSONValue?, _ k: String) throws -> JSONValue? { try JSLoose.rd(o, k) }
        func setTop(_ k: String, _ v: JSONValue) throws {
            guard case var .object(o) = x else { throw JSError("not an object") }
            o[JKey(k)] = v
            x = .object(o)
        }
        func sortTop(_ k: String, _ cmp: (JSONValue, JSONValue) throws -> Double) throws {
            try setTop(k, try JSLoose.sortMember(try r(x, k), cmp))
        }
        func or(_ a: Double, _ rest: () throws -> Double) throws -> Double { try JSLoose.or(a, rest) }
        func sub(_ a: JSONValue, _ c: JSONValue, _ k: String) throws -> Double { JSLoose.sub(try r(a, k), try r(c, k)) }
        func cmp(_ a: JSONValue, _ c: JSONValue, _ k: String) throws -> Double { JSLoose.cmp(try r(a, k), try r(c, k)) }
        func ep(_ o: JSONValue, _ k: String) throws -> JSONValue? { try r(try r(o, "epoch"), k) }

        try sortTop("maps") { a, c in try or(try sub(a, c, "seq")) { try cmp(a, c, "commit") } }
        try sortTop("answers") { a, c in
            try or(try sub(a, c, "observed_at")) { try or(try cmp(a, c, "question_id")) { try cmp(a, c, "sig") } }
        }
        try sortTop("canary_labels") { a, c in try or(try cmp(a, c, "question_id")) { try sub(a, c, "label") } }
        try sortTop("deltas") { a, c in try or(try seqOf(a) - seqOf(c)) { try cmp(a, c, "id") } }
        try sortTop("pcactns") { a, c in
            try or(try sub(a, c, "iat")) { try or(try sub(a, c, "counter")) { JSLoose.cmp(try key(a), try key(c)) } }
        }
        try sortTop("verdicts") { a, c in try or(try cmp(a, c, "pcactn_digest")) { JSLoose.cmp(try key(a), try key(c)) } }
        // sorted without the params opening, so withholding an opening never reorders the commitments-only form
        try sortTop("effects") { a, c in try or(try cmp(a, c, "pcactn_digest")) { JSLoose.cmp(try effectKey(a), try effectKey(c)) } }
        // issue order (not epoch number): a rollback, an epoch issued later with a lower number, must stay visible
        try sortTop("revocation_epochs") { a, c in
            try or(JSLoose.sub(try ep(a, "issued_at"), try ep(c, "issued_at"))) {
                try or(JSLoose.sub(try ep(a, "epoch"), try ep(c, "epoch"))) { JSLoose.cmp(try key(a), try key(c)) }
            }
        }
        try sortTop("anchors") { a, c in
            try or(try cmp(a, c, "kind")) { try or(try sub(a, c, "index")) { try cmp(a, c, "digest") } }
        }
        for k in ["facts", "classifier", "offer_sets", "labels", "settlements"] {
            guard let v = g(x, k), v != .null else { continue }
            try setTop(k, try JSLoose.sortMember(v) { a, c in JSLoose.cmp(try key(a), try key(c)) })
        }
        let acc = try r(x, "accumulator")
        if let rc = g(acc, "receipts"), JS.truthy(rc), case var .object(ao)? = acc {
            ao["receipts"] = try JSLoose.sortMember(rc) { a, c in JSLoose.cmp(try key(a), try key(c)) }
            try setTop("accumulator", .object(ao))
        } else if let rc = g(acc, "receipts"), JS.truthy(rc) {
            throw JSError("sort is not a function")
        }
        return x
    }

    /// Assemble a bundle in normal form. Throws on a malformed part (the exporter's bug, not evidence).
    public static func buildEvidenceBundle(_ parts: JSONValue?) throws -> JSONValue {
        var b: JObject = ["v": .int(1), "kind": .string("pca-intent-evidence")]
        for (k, v) in JSLoose.spread(parts) { b[k] = v }
        let n = try normalizeBundle(.object(b))
        if let bad = bundleShapeError(n) { throw JSError("buildEvidenceBundle: \(bad)") }
        return n
    }

    /// (the commitments-only form, whether a committed member is undefined): an undefined member cannot be hashed.
    private static func commitment(_ b: JSONValue?) throws -> (form: JSONValue, undef: Bool) {
        let n = try normalizeBundle(b)
        var rest = JSLoose.spread(n)
        rest["anchors"] = nil
        var undef = false
        guard let statement = g(n, "statement"), statement != .null else { throw JSError("cannot read 'commit' of undefined") }
        if let c = g(statement, "commit") { rest["statement"] = .object(["commit": c]) } else { rest["statement"] = .object([:]); undef = true }
        var maps: [JSONValue] = []
        for m in g(n, "maps")?.asArray ?? [] {
            let seq = try JSLoose.rd(m, "seq"), commit = try JSLoose.rd(m, "commit"), disclosed = g(m, "disclosed")
            var e: JObject = [:]
            if let s = seq { e["seq"] = s } else { undef = true }
            if let c = commit { e["commit"] = c } else { undef = true }
            if let d = disclosed { e["disclosed"] = d }
            maps.append(.object(e))
        }
        rest["maps"] = .array(maps)
        rest["effects"] = .array(try (g(n, "effects")?.asArray ?? []).map { JSONValue.object(try JSLoose.rest($0, without: "params")) })
        return (.object(rest), undef)
    }

    /// The commitments-only normal form: no anchors, no statement opening, no full maps, no effect params; every signed artifact and
    /// every claim stays in.
    public static func commitmentForm(_ b: JSONValue?) throws -> JSONValue { try commitment(b).form }

    /// The bundle's content address: the hash over the commitments-only normal form.
    public static func evidenceDigest(_ b: JSONValue?) throws -> String {
        let (form, undef) = try commitment(b)
        if undef { throw JSError("canonicalize: undefined member") }
        guard let h = IV.strictHash(.object(["d": .string(EVIDENCE_DOMAIN), "b": form])) else { throw JSError("canonicalize: value out of profile") }
        return h
    }

    /// The public reference to a bundle: its digest and subject (the bundle itself stays with the site).
    public static func evidenceRef(_ bundle: JSONValue?) throws -> JSONValue {
        let digest = try evidenceDigest(bundle)
        return .object(["kind": .string("pca-intent-evidence-ref"), "digest": .string(digest),
                        "subject": .object(JSLoose.spread(try JSLoose.rd(bundle, "subject")))])
    }

    /// The intent-log leaf for an anchored artifact (any kind).
    public static func anchorCommit(_ kind: JSONValue?, _ digest: JSONValue?) throws -> String {
        guard let k = kind, let d = digest,
              let h = IV.strictHash(.object(["d": .string(INTENT_ANCHOR_DOMAIN), "kind": k, "digest": d])) else { throw JSError("canonicalize: value out of profile") }
        return h
    }

    public static func evidenceAnchorCommit(_ digest: JSONValue?) throws -> String { try anchorCommit(.string("evidence"), digest) }

    // ---- accumulator cap ----

    private static func leafCaps(_ conds: JSONValue?, _ path: String) throws -> [Double] {
        switch conds {
        case nil, .null?, .string?: return [] // a string iterates its characters, none of which is a condition
        case let .array(items)?:
            var out: [Double] = []
            for c in items {
                guard case let .object(o) = c else { continue }
                let group = o["all_of"] != nil || o["any_of"] != nil || o["not"] != nil
                if !group, case let .string(f)? = o["field"] {
                    guard f.unicodeScalars.elementsEqual(path.unicodeScalars), o["ref"] == nil, let v = IV.num(o["value"]) else { continue }
                    if o["op"] == .string("lte") { out.append(v) } else if o["op"] == .string("lt") { out.append(v - 1) }
                } else if group, let inner = o["all_of"] {
                    out += try leafCaps(inner, path)
                }
            }
            return out
        default: throw JSError("not iterable")
        }
    }

    private static func numberJSON(_ d: Double) -> JSONValue {
        d.rounded() == d && abs(d) <= MAX_SAFE ? .int(Int64(d)) : .double(d)
    }

    /// The cap `env.acc.<id>.post <= v` that the grant's envelope states for `verb`: per predicate the tightest bound in its `where`
    /// (descending into `all_of`); across predicates (a union) the loosest. null when a predicate admitting the verb states no bound,
    /// or none admits it.
    public static func capOf(_ grant: JSONValue?, _ accId: JSONValue?, _ verb: JSONValue?) throws -> JSONValue {
        guard let grant = grant, let env = PCA.readEnvelope(grant), case let .array(preds)? = env.get("predicates") else { return .null }
        let path = "env.acc.\(JS.toString(accId)).post"
        var cap: Double?
        for p in preds {
            let pv = try JSLoose.rd(p, "verb")
            let verbs: [String]
            if case let .array(a)? = pv { verbs = a.map { JS.toString($0) } } else { verbs = [JS.toString(pv)] }
            var admitted = verbs.contains("*")
            if case let .string(v)? = verb, verbs.contains(where: { $0.unicodeScalars.elementsEqual(v.unicodeScalars) }) { admitted = true }
            if !admitted { continue }
            let caps = try leafCaps(g(p, "where"), path)
            guard let m = caps.min() else { return .null }
            cap = cap.map { max($0, m) } ?? m
        }
        return cap.map(numberJSON) ?? .null
    }

    // ---- trust-input validators ----

    /// Validate `trust.principals`: a non-empty array of closed `{key, pq_pk?}` with canonical keys. nil = valid (an absent value is valid).
    public static func principalsTrustError(_ p: JSONValue?) -> String? {
        guard let p = p else { return nil }
        guard case let .array(items) = p, !items.isEmpty else { return "trust.principals must be a non-empty array of {key, pq_pk?}" }
        for (i, x) in items.enumerated() {
            guard JSLoose.isObj(x) else { return "trust.principals[\(i)] must be an object {key, pq_pk?}" }
            for k in JSLoose.keys(x) where k != "key" && k != "pq_pk" { return "trust.principals[\(i)]: unknown member '\(k)'" }
            guard case let .string(key)? = g(x, "key"), Base64URLStrict.decode(key, length: 32) != nil else {
                return "trust.principals[\(i)].key must be canonical base64url (32 bytes)"
            }
            if let pq = g(x, "pq_pk") {
                guard case let .string(s) = pq, Base64URLStrict.decode(s) != nil else { return "trust.principals[\(i)].pq_pk must be canonical base64url" }
            }
        }
        return nil
    }

    /// Validate `trust.acc` like the core `policy.acc`: closed members, non-negative safe integers. nil = valid.
    public static func accTrustError(_ a: JSONValue?) -> String? {
        guard let a = a else { return nil }
        guard JSLoose.isObj(a) else { return "trust.acc must be an object" }
        for k in JSLoose.keys(a) {
            if k != "max_receipt_age_s" && k != "max_keyset_age_s" { return "trust.acc: unknown member '\(k)'" }
            if !nonNeg(g(a, k)) { return "trust.acc.\(k) must be a non-negative safe integer" }
        }
        return nil
    }
}
