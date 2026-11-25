import Foundation

/// The reason-string forms of the Intent Layer v2 W-B wire validators (the Bool forms in `IntentWB` are the verifier's gates; the
/// evidence replay reports the reference's reason), the label-receipt check, and the verifier-state helpers the replay shares
/// with the host side (`accContextFor`).
extension IntentWB {
    private static func isDigestV(_ v: JSONValue?) -> Bool { IV.digest(v) != nil }

    /// `validateFactWire`: nil = well-formed.
    static func factWireError(_ fv: JSONValue?) -> String? {
        guard case let .object(f)? = fv else { return "fact must be an object" }
        if let e = closedMembersError(f, ["v", "kind", "name", "subject", "value", "t_obs", "oracle", "sig"], SUITE_MEMBERS, "fact") { return e }
        if IV.num(f["v"]) != 1 || !IV.same(f["kind"]?.asString, "pca-fact") { return "fact must be {v: 1, kind: \"pca-fact\"}" }
        if !(f["name"]?.asString.map(IV.isName) ?? false) { return "'fact.name' must match ^[a-z][a-z0-9_]{0,63}$" }
        if IV.bounded(f["subject"], 256) == nil { return "'fact.subject' must be a non-empty string (<= 256 bytes)" }
        if IV.int(f["value"]) == nil && IV.bounded(f["value"], 256) == nil { return "'fact.value' must be a safe integer or a non-empty string (<= 256 bytes)" }
        if IV.nonNeg(f["t_obs"]) == nil { return "'fact.t_obs' must be a non-negative safe integer" }
        if IV.bounded(f["oracle"], 64) == nil { return "'fact.oracle' must be a non-empty string (<= 64 bytes)" }
        if f["sig"]?.asString == nil { return "'fact.sig' must be a string" }
        return nil
    }

    /// `validateClassifierVerdictWire`: nil = well-formed.
    static func verdictWireError(_ vv: JSONValue?) -> String? {
        guard case let .object(v)? = vv else { return "verdict must be an object" }
        if let e = closedMembersError(v, ["v", "kind", "classifier", "session", "content_digest", "label", "measurement", "judge", "sig"], SUITE_MEMBERS, "verdict") { return e }
        if IV.num(v["v"]) != 1 || !IV.same(v["kind"]?.asString, "pca-intent-classification") { return "verdict must be {v: 1, kind: \"pca-intent-classification\"}" }
        if !(v["classifier"]?.asString.map(IV.isName) ?? false) { return "'verdict.classifier' must match ^[a-z][a-z0-9_]{0,63}$" }
        if !isDigestV(v["session"]) { return "'verdict.session' must be canonical base64url (32 bytes)" }
        if !isDigestV(v["content_digest"]) { return "'verdict.content_digest' must be canonical base64url (32 bytes)" }
        if IV.bounded(v["label"], 64) == nil { return "'verdict.label' must be a non-empty string (<= 64 bytes)" }
        if IV.bounded(v["measurement"], 256) == nil { return "'verdict.measurement' must be a non-empty string (<= 256 bytes)" }
        if !isDigestV(v["judge"]) { return "'verdict.judge' must be canonical base64url (32 bytes)" }
        if v["sig"]?.asString == nil { return "'verdict.sig' must be a string" }
        return nil
    }

    /// `validateLabelsWire`: nil = well-formed.
    static func labelsWireError(_ lv: JSONValue?) -> String? {
        guard case let .object(l)? = lv else { return "label receipt must be an object" }
        if let e = closedMembersError(l, ["v", "kind", "site", "session", "response_digest", "fields", "issued_at", "kid", "sig"], SUITE_MEMBERS, "labels") { return e }
        if IV.num(l["v"]) != 1 || !IV.same(l["kind"]?.asString, "pca-labels") { return "label receipt must be {v: 1, kind: \"pca-labels\"}" }
        if IV.bounded(l["site"], 256) == nil { return "'labels.site' must be a non-empty string (<= 256 bytes)" }
        if !isDigestV(l["session"]) { return "'labels.session' must be canonical base64url (32 bytes)" }
        if !isDigestV(l["response_digest"]) { return "'labels.response_digest' must be canonical base64url (32 bytes)" }
        guard case let .object(fields)? = l["fields"] else { return "'labels.fields' must be an object" }
        if fields.isEmpty || fields.count > MAX_LABEL_FIELDS { return "'labels.fields' must hold 1..\(MAX_LABEL_FIELDS) fields" }
        for k in JSLoose.keys(.object(fields)) {
            let f = fields[JKey(k)]
            if IV.bounded(.string(k), 256) == nil { return "label field paths must be non-empty strings (<= 256 bytes)" }
            guard case let .object(fo)? = f, closedMembers(fo, ["class", "value_digest"]) else { return "label field '\(k)' must be exactly {class, value_digest}" }
            guard let cls = fo["class"]?.asString, IV.u16(cls) <= 128, IV.isDataClass(cls) else { return "label field '\(k)': invalid data class" }
            if !isDigestV(fo["value_digest"]) { return "label field '\(k)': value_digest must be canonical base64url (32 bytes)" }
        }
        if IV.nonNeg(l["issued_at"]) == nil { return "'labels.issued_at' must be a non-negative safe integer" }
        if IV.bounded(l["kid"], 64) == nil { return "'labels.kid' must be a non-empty string (<= 64 bytes)" }
        if l["sig"]?.asString == nil { return "'labels.sig' must be a string" }
        return nil
    }

    /// `verifyLabels(receipt, keys)`: wire shape, suite and signature under the signer pinned for (site, kid). nil = valid. Total.
    public static func verifyLabels(_ lv: JSONValue?, _ keys: JSONValue?) -> String? {
        if let w = labelsWireError(lv) { return w }
        guard case let .array(ks)? = keys else { return "label keys must be an array" }
        guard case let .object(r)? = lv else { return "label receipt must be an object" }
        if let se = artifactSuiteError(r) { return "signature suite: \(se)" }
        guard let key = ks.first(where: { $0.isObject && $0.get("site") == r["site"] && $0.get("kid") == r["kid"] }) else {
            return "no pinned label key for site '\(jsOpt(r["site"]))' kid '\(jsOpt(r["kid"]))'"
        }
        guard let pk = key.get("pk")?.asString else { return "bad label receipt signature" }
        let pin = key.get("pq_pk")?.asString
        return verifyArtifactSig(LABELS_DOMAIN, r, pk, pqPin: pin) ? nil : "bad label receipt signature"
    }
}

extension IntentHistory {
    /// `accContextFor(S, history, {params, t}, schema)`: the verifier context (`intentV2.acc`) for a candidate action: the pre-states of the
    /// site-local accumulators and the monitor states. Throws where the reference throws (an unreadable history or a missing key).
    static func accContextFor(_ S: JSONValue?, _ history: [JSONValue], params: JObject, t: JSONValue?, schema: JSONValue?) throws -> (state: JObject, monitors: JObject) {
        var state: JObject = [:]
        guard case let .array(accs)? = JSLoose.get(S, "accumulators") else { throw JSError("S.accumulators is not iterable") }
        for av in accs {
            guard case let .object(a) = av else { throw JSError("cannot read 'holder' of a non-object") }
            if !IV.same(a["holder"]?.get("kind")?.asString, "site_local") { continue }
            // the verifier fails the claim (missing key)
            if a["key"]?.asString != nil && accKeyOf(a, params) == nil { continue }
            guard let pre = accPreState(a, history, params, t, schema) else { throw JSError("accPreState: the history is unreadable or the key parameter is missing") }
            guard let id = a["id"]?.asString else { throw JSError("accumulator without an id") }
            state[JKey(id)] = pre
        }
        var monitors: JObject = [:]
        guard case let .array(ms)? = JSLoose.get(S, "monitors") else { throw JSError("S.monitors is not iterable") }
        for mv in ms {
            guard case let .object(m) = mv, let id = m["id"]?.asString else { throw JSError("monitor without an id") }
            monitors[JKey(id)] = .string(monitorState(m, history))
        }
        return (state, monitors)
    }
}
