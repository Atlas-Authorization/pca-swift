import Foundation

/// Wire-format v2 validation (README §1/3/5), mirroring `wire.ts` / the Rust `validate_wire`: closed field
/// sets, presence, JSON types, safe integers, canonical fixed-length base64url, and that the whole signed
/// body admits the strict canonical encoding. Returns nil when well-formed, else a short reason.
enum Wire {
    static let REQUIRED_FIELDS = [
        "ver", "action", "grant_ref", "cap_chain", "plan", "attestation", "provenance", "freshness",
        "counter", "risk_claim", "aud", "iat", "exp", "sig",
    ]
    static let OPTIONAL_FIELDS = [
        "nonce", "caution", "rationale_commitment", "progress_step", "prohibition_evidence", "tool_binding",
        "threshold", "zk_compliance", "bond_ref",
        // B4 crypto-agility (additive): absent `alg` == "ed25519" and validates exactly as the classical wire.
        "alg", "pq_pk", "pq_sig",
    ]
    static let MAX_AUD_LEN = 256
    static let MAX_NONCE_LEN = 128

    private static func b32(_ v: JSONValue?) -> Bool {
        guard let s = v?.asString else { return false }
        return Base64URLStrict.isValid(s, length: 32)
    }
    private static func b64sig(_ v: JSONValue?) -> Bool {
        guard let s = v?.asString else { return false }
        return Base64URLStrict.isValid(s, length: 64)
    }
    private static func isStr(_ v: JSONValue?) -> Bool { v?.asString != nil }
    private static func isInt(_ v: JSONValue?) -> Bool { v?.safeInt != nil }

    private static func closed(_ o: [String: JSONValue], _ allowed: [String], _ label: String) -> String? {
        for k in o.keys where !allowed.contains(k) { return "unknown field '\(label)\(k)'" }
        return nil
    }

    static func validate(_ pcactn: JSONValue) -> String? {
        guard let p = pcactn.asObject else { return "PCActn is not an object" }
        for k in p.keys where !REQUIRED_FIELDS.contains(k) && !OPTIONAL_FIELDS.contains(k) {
            return "unknown field '\(k)'"
        }
        for k in REQUIRED_FIELDS where p[k] == nil { return "missing field '\(k)'" }

        // every signed byte must be strict-canonical-encodable; `sig`, `threshold` and `pq_sig` are unsigned.
        var body: [String: JSONValue] = [:]
        for (k, v) in p where k != "sig" && k != "threshold" && k != "pq_sig" { body[k] = v }
        do { _ = try Canonical.canonicalizeStrict(.object(body)) } catch { return "\(error)" }

        for k in ["ver", "counter", "iat", "exp"] where !isInt(p[k]) { return "'\(k)' must be a safe integer" }

        if let a = p["aud"]?.asString, !a.isEmpty, a.utf8.count <= MAX_AUD_LEN {} else {
            return "'aud' must be a non-empty string"
        }
        if let n = p["nonce"] {
            guard let s = n.asString, !s.isEmpty, s.utf8.count <= MAX_NONCE_LEN else {
                return "'nonce' must be a non-empty string"
            }
        }
        // B4 crypto-agility: validate `alg`/`sig`/`pq_pk`/`pq_sig` per suite (with no `alg` this is exactly
        // the classical 64-byte `sig` check, and asserts `pq_pk`/`pq_sig` are absent).
        if let e = PQ.validateSignatureWire(p) { return e }
        if !b32(p["grant_ref"]) { return "'grant_ref' is not canonical base64url (32 bytes)" }

        guard let a = p["action"]?.asObject else { return "'action' must be an object" }
        if let e = closed(a, ["verb", "resource", "params_digest", "reversibility_class"], "action.") { return e }
        if !isStr(a["verb"]) || !isStr(a["resource"]) || !isStr(a["reversibility_class"]) {
            return "action.verb/resource/reversibility_class must be strings"
        }
        if !b32(a["params_digest"]) { return "'action.params_digest' is not canonical base64url (32 bytes)" }

        guard let pl = p["plan"]?.asObject else { return "'plan' must be an object" }
        if let e = closed(pl, ["root", "inclusion_proof", "node_id", "conditions_digest"], "plan.") { return e }
        if !b32(pl["root"]) { return "'plan.root' is not canonical base64url (32 bytes)" }
        if !isStr(pl["node_id"]) { return "'plan.node_id' must be a string" }
        if let cd = pl["conditions_digest"], !b32(cd) {
            return "'plan.conditions_digest' must be a canonical base64url string (32 bytes)"
        }
        guard let ip = pl["inclusion_proof"]?.asObject else { return "'plan.inclusion_proof' must be an object" }
        if let e = closed(ip, ["index", "size", "path"], "plan.inclusion_proof.") { return e }
        if !isInt(ip["index"]) { return "'plan.inclusion_proof.index' must be a safe integer" }
        if !isInt(ip["size"]) { return "'plan.inclusion_proof.size' must be a safe integer" }
        guard let path = ip["path"]?.asArray else { return "'plan.inclusion_proof.path' must be an array" }
        for (i, st) in path.enumerated() {
            guard let st = st.asObject else { return "proof step \(i) must be an object" }
            for k in st.keys where k != "side" && k != "hash" { return "unknown field 'path[\(i)].\(k)'" }
            switch st["side"]?.asString {
            case "L", "R": break
            default: return "proof step \(i): side must be 'L' or 'R'"
            }
            if !b32(st["hash"]) { return "proof step \(i): hash is not canonical base64url (32 bytes)" }
        }

        guard let chain = p["cap_chain"]?.asArray else { return "'cap_chain' must be an array" }
        for (i, cv) in chain.enumerated() {
            guard let c = cv.asObject else { return "cap_chain[\(i)] must be an object" }
            if let e = closed(c, ["id", "issuer", "holder", "body_digest", "caveats", "sig", "parent", "alg", "pq_pk", "pq_sig"], "cap_chain[\(i)].") { return e }
            for k in ["id", "issuer", "holder", "body_digest"] where !b32(c[k]) {
                return "cap_chain[\(i)].\(k) is not canonical base64url (32 bytes)"
            }
            // B4 crypto-agility: validate the hop's `alg`/`sig`/`pq_pk`/`pq_sig` per suite, exactly as the
            // leaf. Absent `alg` asserts a 64-byte `sig` and that `pq_pk`/`pq_sig` are absent (byte-identical
            // to the classical pre-B4 hop).
            if let e = PQ.validateSignatureWire(c) { return "cap_chain[\(i)]: \(e)" }
            if let par = c["parent"], !b32(par) { return "cap_chain[\(i)].parent is not canonical base64url (32 bytes)" }
            let ok = (c["caveats"]?.asArray)?.allSatisfy { ($0.asObject.map { isStr($0["type"]) }) ?? false } ?? false
            if !ok { return "cap_chain[\(i)].caveats must be an array of {type,...} objects" }
        }

        guard let at = p["attestation"]?.asObject, isInt(at["epoch"]) else {
            return "'attestation' must be an object with an integer 'epoch'"
        }
        if !(isStr(at["quote_digest"]) && isStr(at["model_id"]) && isStr(at["measurement"]) && isStr(at["operator"])) {
            return "attestation string fields must be strings"
        }

        let pvOk = (p["provenance"]?.asObject).map { pv in
            isStr(pv["causal_hash"]) && (pv["taint_level"]?.isNumber ?? false)
                && ((pv["trusted_refs"]?.asArray)?.allSatisfy { $0.asString != nil } ?? false)
        } ?? false
        if !pvOk { return "'provenance' is malformed" }

        let frOk = (p["freshness"]?.asObject).map { fr in
            isInt(fr["epoch"]) && isStr(fr["beacon_ref"]) && isStr(fr["accumulator_witness"])
        } ?? false
        if !frOk { return "'freshness' is malformed" }

        let rcOk = (p["risk_claim"]?.asObject).map { rc in
            (rc["r"]?.isNumber ?? false) && (rc["inputs"]?.isObject ?? false)
        } ?? false
        if !rcOk { return "'risk_claim' is malformed" }

        // optional signed slots
        if let c = p["caution"] {
            switch c {
            case let .int(i) where i >= 0 && i <= 1: break
            case let .double(d) where d >= 0.0 && d <= 1.0: break
            default: return "'caution' must be a number in [0,1]"
            }
        }
        if let v = p["rationale_commitment"], !b32(v) { return "'rationale_commitment' is not canonical base64url (32 bytes)" }
        if let v = p["tool_binding"], !b32(v) { return "'tool_binding' is not canonical base64url (32 bytes)" }
        if let v = p["progress_step"], !v.isObject { return "'progress_step' must be an object" }
        if let v = p["prohibition_evidence"], !v.isObject && !v.isArray { return "'prohibition_evidence' must be an object or array" }
        if let th = p["threshold"] {
            guard let shares = th.asObject?["shares"]?.asArray else { return "'threshold' must be {shares:[...]}" }
            for (i, sv) in shares.enumerated() {
                guard let s = sv.asObject, isStr(s["role"]) else { return "threshold.shares[\(i)] is malformed" }
                if !b32(s["publicKey"]) { return "threshold.shares[\(i)].publicKey is not canonical base64url (32 bytes)" }
                if !b64sig(s["sig"]) { return "threshold.shares[\(i)].sig is not canonical base64url (64 bytes)" }
            }
        }
        return nil
    }
}
