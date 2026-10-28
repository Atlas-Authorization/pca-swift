import Foundation

// Forbid-wins certificate check (security contract C-241) and linked policy templates (C-242, C-243): a port of
// `certificateConsistent` in packages/pca/src/forbid-certificate.ts and of packages/pca/src/policy-link.ts (the TypeScript is
// authoritative; reason strings are the same). Every function is total; anything malformed fails closed. Where several problems
// exist the reported one follows sorted key order (a Swift dictionary carries no insertion order); the vectors each contain one.

extension PCA {
    private static func isOne(_ v: JSONValue?) -> Bool {
        switch v {
        case .int(1)?: return true
        case let .double(d)?: return d == 1
        default: return false
        }
    }

    private static func u16len(_ s: String) -> Int { s.utf16.count }

    private static func nameOK(_ s: String) -> Bool {
        let u = Array(s.utf8)
        guard !u.isEmpty, u.count <= 64, let f = u.first, f >= 97, f <= 122 else { return false }
        return u.allSatisfy { ($0 >= 97 && $0 <= 122) || ($0 >= 48 && $0 <= 57) || $0 == 95 }
    }

    private static func utf16Less(_ a: String, _ b: String) -> Bool { a.utf16.lexicographicallyPrecedes(b.utf16) }

    // ---- forbid-wins certificate ----------------------------------------------------------------

    /// Whether the certificate's own table entails its decision, winner and shadowed list. `precedence` lists signers from most
    /// to least authoritative. No predicate evaluator is needed.
    public static func forbidCertificateConsistent(_ cert: JSONValue, precedence: [String] = []) -> Bool {
        guard let c = cert.asObject, isOne(c[JKey("v")]), c[JKey("kind")]?.asString == "forbid-wins",
              let raw = c[JKey("clauses")]?.asArray, let winner = c[JKey("winner")]?.asObject,
              let shadowed = c[JKey("shadowed")]?.asArray else { return false }
        if winner[JKey("kind")]?.asString == "malformed" {
            return raw.isEmpty && c[JKey("decision")]?.asString == "deny" && (winner[JKey("id")]?.isNull ?? false) && shadowed.isEmpty
        }
        struct Row { let id: String; let kind: String; let value: String; let signer: String? }
        var table: [Row] = []
        for r in raw {
            guard let o = r.asObject, let id = o[JKey("id")]?.asString, let kind = o[JKey("kind")]?.asString,
                  let value = o[JKey("value")]?.asString,
                  ["permit", "forbid", "escalate"].contains(kind), ["true", "false", "unknown"].contains(value) else { return false }
            table.append(Row(id: id, kind: kind, value: value, signer: o[JKey("signer")]?.asString))
        }
        func rank(_ r: Row) -> Int { r.signer.flatMap { precedence.firstIndex(of: $0) } ?? precedence.count }
        func hit(_ kind: String) -> [Row] { table.filter { $0.kind == kind && $0.value != "false" } }
        let forbids = hit("forbid").sorted { rank($0) != rank($1) ? rank($0) < rank($1) : utf16Less($0.id, $1.id) }
        let permits = hit("permit"), escalates = hit("escalate")
        var win: Row? = nil
        var decision = "deny", kind = "none"
        if let f = forbids.first { win = f; kind = "forbid" }
        else if permits.isEmpty { win = nil }
        else if let e = escalates.first { win = e; decision = "escalate"; kind = "escalate" }
        else { win = permits[0]; decision = "allow"; kind = "permit" }
        var others: [String] = []
        for r in forbids + permits + escalates where !(win != nil && r.id == win!.id && r.kind == win!.kind) { others.append(r.id) }
        let idMatches: Bool = win.map { winner[JKey("id")]?.asString == $0.id } ?? (winner[JKey("id")]?.isNull ?? false)
        return c[JKey("decision")]?.asString == decision && winner[JKey("kind")]?.asString == kind && idMatches
            && shadowed.map { $0.asString } == others.map { Optional($0) }
    }

    // ---- linked templates -------------------------------------------------------------------------

    private static let templateSigDomain = "atlas-pca/policy-template/v1\u{0}"
    private static let tightenSigDomain = "atlas-pca/template-tighten/v1\u{0}"
    private static let nameSource = "^[a-z][a-z0-9_]{0,63}$"

    private static func jsString(_ v: JSONValue?) -> String {
        switch v {
        case let .string(s)?: return s
        case .null?, nil: return "null"
        case let .bool(b)?: return b ? "true" : "false"
        case let .int(i)?: return String(i)
        case let .double(d)?: return String(d)
        default: return "object"
        }
    }

    private static func scan(_ v: JSONValue, _ decl: JObject, _ used: inout Set<String>) -> String? {
        switch v {
        case let .array(a):
            for x in a { if let e = scan(x, decl, &used) { return e } }
            return nil
        case let .object(o):
            for k in o.keys.sorted() where ["__proto__", "constructor", "prototype"].contains(k.s) {
                return "body has the forbidden key '\(k.s)'"
            }
            if let slot = o[JKey("$slot")] {
                for k in o.keys.sorted() where !["$slot", "pre", "post"].contains(k.s) {
                    return "placeholder has unknown member '\(k.s)'"
                }
                guard let name = slot.asString, decl[JKey(name)] != nil else {
                    return "placeholder names undeclared slot '\(jsString(slot))'"
                }
                for k in ["pre", "post"] {
                    if let p = o[JKey(k)], p.asString == nil { return "placeholder \(k) must be a string" }
                }
                used.insert(name)
                return nil
            }
            for k in o.keys.sorted() { if let e = scan(o[k]!, decl, &used) { return e } }
            return nil
        default:
            return nil
        }
    }

    /// nil for a well-formed template definition, else the first problem.
    public static func templateDefError(_ def: JSONValue) -> String? {
        guard let d = def.asObject else { return "template must be an object" }
        if !isOne(d[JKey("v")]) || d[JKey("kind")]?.asString != "pca-policy-template" { return "template v / kind mismatch" }
        guard let id = d[JKey("id")]?.asString, nameOK(id) else { return "template id must match \(nameSource)" }
        guard let ver = d[JKey("version")]?.asString, !ver.isEmpty, u16len(ver) <= 64 else { return "template version must be a string of 1..64 characters" }
        guard let slots = d[JKey("slots")]?.asObject else { return "slots must be an object" }
        if slots.count > 32 { return "more than 32 slots" }
        for n in slots.keys.sorted() {
            if !nameOK(n.s) { return "slot name '\(n.s)' must match \(nameSource)" }
            guard let s = slots[n]?.asObject else { return "slot '\(n.s)' must be an object" }
            let ty = s[JKey("type")]?.asString ?? ""
            if !["string", "integer", "set"].contains(ty) { return "slot '\(n.s)'.type must be string, integer or set" }
            if ty == "set" && s[JKey("values")]?.asArray == nil { return "set slot '\(n.s)' needs a closed values list" }
            if let vals = s[JKey("values")] {
                guard let a = vals.asArray, a.count <= 64, a.allSatisfy({ $0.asString != nil }) else { return "slot '\(n.s)'.values must be a list of strings" }
            }
            if ty == "integer" {
                for k in ["min", "max"] { if let m = s[JKey(k)], m.safeInt == nil { return "slot '\(n.s)'.\(k) must be a safe integer" } }
            }
        }
        guard let body = d[JKey("body")]?.asObject, body[JKey("predicates")]?.asArray != nil else { return "body.predicates must be an array" }
        if let c = body[JKey("caveats")], c.asArray == nil { return "body.caveats must be an array" }
        var used = Set<String>()
        if let e = scan(.object(body), slots, &used) { return e }
        for n in slots.keys.sorted() where !used.contains(n.s) { return "slot '\(n.s)' is declared but never used" }
        return nil
    }

    /// hashCanonical (strict) of the definition; nil when it is out of profile.
    public static func templateDigest(_ def: JSONValue) -> String? {
        guard let b = try? Canonical.canonicalBytes(def) else { return nil }
        return Base64URLStrict.encode(Canonical.sha256(b))
    }

    private static func message(_ domain: String, _ digest: String) -> [UInt8] {
        Array(domain.utf8) + Canonical.sha256(Array(digest.utf8))
    }

    /// Verify a signed template `{def, signer, sig}`: nil when it verifies, else the reason.
    public static func verifyTemplate(_ t: JSONValue, trusted: [String]) -> String? {
        let def = t.get("def") ?? .null
        if let e = templateDefError(def) { return e }
        guard let signer = t.get("signer")?.asString, trusted.contains(signer) else { return "template signer is not trusted" }
        guard let digest = templateDigest(def), let sig = t.get("sig")?.asString,
              Ed25519Strict.verifyB64u(signer, message(templateSigDomain, digest), sig) else { return "bad template signature" }
        return nil
    }

    /// nil for a well-formed tighten overlay: it may only add `where` conditions and caveats.
    public static func tightenOverlayError(_ o: JSONValue) -> String? {
        guard let m = o.asObject else { return "overlay must be an object" }
        if !isOne(m[JKey("v")]) || m[JKey("kind")]?.asString != "pca-template-tighten" { return "overlay v / kind mismatch" }
        for k in m.keys.sorted() where !["v", "kind", "template_id", "version_digest", "add_where", "add_caveats"].contains(k.s) {
            return "overlay has unknown member '\(k.s)' (an overlay can only add where conditions and caveats)"
        }
        guard let id = m[JKey("template_id")]?.asString, nameOK(id) else { return "overlay template_id invalid" }
        guard let vd = m[JKey("version_digest")]?.asString, !vd.isEmpty else { return "overlay version_digest invalid" }
        if let w = m[JKey("add_where")], !(w.asArray?.allSatisfy { $0.isObject } ?? false) { return "overlay add_where must be a list of conditions" }
        if let w = m[JKey("add_caveats")], !(w.asArray?.allSatisfy { $0.get("type")?.asString != nil } ?? false) { return "overlay add_caveats must be a list of caveats" }
        return nil
    }

    /// Verify a signed overlay `{overlay, signer, sig}`: nil when it verifies, else the reason.
    public static func verifyTighten(_ t: JSONValue, trusted: [String]) -> String? {
        let ov = t.get("overlay") ?? .null
        if let e = tightenOverlayError(ov) { return e }
        guard let signer = t.get("signer")?.asString, trusted.contains(signer) else { return "overlay signer is not trusted" }
        guard let b = try? Canonical.canonicalBytes(ov), let sig = t.get("sig")?.asString,
              Ed25519Strict.verifyB64u(signer, message(tightenSigDomain, Base64URLStrict.encode(Canonical.sha256(b))), sig) else { return "bad overlay signature" }
        return nil
    }

    private static func slotValueError(_ name: String, _ d: JObject, _ v: JSONValue?) -> String? {
        let values = d[JKey("values")]?.asArray?.compactMap { $0.asString }
        switch d[JKey("type")]?.asString ?? "" {
        case "string":
            guard let s = v?.asString, !s.isEmpty, u16len(s) <= 256 else { return "slot '\(name)' must be a string of 1..256 characters" }
            if let vs = values, !vs.contains(s) { return "slot '\(name)' is outside its closed value set" }
        case "integer":
            guard let n = v?.safeInt else { return "slot '\(name)' must be a safe integer" }
            if let m = d[JKey("min")]?.safeInt, n < m { return "slot '\(name)' is below its minimum" }
            if let m = d[JKey("max")]?.safeInt, n > m { return "slot '\(name)' is above its maximum" }
        default:
            guard let a = v?.asArray, !a.isEmpty, a.count <= 64, a.allSatisfy({ $0.asString != nil }) else { return "slot '\(name)' must be a non-empty list of strings" }
            let strs = a.compactMap { $0.asString }
            if Set(strs).count != strs.count { return "slot '\(name)' has duplicate members" }
            if let vs = values, strs.contains(where: { !vs.contains($0) }) { return "slot '\(name)' has a member outside its closed set" }
        }
        return nil
    }

    private struct Refusal: Error { let reason: String }

    private static func fill(_ v: JSONValue, _ slots: JObject, _ key: String?) throws -> JSONValue {
        switch v {
        case let .array(a): return .array(try a.map { try fill($0, slots, key) })
        case let .object(o):
            if let name = o[JKey("$slot")]?.asString {
                let val = slots[JKey(name)] ?? .null
                if key == "verb" || key == "resource" {
                    let items = val.asArray ?? [val]
                    if items.contains(where: { $0.asString.map { $0.contains("*") || $0.hasPrefix("re:") } ?? false }) {
                        throw Refusal(reason: "slot '\(name)' would inject a wildcard or regex matcher into a verb or resource")
                    }
                }
                let pre = o[JKey("pre")]?.asString ?? "", post = o[JKey("post")]?.asString ?? ""
                if pre.isEmpty && post.isEmpty { return val }
                guard let s = val.asString, !s.contains("*"), !s.contains("\u{0}") else {
                    throw Refusal(reason: "slot '\(name)' cannot be spliced into a string (wildcard or non-string)")
                }
                let out = pre + s + post
                if pre.isEmpty && out.hasPrefix("re:") { throw Refusal(reason: "slot '\(name)' would inject a regex matcher") }
                return .string(out)
            }
            var m = JObject()
            for (k, x) in o { m[k] = try fill(x, slots, k.s) }
            return .object(m)
        default: return v
        }
    }

    /// Fill a template's slots. Refuses unfilled, extra, mistyped and out-of-domain slots and any slot value that would inject a
    /// wildcard or a regex into a verb or resource. Returns `(policy, nil)` or `(nil, reason)`.
    public static func instantiateTemplate(_ def: JSONValue, _ slots: JSONValue) -> (policy: JSONValue?, reason: String?) {
        if let e = templateDefError(def) { return (nil, e) }
        guard let sl = slots.asObject else { return (nil, "slots must be an object") }
        guard let decl = def.get("slots")?.asObject else { return (nil, "slots must be an object") }
        for k in sl.keys.sorted() where decl[k] == nil { return (nil, "slot '\(k.s)' is not declared by the template") }
        for n in decl.keys.sorted() {
            guard let v = sl[n] else { return (nil, "slot '\(n.s)' is not filled") }
            if let e = slotValueError(n.s, decl[n]?.asObject ?? [:], v) { return (nil, e) }
        }
        do {
            guard let body = try fill(def.get("body") ?? .null, sl, nil).asObject else { return (nil, "instantiation error (fail closed)") }
            return (.object([JKey("predicates"): body[JKey("predicates")] ?? .array([]), JKey("caveats"): body[JKey("caveats")] ?? .array([])]), nil)
        } catch let r as Refusal {
            return (nil, r.reason)
        } catch {
            return (nil, "instantiation error (fail closed)")
        }
    }

    /// nil for a well-formed reference `{template_id, version_digest, slots}`.
    public static func templateRefError(_ r: JSONValue) -> String? {
        guard let m = r.asObject else { return "template_ref must be an object" }
        for k in m.keys.sorted() where !["template_id", "version_digest", "slots", "bind_params_digest"].contains(k.s) { return "template_ref has unknown member '\(k.s)'" }
        guard let id = m[JKey("template_id")]?.asString, nameOK(id) else { return "template_ref.template_id invalid" }
        guard let vd = m[JKey("version_digest")]?.asString, !vd.isEmpty, vd.utf8.count <= 128 else { return "template_ref.version_digest invalid" }
        if m[JKey("slots")] != nil && m[JKey("bind_params_digest")] != nil { return "template_ref has both slots and bind_params_digest" }
        if let b = m[JKey("bind_params_digest")] {
            if let bs = b.asString, !bs.isEmpty, bs.utf8.count <= 128 { return nil }
            return "template_ref.bind_params_digest invalid"
        }
        if m[JKey("slots")]?.asObject == nil { return "template_ref.slots must be an object" }
        return nil
    }

    /// Rebuild the policy a reference denotes from a registry `{templates, overlays?, trusted}`.
    public static func resolveLink(_ ref: JSONValue, registry reg: JSONValue) -> (policy: JSONValue?, overlays: Int, reason: String?) {
        if let e = templateRefError(ref) { return (nil, 0, e) }
        let trusted = reg.get("trusted")?.asArray?.compactMap { $0.asString } ?? []
        let digest = ref.get("version_digest")?.asString ?? ""
        guard let t = reg.get("templates")?.get(digest) else { return (nil, 0, "template version is not in the registry") }
        if let e = verifyTemplate(t, trusted: trusted) { return (nil, 0, e) }
        let def = t.get("def") ?? .null
        if templateDigest(def) != digest { return (nil, 0, "registry entry does not match its digest") }
        if def.get("id") != ref.get("template_id") { return (nil, 0, "template id does not match the reference") }
        var slots = ref.get("slots") ?? .null
        if let bd = ref.get("bind_params_digest")?.asString {
            guard let bound = reg.get("params")?.get(bd), bound.isObject else { return (nil, 0, "parameter object is not available") }
            if templateDigest(bound) != bd { return (nil, 0, "parameter object does not match bind_params_digest") }
            slots = bound
        }
        let inst = instantiateTemplate(def, slots)
        guard let pol = inst.policy?.asObject else { return (nil, 0, inst.reason) }
        var predicates = pol[JKey("predicates")]?.asArray ?? []
        var caveats = pol[JKey("caveats")]?.asArray ?? []
        var applied = 0
        for o in reg.get("overlays")?.asArray ?? [] {
            guard let ov = o.get("overlay"), ov.isObject, ov.get("version_digest") == ref.get("version_digest"),
                  ov.get("template_id") == ref.get("template_id") else { continue }
            if let e = verifyTighten(o, trusted: trusted) { return (nil, 0, e) }
            let add = ov.get("add_where")?.asArray ?? []
            predicates = predicates.map { p in
                var m = p.asObject ?? [:]
                m[JKey("where")] = .array((m[JKey("where")]?.asArray ?? []) + add)
                return .object(m)
            }
            caveats += ov.get("add_caveats")?.asArray ?? []
            applied += 1
        }
        return (.object([JKey("predicates"): .array(predicates), JKey("caveats"): .array(caveats)]), applied, nil)
    }
}
