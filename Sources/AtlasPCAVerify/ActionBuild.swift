import Foundation

/// The build step of an authoring pipeline: from loaded defs to the unsigned schema, the pack, the policy cards, the ontology fragment, the MCP tool map and
/// generated TypeScript declarations, plus the signing and consistency checks of the pack. Every output is a pure function of the defs and the trait registry.
public enum ActionBuild {
    /// Domain of the pack signature; it differs from the schema's, so a signature of one is never valid for the other.
    public static let PACK_SIGN_DOMAIN = Actions.PACK_DIGEST_DOMAIN + "\u{0}"

    private static func u16less(_ a: String, _ b: String) -> Bool { Array(a.utf16).lexicographicallyPrecedes(Array(b.utf16)) }
    private static func sortedByVerb(_ defs: [JSONValue]) throws -> [JSONValue] {
        var t: [(String, JSONValue)] = []
        for d in defs { guard let v = d.get("verb")?.asString else { throw AK.fail("bad_def", "verb") }; t.append((v, d)) }
        return t.sorted { u16less($0.0, $1.0) }.map { $0.1 }
    }

    /// Build every output: `{schema, pack, cards, ontology, mcp: {tools}, types}`. `cfg`: `{ns, version, stability, site, aud}`. Throws on a pack
    /// above the unsharded limit, a duplicate verb, or a unit conflict (never a partial build).
    public static func buildArtifacts(_ defsIn: [JSONValue], _ cfg: JObject, _ reg: TraitRegistry = Actions.coreRegistry, _ attestationVerified: ((JObject) -> Bool)? = nil) throws -> JSONValue {
        let defs = try sortedByVerb(defsIn)
        if defs.count > ActionPacks.MAX_PACK_DEFS { throw AK.fail("pack_too_large", "a pack above \(ActionPacks.MAX_PACK_DEFS) defs must be sharded (\(defs.count) given)") }
        if defs.count > 1 { for i in 1..<defs.count where defs[i].get("verb") == defs[i - 1].get("verb") { throw AK.fail("duplicate_verb", "verb '\(JS.toString(defs[i].get("verb")))' appears twice") } }
        let root = try Actions.packRoot(try defs.map { try Actions.defDigest(AK.o($0)) })
        let meta: JObject = ["site": cfg["site"] ?? .null, "aud": cfg["aud"] ?? .null, "version": cfg["version"] ?? .null,
                             "pack": AK.obj(["ns": cfg["ns"] ?? .null, "version": cfg["version"] ?? .null, "root": .string(root)])]
        let schema = try ActionDerive.toSchemaDoc(defs, reg, meta, attestationVerified)
        let pack = AK.obj(["v": .int(1), "kind": .string("pca-action-pack"), "ns": cfg["ns"] ?? .null, "version": cfg["version"] ?? .null, "stability": cfg["stability"] ?? .null,
                           "traits_digest": .string(Actions.traitsDigest(reg)), "roles_digest": .string(Actions.tablesDigest()), "rules_digest": .string(try ActionLint.lintRulesDigest()), "root": .string(root),
                           "defs": .array(defs), "prev": .null, "evolution": .array([])])
        var cards: [JSONValue] = []
        var tools: JObject = [:]
        for dv in defs {
            let d = AK.o(dv)
            let eff = try ActionEffective.effective(d, reg, attestationVerified)
            cards.append(try ActionDerive.cardOf(d, eff, reg))
            if let mcp = JS.present(AK.o(d["bindings"])["mcp"]) {
                guard let tool = mcp.get("tool")?.asString else { throw AK.fail("bad_def", "mcp.tool") }
                tools[JKey(tool)] = AK.obj(["verb": d["verb"] ?? .null, "annotations": ActionDerive.mcpAnnotationsOf(d, eff)])
            }
        }
        return AK.obj(["schema": schema, "pack": pack, "cards": .array(cards), "ontology": try ActionDerive.toOntology(defs, reg, attestationVerified),
                       "mcp": AK.obj(["tools": .object(tools)]), "types": .string(try generateTypes(defs))])
    }

    /// The tool-to-action map of the defs' MCP bindings: `(tool, args) -> {verb, resource}`, or nil when the tool is unknown or the call does not bind.
    public static func toolActionMapOf(_ defs: [JSONValue]) -> (String, JObject) throws -> JSONValue? {
        var m: [JKey: JObject] = [:]
        for d in defs { if let mcp = JS.present(AK.o(d.get("bindings"))["mcp"]), let t = mcp.get("tool")?.asString { m[JKey(t)] = AK.o(d) } }
        return { tool, args in
            guard let d = m[JKey(tool)] else { return nil }
            let r = try ActionDerive.operationOf(d, args)
            if r.get("ok") != .bool(true) { return nil }
            return AK.obj(["verb": r.get("op")?.get("verb") ?? .null, "resource": r.get("op")?.get("resource") ?? .null])
        }
    }

    // ---- generated types ----

    private static func pascal(_ s: String) -> String {
        var b = ""
        for x in s.split(omittingEmptySubsequences: false, whereSeparator: { $0 == "." || $0 == "_" }) where !x.isEmpty { b += String(x.prefix(1)).uppercased() + String(x.dropFirst()) }
        return b
    }

    private static func isIdent(_ k: String) -> Bool {
        let u = Array(k.utf8)
        guard let f = u.first, (f >= 65 && f <= 90) || (f >= 97 && f <= 122) || f == 95 else { return false }
        return u.allSatisfy { ($0 >= 65 && $0 <= 90) || ($0 >= 97 && $0 <= 122) || ($0 >= 48 && $0 <= 57) || $0 == 95 }
    }
    private static func key(_ k: String) -> String { isIdent(k) ? k : JS.stringify(.string(k)) }
    private static func union(_ values: JSONValue?) -> String { AK.arr(values).map { JS.stringify($0) }.joined(separator: " | ") }

    private static func tsType(_ p: JObject) -> String {
        let t = p["type"]
        if t == .string("integer") || t == .string("duration") { return "number" }
        if t == .string("boolean") { return "boolean" }
        if t == .string("set") {
            let u = p["values"]?.asArray != nil ? union(p["values"]) : ""
            return "Array<" + (u.isEmpty ? "string" : u) + ">"
        }
        if t == .string("array") { return p["items"] == .string("integer") ? "number[]" : "string[]" }
        return AK.pres(p, "values") != nil ? union(p["values"]) : "string"
    }

    private final class Node {
        var leaf: JObject?
        var kids: [String: Node] = [:]
    }

    private static func render(_ n: Node, _ indent: String) -> String {
        var lines: [String] = []
        for k in n.kids.keys.sorted(by: u16less) {
            let c = n.kids[k]!
            if let leaf = c.leaf { lines.append(indent + key(k) + (leaf["required"] == .bool(false) ? "?" : "") + ": " + tsType(leaf) + ";") }
            else { lines.append(indent + key(k) + ": {\n" + render(c, indent + "  ") + "\n" + indent + "};") }
        }
        return lines.joined(separator: "\n")
    }

    /// TypeScript declarations for typed call sites: one params interface per verb, `ActionParams` and `ActionVerb`.
    public static func generateTypes(_ defs: [JSONValue]) throws -> String {
        var out: [String] = ["// Generated by `pca actions build`. Do not edit.", ""]
        var names: [String] = []
        for d in try sortedByVerb(defs) {
            let root = Node()
            let ps = AK.o(d.get("params"))
            for name in AK.sortedKeys(ps) {
                var n = root
                let segs = name.components(separatedBy: ".")
                for (i, sg) in segs.enumerated() {
                    if n.kids[sg] == nil { n.kids[sg] = Node() }
                    n = n.kids[sg]!
                    if i == segs.count - 1 { n.leaf = AK.o(ps[JKey(name)]) }
                }
            }
            guard let verb = d.get("verb")?.asString else { throw AK.fail("bad_def", "verb") }
            let iface = pascal(verb) + "Params"
            names.append("  " + JS.stringify(.string(verb)) + ": " + iface + ";")
            out.append("export interface \(iface) {")
            out.append(render(root, "  "))
            out.append("}")
            out.append("")
        }
        out.append("export interface ActionParams {")
        out += names
        out.append("}")
        out.append("")
        out.append("export type ActionVerb = keyof ActionParams;")
        out.append("")
        return out.joined(separator: "\n")
    }

    // ---- pack signing and consistency ----

    private static func packMessage(_ body: JObject) throws -> [UInt8] {
        guard let m = IV.message(PACK_SIGN_DOMAIN, .object(body)) else { throw AK.fail("bad_pack", "the pack is outside the strict JSON profile") }
        return m
    }

    /// Nil when the pack is internally consistent: every def valid and sorted-unique, the Merkle root and digests recomputed.
    public static func packConsistencyError(_ p: JSONValue?, _ reg: TraitRegistry = Actions.coreRegistry) -> String? {
        guard case let .object(q)? = p else { return "the pack must be an object" }
        if q["kind"] != .string("pca-action-pack") || IV.num(q["v"]) != 1 { return "not a pca-action-pack v1" }
        guard case let .array(defs)? = q["defs"], defs.count <= ActionPacks.MAX_PACK_DEFS else { return "defs must be a list within the unsharded limit" }
        var seen: [JSONValue] = []
        for d in defs {
            if let e = Actions.validateDef(d) { return "def " + (AK.pres(AK.o(d), "verb") != nil ? JS.toString(d.get("verb")) : "?") + ": " + e }
            let v = d.get("verb") ?? .null
            if seen.contains(v) { return "verb '\(JS.toString(v))' is defined twice" }
            seen.append(v)
        }
        do {
            let root = try Actions.packRoot(try defs.map { try Actions.defDigest(AK.o($0)) })
            if q["root"] != .string(root) { return "the pack root does not match its defs" }
        } catch let e as ActionKitError { return "malformed pack: " + e.message } catch { return "malformed pack: \(error)" }
        if q["traits_digest"] != .string(Actions.traitsDigest(reg)) { return "traits_digest does not match the trait registry" }
        return nil
    }

    /// Sign a pack as the registry (Ed25519). Refuses an inconsistent pack.
    public static func signPack(_ pack: JObject, kid: String, key: PCAEdKey, _ reg: TraitRegistry = Actions.coreRegistry) throws -> JSONValue {
        if let bad = packConsistencyError(.object(pack), reg) { throw AK.fail("bad_pack", "signPack: \(bad)") }
        var body = pack
        body[JKey("sig")] = nil
        var out = body
        out["sig"] = AK.obj(["alg": .string("ed25519"), "kid": .string(kid), "value": .string(Base64URLStrict.encode(try key.sign(try packMessage(body))))])
        return .object(out)
    }

    /// The registry key entry for a signer: `{kid, alg, pk}`.
    public static func packKeyOf(_ kid: String, _ key: PCAEdKey) -> JSONValue { AK.obj(["kid": .string(kid), "alg": .string("ed25519"), "pk": .string(key.id)]) }

    /// Verify a signed pack against pinned registry keys: consistency, the key entry by kid, and the signature. Returns `{ok}` or `{ok:false, reason}`.
    public static func verifyPack(_ pack: JSONValue?, _ keys: JSONValue?, _ reg: TraitRegistry = Actions.coreRegistry) -> JSONValue {
        func no(_ r: String) -> JSONValue { AK.obj(["ok": .bool(false), "reason": .string(r)]) }
        if let bad = packConsistencyError(pack, reg) { return no(bad) }
        var body = AK.o(pack)
        let sigv = body.removeValue(forKey: JKey("sig"))
        guard case let .object(sig)? = sigv, sig["alg"] == .string("ed25519"), let kid = sig["kid"]?.asString, let value = sig["value"]?.asString else { return no("missing or malformed signature") }
        guard let k = AK.arr(keys).first(where: { $0.get("kid") == .string(kid) }) else { return no("no registry key with kid '\(kid)'") }
        guard k.get("alg") == .string("ed25519"), let pk = k.get("pk")?.asString, Base64URLStrict.isValid(pk, length: 32) else { return no("the registry key entry is malformed") }
        guard Base64URLStrict.isValid(value, length: 64), let msg = try? packMessage(body), Ed25519Strict.verifyB64u(pk, msg, value) else { return no("pack signature invalid") }
        return AK.obj(["ok": .bool(true)])
    }
}

/// Building, chaining and signing action packs, and verifying an upgrade between two versions.
public enum ActionPacks {
    public static let PACK_SIG_DOMAIN = Actions.PACK_SIG_DOMAIN
    public static let PACK_SHARD_KIND = "pca-action-pack-shard"
    /// Largest shard the builder writes by default.
    public static let DEFAULT_SHARD_DEFS = 512
    /// Most defs an inline pack carries.
    public static let MAX_PACK_DEFS = 4096

    /// Sign `body` under `domain` as the registry: `{alg, kid, value[, pq_value]}`.
    public static func signRegistryDoc(_ domain: String, _ body: JSONValue, kid: String, key: PCASuiteKey) throws -> JSONValue {
        guard let msg = IV.message(domain, body) else { throw AK.fail("bad_doc", "the document is outside the strict JSON profile") }
        let sg = try key.sign(msg)
        var sig: JObject = ["alg": .string(key.alg), "kid": .string(kid), "value": .string(sg.sig)]
        if let q = sg.pqSig { sig["pq_value"] = .string(q) }
        return .object(sig)
    }

    private static func u16less(_ a: String, _ b: String) -> Bool { Array(a.utf16).lexicographicallyPrecedes(Array(b.utf16)) }

    /// Shard names are the resource family (the first segment of `resource.type`) of the defs, split in order into chunks of `max`
    /// (nil = DEFAULT_SHARD_DEFS). Returns a list of `{name, defs}`.
    public static func shardDefs(_ defs: [JSONValue], _ max: JSONValue?) throws -> [JSONValue] {
        var m = Double(DEFAULT_SHARD_DEFS)
        if let mv = JS.present(max) { if let i = IV.int(mv) { m = Double(i) } else { m = Double.nan } }
        if m.isNaN || m < 1 { throw AK.fail("bad_shard_size", "the shard size must be a positive integer") }
        let mx = Int(Swift.min(m, Double(Int32.max)))
        var fam: [String: [JSONValue]] = [:]
        for d in defs {
            guard let t = d.get("resource")?.get("type")?.asString else { throw AK.fail("bad_def", "resource.type") }
            let u = Array(t.utf16)
            let family = u.firstIndex(of: 46).map { String(decoding: u[..<$0], as: UTF16.self) } ?? t
            fam[family, default: []].append(d)
        }
        var out: [JSONValue] = []
        for family in fam.keys.sorted(by: u16less) {
            let l = fam[family]!
            var n = 1, i = 0
            while i < l.count {
                out.append(AK.obj(["name": .string(l.count > mx ? "\(family)-\(n)" : family), "defs": .array(Array(l[i..<Swift.min(i + mx, l.count)]))]))
                i += mx
                n += 1
            }
        }
        return out
    }

    private static func sortedUniqueDefsError(_ defs: [JSONValue]) -> String? {
        for i in defs.indices {
            if let e = Actions.validateDef(defs[i]) { return "def \(i): \(e)" }
            if i > 0, !u16less(defs[i - 1].get("verb")?.asString ?? "", defs[i].get("verb")?.asString ?? "") {
                return "defs must be sorted by verb and unique (at '\(JS.toString(defs[i].get("verb")))')"
            }
        }
        return nil
    }

    /// Build, chain and sign a pack. `a` holds `ns, version, stability, defs, source, kid` and optionally `prev: {pack, shards?}` and `shard: true | {max?}`;
    /// `shardUri` names a shard's location (nil = `shards/<name>.json`). Returns `{pack, shards}`. Throws ActionKitError on any inconsistency.
    public static func buildPack(_ a: JObject, key: PCASuiteKey, reg: TraitRegistry? = nil, _ attestationVerified: ((JObject) -> Bool)? = nil, shardUri: ((String) -> String)? = nil) throws -> JSONValue {
        let r = reg ?? Actions.coreRegistry
        var defs: [JSONValue] = []
        for d in AK.arr(a["defs"]) { defs.append(d) }
        var t: [(String, JSONValue)] = []
        for d in defs { guard let v = d.get("verb")?.asString else { throw AK.fail("bad_pack", "def without a verb") }; t.append((v, d)) }
        defs = t.sorted { u16less($0.0, $1.0) }.map { $0.1 }
        if let de = sortedUniqueDefsError(defs) { throw AK.fail("bad_pack", de) }
        if defs.isEmpty { throw AK.fail("empty_pack", "a pack has at least one def") }
        guard let ns = a["ns"]?.asString, let version = a["version"]?.asString, let kid = a["kid"]?.asString else { throw AK.fail("bad_pack", "ns, version and kid are required") }
        let prev: JObject? = a["prev"]?.asObject
        var prevDefs: [JSONValue] = []
        if let pv = prev {
            let pp = AK.o(pv["pack"])
            prevDefs = try Actions.packDefs(pp, AK.o(pv["shards"]))
            if pp["ns"] != a["ns"] { throw AK.fail("bad_chain", "the previous pack is of another namespace") }
            guard let c = Actions.compareVersions(version, pp["version"]?.asString ?? ""), c > 0 else { throw AK.fail("bad_chain", "the version must increase") }
        }
        let records = try ActionEvolve.evolutionRecords(ns, prevDefs, defs, r, attestationVerified)
        let evolution = try ActionEvolve.signEvolution(records, kid: kid, key: key)
        let root = try Actions.packRoot(try defs.map { try Actions.defDigest(AK.o($0)) })
        let wantShards = (a[JKey("shard")] != nil && a["shard"] != .bool(false)) || defs.count > MAX_PACK_DEFS
        var shards: JObject = [:]
        var body: JSONValue = .array(defs)
        if wantShards {
            let opts = a["shard"]?.asObject != nil ? a["shard"] : JSONValue.object([:])
            var refs: [JSONValue] = []
            for s0 in try shardDefs(defs, opts?.get("max")) {
                guard let name = s0.get("name")?.asString else { continue }
                let doc = AK.obj(["v": .int(1), "kind": .string(PACK_SHARD_KIND), "ns": .string(ns), "version": .string(version), "name": .string(name), "defs": s0.get("defs") ?? .array([])])
                shards[JKey(name)] = doc
                guard let dg = Actions.shardDigest(doc) else { throw AK.fail("bad_pack", "a shard is outside the strict JSON profile") }
                refs.append(AK.obj(["name": .string(name), "digest": .string(dg), "uri": .string(shardUri?(name) ?? "shards/\(name).json")]))
            }
            body = AK.obj(["shards": .array(refs)])
        }
        var unsigned: JObject = ["v": .int(1), "kind": .string("pca-action-pack"), "ns": .string(ns), "version": .string(version), "stability": a["stability"] ?? .null,
                                 "traits_digest": .string(Actions.traitsDigest(r)), "roles_digest": .string(Actions.tablesDigest()), "rules_digest": .string(Actions.rulesDigest()),
                                 "root": .string(root), "defs": body, "prev": .null, "evolution": .array(evolution)]
        if let s = a["source"] { unsigned["source"] = s }
        if let pv = prev {
            guard let pd = Actions.packDigest(AK.o(pv["pack"])) else { throw AK.fail("bad_pack", "the previous pack is outside the strict JSON profile") }
            unsigned["prev"] = .string(pd)
        }
        if let pe = Actions.packShapeError(.object(unsigned), signed: false) { throw AK.fail("bad_pack", pe) }
        var pack = unsigned
        pack["sig"] = try signRegistryDoc(PACK_SIG_DOMAIN, .object(unsigned), kid: kid, key: key)
        return AK.obj(["pack": .object(pack), "shards": .object(shards)])
    }

    /// Verify `next` as the successor of `prev`: both verify, same namespace, `next.prev` is `prev`'s digest, the version increases, and the signed
    /// evolution is EXACTLY the computed change. Returns `{ok}` or `{ok:false, reason}`.
    public static func verifyUpgrade(_ prev: JObject, _ next: JObject, _ keys: JSONValue?, _ prevShards: JObject?, _ shards: JObject?, _ attestationVerified: ((JObject) -> Bool)? = nil) -> JSONValue {
        func no(_ r: String) -> JSONValue { AK.obj(["ok": .bool(false), "reason": .string(r)]) }
        let a = Actions.verifyPack(.object(prev), keys: keys, shards: prevShards ?? [:])
        if !a.ok { return no("previous pack: \(a.reason)") }
        let b = Actions.verifyPack(.object(next), keys: keys, shards: shards ?? [:])
        if !b.ok { return no("pack: \(b.reason)") }
        if next["ns"] != prev["ns"] { return no("the packs are of different namespaces") }
        if next["prev"] != .string(a.digest) { return no("chain gap: prev does not name the previous pack") }
        guard let nv = next["version"]?.asString, let pv = prev["version"]?.asString, let c = Actions.compareVersions(nv, pv), c > 0 else { return no("the version does not increase") }
        let ee = ActionEvolve.evolutionError(next["ns"]?.asString ?? "", a.defs, b.defs, AK.arr(next["evolution"]), keys, Actions.coreRegistry, attestationVerified)
        return ee == nil ? AK.obj(["ok": .bool(true)]) : no(ee!)
    }
}

/// The transparency statement of a signed pack: the payload the registry signs into a transparency log (small: the digest, not the pack).
public enum ActionTransparency {
    public static let PACK_STATEMENT_CONTENT_TYPE = "application/pca-action-pack+json"

    public static func packStatementPayload(_ p: JObject) -> JSONValue {
        AK.obj(["v": .int(1), "kind": .string("pca-action-pack-statement"), "ns": p["ns"] ?? .null, "version": p["version"] ?? .null,
                "digest": Actions.packDigest(p).map { .string($0) } ?? .null, "root": p["root"] ?? .null, "prev": p["prev"] ?? .null])
    }
}
