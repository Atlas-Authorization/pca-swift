import Foundation

/// The signed per-definition changes between two versions of a pack (an evolution record per changed verb). A grant that pinned a
/// definition digest follows a record chain only through steps the registry signed as `equal` or `narrow`; everything else
/// needs the principal. Signing supports every suite the core signer does.
public enum ActionEvolve {
    public static let EVOLUTION_RECORD_KIND = "pca-evolution-record"

    private static func byVerb(_ defs: [JSONValue]) throws -> [String: JObject] {
        var m: [String: JObject] = [:]
        for d in defs {
            guard let v = d.get("verb")?.asString else { throw AK.fail("bad_def", "verb") }
            if m[v] != nil { throw AK.fail("duplicate_def", "verb '\(v)' appears twice") }
            m[v] = AK.o(d)
        }
        return m
    }

    /// The unsigned records that take `prev` to `next` (sorted by verb). A verb rename is `removed` + `added`.
    public static func evolutionRecords(_ ns: String, _ prev: [JSONValue], _ next: [JSONValue], _ reg: TraitRegistry = Actions.coreRegistry,
                                        _ attestationVerified: ((JObject) -> Bool)? = nil) throws -> [JSONValue] {
        let a = try byVerb(prev), b = try byVerb(next)
        var out: [JSONValue] = []
        for verb in Set(a.keys).union(b.keys).sorted(by: { Array($0.utf16).lexicographicallyPrecedes(Array($1.utf16)) }) {
            var r: JObject = ["v": .int(1), "kind": .string(EVOLUTION_RECORD_KIND), "ns": .string(ns), "verb": .string(verb)]
            switch (a[verb], b[verb]) {
            case (nil, let n?):
                r["from"] = .null; r["to"] = .string(try Actions.defDigest(n)); r["class"] = .string("added"); r["reasons"] = .array([])
            case (let o?, nil):
                r["from"] = .string(try Actions.defDigest(o)); r["to"] = .null; r["class"] = .string("removed"); r["reasons"] = .array([])
            case let (o?, n?):
                let from = try Actions.defDigest(o), to = try Actions.defDigest(n)
                if from == to { continue }
                let d = try ActionDiff.diffDefs(o, n, reg, attestationVerified)
                r["from"] = .string(from); r["to"] = .string(to); r["class"] = d.get("class") ?? .null; r["reasons"] = d.get("reasons") ?? .null
            case (nil, nil): continue
            }
            out.append(.object(r))
        }
        return out
    }

    /// Sign the records as the registry under any signature suite the core supports (Ed25519, hybrids, pure PQ).
    public static func signEvolution(_ records: [JSONValue], kid: String, key: PCASuiteKey) throws -> [JSONValue] {
        var out: [JSONValue] = []
        for r in records {
            if let bad = Actions.evolutionRecordError(r, signed: false) { throw PCAProducerError("signEvolutionRecord: \(bad)") }
            guard let msg = IV.message(Actions.EVOLUTION_DOMAIN, r) else { throw PCAProducerError("signEvolutionRecord: the record is outside the strict JSON profile") }
            let sg = try key.sign(msg)
            var sig: JObject = ["alg": .string(key.alg), "kid": .string(kid), "value": .string(sg.sig)]
            if let q = sg.pqSig { sig["pq_value"] = .string(q) }
            var s = AK.o(r)
            s["sig"] = .object(sig)
            out.append(.object(s))
        }
        return out
    }

    /// Nil = the record verifies under the pinned registry keys, else the reason (the order of the reference's checks).
    private static func recordSigError(_ r: JSONValue, _ keys: JSONValue?) -> String? {
        if let e = Actions.evolutionRecordError(r) { return e }
        guard case let .array(ks)? = keys else { return "the registry keys must be an array" }
        let sig = AK.o(AK.o(r)["sig"])
        var found: JObject?
        for k in ks { if case let .object(o) = k, let kid = AK.pres(o, "kid"), kid == sig["kid"] { found = o; break } }
        guard let key = found else { return "no registry key with kid '\(sig["kid"].map { JS.toString($0) } ?? "undefined")'" }
        if let pq = key["pq_pk"], pq.asString == nil { return "the registry key pq_pk must be a string" }
        guard let pk = key["pk"]?.asString, Base64URLStrict.isValid(pk, length: 32) else { return "registry key pk is not canonical base64url (32 bytes)" }
        guard let ka = IV.sigAlg(key["alg"]), ka == IV.sigAlg(sig["alg"]) else { return "sig.alg does not match the pinned key suite" }
        return Actions.verifyEvolutionRecord(r, keys) ? nil : "signature invalid"
    }

    private static func key(_ r: JObject) -> String {
        let dd = Actions.evolutionDiffDigest(.object(r)) ?? "null"
        return "\(JS.toString(r["verb"]))|\(JS.toString(r["from"] ?? .null))|\(JS.toString(r["to"] ?? .null))|\(JS.toString(r["class"]))|\(dd)"
    }

    private static func u16less(_ a: String, _ b: String) -> Bool { Array(a.utf16).lexicographicallyPrecedes(Array(b.utf16)) }

    /// Does `records` EXACTLY describe the change from `prev` to `next`? Every record verifies under the pinned registry keys and names
    /// `ns`; none is missing and none is extra; the class of each is the one the diff computes. Nil = consistent, else the reason.
    public static func evolutionError(_ ns: String, _ prev: [JSONValue], _ next: [JSONValue], _ records: [JSONValue], _ keys: JSONValue?,
                                      _ reg: TraitRegistry = Actions.coreRegistry, _ attestationVerified: ((JObject) -> Bool)? = nil) -> String? {
        do {
            for r in records {
                if let why = recordSigError(r, keys) { return "evolution record: \(why)" }
                if r.get("ns")?.asString.map({ IV.same($0, ns) }) != true { return "evolution record names namespace '\(JS.toString(r.get("ns")))', not '\(ns)'" }
            }
            var want: [String] = [], have: [String] = []
            for r in try evolutionRecords(ns, prev, next, reg, attestationVerified) { want.append(key(AK.o(r))) }
            for r in records { var u = AK.o(r); u[JKey("sig")] = nil; have.append(key(u)) }
            want.sort(by: u16less); have.sort(by: u16less)
            if want.count != have.count { return "evolution has \(have.count) records, the change needs \(want.count)" }
            for i in want.indices where want[i] != have[i] { return "evolution records do not match the computed change (a missing, extra or mis-classified record)" }
            return nil
        } catch let e as ActionKitError {
            return "evolution error: \(e.message)"
        } catch {
            return "evolution error: \(error)"
        }
    }
}
