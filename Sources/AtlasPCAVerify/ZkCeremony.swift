import Foundation

// Trusted-setup bookkeeping for the Groth16 circuits (pure: no file or process access).
//
// A verifying key is only as trustworthy as the ceremony that made it. This answers one question: "was this key produced by a multi-party
// ceremony we can check?". The answer is `multi-party` only when the caller supplies a transcript, pins its SHA-256 (published out of band
// by the ceremony coordinator), the transcript is well-formed (at least two distinct contributions chained from the initial key, a public
// random beacon applied last) and names exactly this verifying key. Everything else is `single-party`. The cryptographic check of the
// contributions themselves is the ceremony tooling's; nothing here claims more than the pinned transcript says.
//
// The checks take JSON values as presented (a transcript is a document from outside), and compare them the way the reference does: a
// hash member is read through its string form, members are compared strictly, and two arrays or objects are never equal.
extension PCAZk {
    static func hex(_ b: [UInt8]) -> String {
        let digits = Array("0123456789abcdef".utf8)
        var out = [UInt8]()
        out.reserveCapacity(b.count * 2)
        for x in b { out.append(digits[Int(x >> 4)]); out.append(digits[Int(x & 15)]) }
        return String(decoding: out, as: UTF8.self)
    }

    static func isHex(_ b: ArraySlice<UInt8>) -> Bool { b.allSatisfy { ($0 >= 0x30 && $0 <= 0x39) || ($0 >= 0x61 && $0 <= 0x66) } }

    /// `^[0-9a-f]{64}$` over the value's string form (an absent member reads "undefined").
    static func isH64(_ v: JSONValue?) -> Bool {
        let b = Array(JS.toString(v).utf8)
        return b.count == 64 && isHex(b[...])
    }

    static func sha256Hex(_ v: JSONValue?) throws -> String {
        guard let v = v else { throw JSError("canonicalize: unsupported type undefined") }
        return hex(Canonical.sha256(Array(try Canonical.canonicalizeStrict(v).utf8)))
    }

    /// Id of a verifying key: `vk_` + SHA-256 of its canonical JSON. A new setup always yields a new id.
    public static func vkId(_ vkey: JSONValue?) throws -> String { try "vk_" + sha256Hex(vkey) }

    /// What a verifying key was built from: `{circuit, sourceSha256, r1csSha256, vkId}` from `{circuit, sourceSha256, r1csSha256, vkey}`.
    /// Throws on an empty circuit id or a hash that is not a SHA-256.
    public static func circuitProvenance(_ args: JSONValue?) throws -> JSONValue {
        guard let a = JS.present(args) else { throw JSError("circuitProvenance: no arguments") }
        let circuit = JSLoose.get(a, "circuit"), source = JSLoose.get(a, "sourceSha256"), r1cs = JSLoose.get(a, "r1csSha256")
        guard isH64(source), isH64(r1cs), circuit != .string("") else { throw JSError("circuitProvenance: bad circuit id or hash") }
        let id = try vkId(JSLoose.get(a, "vkey"))
        var o: JObject = [:]
        o[o: "circuit"] = circuit
        o[o: "sourceSha256"] = source
        o[o: "r1csSha256"] = r1cs
        o[o: "vkId"] = .string(id)
        return .object(o)
    }

    /// The first reason `prov` does not describe `expect.vkey` built from the expected sources and constraint system (`expect` is
    /// `{circuit, sourceSha256, r1csSha256?, vkey}`), or nil.
    public static func checkCircuitProvenance(_ prov: JSONValue?, expect: JSONValue?) throws -> String? {
        guard let p = prov, p.isObject || p.isArray else { return "not a provenance record" }
        guard let e = JS.present(expect) else { throw JSError("checkCircuitProvenance: no expectation") }
        if !strictEq(JSLoose.get(p, "circuit"), JSLoose.get(e, "circuit")) { return "record is for another circuit" }
        if !strictEq(JSLoose.get(p, "sourceSha256"), JSLoose.get(e, "sourceSha256")) { return "circuit sources differ from the pinned version" }
        let r1cs = JSLoose.get(p, "r1csSha256"), want = JSLoose.get(e, "r1csSha256")
        if r1cs?.asString == nil || !isH64(r1cs) || (want != nil && !strictEq(r1cs, want)) { return "constraint system differs" }
        let id = try vkId(JSLoose.get(e, "vkey"))
        if !strictEq(JSLoose.get(p, "vkId"), .string(id)) { return "verifying key is not the recorded one" }
        return nil
    }

    /// SHA-256 (hex) of the transcript's canonical JSON: the value a coordinator publishes and a verifier pins.
    public static func transcriptSha256(_ t: JSONValue?) throws -> String { try sha256Hex(t) }

    /// `Number.isSafeInteger`.
    static func safeInteger(_ v: JSONValue?) -> Double? {
        guard let d = IV.num(v), d.isFinite, d.rounded(.towardZero) == d, abs(d) <= Double(Canonical.MAX_SAFE) else { return nil }
        return d
    }

    /// The first problem with a transcript, or nil when it is well-formed. Any odd shape is a problem. The required number of
    /// contributions is the largest of 2, `minContributions` and the transcript's own `minContributions`; `r1csSha256` and `circuit`,
    /// when given, must equal the transcript's.
    public static func checkTranscript(_ t: JSONValue?, minContributions: Double? = nil, r1csSha256: JSONValue? = nil, circuit: JSONValue? = nil) -> String? {
        guard let x = t?.asObject, IV.num(x["version"]) == 1 else { return "not a version-1 transcript" }
        guard let name = x["circuit"]?.asString, !name.isEmpty else { return "no circuit id" }
        if circuit != nil && !strictEq(x["circuit"], circuit) { return "transcript is for another circuit" }
        if x["curve"] != .string("bn128") && x["curve"] != .string("bls12-381") { return "unknown curve" }
        for k in ["r1csSha256", "ptauSha256", "initZkeySha256"] where !isH64(x[JKey(k)]) { return "\(k) is not a SHA-256" }
        if r1csSha256 != nil && !strictEq(x["r1csSha256"], r1csSha256) { return "transcript is for a different constraint system" }
        // Math.max: a NaN bound makes every comparison false
        let bounds: [Double] = [2, minContributions ?? 2, safeInteger(x["minContributions"]) ?? 2]
        let need: Double = bounds.contains(where: { $0.isNaN }) ? Double.nan : (bounds.max() ?? 2)
        guard let cs = x["contributions"]?.asArray, !(Double(cs.count) < need) else { return "fewer than \(JS.toString(.double(need))) contributions" }
        var names = Set<JKey>(), keys = Set<JKey>()
        var prev = x["initZkeySha256"]
        for (i, c) in cs.enumerated() {
            // Object.is(index, i): the number i, and not -0
            guard let index = IV.num(JSLoose.get(c, "index")), index == Double(i), index.sign == .plus, let who = JSLoose.get(c, "name")?.asString, !who.isEmpty,
                  JS.truthy(c) else { return "contribution \(i) is malformed" }
            let zkey = JSLoose.get(c, "zkeySha256")
            if !isH64(zkey) || !strictEq(JSLoose.get(c, "prevZkeySha256"), prev) { return "contribution \(i) does not chain from the previous key" }
            // a key that is not a string is never found again (it is its own object)
            if names.contains(JKey(who)) || (zkey?.asString).map({ keys.contains(JKey($0)) }) ?? false { return "contribution \(i) repeats a name or key" }
            names.insert(JKey(who))
            if let z = zkey?.asString { keys.insert(JKey(z)) }
            prev = zkey
        }
        let b = x["beacon"]
        guard JS.truthy(b), isH64(JSLoose.get(b, "hashHex")), let rounds = safeInteger(JSLoose.get(b, "iterationsExp")), rounds >= 10, rounds <= 63 else { return "no valid random beacon" }
        if !strictEq(JSLoose.get(b, "prevZkeySha256"), prev) || !isH64(JSLoose.get(b, "zkeySha256")) { return "beacon is not applied after the last contribution" }
        if !strictEq(x["finalZkeySha256"], JSLoose.get(b, "zkeySha256")) { return "final key is not the beacon output" }
        guard let id = x["vkId"]?.asString else { return "no verifying-key id" }
        let idBytes = Array(id.utf8)
        guard idBytes.count == 67, Array(idBytes[0..<3]) == Array("vk_".utf8), isHex(idBytes[3...]) else { return "no verifying-key id" }
        return nil
    }

    /// "multi-party" only when the evidence `{transcript, sha256, r1csSha256?, circuit?}` pins the transcript's hash, the transcript is
    /// well-formed and it names `vkey`. Anything else, an error included, is "single-party".
    public static func ceremonyOf(_ vkey: JSONValue?, _ evidence: JSONValue? = nil) -> String {
        guard JS.truthy(vkey), JS.truthy(evidence) else { return "single-party" }
        let t = JSLoose.get(evidence, "transcript")
        if checkTranscript(t, r1csSha256: JSLoose.get(evidence, "r1csSha256"), circuit: JSLoose.get(evidence, "circuit")) != nil { return "single-party" }
        guard let sha = try? transcriptSha256(t), let id = try? vkId(vkey) else { return "single-party" }
        if !strictEq(.string(sha), JSLoose.get(evidence, "sha256")) || !strictEq(t?.get("vkId"), .string(id)) { return "single-party" }
        return "multi-party"
    }
}
