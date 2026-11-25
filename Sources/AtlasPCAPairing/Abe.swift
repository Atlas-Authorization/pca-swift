import Foundation
import CBlst
import CryptoKit
import AtlasPCAVerify

/// Proof-carrying encryption: FAME ciphertext-policy ABE (Fame.swift) in the asymmetric BLS12-381 pairing, with the payload sealed
/// under AES-256-GCM and the whole header authenticated. Keys, ciphertexts and policies are JSON values, parsed fail-closed: a
/// malformed ciphertext or key is a refusal, never a trap.
///
/// Honest limits (as the reference): no key revocation, the policy is public in the ciphertext, the master-key holder decrypts
/// everything, and it is not post-quantum or constant time.
public enum Abe {
    public static let alg = "fame-cpabe-bls12381-type3/aes-256-gcm"
    static let cekInfo = Array("atlas-pca-abe/cek/v3".utf8)
    static let saltLen = 16

    static let v2: JSONValue = .int(2)

    // ---- wire

    static func get(_ v: JSONValue?, _ k: String) -> JSONValue? { v?.objectValue?[JKey(k)] }
    static func isV2(_ v: JSONValue?) -> Bool { AbePolicy.isNum(v, 2) }
    public static func unb64u(_ x: JSONValue?) -> [UInt8]? { x?.stringValue.flatMap { PCAWire.b64uDecode($0) } }
    static func b64s(_ b: [UInt8]) -> JSONValue { .string(PCAWire.b64uEncode(b)) }

    static func g1From(_ x: JSONValue?) -> G1? {
        guard let b = unb64u(x), b.count == 48, let p = G1(compressed: b), !p.isIdentity else { return nil }
        return p
    }

    static func g2From(_ x: JSONValue?) -> G2? {
        guard let b = unb64u(x), b.count == 96, let p = G2(compressed: b), !p.isIdentity else { return nil }
        return p
    }

    static func tri(_ x: JSONValue?) -> [JSONValue]? { x?.arrayValue.flatMap { $0.count == 3 ? $0 : nil } }

    static func readTri1(_ x: JSONValue?) -> [G1]? {
        guard let l = tri(x) else { return nil }
        var out: [G1] = []
        for e in l { guard let p = g1From(e) else { return nil }; out.append(p) }
        return out
    }

    static func readTri2(_ x: JSONValue?) -> [G2]? {
        guard let l = tri(x) else { return nil }
        var out: [G2] = []
        for e in l { guard let p = g2From(e) else { return nil }; out.append(p) }
        return out
    }

    static func tri1JSON(_ x: [G1]) -> JSONValue { .array(x.map { b64s($0.compressed) }) }
    static func tri2JSON(_ x: [G2]) -> JSONValue { .array(x.map { b64s($0.compressed) }) }

    // ---- setup / keygen

    /// A fresh master key pair (mpk, msk) as JSON values.
    public static func setup() throws -> (mpk: JSONValue, msk: JSONValue) {
        let s = (0..<7).map { _ in Fame.randomScalar() }
        let (pk, sk) = try Fame.setup(a: [s[0], s[1]], b: [s[2], s[3]], d: [s[4], s[5], s[6]])
        return (mpkJSON(pk), mskJSON(sk))
    }

    static func mpkJSON(_ pk: Fame.Mpk) -> JSONValue {
        .object(["v": v2, "curve": .string("bls12-381"), "h": .array([b64s(pk.h1.compressed), b64s(pk.h2.compressed)]), "t": .array([b64s(pk.t1), b64s(pk.t2)])])
    }

    static func mskJSON(_ sk: Fame.Msk) -> JSONValue {
        .object(["v": v2, "curve": .string("bls12-381"), "a": .array(sk.a.map { b64s($0.bytes) }), "b": .array(sk.b.map { b64s($0.bytes) }), "g": tri1JSON(sk.g)])
    }

    /// Exactly one encoding per scalar: 32 bytes, non-zero, and < r.
    static func canonicalScalar(_ x: JSONValue?) -> Fr? {
        guard let b = unb64u(x), let f = Fr(canonical: b), !f.isZero else { return nil }
        return f
    }

    static func parseMsk(_ x: JSONValue?) throws -> Fame.Msk {
        let bad = PairingError("invalid master secret key")
        guard let m = x, m.objectValue != nil, isV2(get(m, "v")) else { throw bad }
        var msk = Fame.Msk()
        for (k, isA) in [("a", true), ("b", false)] {
            guard let l = get(m, k)?.arrayValue, l.count == 2 else { throw bad }
            var out: [Fr] = []
            for e in l { guard let f = canonicalScalar(e) else { throw bad }; out.append(f) }
            if isA { msk.a = out } else { msk.b = out }
        }
        guard let g = readTri1(get(m, "g")) else { throw bad }
        msk.g = g
        return msk
    }

    static func parseMpk(_ x: JSONValue?) throws -> Fame.Mpk {
        let bad = PairingError("invalid master public key")
        guard let m = x, m.objectValue != nil, isV2(get(m, "v")), let h = get(m, "h")?.arrayValue, let t = get(m, "t")?.arrayValue,
              h.count == 2, t.count == 2, let h1 = g2From(h[0]), let h2 = g2From(h[1]) else { throw bad }
        var mpk = Fame.Mpk()
        mpk.h1 = h1; mpk.h2 = h2
        guard let t1 = unb64u(t[0]), Gt.isElement(t1), let t2 = unb64u(t[1]), Gt.isElement(t2) else { throw bad }
        mpk.t1 = t1; mpk.t2 = t2
        return mpk
    }

    /// Issues a decryption key for the (deduplicated, in order) attribute tokens and returns the issued names.
    static func issue(_ mskJSON: JSONValue?, _ attrs: [String]) throws -> (key: JObject, names: [String]) {
        let msk = try parseMsk(mskJSON)
        var seen = Set<JKey>()
        var names: [JKey] = []
        for a in attrs { let k = JKey(a); if seen.insert(k).inserted, !a.isEmpty { names.append(k) } }
        let r = [Fame.randomScalar(), Fame.randomScalar()]
        let sigmas = names.map { _ in Fame.randomScalar() }
        let key = try Fame.keygen(msk, attrs: names, r: r, sigmas: sigmas, sigmaPrime: Fame.randomScalar())
        var am: JObject = [:]
        for n in names { am[n] = .object(["k": tri1JSON(key.attrs[n]!)]) }
        let out: JObject = ["v": v2, "curve": .string("bls12-381"), "k0": tri2JSON(key.k0), "kp": tri1JSON(key.kp), "attrs": .object(am)]
        return (out, names.map { $0.s })
    }

    /// Issues a decryption key for an explicit set of attribute tokens.
    public static func keygenForAttributes(msk: JSONValue, attrs: [String]) throws -> JSONValue { .object(try issue(msk, attrs).key) }

    /// Validates an untrusted key; a malformed attribute component is treated as not held. Nil if K0, K' or the container is malformed.
    static func parseKey(_ x: JSONValue?) -> Fame.Key? {
        guard let m = x, m.objectValue != nil, isV2(get(m, "v")), let am = get(m, "attrs")?.objectValue,
              let k0 = readTri2(get(m, "k0")), let kp = readTri1(get(m, "kp")) else { return nil }
        var key = Fame.Key()
        key.k0 = k0; key.kp = kp
        for (name, comp) in am { if let k = readTri1(get(comp, "k")) { key.attrs[name] = k } }
        return key
    }

    // ---- ciphertext

    struct Ct {
        var salt = "", iv = "", ct = "", tag = ""
        var ct0: [String] = []
        var tree: AbeTree!
        var rows: [[String]] = []

        func headerJSON() -> JSONValue {
            .object(["v": Abe.v2, "alg": .string(Abe.alg), "salt": .string(salt), "ct0": .array(ct0.map { .string($0) }),
                     "tree": tree.toJSON(), "rows": .array(rows.map { .array($0.map { .string($0) }) })])
        }

        /// The authenticated header: the canonical JSON of everything but the sealed fields.
        func aad() throws -> [UInt8] { Array(try PCAWire.canonicalStrict(headerJSON()).utf8) }

        func json() -> JSONValue {
            var o = headerJSON().objectValue!
            o[JKey("iv")] = .string(iv); o[JKey("ct")] = .string(ct); o[JKey("tag")] = .string(tag)
            return .object(o)
        }
    }

    static func strTri(_ x: JSONValue?) -> [String]? {
        guard let l = tri(x) else { return nil }
        var out: [String] = []
        for e in l { guard let s = e.stringValue, PCAWire.b64uDecode(s) != nil else { return nil }; out.append(s) }
        return out
    }

    static func parseCt(_ x: JSONValue?) -> Ct? {
        guard let m = x, m.objectValue != nil, isV2(get(m, "v")), get(m, "alg")?.stringValue == alg else { return nil }
        var c = Ct()
        for k in ["salt", "iv", "ct", "tag"] {
            guard let s = get(m, k)?.stringValue, PCAWire.b64uDecode(s) != nil else { return nil }
            switch k { case "salt": c.salt = s; case "iv": c.iv = s; case "ct": c.ct = s; default: c.tag = s }
        }
        var nodes = 0
        guard let ct0 = strTri(get(m, "ct0")), let tree = AbePolicy.parseTree(get(m, "tree"), 0, &nodes), let rows = get(m, "rows")?.arrayValue else { return nil }
        c.ct0 = ct0
        c.tree = tree
        if rows.count != tree.leafCount || tree.firstRepeatedAttribute() != nil { return nil }
        for r in rows { guard let t = strTri(r) else { return nil }; c.rows.append(t) }
        return c
    }

    /// Validates an untrusted value as a ciphertext; nil (fail closed) on any deviation.
    public static func parseCiphertext(_ x: JSONValue) -> JSONValue? { parseCt(x)?.json() }

    /// HKDF-SHA256(ikm, salt, info) to 32 bytes (one block).
    static func cek(_ ikm: [UInt8], _ salt: [UInt8]) -> SymmetricKey {
        let prk = HMAC<SHA256>.authenticationCode(for: Data(ikm), using: SymmetricKey(data: Data(salt)))
        let okm = HMAC<SHA256>.authenticationCode(for: Data(cekInfo + [1]), using: SymmetricKey(data: Data(prk)))
        return SymmetricKey(data: Data(okm))
    }

    /// Encrypts `plaintext` so that it decrypts only for a holder whose attributes satisfy `policy`. Throws on an invalid policy
    /// (including one naming an attribute twice) or master public key.
    public static func encryptForPolicy(mpk: JSONValue, policy: JSONValue, plaintext: [UInt8]) throws -> JSONValue {
        let (treeOpt, why) = AbePolicy.normalize(policy)
        guard let tree = treeOpt else { throw PairingError("invalid policy: " + (why ?? "")) }
        if tree.firstRepeatedAttribute() != nil { throw PairingError("invalid policy: an attribute is named by more than one leaf (single-use attributes only)") }
        let pk = try parseMpk(mpk)
        var rng = SystemRandomNumberGenerator()
        let salt = (0..<saltLen).map { _ in UInt8.random(in: 0...255, using: &rng) }
        let (fc, k) = try Fame.encrypt(pk, tree, s: [Fame.randomScalar(), Fame.randomScalar()])
        var c = Ct()
        c.salt = PCAWire.b64uEncode(salt)
        c.tree = tree
        c.ct0 = fc.ct0.map { PCAWire.b64uEncode($0.compressed) }
        c.rows = fc.rows.map { $0.map { PCAWire.b64uEncode($0.compressed) } }
        let aad: [UInt8]
        do { aad = try c.aad() } catch { throw PairingError("policy cannot be authenticated (header outside the canonical JSON profile)") }
        let sealed = try AES.GCM.seal(Data(plaintext), using: cek(k, salt), nonce: AES.GCM.Nonce(), authenticating: Data(aad))
        c.iv = PCAWire.b64uEncode(Array(sealed.nonce))
        c.ct = PCAWire.b64uEncode(Array(sealed.ciphertext))
        c.tag = PCAWire.b64uEncode(Array(sealed.tag))
        return c.json()
    }

    /// The plaintext iff the key's attributes satisfy the ciphertext's policy AND the AEAD authenticates; otherwise nil. Never traps.
    public static func decrypt(key: JSONValue, ciphertext: JSONValue) -> [UInt8]? {
        guard let ct = parseCt(ciphertext), let fk = parseKey(key),
              let salt = PCAWire.b64uDecode(ct.salt), let iv = PCAWire.b64uDecode(ct.iv), let body = PCAWire.b64uDecode(ct.ct), let tag = PCAWire.b64uDecode(ct.tag),
              let ct0 = readTri2(.array(ct.ct0.map { .string($0) })) else { return nil }
        var fc = Fame.Ct()
        fc.ct0 = ct0
        for r in ct.rows { guard let t = readTri1(.array(r.map { .string($0) })) else { return nil }; fc.rows.append(t) }
        guard let k = Fame.decrypt(fk, ct.tree, fc), let aad = try? ct.aad() else { return nil } // a header outside the canonical profile cannot be authentic
        guard iv.count == 12, tag.count == 16, let nonce = try? AES.GCM.Nonce(data: Data(iv)),
              let box = try? AES.GCM.SealedBox(nonce: nonce, ciphertext: Data(body), tag: Data(tag)),
              let pt = try? AES.GCM.open(box, using: cek(k, salt), authenticating: Data(aad)) else { return nil }
        return Array(pt)
    }

    /// `decrypt` with the plaintext decoded as UTF-8 text (invalid sequences replaced, a leading BOM dropped).
    public static func decryptText(key: JSONValue, ciphertext: JSONValue) -> String? {
        guard var pt = decrypt(key: key, ciphertext: ciphertext) else { return nil }
        if pt.starts(with: [0xEF, 0xBB, 0xBF]) { pt.removeFirst(3) }
        return String(decoding: pt, as: UTF8.self)
    }

    // ---- capability attributes and payloads

    public struct CapabilityOptions {
        /// `chain` is supplied (root first, ending in the capability): required for scope/act/verb/resource tokens on a delegated hop.
        /// A supplied chain that fails verification yields no attributes.
        public var chain: [JSONValue]?
        /// Pins the root issuer (default: the chain's own root issuer).
        public var principal: String?
        /// Pins post-quantum authority by Ed25519 root identity.
        public var pqPins: [String: String]?
        public init(chain: [JSONValue]? = nil, principal: String? = nil, pqPins: [String: String]? = nil) {
            self.chain = chain; self.principal = principal; self.pqPins = pqPins
        }
    }

    static func jsVerbs(_ v: JSONValue?) -> [String] {
        if let s = v?.stringValue { return [s] }
        return (v?.arrayValue ?? []).compactMap { $0.stringValue }
    }

    /// `===` on identifiers; objects are never identical; a missing member equals null.
    static func sameID(_ a: JSONValue?, _ b: JSONValue?) -> Bool {
        if let x = a?.stringValue { return b?.stringValue.map { $0 == x } ?? false }
        let an = a == nil || a == .null, bn = b == nil || b == .null
        return an && bn
    }

    /// The canonical attribute set a capability possesses, in insertion order. scope:, act:, verb: and resource: tokens come only
    /// from the ROOT capability: a delegated hop's own caveats are restrictions, never grants.
    static func capAttrs(_ capability: JSONValue, _ opts: CapabilityOptions) -> [String] {
        var out: [String] = []
        var seen = Set<JKey>()
        func add(_ s: String) { if seen.insert(JKey(s)).inserted { out.append(s) } }
        var scopeSource: JSONValue?, envSource: JSONValue?
        if let chain = opts.chain {
            guard let first = chain.first, let last = chain.last, first.objectValue != nil, last.objectValue != nil,
                  sameID(get(last, "id"), get(capability, "id")) else { return [] }
            let principal = opts.principal ?? get(first, "issuer")?.stringValue
            if PCAWire.verifyChain(chain, expectedRootIssuer: principal, pqPins: opts.pqPins) != nil { return [] }
            scopeSource = get(first, "caveats"); envSource = first
        } else if get(capability, "parent") == nil {
            scopeSource = get(capability, "caveats"); envSource = capability
        }
        if let h = get(capability, "holder")?.stringValue, !h.isEmpty { add("holder:" + h) }
        for cv in scopeSource?.arrayValue ?? [] where cv.objectValue != nil {
            if get(cv, "type")?.stringValue == "scope", let v = get(cv, "value")?.stringValue { add("scope:" + v) }
            if get(cv, "type")?.stringValue == "scopes", let vs = get(cv, "values")?.arrayValue {
                for s in vs { if let v = s.stringValue { add("scope:" + v) } }
            }
        }
        if let env = envSource.flatMap({ PCAWire.readEnvelope($0) }), let plist = get(env, "predicates")?.arrayValue {
            // an array counts as a predicate that names no verb or resource
            var preds: [JSONValue] = []
            for p in plist { if p.objectValue != nil { preds.append(p) } else if p.arrayValue != nil { preds.append(.object([:])) } }
            for p in preds {
                guard let r = get(p, "resource")?.stringValue else { continue }
                for v in jsVerbs(get(p, "verb")) {
                    if let pair = try? PCAWire.canonicalStrict(.array([.string(v), .string(r)])) { add("act:" + pair) }
                }
            }
            if preds.count == 1 {
                for v in jsVerbs(get(preds[0], "verb")) { add("verb:" + v) }
                if let r = get(preds[0], "resource")?.stringValue { add("resource:" + r) }
            }
        }
        return out
    }

    /// The sorted canonical attribute set a capability possesses.
    public static func capabilityAttributes(_ capability: JSONValue, _ opts: CapabilityOptions = CapabilityOptions()) -> [String] {
        capAttrs(capability, opts).map { JKey($0) }.sorted().map { $0.s }
    }

    /// Issues a key bound to a capability's attributes plus any extra tokens; the holder is recorded.
    public static func keygenForCapability(msk: JSONValue, capability: JSONValue, extra: [String], _ opts: CapabilityOptions = CapabilityOptions()) throws -> (key: JSONValue, attrs: [String]) {
        var attrs = capAttrs(capability, opts)
        for a in extra where !a.isEmpty { attrs.append(a) }
        var (key, names) = try issue(msk, attrs)
        if let h = get(capability, "holder")?.stringValue { key[JKey("holder")] = .string(h) }
        return (.object(key), names)
    }

    /// Encrypts a JSON payload under a capability policy.
    public static func encryptToolPayload(mpk: JSONValue, policy: JSONValue, payload: JSONValue) throws -> JSONValue {
        try encryptForPolicy(mpk: mpk, policy: policy, plaintext: Array(PCAWire.canonical(payload).utf8))
    }

    /// Decrypts a tool payload with a capability-derived key and parses it.
    public static func decryptWithCapability(key: JSONValue, ciphertext: JSONValue) -> (payload: JSONValue?, reason: String?) {
        guard let pt = decrypt(key: key, ciphertext: ciphertext) else { return (nil, "capability does not satisfy the policy, or ciphertext is invalid") }
        guard let v = try? PCAWire.parseLenient(String(decoding: pt, as: UTF8.self)) else { return (nil, "decrypted payload is not valid JSON") }
        return (v, nil)
    }
}

extension Abe {
    /// The attribute tokens of a capability (the reference's `Attr`): `holder:`, `verb:`, `resource:`, `scope:` and the bound pair `act:["verb","resource"]`.
    public enum Attr {
        public static func holder(_ key: String) -> String { "holder:" + key }
        public static func verb(_ v: String) -> String { "verb:" + v }
        public static func resource(_ r: String) -> String { "resource:" + r }
        public static func scope(_ s: String) -> String { "scope:" + s }
        /// A bound (verb, resource) pair: only a predicate that grants exactly this verb ON exactly this resource yields it.
        public static func act(_ verb: String, _ resource: String) -> String { "act:" + ((try? PCAWire.canonicalStrict(.array([.string(verb), .string(resource)]))) ?? "") }
    }

    /// Validates a policy and returns the normalised tree ({kind:"leaf",attr} / {kind:"gate",t,of}), or the reason it was refused.
    public static func normalizePolicy(_ policy: JSONValue) -> (tree: JSONValue?, reason: String?) {
        let (t, why) = AbePolicy.normalize(policy)
        return (t?.toJSON(), why)
    }

    /// The pure, non-cryptographic check (a convenience and test oracle) that the attribute set satisfies the tree.
    public static func satisfies(tree: JSONValue, attrs: [String]) -> Bool { AbePolicy.satisfies(tree, attrs) }

    /// Every attribute named by the tree, unique and sorted; nil for an invalid tree.
    public static func policyAttributes(tree: JSONValue) -> [String]? { AbePolicy.policyAttributes(tree) }
}
