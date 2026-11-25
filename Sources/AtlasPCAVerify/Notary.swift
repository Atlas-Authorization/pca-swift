import Foundation

/// External-fact attestation (the notary primitive): a notary witnesses one HTTP request/response and signs a canonical record of it
/// (method, URL, a digest of the request headers, status, and a salted-Merkle commitment to the body). A prover discloses ONE body field
/// with an inclusion proof; the fact is bound two ways to a PCActn; an `attested_fact` caveat gates an action on it.
///
/// Trust boundary: the notary is the trust assumption. This is NOT trustless (MPC-TLS / zkTLS): a colluding or compromised notary can
/// attest anything. Everything fails closed: a wrong key, a tampered session or root, a lie about a field, or a fact bound to another
/// action is refused. Values travel as `JSONValue` so a malformed input is refused the way the reference refuses it.
public enum PCANotary {
    public static let BODY_COMMIT_ALG = "salted-merkle-sha256-v1"
    public static let ATTESTED_FACT_CAVEAT = "attested_fact"
    static let NOTARY_DOMAIN = "atlas-pca/notary/v1\0"

    /// A trusted notary public key: its b64u form or the raw 32 bytes.
    public enum NotaryKey {
        case b64u(String)
        case bytes([UInt8])
        public init(_ key: PCAEdKey) { self = .b64u(key.id) }
        var text: String {
            switch self { case let .b64u(s): return s; case let .bytes(b): return Base64URLStrict.encode(b) }
        }
    }

    // MARK: helpers

    private static func canonBytes(_ v: JSONValue) throws -> [UInt8] {
        guard let c = IV.strictCanon(v) else { throw JSError("canonicalize: \(IV.strictCanonError(v) ?? "out of profile")") }
        return Canonical.utf8(c)
    }

    /// Equality of the strict canonical forms; false (never a throw) when either side cannot be canonicalised.
    private static func canonicalEqual(_ a: JSONValue?, _ b: JSONValue?) -> Bool {
        guard let a = a, let b = b, let x = IV.strictHash(a), let y = IV.strictHash(b) else { return false }
        return IV.same(x, y)
    }

    private static func leafObject(_ path: JSONValue, _ value: JSONValue, _ salt: JSONValue) -> JSONValue {
        .object(["p": path, "v": value, "s": salt])
    }

    private static func leafHash(_ leaf: JSONValue) throws -> [UInt8] { Canonical.sha256([0x00] + (try canonBytes(leaf))) }

    private static func prove(_ hs: [[UInt8]], _ idx: Int, _ out: inout [JSONValue]) {
        if hs.count == 1 { return }
        let k = Int(Merkle.split(UInt64(hs.count)))
        if idx < k {
            prove(Array(hs[..<k]), idx, &out)
            out.append(.object(["side": .string("R"), "hash": .string(Base64URLStrict.encode(Merkle.build(Array(hs[k...]))))]))
        } else {
            prove(Array(hs[k...]), idx - k, &out)
            out.append(.object(["side": .string("L"), "hash": .string(Base64URLStrict.encode(Merkle.build(Array(hs[..<k]))))]))
        }
    }

    /// Notary signature input: `NOTARY_DOMAIN || sha256(canonical(session))`.
    public static func notaryMessage(_ session: JSONValue) throws -> [UInt8] {
        Canonical.utf8(NOTARY_DOMAIN) + Canonical.sha256(try canonBytes(session))
    }

    // MARK: notarizeResponse

    private struct Bare { let path: [JSONValue]; let value: JSONValue }

    private static func flatten(_ value: JSONValue?, _ prefix: [JSONValue]) -> [Bare] {
        switch value {
        case let .array(a)?:
            if a.isEmpty { return [Bare(path: prefix, value: .array([]))] }
            return a.enumerated().flatMap { flatten($0.element, prefix + [.int(Int64($0.offset))]) }
        case let .object(o)?:
            if o.isEmpty { return [Bare(path: prefix, value: .object([:]))] }
            return o.keys.sorted { Canonical.compareUtf8($0.s, $1.s) < 0 }.flatMap { flatten(o[$0], prefix + [.string($0.s)]) }
        default:
            return [Bare(path: prefix, value: value ?? .null)]
        }
    }

    /// `size`-code-point chunks (never splits a surrogate pair); an empty string is one empty chunk.
    private static func chunk(_ s: String, _ size: Int) -> [Bare] {
        let chars = Array(s.unicodeScalars)
        if chars.isEmpty { return [Bare(path: [.string("#chunk"), .int(0)], value: .string(""))] }
        var out: [Bare] = []
        var i = 0, idx: Int64 = 0
        while i < chars.count {
            let end = size > chars.count - i ? chars.count : i + size
            out.append(Bare(path: [.string("#chunk"), .int(idx)], value: .string(IV.text(chars[i..<end]))))
            i = end; idx += 1
        }
        return out
    }

    private static func randomSalt() -> [UInt8] { (0..<16).map { _ in UInt8.random(in: 0...255) } }

    /// Lower-cased header names, then the strict hash. Two names that differ only in case keep the LAST in the reference's insertion order,
    /// which a parsed object does not have: that is refused unless the values agree.
    private static func headersDigest(_ headers: JSONValue?) throws -> String {
        var norm: JObject = [:]
        let entries: [(String, JSONValue)]
        switch headers {
        case nil, .null?: entries = []
        case let .object(o)?: entries = o.map { ($0.key.s, $0.value) }
        case let .array(a)?: entries = a.enumerated().map { (String($0.offset), $0.element) }
        case .bool?, .int?, .double?: entries = []
        default: throw JSError("notarizeResponse: request.headers must be an object")
        }
        for (k, v) in entries {
            let lk = JKey(k.lowercased())
            if let old = norm[lk], old != v { throw JSError("notarizeResponse: headers differ only in case with different values") }
            norm[lk] = v
        }
        guard let h = IV.strictHash(.object(norm)) else { throw JSError("canonicalize: out of profile") }
        return h
    }

    /// Witness a request/response: the signed attestation plus the prover's private opening witness (`{session, leaves}`).
    /// `input` = {request: {method, url, headers?}, response: {status, body?}}. `salt` supplies the 16 hiding bytes per leaf.
    public static func notarizeResponse(_ input: JSONValue?, notaryKey: PCAEdKey, observedAt: JSONValue? = nil, textChunkSize: JSONValue? = nil,
                                        nowMs: Int64? = nil, salt: (() -> [UInt8])? = nil) throws -> JSONValue {
        guard let inp = input?.asObject else { throw JSError("notarizeResponse: input must be an object") }
        guard let req = inp["request"]?.asObject, let res = inp["response"]?.asObject else { throw JSError("notarizeResponse: request and response are required") }
        guard let method = JS.nonEmptyString(req["method"]) else { throw JSError("notarizeResponse: request.method is required") }
        guard JS.nonEmptyString(req["url"]) != nil, let url = req["url"] else { throw JSError("notarizeResponse: request.url is required") }
        guard IV.safe(res["status"]) != nil, let status = res["status"] else { throw JSError("notarizeResponse: response.status must be an integer") }

        let body = res["body"]
        let bare: [Bare]
        if case let .string(s)? = body, let n = IV.num(textChunkSize), n >= 1 {
            bare = chunk(s, Int(min(n.rounded(.down), 1e15)))
        } else {
            bare = flatten(body, [])
        }
        let gen = salt ?? randomSalt
        let leaves: [JSONValue] = bare.map {
            .object(["path": .array($0.path), "value": $0.value, "salt": .string(Base64URLStrict.encode(gen()))])
        }
        let hs = try leaves.map { l -> [UInt8] in
            let o = l.asObject!
            return try leafHash(leafObject(o["path"]!, o["value"]!, o["salt"]!))
        }
        let root = Base64URLStrict.encode(Merkle.build(hs))
        let digest = try headersDigest(req["headers"])
        let now = nowMs ?? Int64((Date().timeIntervalSince1970 * 1000).rounded(.down))
        let session: JSONValue = .object([
            "v": .int(1), "method": .string(method.uppercased()), "url": url, "requestHeadersDigest": .string(digest), "responseStatus": status,
            "responseBodyCommit": .object(["alg": .string(BODY_COMMIT_ALG), "root": .string(root), "size": .int(Int64(leaves.count))]),
            "observedAt": JS.present(observedAt) ?? .int(now),
        ])
        let sig = try notaryKey.sign(try notaryMessage(session))
        let attestation: JSONValue = .object(["session": session, "notary": .string(notaryKey.id), "sig": .string(Base64URLStrict.encode(sig))])
        return .object(["attestation": attestation, "witness": .object(["session": session, "leaves": .array(leaves)])])
    }

    // MARK: discloseField

    /// A redactable disclosure of ONE committed field (by path; a bare string is a single top-level key): the opened leaf and its inclusion
    /// proof. Throws when the path names no committed leaf. The attestation is not read (the proof binds to the attested root when verified).
    public static func discloseField(_ attestation: JSONValue?, _ witness: JSONValue?, _ path: JSONValue?) throws -> JSONValue {
        let want: JSONValue
        switch path {
        case let .string(s)?: want = .array([.string(s)])
        case let .array(a)?: want = .array(a)
        default: throw JSError("discloseField: path must be an array or a string")
        }
        guard let w = witness?.asObject, let leaves = w["leaves"]?.asArray else { throw JSError("discloseField: witness has no leaves") }
        var idx = -1
        for (i, l) in leaves.enumerated() {
            if l == .null { throw JSError("discloseField: malformed leaf") }
            if canonicalEqual(l.asObject?["path"], want) { idx = i; break }
        }
        if idx < 0 { throw JSError("discloseField: no committed field at path \(JS.stringify(want))") }
        var hs: [[UInt8]] = []
        for l in leaves {
            guard let o = l.asObject, let p = o["path"], let v = o["value"], let s = o["salt"] else { throw JSError("canonicalize: unsupported type undefined") }
            hs.append(try leafHash(leafObject(p, v, s)))
        }
        var steps: [JSONValue] = []
        prove(hs, idx, &steps)
        let leaf = leaves[idx].asObject!
        return .object(["path": leaf["path"]!, "value": leaf["value"]!, "salt": leaf["salt"]!,
                        "proof": .object(["index": .int(Int64(idx)), "size": .int(Int64(leaves.count)), "path": .array(steps)])])
    }

    // MARK: verification (fail closed)

    private static func validCommit(_ c: JSONValue?) -> Bool {
        guard let r = c?.asObject, r["alg"]?.asString.map({ IV.same($0, BODY_COMMIT_ALG) }) == true,
              let root = r["root"]?.asString, Base64URLStrict.decode(root, length: 32) != nil,
              let size = IV.safe(r["size"]), size >= 1 else { return false }
        return true
    }

    private static func validSession(_ s: JSONValue?) -> Bool {
        guard let r = s?.asObject, IV.num(r["v"]) == 1, r["method"]?.asString != nil, r["url"]?.asString != nil, r["requestHeadersDigest"]?.asString != nil,
              let rs = IV.safe(r["responseStatus"]), !IV.isNegZero(rs), let oa = IV.safe(r["observedAt"]), !IV.isNegZero(oa),
              validCommit(r["responseBodyCommit"]) else { return false }
        return true
    }

    /// The attestation's recorded signer equals the trusted notary key, its session is well-formed, and the signature verifies over it.
    public static func verifyNotaryAttestation(_ attestation: JSONValue?, notaryKey: NotaryKey?) -> Bool {
        guard let a = attestation?.asObject, let session = a["session"], validSession(session), let notary = a["notary"]?.asString,
              let sig = a["sig"]?.asString, let key = notaryKey, IV.same(notary, key.text), let msg = try? notaryMessage(session) else { return false }
        return Ed25519Strict.verifyB64u(notary, msg, sig)
    }

    /// The attestation is authentic AND the disclosed leaf is included under the attested body root at a position consistent with the
    /// committed size. A lie about the value, path or salt breaks inclusion.
    public static func verifyDisclosedField(_ attestation: JSONValue?, _ disclosure: JSONValue?, notaryKey: NotaryKey?) -> Bool {
        guard verifyNotaryAttestation(attestation, notaryKey: notaryKey), let d = disclosure?.asObject, let path = d["path"], path.isArray,
              d["salt"]?.asString != nil, let proof = d["proof"]?.asObject, proof["path"]?.isArray == true,
              let commit = attestation?.get("session")?.get("responseBodyCommit")?.asObject, let root = commit["root"]?.asString,
              let ps = IV.num(proof["size"]), let cs = IV.num(commit["size"]), ps == cs else { return false }
        // an unset hash_suite is sha256; any other suite names a digest that is not the 32-byte root the commitment carries
        if let hs = proof["hash_suite"], hs != .string("sha256") { return false }
        guard let value = d["value"], let salt = d["salt"] else { return false }
        let leaf = leafObject(path, value, salt)
        guard IV.strictCanon(leaf) != nil else { return false }
        return Merkle.verifyInclusion(root, proof, leaf)
    }

    // MARK: PCA binding

    /// A stable digest of this attested FACT (independent of any PCActn binding): the agent places it in `provenance.trusted_refs`.
    public static func factRef(_ attestation: JSONValue?) throws -> String {
        guard let a = attestation?.asObject, let session = a["session"], let notary = a["notary"], let sig = a["sig"],
              let h = IV.strictHash(.object(["fact": .string("atlas-pca-notary/v1"), "session": session, "notary": notary, "sig": sig])) else {
            throw JSError("factRef: attestation is not canonicalisable")
        }
        return h
    }

    /// Stamp the action's digest into the attestation ("I am for THIS action"); a new attestation, the input untouched.
    public static func bindFactToPcActn(_ attestation: JSONValue?, _ pcActn: JSONValue?) throws -> JSONValue {
        var out: JObject
        switch attestation {
        case let .object(o)?: out = o
        case .null?: out = [:]
        default: throw JSError("bindFactToPcActn: attestation must be an object")
        }
        guard let p = pcActn, let d = IV.strictHash(p) else { throw JSError("canonicalize: unsupported type") }
        out["fact_binding"] = .object(["pcactn_digest": .string(d)])
        return .object(out)
    }

    /// True iff the fact names the action (`fact_binding.pcactn_digest`) AND the action commits to the fact (`provenance.trusted_refs`
    /// lists `factRef`). Fail closed if either side is missing.
    public static func factMatchesPcActn(_ attestation: JSONValue?, _ pcActn: JSONValue?) -> Bool {
        guard let a = attestation?.asObject, let binding = a["fact_binding"]?.asObject, let dg = binding["pcactn_digest"]?.asString,
              let p = pcActn, let pd = IV.strictHash(p), IV.same(dg, pd),
              let refs = p.asObject?["provenance"]?.asObject?["trusted_refs"]?.asArray, let ref = try? factRef(attestation) else { return false }
        return refs.contains { $0.asString.map { IV.same($0, ref) } == true }
    }

    // MARK: attested_fact caveat

    /// A caveat admitting an action only when a notarized response field equals `equals` (optionally from an exact URL, and bound to the PCActn).
    public static func requireAttestedFact(notary: NotaryKey?, path: JSONValue?, equals: JSONValue? = nil, url: JSONValue? = nil, bindToPcActn: JSONValue? = nil) throws -> JSONValue {
        guard let n = notary else { throw JSError("requireAttestedFact: notary must be a key") }
        var o: JObject = ["type": .string(ATTESTED_FACT_CAVEAT), "notary": .string(n.text)]
        // a string would pass for a one-segment path that no disclosure ever matches: refuse anything that is not an array
        guard case let .array(a)? = path else { throw JSError("requireAttestedFact: path must be an array of segments") }
        o["path"] = .array(a)
        if let e = equals { o["equals"] = e }
        if let u = url { o["url"] = u }
        if let b = bindToPcActn { o["bindToPcActn"] = b }
        return .object(o)
    }

    public static func isAttestedFactCaveat(_ cv: JSONValue?) -> Bool {
        guard let o = cv?.asObject, o["type"]?.asString.map({ IV.same($0, ATTESTED_FACT_CAVEAT) }) == true, o["notary"]?.asString != nil,
              o["path"]?.isArray == true else { return false }
        return true
    }

    private static func strictEq(_ a: JSONValue?, _ b: JSONValue?) -> Bool {
        if a == nil && b == nil { return true }
        if a == .null && b == .null { return true }
        return IV.scalarEq(a, b)
    }

    /// `key` is listed in `ring`, no entry for it is revoked, and `observedAt` lies in some entry's [notBefore, notAfter) window.
    public static func notaryKeyUsable(_ ring: JSONValue?, _ key: JSONValue?, _ observedAt: JSONValue?) -> Bool {
        guard let entries = ring?.asArray, let at = IV.safe(observedAt) else { return false }
        let mine = entries.filter { JS.truthy($0) && strictEq($0.asObject?["key"], key) }.compactMap { $0.asObject }
        // an entry that is truthy but not an object has no key and never matches (unless both are undefined, which the key argument rules out)
        if mine.isEmpty { return false }
        if mine.contains(where: { $0["revoked"] == .bool(true) }) { return false }
        return mine.contains { e in
            if let nb = e["notBefore"], !(at >= JS.toNumber(nb)) { return false }
            if let na = e["notAfter"], !(at < JS.toNumber(na)) { return false }
            return true
        }
    }

    private static func refuse(_ reason: String) -> JSONValue { .object(["ok": .bool(false), "reason": .string(reason)]) }

    /// Evaluate an attested_fact caveat against disclosed evidence `{attestation, disclosure, pcActn?}`. `policy` = {now?, maxAgeMs?, keyring?}.
    /// Admits only when every step passes, in the reference's order; the result is `{ok, reason?, trust?}`.
    public static func evaluateAttestedFactCaveat(_ caveat: JSONValue?, _ evidence: JSONValue?, _ policy: JSONValue? = nil, nowMs: Double? = nil) -> JSONValue {
        guard let cv = caveat?.asObject, cv["type"]?.asString.map({ IV.same($0, ATTESTED_FACT_CAVEAT) }) == true else { return refuse("not an attested_fact caveat") }
        guard let notary = cv["notary"]?.asString, cv["path"]?.isArray == true else { return refuse("caveat is malformed (notary/path)") }
        // destructuring null / undefined throws in the reference: refused with the error reason
        guard evidence != nil, evidence != .null else { return refuse("attested_fact evaluation error (fail closed): evidence is null or undefined") }
        let ev = evidence?.asObject
        let attestation = ev?["attestation"], disclosure = ev?["disclosure"], pcActn = ev?["pcActn"]
        if !verifyNotaryAttestation(attestation, notaryKey: .b64u(notary)) { return refuse("notary attestation does not verify (fail closed)") }
        if policy == .null { return refuse("attested_fact evaluation error (fail closed): policy is null") }
        let pol = policy?.asObject ?? [:]
        let session = attestation?.get("session")
        if let ring = pol["keyring"], !notaryKeyUsable(ring, attestation?.get("notary"), session?.get("observedAt")) {
            return refuse("notary key is not trusted for this observation time (unlisted, revoked or out of window)")
        }
        if let maxAge = pol["maxAgeMs"] {
            let now = JS.present(pol["now"]) ?? .double(nowMs ?? Date().timeIntervalSince1970 * 1000)
            guard let m = IV.num(maxAge), m.isFinite, let n = IV.num(now), n.isFinite, let o = IV.num(session?.get("observedAt")) else {
                return refuse("attestation is stale or from the future")
            }
            let age = n - o
            if age < 0 || age > m { return refuse("attestation is stale or from the future") }
        }
        if let u = cv["url"] {
            let sessionUrl = session?.get("url")?.asString
            guard let want = u.asString, let have = sessionUrl, IV.same(want, have) else { return refuse("attested session URL does not match the caveat") }
        }
        if !verifyDisclosedField(attestation, disclosure, notaryKey: .b64u(notary)) { return refuse("disclosed field does not verify under the attested root") }
        if !canonicalEqual(disclosure?.get("path"), cv["path"]) { return refuse("disclosed field is not the path the caveat requires") }
        if !canonicalEqual(disclosure?.get("value"), cv["equals"]) { return refuse("disclosed field value does not satisfy the caveat") }
        if JS.truthy(cv["bindToPcActn"]) {
            if !JS.truthy(pcActn) { return refuse("caveat requires PCActn binding but no PCActn was supplied") }
            if !factMatchesPcActn(attestation, pcActn) { return refuse("fact is not bound to this PCActn") }
        }
        return .object(["ok": .bool(true), "trust": .string("notary-trusted")])
    }
}
