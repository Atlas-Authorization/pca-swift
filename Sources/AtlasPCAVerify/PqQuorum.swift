import Foundation

/// Post-quantum t-of-n threshold AUTHORIZATION by composition (a "quorum certificate"): a quorum set is n registered post-quantum signers (ML-DSA-65 / -87,
/// SLH-DSA, FN-DSA, or Ed25519 + PQ hybrids), a threshold t and a diversity commitment k (the minimum number of hash-based signers); a proof is at least t
/// INDEPENDENT per-signer signatures over one domain-separated message. Rotation: the old quorum signs the id of the next set at the next epoch, and a chain
/// of such certificates is verified link by link. No new cryptography: counting, binding and de-duplication on top of the suite seam.
/// Sets, shares, proofs and certificates are `JSONValue` objects with the reference's member names. Verifiers never throw; signers and digests throw.
public enum PqQuorum {
    public static let PQ_QUORUM_MAX_SIGNERS = 256
    public static let PQ_QUORUM_MAX_CHAIN = 1024
    static let SET_DOMAIN = "atlas-pca/pq-quorum-set/v1"
    static let MSG_DOMAIN = "atlas-pca/pq-quorum-msg/v1\u{0}"
    static let ROTATION_KIND = "pq-quorum-rotation"
    static let ED_PK_BYTES = 32

    private static func s(_ x: String) -> JSONValue { .string(x) }
    private static let badSet: JSONValue = .object(["ok": .bool(false), "reason": .string("bad-set")])

    struct Entry {
        let alg: String
        let ed: String?
        let pq: String
        var key: String { "\(alg)|\(ed ?? "")|\(pq)" }
        var json: JSONValue {
            var o: JObject = ["alg": .string(alg), "pq": .string(pq)]
            if let e = ed { o["ed"] = .string(e) }
            return .object(o)
        }
    }

    struct Loaded {
        let t: Int64
        let minHashBased: Int64
        let entries: [Entry]
        let id: String
        var json: JSONValue { .object(["t": .int(t), "minHashBased": .int(minHashBased), "signers": .array(entries.map { $0.json }), "id": .string(id)]) }
    }

    /// The suite of a quorum entry: a registered post-quantum suite or hybrid (never plain ed25519, never LESS). The table is read directly: building or
    /// loading a set needs key lengths only, so it works for a suite whose verify backend is not registered (a share of it is then refused at verification).
    private static func pqSuite(_ alg: String) -> PQ.Suite? {
        guard let st = PQ.suites[alg], st.pq != nil || st.slh != nil || st.fnDsa != nil else { return nil }
        return st
    }

    private static func hashBased(_ alg: String) -> Bool { PQ.suites[alg]?.slh != nil }

    private static func normalizeEntry(_ alg: JSONValue?, _ ed: JSONValue?, _ pq: JSONValue?) -> Entry? {
        guard let name = alg?.asString, let suite = pqSuite(name), let p = pq?.asString, Base64URLStrict.decode(p, length: suite.pqPkBytes) != nil else { return nil }
        if suite.needsPqSig {
            guard let e = ed?.asString, Base64URLStrict.decode(e, length: ED_PK_BYTES) != nil else { return nil }
            return Entry(alg: name, ed: e, pq: p)
        }
        if ed != nil { return nil } // an Ed25519 key on a suite without one (null counts as present)
        return Entry(alg: name, ed: nil, pq: p)
    }

    private static func sha384(_ b: [UInt8]) -> [UInt8] { AHash.sha384.digest(b) }

    private static func finalize(_ entries: [Entry], _ tV: JSONValue?, _ kV: JSONValue?) -> Loaded? {
        let n = entries.count
        guard n >= 1, n <= PQ_QUORUM_MAX_SIGNERS, let t = IV.safe(tV), t >= 1, t <= Double(n), let k = IV.safe(kV), k >= 0, k <= t else { return nil }
        let sorted = entries.sorted { $0.key.utf16.lexicographicallyPrecedes($1.key.utf16) }
        // distinct per KEY COMPONENT across all entries
        var seen = Set<JKey>()
        for e in sorted {
            for c in e.ed.map({ [$0, e.pq] }) ?? [e.pq] {
                if seen.contains(JKey(c)) { return nil }
                seen.insert(JKey(c))
            }
        }
        if Double(sorted.filter { hashBased($0.alg) }.count) < k { return nil }
        // the id binds the numbers as given: a -0 commitment has no canonical form, so no id
        let body: JSONValue = .object(["d": s(SET_DOMAIN), "t": tV ?? .null, "k": kV ?? .null,
                                       "s": .array(sorted.map { .object(["a": s($0.alg), "e": $0.ed.map { s($0) } ?? .null, "p": s($0.pq)]) })])
        guard let canon = IV.strictCanon(body) else { return nil }
        return Loaded(t: Int64(t), minHashBased: Int64(k), entries: sorted, id: Base64URLStrict.encode(sha384(Canonical.utf8(canon))))
    }

    private static func keyOf(_ suite: PQ.Suite, _ keys: JSONValue) -> JSONValue? {
        if suite.pq == .mlDsa65 { return keys.get("mlDsaPub") }
        if suite.pq == .mlDsa87 { return keys.get("mlDsa87Pub") }
        if suite.slh == "SLH-DSA-SHA2-128f" { return keys.get("slhDsaPub") }
        if suite.fnDsa == "fn-dsa-512" { return keys.get("fnDsa512Pub") }
        if suite.fnDsa == "fn-dsa-1024" { return keys.get("fnDsa1024Pub") }
        return keys.get("slhDsa256sPub")
    }

    /// Build a quorum set from `[{alg, keys: {edPub?, mlDsaPub?, mlDsa87Pub?, slhDsaPub?, slhDsa256sPub?, fnDsa512Pub?, fnDsa1024Pub?}}]` (base64url public
    /// keys), the threshold `t` and the diversity commitment `minHashBased` (absent = 0): `{ok: true, set: {t, minHashBased, signers: [{alg, ed?, pq}], id}}`
    /// with the signers in canonical order, or `{ok: false, reason: "bad-set"}`.
    public static func buildQuorumSet(_ signers: JSONValue?, t: JSONValue?, minHashBased: JSONValue? = nil) -> JSONValue {
        guard case let .array(list)? = signers else { return badSet }
        var entries: [Entry] = []
        for sg in list {
            guard sg.isObject, let keys = sg.get("keys"), keys.isObject, let name = sg.get("alg")?.asString, let suite = PQ.suites[name],
                  let e = normalizeEntry(sg.get("alg"), keys.get("edPub"), keyOf(suite, keys)) else { return badSet }
            entries.append(e)
        }
        guard let set = finalize(entries, t, minHashBased ?? .int(0)) else { return badSet }
        return .object(["ok": .bool(true), "set": set.json])
    }

    static func load(_ x: JSONValue?) -> Loaded? {
        guard let v = x, v.isObject, case let .array(list)? = v.get("signers"), let id = v.get("id")?.asString else { return nil }
        var entries: [Entry] = []
        for sg in list {
            guard sg.isObject, let e = normalizeEntry(sg.get("alg"), sg.get("ed"), sg.get("pq")) else { return nil }
            entries.append(e)
        }
        guard let set = finalize(entries, v.get("t"), v.get("minHashBased")) else { return nil }
        // the wire order must already be the canonical one
        for (i, e) in set.entries.enumerated() where !IV.same(e.key, entries[i].key) { return nil }
        return IV.same(set.id, id) ? set : nil
    }

    /// Re-validate a set received over the wire: every entry, the canonical order, and the id RE-DERIVED from the content. Same result shape as `buildQuorumSet`.
    public static func loadQuorumSet(_ x: JSONValue?) -> JSONValue {
        guard let set = load(x) else { return badSet }
        return .object(["ok": .bool(true), "set": set.json])
    }

    /// The bytes every signer of a quorum signs: the domain prefix followed by SHA-384 of the canonical `{set_id, epoch, action}`. The arguments are not
    /// validated (any JSON value is bound as given); throws only for a value the strict canonical form refuses.
    public static func quorumMessage(setId: JSONValue, epoch: JSONValue, actionDigest: JSONValue) throws -> [UInt8] {
        guard let canon = IV.strictCanon(.object(["set_id": setId, "epoch": epoch, "action": actionDigest])) else {
            throw PCAProducerError("quorumMessage: a value is outside the canonical profile")
        }
        return Canonical.utf8(MSG_DOMAIN) + sha384(Canonical.utf8(canon))
    }

    /// The action digest of an arbitrary message: base64url(SHA-384(message)).
    public static func quorumActionDigest(_ message: [UInt8]) -> String { Base64URLStrict.encode(sha384(message)) }

    /// `list[index]` as the reference reads it: an index is a number or its canonical decimal text.
    private static func element(_ list: JSONValue?, _ index: JSONValue?) -> JSONValue? {
        guard case let .array(a)? = list, let i = index, let n = JS.indexKey(JS.toString(i)), Int(n) < a.count else { return nil }
        return a[Int(n)]
    }

    /// One signer's share `{i, sig, pq_sig?}` over the quorum message of (`set.id`, `epoch`, `actionDigest`). `key` must be the suite key of the entry at
    /// `index`. Throws for an unknown index, a key of another suite, and a value the canonical form refuses. The set itself is not validated here.
    public static func signQuorumShare(set: JSONValue, index: JSONValue, epoch: JSONValue, actionDigest: JSONValue, key: PCASuiteKey) throws -> JSONValue {
        guard let e = element(set.get("signers"), index) else { throw PCAProducerError("signQuorumShare: no such signer index") }
        guard let id = set.get("id") else { throw PCAProducerError("signQuorumShare: the set has no id") }
        let msg = try quorumMessage(setId: id, epoch: epoch, actionDigest: actionDigest)
        guard let alg = e.get("alg")?.asString, key.alg == alg else { throw PCAProducerError("signQuorumShare: the key is not the suite key of this signer") }
        let p = try key.sign(msg)
        var out: JObject = ["i": index, "sig": s(p.sig)]
        if let q = p.pqSig { out["pq_sig"] = s(q) }
        return .object(out)
    }

    /// `{set_id, sigs}` from a set and its shares (nothing is verified here).
    public static func assembleQuorumProof(set: JSONValue, shares: [JSONValue]) throws -> JSONValue {
        if set.isNull { throw PCAProducerError("assembleQuorumProof: the set is null") }
        var out: JObject = ["sigs": .array(shares)]
        if let id = set.get("id") { out["set_id"] = id }
        return .object(out)
    }

    private static func verifyShare(_ e: Entry, _ msg: [UInt8], _ sig: String, _ pqSig: JSONValue?) -> Bool {
        // the entry's key is the verifier's own registered key (the set is pinned by its id), never a key read off the share
        PQ.verifySuite(alg: e.alg, holder: e.ed ?? "", pq: PQ.resolvePqKey(identity: nil, artifactPk: nil, trustedPk: e.pq), message: msg, sig: sig, pqSig: pqSig?.asString)
    }

    private static func refuse(_ reason: String, detail: Int64? = nil) -> JSONValue {
        var o: JObject = ["ok": .bool(false), "reason": s(reason)]
        if let d = detail { o["detail"] = .int(d) }
        return .object(o)
    }

    /// Verify a quorum proof: `input` is `{set, proof, epoch, actionDigest, expectedSetId?, requireHashBased?}`; the answer is
    /// `{ok: true, signers, count, hashBased}` or `{ok: false, reason, detail?}` with reason one of malformed, bad-set, set-mismatch, too-many-signatures,
    /// unknown-signer, duplicate-signer, bad-signature, below-threshold, diversity-unmet. The first failing share wins and is reported before the threshold.
    public static func verifyQuorum(_ input: JSONValue?) -> JSONValue {
        guard let inp = input, inp.isObject else { return refuse("malformed") }
        guard let set = load(inp.get("set")) else { return refuse("bad-set") }
        if let want = inp.get("expectedSetId"), !IV.same(want.asString, set.id) { return refuse("set-mismatch") }
        guard let epoch = inp.get("epoch"), IV.nonNeg(epoch) != nil, let digest = inp.get("actionDigest"), digest.asString != nil else { return refuse("malformed") }
        guard let p = inp.get("proof"), p.isObject, let proofSet = p.get("set_id")?.asString, case let .array(sigs)? = p.get("sigs") else { return refuse("malformed") }
        if !IV.same(proofSet, set.id) { return refuse("set-mismatch") }
        if sigs.count > set.entries.count { return refuse("too-many-signatures") } // before any signature work
        guard let msg = try? quorumMessage(setId: s(set.id), epoch: epoch, actionDigest: digest) else { return refuse("malformed") }
        var seen = Set<Int64>()
        var hashBasedCount: Int64 = 0
        for raw in sigs {
            guard raw.isObject, let sig = raw.get("sig")?.asString else { return refuse("malformed") }
            guard let i = IV.nonNeg(raw.get("i")), i < Int64(set.entries.count) else { return refuse("unknown-signer") }
            if seen.contains(i) { return refuse("duplicate-signer", detail: i) }
            seen.insert(i)
            let e = set.entries[Int(i)]
            let pqSig = raw.get("pq_sig")
            // a hybrid share carries pq_sig, a pure one must not
            if (PQ.suites[e.alg]?.needsPqSig ?? false) != (pqSig != nil) { return refuse("bad-signature", detail: i) }
            if !verifyShare(e, msg, sig, pqSig) { return refuse("bad-signature", detail: i) }
            if hashBased(e.alg) { hashBasedCount += 1 }
        }
        if Int64(seen.count) < set.t { return refuse("below-threshold") }
        // the stricter of the set's commitment and the verifier's policy (`Math.max` with the reference's number coercion)
        let asked = JS.present(inp.get("requireHashBased")).map { JS.toNumber($0) } ?? 0
        let k = asked.isNaN ? Double.nan : Swift.max(Double(set.minHashBased), asked)
        guard IV.isSafeDouble(k), k >= 0 else { return refuse("malformed") }
        if Double(hashBasedCount) < k { return refuse("diversity-unmet") }
        return .object(["ok": .bool(true), "signers": .array(seen.sorted().map { .int($0) }), "count": .int(Int64(seen.count)), "hashBased": .int(hashBasedCount)])
    }

    /// True when the quorum approved `message` at `epoch` (the action digest is `quorumActionDigest(message)`).
    public static func verifyQuorumApproval(set: JSONValue?, proof: JSONValue?, message: [UInt8], epoch: JSONValue?, expectedSetId: JSONValue? = nil,
                                            requireHashBased: JSONValue? = nil) -> Bool {
        var input: JObject = ["actionDigest": s(quorumActionDigest(message))]
        if let v = set { input["set"] = v }
        if let v = proof { input["proof"] = v }
        if let v = epoch { input["epoch"] = v }
        if let v = expectedSetId { input["expectedSetId"] = v }
        if let v = requireHashBased { input["requireHashBased"] = v }
        return verifyQuorum(.object(input)).get("ok") == .bool(true)
    }

    // ---- rotation --------------------------------------------------------------------------------------------------------------

    /// What the current quorum signs to hand over to the set `toSetId` at `toEpoch`. Throws for a value the canonical form refuses.
    public static func rotationActionDigest(toSetId: JSONValue, toEpoch: JSONValue) throws -> String {
        guard let canon = IV.strictCanon(.object(["kind": s(ROTATION_KIND), "to_set_id": toSetId, "to_epoch": toEpoch])) else {
            throw PCAProducerError("rotationActionDigest: a value is outside the canonical profile")
        }
        return Base64URLStrict.encode(sha384(Canonical.utf8(canon)))
    }

    /// `fromEpoch + 1` as the reference computes it (a number is incremented; text is concatenated, which no verifier accepts as an epoch).
    private static func next(_ epoch: JSONValue) -> JSONValue {
        if case .string = epoch { return s(JS.toString(epoch) + "1") }
        if epoch.isObject || epoch.isArray { return s(JS.toString(epoch) + "1") }
        return PD.num(JS.toNumber(epoch) + 1)
    }

    /// `{from_set_id, from_epoch, to_set, to_epoch: fromEpoch + 1, proof}` (nothing is verified here).
    public static func buildRotationCert(from: JSONValue, fromEpoch: JSONValue, to: JSONValue, shares: [JSONValue]) throws -> JSONValue {
        var out: JObject = ["from_epoch": fromEpoch, "to_set": to, "to_epoch": next(fromEpoch), "proof": try assembleQuorumProof(set: from, shares: shares)]
        if let id = from.get("id") { out["from_set_id"] = id }
        return .object(out)
    }

    /// One signer's share of the rotation from `from` (at `fromEpoch`) to the set `to`.
    public static func signRotationShare(from: JSONValue, index: JSONValue, fromEpoch: JSONValue, to: JSONValue, key: PCASuiteKey) throws -> JSONValue {
        guard let toId = to.get("id") else { throw PCAProducerError("signRotationShare: the next set has no id") }
        return try signQuorumShare(set: from, index: index, epoch: fromEpoch, actionDigest: s(try rotationActionDigest(toSetId: toId, toEpoch: next(fromEpoch))), key: key)
    }

    /// Walk a rotation chain from a pinned genesis set and epoch: `{ok: true, set, epoch, length}` (the current set) or `{ok: false, reason, at}` where `at`
    /// is the failing link (-1 before any link). Each link must name the current set, step the epoch by exactly one, carry a loadable and different next
    /// set, and be approved by the CURRENT quorum.
    public static func verifyRotationChain(genesisSet: JSONValue?, genesisEpoch: JSONValue?, chain: JSONValue?) -> JSONValue {
        func no(_ reason: String, _ at: Int) -> JSONValue { .object(["ok": .bool(false), "reason": s(reason), "at": .int(Int64(at))]) }
        guard var cur = load(genesisSet), var epoch = IV.nonNeg(genesisEpoch) else { return no("bad-set", -1) }
        guard case let .array(links)? = chain else { return no("malformed", -1) }
        if links.count > PQ_QUORUM_MAX_CHAIN { return no("chain-too-long", -1) }
        for (n, c) in links.enumerated() {
            guard c.isObject, let fromId = c.get("from_set_id")?.asString, let fromEpoch = IV.nonNeg(c.get("from_epoch")), let toEpoch = IV.nonNeg(c.get("to_epoch")) else {
                return no("malformed", n)
            }
            if !IV.same(fromId, cur.id) { return no("chain-broken", n) }
            if fromEpoch != epoch || toEpoch != epoch + 1 { return no("non-monotone-epoch", n) }
            guard let nextSet = load(c.get("to_set")), !IV.same(nextSet.id, cur.id) else { return no("bad-rotation", n) }
            guard let digest = try? rotationActionDigest(toSetId: s(nextSet.id), toEpoch: .int(toEpoch)) else { return no("malformed", -1) }
            var input: JObject = ["set": cur.json, "epoch": .int(epoch), "actionDigest": s(digest), "expectedSetId": s(cur.id)]
            if let p = c.get("proof") { input["proof"] = p }
            let v = verifyQuorum(.object(input))
            if v.get("ok") != .bool(true) { return no(v.get("reason")?.asString ?? "malformed", n) }
            cur = nextSet
            epoch = toEpoch
        }
        return .object(["ok": .bool(true), "set": cur.json, "epoch": .int(epoch), "length": .int(Int64(links.count))])
    }

    /// Two certificates that leave the same set at the same epoch for DIFFERENT next sets (a structural comparison; nothing is verified).
    public static func isRotationFork(_ a: JSONValue?, _ b: JSONValue?) -> Bool {
        guard let x = a, let y = b, x.isObject, y.isObject, let xs = x.get("to_set"), let ys = y.get("to_set"), xs.isObject, ys.isObject,
              IV.strictEq(x.get("from_set_id"), y.get("from_set_id")), IV.strictEq(x.get("from_epoch"), y.get("from_epoch")),
              let xi = xs.get("id")?.asString, let yi = ys.get("id")?.asString else { return false }
        return !IV.same(xi, yi)
    }

    // ---- size model ------------------------------------------------------------------------------------------------------------

    /// `Array.prototype.slice(start, end)` bounds over a list of `count` elements.
    private static func sliceBounds(_ count: Int, _ start: Double, _ end: Double) -> Range<Int> {
        func at(_ v: Double) -> Int {
            let r = v.isNaN ? 0 : v.rounded(.towardZero)
            return Int(r < 0 ? Swift.max(Double(count) + r, 0) : Swift.min(r, Double(count)))
        }
        let lo = at(start), hi = at(end)
        return lo..<Swift.max(lo, hi)
    }

    /// The proof size of a set: `{minBytes, maxBytes, chosenBytes?, t, compact: false}` (the t smallest and the t largest shares; `chosenBytes` for the given
    /// signer indices, an unknown index counting 0). A quorum proof is t whole signatures: it is never compact. Throws for a value that is not a set.
    public static func quorumProofSize(set: JSONValue, indices: JSONValue? = nil) throws -> JSONValue {
        guard case let .array(signers)? = set.get("signers") else { throw PCAProducerError("quorumProofSize: not a quorum set") }
        func shareBytes(_ e: JSONValue) throws -> Int64 {
            guard let alg = e.get("alg")?.asString, let st = PQ.suites[alg] else { throw PCAProducerError("quorumProofSize: unknown suite") }
            return Int64(st.sigBytes + (st.needsPqSig ? st.pqSigBytes : 0))
        }
        let sizes = try signers.map(shareBytes).sorted()
        let t = JS.toNumber(set.get("t"))
        var out: JObject = ["minBytes": .int(sizes[sliceBounds(sizes.count, 0, t)].reduce(0, +)),
                            "maxBytes": .int(sizes[sliceBounds(sizes.count, Double(sizes.count) - t, Double(sizes.count))].reduce(0, +)), "compact": .bool(false)]
        if let tv = set.get("t") { out["t"] = tv }
        if let idx = indices {
            guard case let .array(list) = idx else { throw PCAProducerError("quorumProofSize: indices is not a list") }
            out["chosenBytes"] = .int(try list.reduce(Int64(0)) { sum, i in sum + (try element(.array(signers), i).map(shareBytes) ?? 0) })
        }
        return .object(out)
    }
}
