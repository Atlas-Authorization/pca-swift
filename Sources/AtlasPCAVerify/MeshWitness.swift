import Foundation

/// The issuing side of the agent mesh (the TypeScript `mesh` and `durable-mesh-witness`): an independent log witness (`MeshWitness`) with its durable stores,
/// the issuer-side domain (`MeshDomain`: delegation log, revocation set, head publication, per-hop evidence) and the proofs they use (`RevocationSet`,
/// `consistencyProof`). Verification of a whole proof is `Mesh.verifyMeshProof`; signing the leaf action and assembling the proof are in `PCASigners`.
/// Records are `JSONValue` objects with the reference's member names; keys are `PCAEdKey`.

/// The id a domain's revocation set uses to revoke an agent KEY (kills every capability it issues).
public func keyRevocationId(_ agentPublic: String) -> String { "key:" + agentPublic }

private func u16less(_ a: String, _ b: String) -> Bool { a.utf16.lexicographicallyPrecedes(b.utf16) }
private func utf8less(_ a: String, _ b: String) -> Bool { a.utf8.lexicographicallyPrecedes(b.utf8) }
private func s(_ x: String) -> JSONValue { .string(x) }

// ---- revocation set and consistency proofs -------------------------------------------------------------------------------------

/// A sorted set of revoked ids (UTF-8 byte order). `root` is bound to the size, so a prefix of the set never has the full root.
public final class RevocationSet {
    private var ids: [String] = []

    public init(_ initial: [String] = []) { for i in initial { revoke(i) } }

    public var size: Int { ids.count }

    private func lowerBound(_ rid: String) -> Int {
        var lo = 0, hi = ids.count
        while lo < hi {
            let mid = (lo + hi) >> 1
            if utf8less(ids[mid], rid) { lo = mid + 1 } else { hi = mid }
        }
        return lo
    }

    /// Idempotent. True when newly revoked.
    @discardableResult
    public func revoke(_ rid: String) -> Bool {
        let lo = lowerBound(rid)
        if lo < ids.count && IV.same(ids[lo], rid) { return false }
        ids.insert(rid, at: lo)
        return true
    }

    public func has(_ rid: String) -> Bool {
        let lo = lowerBound(rid)
        return lo < ids.count && IV.same(ids[lo], rid)
    }

    /// The sorted revoked ids (a copy).
    public func list() -> [String] { ids }

    public var root: String { IntentRevocation.revsetRoot(ids) ?? "" }

    private func proof(_ i: Int) throws -> JSONValue { try PCAGrants.merkleProof(ids.map { .string($0) }, i) }

    /// The inclusion proof of a revoked id; throws when the id is not revoked.
    public func membershipProof(_ rid: String) throws -> JSONValue {
        let lo = lowerBound(rid)
        guard lo < ids.count && IV.same(ids[lo], rid) else { throw PCAProducerError("membershipProof: id is not revoked") }
        return try proof(lo)
    }

    /// `{size, lo?: {id, proof}, hi?: {id, proof}}`: the neighbours of `rid` in the sorted set. Throws when the id IS revoked (no such proof can exist).
    public func nonMembershipProof(_ rid: String) throws -> JSONValue {
        if has(rid) { throw PCAProducerError("nonMembershipProof: id is revoked") }
        let lo = lowerBound(rid), n = ids.count
        var p: JObject = ["size": .int(Int64(n))]
        if lo > 0 { p["lo"] = .object(["id": s(ids[lo - 1]), "proof": try proof(lo - 1)]) }
        if lo < n { p["hi"] = .object(["id": s(ids[lo]), "proof": try proof(lo)]) }
        return .object(p)
    }
}

/// RFC 9162 consistency proof `{oldSize, newSize, path}` between the first `oldSize` and the first `newSize` commits (`newSize` nil = all of them). Throws on
/// invalid sizes.
public func consistencyProof(_ commits: [String], oldSize: Int, newSize: Int? = nil) throws -> JSONValue {
    let all = commits.count, new = newSize ?? all
    if oldSize < 0 || oldSize > new || new > all { throw PCAProducerError("consistencyProof: invalid sizes") }
    var out: [[UInt8]] = []
    func sub(_ m: Int, _ hs: ArraySlice<[UInt8]>, _ b: Bool) {
        let n = hs.count
        if m == n {
            if !b { out.append(Merkle.build(Array(hs))) }
            return
        }
        var k = 1
        while k * 2 < n { k *= 2 }
        let arr = Array(hs)
        if m <= k {
            sub(m, arr[..<k], b)
            out.append(Merkle.build(Array(arr[k...])))
        } else {
            sub(m - k, arr[k...], false)
            out.append(Merkle.build(Array(arr[..<k])))
        }
    }
    if oldSize > 0 && oldSize < new { sub(oldSize, commits[..<new].map { Merkle.leafHash(.string($0)) }[...], true) }
    return .object(["oldSize": .int(Int64(oldSize)), "newSize": .int(Int64(new)), "path": .array(out.map { .string(Base64URLStrict.encode($0)) })])
}

// ---- witness stores --------------------------------------------------------------------------------------------------------------

/// Durable memory of a `MeshWitness`: `load` returns nil on a first run, throws on a damaged store (a witness never starts empty over damaged memory).
public protocol MeshWitnessStore: AnyObject {
    func load() throws -> JSONValue?
    func save(_ state: JSONValue) throws
}

/// In-process store (a test double, and the default when no store is given). It does not survive a restart.
public final class MemoryMeshWitnessStore: MeshWitnessStore {
    private var state: JSONValue?
    public init() {}
    public func load() throws -> JSONValue? { state }
    public func save(_ state: JSONValue) throws { self.state = state }
}

/// A file-backed store. Every save writes a temporary file, fsyncs it, renames it over the real file and fsyncs the directory, so a crash leaves the old state
/// or the new one, never a torn file. The file carries a digest of its state: a file that does not parse, has the wrong shape or fails the digest makes `load`
/// throw (a witness never starts empty over a damaged file). A missing file is a first run. Single process: two witnesses must not share one file.
public final class FileMeshWitnessStore: MeshWitnessStore {
    private let path: String
    public init(path: String) { self.path = path }

    public func load() throws -> JSONValue? {
        guard FileManager.default.fileExists(atPath: path) else { return nil }
        guard let data = FileManager.default.contents(atPath: path), let text = String(data: data, encoding: .utf8), let doc = try? StrictJSON.parseLenient(text) else {
            throw PCAProducerError("FileMeshWitnessStore: the state file is not valid JSON; refusing to start empty")
        }
        guard case let .object(o) = doc, case .int(1)? = o["v"], let digest = o["digest"]?.asString, let state = o["state"], state.isObject else {
            throw PCAProducerError("FileMeshWitnessStore: the state file has an unexpected shape; refusing to start empty")
        }
        if !IV.same(Canonical.hashCanonical(state), digest) { throw PCAProducerError("FileMeshWitnessStore: the state file fails its digest; refusing to start empty") }
        return state
    }

    public func save(_ state: JSONValue) throws {
        var doc: JObject = [:]
        doc[o: "v"] = .int(1)
        doc[o: "state"] = state
        doc[o: "digest"] = s(Canonical.hashCanonical(state))
        let body = Data(JS.stringify(.object(doc)).utf8)
        let tmp = path + ".tmp"
        let fd = open(tmp, O_WRONLY | O_CREAT | O_TRUNC, 0o600)
        if fd < 0 { throw PCAProducerError("FileMeshWitnessStore: cannot write the state file") }
        defer { close(fd) }
        let written = body.withUnsafeBytes { write(fd, $0.baseAddress, body.count) }
        if written != body.count || fsync(fd) != 0 { throw PCAProducerError("FileMeshWitnessStore: cannot write the state file") }
        if rename(tmp, path) != 0 { throw PCAProducerError("FileMeshWitnessStore: cannot replace the state file") }
        let dir = (path as NSString).deletingLastPathComponent
        let dfd = open(dir.isEmpty ? "." : dir, O_RDONLY)
        if dfd >= 0 { fsync(dfd); close(dfd) } // some platforms cannot fsync a directory; the rename above is already atomic
    }
}

// ---- witness -------------------------------------------------------------------------------------------------------------------

/// An independent log witness. It cosigns a domain head only if (1) the domain signed it, (2) it is an RFC 9162-verified append-only extension of the last head
/// THIS witness cosigned for that domain, (3) its revocation list reproduces `rev_root` and is a superset of the previously cosigned list, and (4) the timestamp
/// does not regress (nor run ahead of the witness's own clock, when configured). State is committed only after every check passes (and after the store saved it).
/// First sight of a domain is trust-on-first-use.
public final class MeshWitness {
    private static let MAX_REV_IDS = 1_000_000
    private struct Seen { var head: JObject; var rev: [String] }

    private let secret: PCAEdKey
    private let store: MeshWitnessStore?
    private let clock: (() -> Double)?
    private let skew: Double
    private var seen: [JKey: Seen] = [:]
    /// The witness's public key (base64url).
    public let id: String

    /// `secret` is the witness key; `store` is durable memory (a damaged state makes init throw); `clock` (ms) and `maxClockSkewMs` refuse heads from the
    /// witness's future.
    public init(secret: PCAEdKey, store: MeshWitnessStore? = nil, clock: (() -> Double)? = nil, maxClockSkewMs: Double? = nil) throws {
        self.secret = secret
        self.store = store
        self.clock = clock
        self.skew = maxClockSkewMs ?? Mesh.DEFAULT_MAX_SKEW_MS
        self.id = Base64URLStrict.encode(secret.pub)
        if let loaded = try store?.load() { try importState(loaded) }
    }

    /// The newest head this witness cosigned for `domain` (what a domain must prove consistency from).
    public func lastSeen(_ domain: String) -> JSONValue? { seen[JKey(domain)].map { .object($0.head) } }

    private func stateOf(_ m: [JKey: Seen]) -> JSONValue {
        let items = m.values.sorted { u16less($0.head["domain"]?.asString ?? "", $1.head["domain"]?.asString ?? "") }
        return .object(["seen": .array(items.map { .object(["head": .object($0.head), "rev_ids": .array($0.rev.map { s($0) })]) })])
    }

    /// Cosign a head: `req` is `{head: CosignedHead, consistency?, rev_ids}`. Throws (and changes nothing) if any rule is violated.
    public func cosign(_ req: JSONValue) throws -> JSONValue {
        guard let ch = req.get("head"), case let .string(sig)? = ch.get("sig"), let h = Mesh.validHead(ch.get("head")), let domain = h["domain"]?.asString else {
            throw PCAProducerError("witness: malformed head")
        }
        guard let msg = Mesh.msg(Mesh.HEAD_DOMAIN, .object(h)), Ed25519Strict.verifyB64u(domain, msg, sig) else { throw PCAProducerError("witness: head not signed by its domain") }
        let ts = IV.num(h["timestamp"]) ?? .nan
        if let c = clock, !(c().isFinite && skew.isFinite && ts <= c() + skew) { throw PCAProducerError("witness: head timestamp is in the future") }
        guard case let .array(raw)? = req.get("rev_ids"), raw.count <= Self.MAX_REV_IDS, raw.allSatisfy({ $0.asString != nil }) else { throw PCAProducerError("witness: malformed revocation list") }
        let rs = RevocationSet(raw.compactMap { $0.asString })
        if Int64(rs.size) != Mesh.natV(h["rev_size"]) || !IV.same(rs.root, h["rev_root"]?.asString) { throw PCAProducerError("witness: revocation list does not match head") }
        if let prev = seen[JKey(domain)] {
            let why = Mesh.checkHeadAdvance(.object(prev.head), .object(h), req.get("consistency"))
            if !why.isEmpty { throw PCAProducerError("witness: " + why) }
            if !(ts >= (IV.num(prev.head["timestamp"]) ?? .nan)) { throw PCAProducerError("witness: timestamp regresses") }
            let now = Set(rs.list().map { JKey($0) })
            if !prev.rev.allSatisfy({ now.contains(JKey($0)) }) { throw PCAProducerError("witness: revocation set drops a previously cosigned revocation") }
        }
        if let st = store {
            var nxt = seen
            nxt[JKey(domain)] = Seen(head: h, rev: rs.list())
            do { try st.save(stateOf(nxt)) } catch { throw PCAProducerError("witness: could not persist state; refusing to cosign") } // persist first, commit to memory second
        }
        seen[JKey(domain)] = Seen(head: h, rev: rs.list())
        guard let cos = Mesh.msg(Mesh.COSIG_DOMAIN, .object(h)) else { throw PCAProducerError("witness: malformed head") }
        return .object(["witness": s(id), "sig": s(Base64URLStrict.encode(try secret.sign(cos)))])
    }

    /// Memory for persistence, in a deterministic order.
    public func exportState() -> JSONValue { stateOf(seen) }

    /// Restore memory; each record must be internally consistent (its revocation list reproduces its root).
    public func importState(_ state: JSONValue?) throws {
        var nxt: [JKey: Seen] = [:]
        var items: [JSONValue] = []
        if let sv = state?.get("seen"), !sv.isNull {
            guard case let .array(a) = sv else { throw PCAProducerError("witness: malformed state") }
            items = a
        }
        for it in items {
            guard case .object = it, let h = Mesh.validHead(it.get("head")), case let .array(ids)? = it.get("rev_ids"), ids.allSatisfy({ $0.asString != nil }),
                  let domain = h["domain"]?.asString else { throw PCAProducerError("witness: malformed state") }
            let rs = RevocationSet(ids.compactMap { $0.asString })
            if Int64(rs.size) != Mesh.natV(h["rev_size"]) || !IV.same(rs.root, h["rev_root"]?.asString) { throw PCAProducerError("witness: malformed state") }
            nxt[JKey(domain)] = Seen(head: h, rev: rs.list())
        }
        seen = nxt
    }
}

// ---- domain ------------------------------------------------------------------------------------------------------------------

/// Issuer-side state of one organisation: an append-only delegation log, a revocation set and head publication (in memory, so the protocol can be exercised end
/// to end).
public final class MeshDomain {
    private let secret: PCAEdKey
    private var log: [String] = []
    private let rev = RevocationSet()
    private var snaps: [JKey: (log: [String], rev: RevocationSet)] = [:]
    public let name: String
    /// The domain's public key (base64url).
    public let id: String

    public init(name: String, secret: PCAEdKey) {
        self.name = name
        self.secret = secret
        self.id = Base64URLStrict.encode(secret.pub)
    }

    /// Vouch that an agent key belongs to this domain: `{agent, domain, role, sig}`.
    public func enroll(agent: String, role: String) throws -> JSONValue {
        let body: JSONValue = .object(["agent": s(agent), "domain": s(id), "role": s(role)])
        guard let m = Mesh.msg(Mesh.BINDING_DOMAIN, body) else { throw PCAProducerError("enroll: not canonicalizable") }
        return .object(["agent": s(agent), "domain": s(id), "role": s(role), "sig": s(Base64URLStrict.encode(try secret.sign(m)))])
    }

    /// Log a delegation hop issued in this domain. Idempotent; returns its index.
    @discardableResult
    public func record(_ cap: JSONValue) throws -> Int {
        guard IV.strictHash(cap) != nil else { throw PCAProducerError("record: the capability is not canonicalizable") }
        let h = Capability.capHash(cap)
        if let i = log.firstIndex(where: { IV.same($0, h) }) { return i }
        log.append(h)
        return log.count - 1
    }

    /// Revoke a capability id (`cap["id"]`) or an agent key (`keyRevocationId`).
    public func revoke(_ rid: String) { rev.revoke(rid) }

    public func revocationSetCopy() -> RevocationSet { RevocationSet(rev.list()) }

    /// RFC 9162 consistency proof between two sizes of this domain's current log.
    public func consistencyProof(oldSize: Int, newSize: Int? = nil) throws -> JSONValue { try AtlasPCAVerify.consistencyProof(log, oldSize: oldSize, newSize: newSize) }

    /// The proof a verifier holding `pin` (`{size}`) needs to accept `head` (a head this domain published, larger than the pin).
    public func pinProof(pin: JSONValue, head: JSONValue) throws -> JSONValue {
        guard let sig = head.get("sig")?.asString, let snap = snaps[JKey(sig)] else { throw PCAProducerError("pinProof: unknown head") }
        guard let old = pin.get("size").flatMap({ ToolSchema.fin($0) }), let new = head.get("head")?.get("size").flatMap({ ToolSchema.fin($0) }),
              old == old.rounded(), new == new.rounded() else { throw PCAProducerError("consistencyProof: invalid sizes") }
        return .object(["domain": s(id), "proof": try AtlasPCAVerify.consistencyProof(snap.log, oldSize: Int(old), newSize: Int(new))])
    }

    /// Publish a head: domain-signed, then cosigned by `witnesses`, each shown a real consistency proof from ITS last-seen head plus the revocation list. Throws if
    /// a witness refuses (unless `threshold` tolerates it); nothing is recorded as published on failure.
    public func publishHead(witnesses: [MeshWitness], timestamp: JSONValue, threshold: Int? = nil) throws -> JSONValue {
        let root = log.isEmpty ? "" : (Merkle.merkleRoot(log.map { .string($0) }) ?? "")
        let head: JObject = ["domain": s(id), "size": .int(Int64(log.count)), "root": s(root), "rev_root": s(rev.root), "rev_size": .int(Int64(rev.size)), "timestamp": timestamp]
        guard let m = Mesh.msg(Mesh.HEAD_DOMAIN, .object(head)) else { throw PCAProducerError("publishHead: the head is not canonicalizable") }
        let sig = s(Base64URLStrict.encode(try secret.sign(m)))
        var cosigs: [JSONValue] = []
        let revIds = JSONValue.array(rev.list().map { s($0) })
        var errors: [Error] = []
        for w in witnesses {
            var consistency: JSONValue?
            if let prev = w.lastSeen(id), let ps = IV.num(prev.get("size")) {
                if Int(ps) < log.count { consistency = try AtlasPCAVerify.consistencyProof(log, oldSize: Int(ps), newSize: log.count) }
                else if Int(ps) > log.count { consistency = .object(["oldSize": .int(Int64(ps)), "newSize": .int(Int64(log.count)), "path": .array([])]) } // refused as a rollback
            }
            do {
                var req: JObject = ["head": .object(["head": .object(head), "sig": sig, "cosigs": .array(cosigs)]), "rev_ids": revIds]
                if let c = consistency { req["consistency"] = c }
                cosigs.append(try w.cosign(.object(req)))
            } catch { errors.append(error) }
        }
        let need = threshold ?? witnesses.count
        if cosigs.count < need { throw errors.first ?? PCAProducerError("publishHead: not enough witnesses") }
        snaps[JKey(sig.asString ?? "")] = (log, RevocationSet(rev.list()))
        return .object(["head": .object(head), "sig": sig, "cosigs": .array(cosigs)])
    }

    /// Per-hop evidence against a previously published head. Throws if the cap is not in that head's log or if the cap or issuer key is revoked as of that head (no
    /// non-membership proof can exist).
    public func evidence(cap: JSONValue, head: JSONValue, binding: JSONValue? = nil) throws -> JSONValue {
        guard let sig = head.get("sig")?.asString, let snap = snaps[JKey(sig)] else { throw PCAProducerError("evidence: unknown head") }
        let h = Capability.capHash(cap)
        guard let idx = snap.log.firstIndex(where: { IV.same($0, h) }) else { throw PCAProducerError("evidence: capability not in this head") }
        guard let capId = cap.get("id")?.asString, let issuer = cap.get("issuer")?.asString else { throw PCAProducerError("evidence: malformed capability") }
        var ev: JObject = ["domain": s(id), "head": head, "inclusion": try PCAGrants.merkleProof(snap.log.map { .string($0) }, idx),
                           "revocation": .object(["cap": try snap.rev.nonMembershipProof(capId), "issuer_key": try snap.rev.nonMembershipProof(keyRevocationId(issuer))])]
        if let b = binding, !b.isNull { ev["binding"] = b }
        return .object(ev)
    }
}
