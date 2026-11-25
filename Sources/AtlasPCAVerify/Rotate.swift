import Foundation

/// Key rotation for PCA capability chains: rotate a leaf (agent) key, re-root a chain under a new principal key, revoke and
/// re-issue a compromised delegation subtree, and `applyRotation` (write every revocation record to a registry all or nothing).
/// Every function returns the re-issued chain plus a revocation record `{capId?, holder?, issuer?, subtreeRoot?, capIds, reason,
/// revokedAt}` in the reference's shape. Chains are re-issued with the real producers (`PCAIssue.mintRoot` / `delegate`), so a
/// re-issue carries exactly the caveats of the hop it replaces and can never widen authority.
public enum PCARotate {
    private static func nn(_ v: JSONValue?, _ k: String) -> JSONValue? { PCARevoke.nn(v, k) }
    private static func member(_ v: JSONValue?, _ k: String) -> JSONValue? { PCARevoke.member(v, k) }

    private static func requireNonEmpty(_ chain: JSONValue?, _ ctx: String) throws -> [JSONValue] {
        guard let c = chain?.asArray, !c.isEmpty else { throw JSError("\(ctx): empty chain") }
        return c
    }

    /// `now` when given must be a finite number (null included: only an absent `now` defaults to the clock).
    private static func checkNow(_ opts: JSONValue?, _ ctx: String) throws -> JSONValue {
        guard let n = member(opts, "now") else { return PCARevoke.num(PCARevoke.nowMs()) }
        if PCARevoke.finite(n) == nil { throw JSError("\(ctx): now must be a finite number") }
        return n
    }

    private static func reason(_ opts: JSONValue?, _ d: String) -> JSONValue { nn(opts, "reason") ?? .string(d) }

    /// A hop the reference reads members of: `null` throws there.
    private static func hop(_ c: JSONValue, _ ctx: String) throws -> JSONValue {
        if c.isNull { throw JSError("\(ctx): malformed capability (null hop)") }
        return c
    }

    private static func appendedCaveats(_ parent: JSONValue, _ child: JSONValue) throws -> [JSONValue] {
        guard let c = member(child, "caveats")?.asArray, let p = member(parent, "caveats")?.asArray else { throw JSError("malformed capability: caveats must be arrays") }
        if c.count < p.count { throw JSError("malformed chain: a child carries fewer caveats than its parent (not an attenuation)") }
        return Array(c[p.count...])
    }

    private static func holderStr(_ c: JSONValue, _ ctx: String) throws -> String {
        guard let h = member(c, "holder")?.asString else { throw JSError("\(ctx): a capability holder must be a string") }
        return h
    }

    private static func idOrNull(_ c: JSONValue) -> JSONValue { member(c, "id") ?? .null }
    private static func put(_ m: inout JObject, _ k: String, _ v: JSONValue?) { if let v = v { m[JKey(k)] = v } }
    private static func suite(_ k: PCAEdKey) -> PCASuiteKey { PCASuiteKey.ed25519(k) }

    /// Rotate the LEAF holder's key: the leaf is re-signed by its issuer (`oldHolder`, the parent holder) to `newKey`, with the
    /// leaf's own appended caveats. `opts` = `{reason?, now?}`. Returns `{chain, revocation}` (the old leaf revoked).
    public static func rotateAgentKey(_ chain: JSONValue?, oldHolder: PCAEdKey, newKey: PCAEdKey, opts: JSONValue? = nil) throws -> JSONValue {
        let ctx = "rotateAgentKey"
        let c = try requireNonEmpty(chain, ctx)
        if c.count < 2 { throw JSError("rotateAgentKey: a root-only chain has no leaf delegation to re-issue; use rotatePrincipalKey") }
        let parent = try hop(c[c.count - 2], ctx), leaf = try hop(c[c.count - 1], ctx)
        if member(leaf, "issuer")?.asString != oldHolder.id { throw JSError("rotateAgentKey: oldHolderSecret is not the leaf's issuer") }
        if member(leaf, "holder")?.asString == newKey.id { throw JSError("rotateAgentKey: newKeyPair is the key being rotated out") }
        let revokedAt = try checkNow(opts, ctx)
        let newLeaf = try PCAIssue.delegate(parent: parent, toHolder: newKey.id, added: try appendedCaveats(parent, leaf), signer: suite(oldHolder))
        var r: JObject = [:]
        put(&r, "capId", member(leaf, "id")); put(&r, "holder", member(leaf, "holder")); put(&r, "issuer", member(leaf, "issuer"))
        r["capIds"] = .array([idOrNull(leaf)])
        r["reason"] = reason(opts, "agent key rotated")
        r["revokedAt"] = revokedAt
        return .object(["chain": .array(Array(c[..<(c.count - 1)]) + [newLeaf]), "revocation": .object(r)])
    }

    /// Re-root a chain under a new principal key. `args` = `{chain?, oldRoot?, reason?, now?}` (`chain ?? [oldRoot]`); every
    /// non-root hop is re-signed by its issuer, `holderSecrets[i - 1]` for hop i. Returns `{chain, revocation}` (the whole old
    /// chain revoked with the old root).
    public static func rotatePrincipalKey(_ args: JSONValue?, oldPrincipal: PCAEdKey, newPrincipal: PCAEdKey, holderSecrets: [PCAEdKey]) throws -> JSONValue {
        let ctx = "rotatePrincipalKey"
        let chain: JSONValue
        if let c = nn(args, "chain") { chain = c }
        else if let r = member(args, "oldRoot"), JS.truthy(r) { chain = .array([r]) }
        else { chain = .array([]) }
        let c = try requireNonEmpty(chain, ctx)
        let oldRoot = try hop(c[0], ctx)
        if member(oldRoot, "parent") != nil { throw JSError("rotatePrincipalKey: chain[0] is not a root (it has a parent)") }
        let rootIssuer = member(oldRoot, "issuer")?.asString
        if rootIssuer != oldPrincipal.id { throw JSError("rotatePrincipalKey: oldPrincipalSecret is not the root's issuer") }
        if holderSecrets.count != c.count - 1 {
            throw JSError("rotatePrincipalKey: expected \(c.count - 1) holderSecrets (one per non-root hop), got \(holderSecrets.count)")
        }
        if rootIssuer == newPrincipal.id { throw JSError("rotatePrincipalKey: newPrincipalKeyPair is the key being rotated out") }
        let revokedAt = try checkNow(args, ctx)
        guard let caveats = member(oldRoot, "caveats")?.asArray else { throw JSError("rotatePrincipalKey: the root has no caveats") }
        var out = [try PCAIssue.mintRoot(principal: suite(newPrincipal), holder: try holderStr(oldRoot, ctx), caveats: caveats)]
        for i in 1..<max(c.count, 1) {
            let oldParent = try hop(c[i - 1], ctx), oldChild = try hop(c[i], ctx)
            let signer = holderSecrets[i - 1]
            if member(oldChild, "issuer")?.asString != signer.id { throw JSError("rotatePrincipalKey: holderSecret for hop \(i) is not that hop's issuer") }
            out.append(try PCAIssue.delegate(parent: out[i - 1], toHolder: try holderStr(oldChild, ctx), added: try appendedCaveats(oldParent, oldChild), signer: suite(signer)))
        }
        var r: JObject = [:]
        put(&r, "capId", member(oldRoot, "id")); put(&r, "issuer", member(oldRoot, "issuer")); put(&r, "holder", member(oldRoot, "holder"))
        put(&r, "subtreeRoot", member(oldRoot, "id"))
        r["capIds"] = .array(c.map(idOrNull))
        r["reason"] = reason(args, "principal key rotated (re-root)")
        r["revokedAt"] = revokedAt
        return .object(["chain": .array(out), "revocation": .object(r)])
    }

    private static func indexOfHolder(_ c: [JSONValue], _ holder: JSONValue, _ ctx: String) throws -> Int? {
        // `===`: two objects / arrays are never identical
        if holder.isObject || holder.isArray { for h in c { _ = try hop(h, ctx) }; return nil }
        for (i, h) in c.enumerated() { if member(try hop(h, ctx), "holder") == holder { return i } }
        return nil
    }

    /// Treat `compromisedHolder` as compromised: revoke the hop it first holds and every descendant, and re-delegate from the
    /// safe ancestor (`ancestor`, the holder just above) straight to `newKey`, carrying the old leaf's appended caveats (never
    /// wider). `opts` = `{reason?, now?}`. Returns `{chain, revocation}`.
    public static func revokeAndReissueSubtree(_ chain: JSONValue?, _ compromisedHolder: JSONValue, newKey: PCAEdKey, ancestor: PCAEdKey, opts: JSONValue? = nil) throws -> JSONValue {
        let ctx = "revokeAndReissueSubtree"
        let c = try requireNonEmpty(chain, ctx)
        guard let idx = try indexOfHolder(c, compromisedHolder, ctx) else { throw JSError("revokeAndReissueSubtree: holder \(JS.toString(compromisedHolder)) is not in the chain") }
        if idx == 0 { throw JSError("revokeAndReissueSubtree: the compromised holder is the root holder (no safe delegation ancestor); rotate the root with rotatePrincipalKey") }
        let anc = try hop(c[idx - 1], ctx), subtreeRoot = c[idx], leaf = try hop(c[c.count - 1], ctx)
        if member(anc, "holder")?.asString != ancestor.id { throw JSError("revokeAndReissueSubtree: ancestorSecret is not the safe ancestor's holder") }
        for h in c[idx...] {
            if member(try hop(h, ctx), "holder")?.asString == newKey.id { throw JSError("revokeAndReissueSubtree: newKeyPair is a key held inside the compromised subtree") }
        }
        let revokedAt = try checkNow(opts, ctx)
        let newHop = try PCAIssue.delegate(parent: anc, toHolder: newKey.id, added: try appendedCaveats(anc, leaf), signer: suite(ancestor))
        var r: JObject = [:]
        put(&r, "capId", member(subtreeRoot, "id"))
        r["holder"] = compromisedHolder
        put(&r, "issuer", member(subtreeRoot, "issuer")); put(&r, "subtreeRoot", member(subtreeRoot, "id"))
        r["capIds"] = .array(c[idx...].map(idOrNull))
        r["reason"] = reason(opts, "delegation subtree compromised")
        r["revokedAt"] = revokedAt
        return .object(["chain": .array(Array(c[..<idx]) + [newHop]), "revocation": .object(r)])
    }

    /// `revokeAndReissueSubtree` end to end: one revocation record per revoked hop (each naming the subtree root) plus the
    /// re-issued chain, `{revocations, reissued}`.
    public static func compromisedKeyFlow(_ chain: JSONValue?, _ compromisedHolder: JSONValue, newKey: PCAEdKey, ancestor: PCAEdKey, opts: JSONValue? = nil) throws -> JSONValue {
        let ctx = "compromisedKeyFlow"
        let c = try requireNonEmpty(chain, ctx)
        guard let idx = try indexOfHolder(c, compromisedHolder, ctx) else { throw JSError("compromisedKeyFlow: holder \(JS.toString(compromisedHolder)) is not in the chain") }
        let reissued = try revokeAndReissueSubtree(chain, compromisedHolder, newKey: newKey, ancestor: ancestor, opts: opts).get("chain") ?? .null
        let rootId = member(c[idx], "id")
        let revokedAt = try checkNow(opts, ctx)
        let why = reason(opts, "delegation subtree compromised")
        let revocations: [JSONValue] = c[idx...].map { h in
            var r: JObject = [:]
            put(&r, "capId", member(h, "id")); put(&r, "holder", member(h, "holder")); put(&r, "issuer", member(h, "issuer"))
            put(&r, "subtreeRoot", rootId)
            r["capIds"] = .array([idOrNull(h)])
            r["reason"] = why
            r["revokedAt"] = revokedAt
            return .object(r)
        }
        return .object(["revocations": .array(revocations), "reissued": reissued])
    }

    /// Where `applyRotation` writes: a revocation registry (or anything with its `revoke` / `unrevoke` / `lookup`).
    public protocol Sink: AnyObject {
        func revoke(_ input: JSONValue) throws -> JSONValue
        func unrevoke(_ key: JSONValue) throws -> Bool
        func lookup(_ kind: String, _ value: String) throws -> JSONValue?
    }

    /// Write the cap ids of one record or an array of records (`capIds ?? [capId]`, first record wins per id) to `sink`, all or
    /// none: on a failure every id this call newly added is unrevoked again (best effort) and the failure rethrown. Refuses an
    /// invalid id, an empty set, and a `reissued` chain that still contains a revoked cap. Returns the ids in order.
    public static func applyRotation(_ sink: Sink, _ records: JSONValue, reissued: JSONValue? = nil) throws -> [String] {
        let list = records.asArray ?? [records]
        var todo: [(id: String, record: JSONValue)] = []
        for r in list {
            if r.isNull { throw JSError("applyRotation: a record is null") }
            let ids = try nn(r, "capIds").map { try JS.spread($0) } ?? (member(r, "capId").map { [$0] } ?? [])
            for id in ids {
                guard let s = id.asString, !s.isEmpty else { throw JSError("applyRotation: a record names an invalid capability id") }
                if !todo.contains(where: { $0.id == s }) { todo.append((s, r)) }
            }
        }
        if todo.isEmpty { throw JSError("applyRotation: the record names no capability to revoke") }
        var kept: [JSONValue] = []
        if let rs = JS.present(reissued) {
            guard let a = rs.asArray else { throw JSError("applyRotation: reissued must be a capability chain") }
            kept = try a.map { idOrNull(try hop($0, "applyRotation")) }
        }
        if todo.contains(where: { t in kept.contains(.string(t.id)) }) { throw JSError("applyRotation: the re-issued chain contains a capability that is being revoked") }
        var added: [String] = []
        do {
            for t in todo {
                if try sink.lookup("cap", t.id) == nil { added.append(t.id) }
                var input: JObject = ["kind": .string("cap"), "value": .string(t.id)]
                put(&input, "reason", member(t.record, "reason")); put(&input, "revokedAt", member(t.record, "revokedAt"))
                _ = try sink.revoke(.object(input))
            }
        } catch {
            // best effort: the original failure is the one to report
            for id in added { _ = try? sink.unrevoke(.object(["kind": .string("cap"), "value": .string(id)])) }
            throw error
        }
        return todo.map { $0.id }
    }
}

extension PCARevoke.Registry: PCARotate.Sink {}
