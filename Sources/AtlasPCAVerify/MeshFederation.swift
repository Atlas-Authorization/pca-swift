import Foundation

/// The rest of the mesh module beside the verifier (`Mesh.verifyMeshProof`) and the issuing classes (`MeshDomain`, `MeshWitness`): the effective authority of
/// a caveat list as a value, the proof-size and revocation-latency models, the worked example, and the federation primitives (cross-domain capability
/// translation, the federated budget tree, cross-reference commitments). Records are `JSONValue` objects with the reference's member names. Verifiers and
/// the budget operations never throw (they answer `{ok: false, reason}` or `{error}`); signers, translators and digests throw.
extension Mesh {
    /// How far ahead of a witness's own clock a head may be (ms).
    public static let DEFAULT_MAX_CLOCK_SKEW_MS = DEFAULT_MAX_SKEW_MS
    /// The longest delegation chain a verifier walks (also the depth bound of a federated budget tree).
    public static let DEFAULT_MAX_CHAIN_LENGTH = Int(DEFAULT_MAX_CHAIN)
    static let XCAP_DOMAIN = "atlas-pca/mesh-xcap/v1\u{0}"
    static let XANCHOR_DOMAIN = "atlas-pca/mesh-xanchor/v1\u{0}"
    static let ACTION_DIGEST_DOMAIN = "atlas-pca/mesh-action-digest/v1\u{0}"

    private static func s(_ x: String) -> JSONValue { .string(x) }
    private static func isRec(_ v: JSONValue?) -> Bool { v?.isObject == true }
    private static func isStr(_ v: JSONValue?) -> Bool { v?.asString != nil }
    private static func refuse(_ reason: String) -> JSONValue { .object(["ok": .bool(false), "reason": s(reason)]) }
    private static func errorOf(_ m: String) -> JSONValue { .object(["error": s(m)]) }
    private static func isCaveatArray(_ v: JSONValue?) -> Bool {
        guard case let .array(a)? = v else { return false }
        return a.allSatisfy { isRec($0) && isStr($0.get("type")) }
    }

    // ---- effective authority ---------------------------------------------------------------------------------------------------

    static func authorityJSON(_ e: Authority) -> JSONValue {
        var o: JObject = ["prefixes": .array(e.prefixes.map { s($0) })]
        if e.hasAct { o["actions"] = .array(e.actions.map { s($0) }) }
        if e.hasAmount { o["maxAmount"] = PD.num(e.maxAmount) }
        if e.hasExp { o["expiresAt"] = PD.num(e.expiresAt) }
        if e.hasAud { o["audience"] = .array(e.audience.map { s($0) }) }
        if e.hasHops { o["maxHops"] = PD.num(e.maxHops) }
        return .object(o)
    }

    /// The conjunction of all caveats as one authority `{actions?, prefixes, maxAmount?, expiresAt?, audience?, maxHops?}` (an absent member is
    /// unconstrained), or `{error}` for an unknown or malformed caveat (fail closed; the first one in order wins). Throws, as the reference does, for a
    /// value that is not a list and for a null entry.
    public static func effectiveAuthority(_ caveats: JSONValue) throws -> JSONValue {
        let items: [JSONValue]
        switch caveats {
        case let .array(a): items = a
        // a string is walked character by character, and a character has no type
        case let .string(t): items = t.isEmpty ? [] : [.string(t)]
        default: throw PCAProducerError("effectiveAuthority: caveats is not iterable")
        }
        let stop = items.firstIndex { !$0.isObject }
        let (e, why) = effective(.array(Array(items[..<(stop ?? items.count)])))
        if !why.isEmpty { return errorOf(why) }
        guard let i = stop else { return authorityJSON(e) }
        if items[i].isNull { throw PCAProducerError("effectiveAuthority: a caveat is null") }
        return errorOf("unknown caveat type \"undefined\" (fail closed)")
    }

    // ---- size and latency models -----------------------------------------------------------------------------------------------

    /// Byte lengths of the canonical JSON of a compact proof and of its parts, and what the same evidence costs uncompacted (every hop carrying its whole
    /// head and its revocation leaves): `{total_bytes, chain_bytes, heads_bytes, rev_leaves_bytes, hops_bytes, uncompacted_bytes}`. Throws for a value that
    /// is not a proof (a missing member, a hop without its head or revocation brackets).
    public static func meshProofSize(_ p: JSONValue) throws -> JSONValue {
        func bytes(_ v: JSONValue?) throws -> Int64 {
            guard let x = v, let c = IV.strictCanon(x) else { throw PCAProducerError("meshProofSize: a member is missing or outside the canonical profile") }
            return Int64(Canonical.utf8(c).count)
        }
        /// `container[index]` of the reference: an array answers an index (a number or its decimal text), an object its member; nothing else has members.
        func member(_ container: JSONValue?, _ index: JSONValue?) throws -> JSONValue? {
            guard let c = container, !c.isNull else { throw PCAProducerError("meshProofSize: an indexed list is missing") }
            guard let i = index else { return nil }
            switch c {
            case let .array(a):
                guard let n = JS.indexKey(JS.toString(i)), Int(n) < a.count else { return nil }
                return a[Int(n)]
            case let .object(o): return o[JKey(JS.toString(i))]
            default: return nil
            }
        }
        let revLeaves = p.get("rev_leaves")
        func expand(_ c: JSONValue?) throws -> JSONValue {
            guard let c = c, !c.isNull, let size = c.get("size") else { throw PCAProducerError("meshProofSize: a hop has no revocation bracket") }
            var o: JObject = ["size": size]
            for side in ["lo", "hi"] {
                if let i = c.get(side), let leaf = try member(revLeaves, i), JS.truthy(leaf) { o[JKey(side)] = leaf }
            }
            return .object(o)
        }
        if p.isNull { throw PCAProducerError("meshProofSize: not a proof") }
        let chain = try bytes(p.get("chain"))
        var uncompacted = chain + (try bytes(p.get("action"))) + (try bytes(p.get("action_sig")))
        guard case let .array(hops)? = p.get("hops") else { throw PCAProducerError("meshProofSize: hops is not a list") }
        for h in hops {
            guard var o = h.asObject, let rev = h.get("revocation"), !rev.isNull, let head = try member(p.get("heads"), h.get("head")) else {
                throw PCAProducerError("meshProofSize: malformed hop")
            }
            o["head"] = head
            o["revocation"] = .object(["cap": try expand(rev.get("cap")), "issuer_key": try expand(rev.get("issuer_key"))])
            uncompacted += try bytes(.object(o))
        }
        return .object(["total_bytes": .int(try bytes(p)), "chain_bytes": .int(chain), "heads_bytes": .int(try bytes(p.get("heads"))),
                        "rev_leaves_bytes": .int(try bytes(revLeaves)), "hops_bytes": .int(try bytes(p.get("hops"))), "uncompacted_bytes": .int(uncompacted)])
    }

    /// How long a revocation can stay unseen: `{published_ms, unpinned_ms, pinned_ms, honest_provers_viable}` for `{maxHeadAgeMs, headIntervalMs,
    /// maxClockSkewMs?, pinRefreshMs?}` (finite numbers >= 0). Invalid parameters give infinite bounds and `honest_provers_viable: false`.
    public static func revocationLatencyBound(_ p: JSONValue?) -> JSONValue {
        func ok(_ v: JSONValue?) -> Double? {
            guard let d = IV.num(v), d.isFinite, d >= 0 else { return nil }
            return d
        }
        let never: JSONValue = .object(["published_ms": .double(.infinity), "unpinned_ms": .double(.infinity), "pinned_ms": .double(.infinity), "honest_provers_viable": .bool(false)])
        let skewV = p?.get("maxClockSkewMs"), pinV = p?.get("pinRefreshMs")
        guard let age = ok(p?.get("maxHeadAgeMs")), let intervalV = p?.get("headIntervalMs"), let interval = ok(intervalV),
              skewV == nil || ok(skewV) != nil, pinV == nil || ok(pinV) != nil else { return never }
        let skew = ok(skewV) ?? 0
        let unpinned = age + skew
        return .object(["published_ms": intervalV, "unpinned_ms": PD.num(unpinned), "pinned_ms": PD.num(ok(pinV).map { Swift.min(unpinned, $0) } ?? unpinned),
                        "honest_provers_viable": .bool(interval + skew < age)])
    }

    // ---- worked example: human -> orchestrator (org A) -> tool agent (org B) -> service (org C) ----------------------------------

    /// The parts of the worked example, so callers can build variants (revocation, widening, forks).
    public struct MeshExample {
        public let trust: JSONValue
        public let proof: JSONValue
        /// The uncompacted evidence the proof was assembled from.
        public let evidence: [JSONValue]
        /// `A`, `B`, `C`.
        public let domains: [String: MeshDomain]
        public let witnesses: [MeshWitness]
        /// `human`, `orchestrator`, `tool`, `service`, `leaf`.
        public let keys: [String: PCAEdKey]
        public let chain: [JSONValue]
        /// `A0` is A's earlier head (size 1); `A` its current head (size 2), cosigned only after a verified consistency proof; `B`, `C`.
        public let heads: [String: JSONValue]
        /// `orchestrator`, `tool`, `service`.
        public let bindings: [String: JSONValue]
    }

    /// The example's fixed test seeds: the first 32 bytes of the TEXT of the label's canonical hash (not the decoded digest).
    static func exampleSeed(_ label: String) -> [UInt8] {
        Array(Canonical.utf8(Canonical.hashCanonical(.object(["seed": s("atlas-pca/mesh-example/" + label)]))).prefix(32))
    }

    /// A whole compacted proof over three organisations and three witnesses, with the trust configuration that accepts it at `now` (ms).
    public static func buildMeshExample(now: Double = 1_800_000_000_000) throws -> MeshExample { try buildMeshExample(now: now) { try PCAEdKey(seed: $0) } }

    /// `buildMeshExample` with the key constructor injected (the byte-for-byte replay signs deterministically where the platform hedges).
    static func buildMeshExample(now: Double, key: ([UInt8]) throws -> PCAEdKey) throws -> MeshExample {
        func k(_ label: String) throws -> PCAEdKey { try key(exampleSeed(label)) }
        func caveat(_ type: String, _ member: String, _ value: JSONValue) -> JSONValue { .object(["type": s(type), JKey(member): value]) }
        func strs(_ a: [String]) -> JSONValue { .array(a.map { s($0) }) }
        let human = try k("human"), orchestrator = try k("orchestrator"), tool = try k("tool"), service = try k("service"), leaf = try k("leaf")
        let a = MeshDomain(name: "org-A", secret: try k("domain-A")), b = MeshDomain(name: "org-B", secret: try k("domain-B")), c = MeshDomain(name: "org-C", secret: try k("domain-C"))
        let witnesses = [try MeshWitness(secret: try k("witness-1")), try MeshWitness(secret: try k("witness-2")), try MeshWitness(secret: try k("witness-3"))]

        let root = try PCAIssue.mintRoot(principal: .ed25519(human), holder: orchestrator.id, caveats: [
            caveat("scope", "actions", strs(["payments.refund", "payments.read", "orders.read"])), caveat("resource", "prefix", s("/orders/")),
            caveat("max_amount", "max", .int(500)), caveat("expires", "at", PD.num(now + 3_600_000)), caveat("audience", "domains", strs([c.id])),
        ])
        let c1 = try PCAIssue.delegate(parent: root, toHolder: tool.id, added: [caveat("scope", "actions", strs(["payments.refund", "payments.read"])), caveat("max_amount", "max", .int(100))],
                                       signer: .ed25519(orchestrator))
        let c2 = try PCAIssue.delegate(parent: c1, toHolder: service.id, added: [caveat("resource", "prefix", s("/orders/42")), caveat("max_hops", "n", .int(4))], signer: .ed25519(tool))
        let c3 = try PCAIssue.delegate(parent: c2, toHolder: leaf.id, added: [caveat("scope", "actions", strs(["payments.refund"])), caveat("max_amount", "max", .int(50))], signer: .ed25519(service))
        let chain = [root, c1, c2, c3]

        try a.record(root)
        let hA0 = try a.publishHead(witnesses: witnesses, timestamp: PD.num(now - 2_000))
        try a.record(c1)
        let hA = try a.publishHead(witnesses: witnesses, timestamp: PD.num(now - 1_000)) // size 1 -> 2: consistency-proven by every witness
        try b.record(c2)
        try c.record(c3)
        let hB = try b.publishHead(witnesses: witnesses, timestamp: PD.num(now - 1_000))
        let hC = try c.publishHead(witnesses: witnesses, timestamp: PD.num(now - 1_000))
        let bOrch = try a.enroll(agent: orchestrator.id, role: "orchestrator")
        let bTool = try b.enroll(agent: tool.id, role: "tool-agent")
        let bSvc = try c.enroll(agent: service.id, role: "service-agent")

        let evidence = [try a.evidence(cap: root, head: hA), try a.evidence(cap: c1, head: hA, binding: bOrch), try b.evidence(cap: c2, head: hB, binding: bTool),
                        try c.evidence(cap: c3, head: hC, binding: bSvc)]
        let action: JSONValue = .object(["type": s("payments.refund"), "resource": s("/orders/42/line/1"), "amount": .int(25), "service_domain": s(c.id), "nonce": s("n-0001"),
                                         "at": PD.num(now)])
        let proof = try PCASigners.assembleMeshProof(chain: chain, hops: evidence, action: action, leaf: leaf)
        let trust: JSONValue = .object(["humanPrincipal": s(human.id), "witnesses": strs(witnesses.map { $0.id }), "threshold": .int(2), "now": PD.num(now),
                                        "allowedDomains": strs([a.id, b.id, c.id]), "rootDomain": s(a.id)])
        return MeshExample(trust: trust, proof: proof, evidence: evidence, domains: ["A": a, "B": b, "C": c], witnesses: witnesses,
                           keys: ["human": human, "orchestrator": orchestrator, "tool": tool, "service": service, "leaf": leaf], chain: chain,
                           heads: ["A0": hA0, "A": hA, "B": hB, "C": hC], bindings: ["orchestrator": bOrch, "tool": bTool, "service": bSvc])
    }

    /// A witness refuses a forked log that is LARGER than the head it last cosigned (a size-only check would accept it):
    /// `{honest_extension_cosigned, fork_larger_than_prior, size_only_check_would_accept, fork_rejected, fork_reason}`.
    public static func demonstrateForkRejection() throws -> JSONValue {
        let k = try PCAEdKey(seed: exampleSeed("fork-domain")), hk = try PCAEdKey(seed: exampleSeed("fork-human"))
        func mk(_ n: Int) throws -> JSONValue {
            try PCAIssue.mintRoot(principal: .ed25519(hk), holder: hk.id, caveats: [.object(["type": s("scope"), "actions": .array([s("a\(n)")])])])
        }
        let w = try MeshWitness(secret: try PCAEdKey(seed: exampleSeed("fork-witness")))
        let honest = MeshDomain(name: "X", secret: k)
        try honest.record(try mk(0))
        try honest.record(try mk(1))
        _ = try honest.publishHead(witnesses: [w], timestamp: .int(100))
        try honest.record(try mk(2))
        let honestOk = (try? honest.publishHead(witnesses: [w], timestamp: .int(200))) != nil
        guard let prior = w.lastSeen(honest.id), let priorSize = IV.num(prior.get("size")) else { throw PCAProducerError("demonstrateForkRejection: the witness saw no head") }
        let fork = MeshDomain(name: "X", secret: k) // same key, rewritten history (entry 0 differs), grown past the prior size
        for n in [100, 1, 2, 3] { try fork.record(try mk(n)) }
        var reason = "", rejected = false
        do { _ = try fork.publishHead(witnesses: [w], timestamp: .int(300)) } catch {
            rejected = true
            reason = (error as? PCAProducerError)?.message ?? "\(error)"
        }
        return .object(["honest_extension_cosigned": .bool(honestOk), "fork_larger_than_prior": .bool(4 > priorSize), "size_only_check_would_accept": .bool(4 >= priorSize),
                        "fork_rejected": .bool(rejected), "fork_reason": s(reason)])
    }

    // ---- 1. cross-domain capability translation ----------------------------------------------------------------------------------

    private static func xcapBody(_ from: JSONValue, _ to: JSONValue, _ tip: String, _ caveats: [JSONValue], _ issuedAt: JSONValue) -> JSONValue {
        .object(["v": s("atlas-pca/mesh-xcap/v1"), "from": from, "to": to, "source_tip": s(tip), "caveats": .array(caveats), "issued_at": issuedAt])
    }

    private static func pins(_ v: JSONValue?) -> [String: String]? {
        guard case let .object(o)? = v else { return nil }
        var out: [String: String] = [:]
        for (k, x) in o { if let t = x.asString { out[k.s] = t } }
        return out
    }

    /// Attenuate a capability chain rooted in one Guardian's grant into a capability valid in another domain. The bridge can ONLY NARROW: the translated
    /// caveats are the chain tip's followed by `additionalCaveats`. `args` is `{fromGuardian, toGuardian, additionalCaveats?, issued_at, pqPins?}`; the result
    /// is `{source, fromGuardian, toGuardian, bridge, source_tip, caveats, issued_at, sig}`. Throws for an invalid source chain or malformed arguments.
    public static func translateCapability(_ chain: JSONValue, _ args: JSONValue, bridge: PCAEdKey) throws -> JSONValue {
        let hops = chain.asArray ?? []
        if let why = Capability.verifyChain(hops, expectedRootIssuer: nil, pqPins: pins(args.get("pqPins"))) { throw PCAProducerError("translateCapability: invalid source chain: \(why)") }
        let extra = args.get("additionalCaveats")
        if extra != nil && !isCaveatArray(extra) { throw PCAProducerError("translateCapability: additionalCaveats must be an array of caveats") }
        guard let tip = hops.last, case let .array(tipCaveats)? = tip.get("caveats") else { throw PCAProducerError("translateCapability: invalid source chain: malformed tip") }
        let caveats = tipCaveats + (extra?.asArray ?? [])
        guard let from = args.get("fromGuardian"), let to = args.get("toGuardian"), let issuedAt = args.get("issued_at") else {
            throw PCAProducerError("translateCapability: fromGuardian, toGuardian and issued_at are required")
        }
        let tipHash = Capability.capHash(tip)
        guard let m = msg(XCAP_DOMAIN, xcapBody(from, to, tipHash, caveats, issuedAt)) else { throw PCAProducerError("translateCapability: the translation is outside the canonical profile") }
        return .object(["source": chain, "fromGuardian": from, "toGuardian": to, "bridge": s(bridge.id), "source_tip": s(tipHash), "caveats": .array(caveats), "issued_at": issuedAt,
                        "sig": s(Base64URLStrict.encode(try bridge.sign(m)))])
    }

    /// The effective authority of a translated capability's caveats, or `{error}` (a malformed capability included). Never throws.
    public static func translatedEffectiveAuthority(_ tc: JSONValue?) -> JSONValue {
        guard isRec(tc), isCaveatArray(tc?.get("caveats")) else { return errorOf("malformed translated capability") }
        let (e, why) = effective(tc?.get("caveats"))
        return why.isEmpty ? authorityJSON(e) : errorOf(why)
    }

    /// Verify a translated capability: `{ok: true, from, to, bridge, effective}` or `{ok: false, reason}`. In order: shape, the source chain (`rootIssuer`
    /// and `pqPins` of `opts` are the verifier's pins), the `fromGuardian` / `toGuardian` / `bridge` pins, a real domain crossing, the source tip binding, the
    /// append-only prefix over the tip's caveats, the bridge signature, monotone narrowing of the effective authority, and expiry when `opts.now` is given.
    /// Options that are JSON null are refused as malformed. Never throws.
    public static func verifyTranslatedCapability(_ tc: JSONValue?, _ opts: JSONValue? = nil) -> JSONValue {
        let bad = refuse("malformed translated capability")
        guard let t = tc, isRec(t), case let .array(source)? = t.get("source"), let from = t.get("fromGuardian")?.asString, let to = t.get("toGuardian")?.asString,
              let bridge = t.get("bridge")?.asString, let tipRef = t.get("source_tip")?.asString, let sig = t.get("sig")?.asString, let issuedAt = t.get("issued_at"), num(issuedAt),
              case let .array(caveats)? = t.get("caveats"), isCaveatArray(t.get("caveats")) else { return bad }
        if opts?.isNull == true { return bad }
        func opt(_ k: String) -> JSONValue? { opts?.get(k) }

        // (1) source chain; a pinned root issuer that is not a string can equal no issuer
        let rootIssuer = opt("rootIssuer").map { $0.asString ?? "\u{0}" }
        if let why = Capability.verifyChain(source, expectedRootIssuer: rootIssuer, pqPins: pins(opt("pqPins"))) { return refuse("source chain: \(why)") }

        // (2) guardian / bridge pins (compared without coercion)
        if let v = opt("fromGuardian"), !IV.strictEq(JSONValue.string(from), v) { return refuse("source guardian mismatch") }
        if let v = opt("toGuardian"), !IV.strictEq(JSONValue.string(to), v) { return refuse("target guardian mismatch") }
        if let v = opt("bridge"), !IV.strictEq(JSONValue.string(bridge), v) { return refuse("bridge key mismatch") }
        if IV.same(from, to) { return refuse("translation does not cross a domain boundary") }

        // (3) source tip binding
        guard let tip = source.last, case let .array(tipCaveats)? = tip.get("caveats") else { return bad }
        if !IV.same(tipRef, Capability.capHash(tip)) { return refuse("source_tip does not match the source chain tip") }

        // (4) append-only prefix over the source tip's caveats (the rule of chain attenuation)
        if caveats.count < tipCaveats.count { return refuse("translation drops a source caveat (widening)") }
        for j in tipCaveats.indices {
            guard let x = IV.strictHash(caveats[j]), let y = IV.strictHash(tipCaveats[j]) else { return bad }
            if x != y { return refuse("translation altered or reordered source caveat \(j) (widening)") }
        }

        // (5) bridge signature
        guard let m = msg(XCAP_DOMAIN, xcapBody(.string(from), .string(to), tipRef, caveats, issuedAt)) else { return bad }
        if !Ed25519Strict.verifyB64u(bridge, m, sig) { return refuse("translation not signed by the declared bridge key") }

        // (6) monotone narrowing of the effective authority (defence in depth; unknown caveats fail closed)
        let (effS, whyS) = effective(.array(tipCaveats))
        if !whyS.isEmpty { return refuse("source caveats: \(whyS)") }
        let (effT, whyT) = effective(.array(caveats))
        if !whyT.isEmpty { return refuse(whyT) }
        if !narrows(effT, effS) { return refuse("translated authority widens the source authority") }

        // (7) optional expiry (`Number.isFinite(now)` takes no coercion: only a finite number is a clock)
        if let now = opt("now"), effT.hasExp, !(IV.num(now).map { $0.isFinite && $0 <= effT.expiresAt } ?? false) { return refuse("translated capability expired") }
        return .object(["ok": .bool(true), "from": s(from), "to": s(to), "bridge": s(bridge), "effective": authorityJSON(effT)])
    }

    // ---- 2. consolidated cross-domain budget (the budget tree spans domains) -----------------------------------------------------

    private static func validBudgetState(_ st: JSONValue?) -> JObject? {
        guard let state = st, case let .object(nodes)? = state.get("nodes"), let root = state.get("root")?.asString, num(state.get("kappa")), num(state.get("bMax")),
              f(state.get("kappa")) > 0, f(state.get("bMax")) >= 0, nodes[JKey(root)] != nil else { return nil }
        for n in nodes.values {
            guard isRec(n), isStr(n.get("domain")), num(n.get("B")), f(n.get("B")) >= 0, n.get("parent") == nil || isStr(n.get("parent")) else { return nil }
        }
        return nodes
    }

    private static func withNodes(_ state: JSONValue, _ nodes: JObject) -> JSONValue {
        var o = state.asObject ?? [:]
        o["nodes"] = .object(nodes)
        return .object(["ok": .bool(true), "state": .object(o)])
    }

    /// `B - c` floored at zero (a spend that is not a positive finite number debits nothing).
    private static func debited(_ node: JSONValue, _ c: Double) -> JSONValue {
        var o = node.asObject ?? [:]
        let left = f(node.get("B")) - Risk.nz(c)
        o["B"] = PD.num(left > 0 ? left : 0)
        return .object(o)
    }

    /// A budget tree with one root: `{ok: true, state: {nodes, root, kappa, bMax}}` for `{rootId, rootDomain, B0, kappa, bMax}`, or `{ok: false, reason}`.
    public static func createFederatedBudget(_ args: JSONValue?) -> JSONValue {
        guard let a = args, isRec(a), let rootId = a.get("rootId")?.asString, let rootDomain = a.get("rootDomain"), isStr(rootDomain) else { return refuse("malformed root") }
        guard let kappa = a.get("kappa"), num(kappa), f(kappa) > 0 else { return refuse("kappa must be finite and > 0") }
        guard let bMax = a.get("bMax"), num(bMax), f(bMax) >= 0 else { return refuse("bMax must be finite and >= 0") }
        guard let b0 = a.get("B0"), num(b0), f(b0) >= 0 else { return refuse("B0 must be finite and >= 0") }
        if f(b0) > f(bMax) { return refuse("B0 exceeds bMax") }
        let nodes: JObject = [JKey(rootId): .object(["domain": rootDomain, "B": b0])]
        return .object(["ok": .bool(true), "state": .object(["nodes": .object(nodes), "root": s(rootId), "kappa": kappa, "bMax": bMax])])
    }

    /// Give a new node `{id, domain, parent, alloc}` a ceiling of `alloc` (at most the parent's CURRENT remaining budget; the parent is not reduced).
    public static func allocateSub(_ state: JSONValue?, _ args: JSONValue?) -> JSONValue {
        guard let st = state, var nodes = validBudgetState(st) else { return refuse("malformed budget state") }
        guard let a = args, isRec(a), let id = a.get("id")?.asString, let domain = a.get("domain"), isStr(domain), let parentId = a.get("parent")?.asString else { return refuse("malformed allocation") }
        if nodes[JKey(id)] != nil { return refuse("node id already exists") }
        guard let parent = nodes[JKey(parentId)] else { return refuse("unknown parent") }
        guard let alloc = a.get("alloc"), num(alloc), f(alloc) >= 0 else { return refuse("allocation must be finite and >= 0") }
        if !(f(parent.get("B")).isFinite && f(alloc) <= f(parent.get("B"))) { return refuse("allocation exceeds parent remaining budget") }
        nodes[JKey(id)] = .object(["domain": domain, "parent": s(parentId), "B": alloc])
        return withNodes(st, nodes)
    }

    /// A node spends `c`: every node between it and the root must cover the cost, then all of them are debited together (nothing changes on a refusal).
    public static func spendFederated(_ state: JSONValue?, _ nodeId: JSONValue?, _ c: JSONValue?) -> JSONValue {
        guard let st = state, var nodes = validBudgetState(st), let rootId = st.get("root")?.asString else { return refuse("malformed budget state") }
        guard let spender = nodeId?.asString else { return refuse("malformed node id") }
        guard num(c), f(c) >= 0 else { return refuse("spend must be finite and >= 0") }
        let cost = f(c)
        var path: [String] = []
        var seen = Set<JKey>()
        var cur: String? = spender
        while let id = cur {
            guard let n = nodes[JKey(id)] else { return refuse("unknown node") }
            if seen.contains(JKey(id)) { return refuse("cycle in budget tree") }
            if path.count >= DEFAULT_MAX_CHAIN_LENGTH { return refuse("budget tree too deep") }
            seen.insert(JKey(id))
            path.append(id)
            cur = n.get("parent")?.asString
        }
        guard let top = path.last, IV.same(top, rootId), let root = nodes[JKey(rootId)], let own = nodes[JKey(spender)] else { return refuse("node is not rooted at the budget root") }
        if IV.same(spender, rootId) {
            if !(f(root.get("B")) >= cost) { return refuse("root budget insufficient") }
            nodes[JKey(rootId)] = debited(root, cost)
            return withNodes(st, nodes)
        }
        // strict-interior ancestors (everything between the spender and the root)
        let interior = path.dropFirst().dropLast()
        for id in interior where !(f(nodes[JKey(id)]?.get("B")) >= cost) { return refuse("ancestor \"\(id)\" budget insufficient") }
        // root and spender: the consolidated debit (both or neither)
        let x = Risk.nz(cost)
        if !(f(own.get("B")).isFinite && f(own.get("B")) >= x) { return refuse("sub-agent budget insufficient") }
        if !(f(root.get("B")).isFinite && f(root.get("B")) >= x) { return refuse("parent budget insufficient") }
        nodes[JKey(spender)] = debited(own, cost)
        nodes[JKey(rootId)] = debited(root, cost)
        for id in interior { if let n = nodes[JKey(id)] { nodes[JKey(id)] = debited(n, cost) } }
        return withNodes(st, nodes)
    }

    /// The bound on the total risk the whole delegation tree can spend: `max(0, bMax) / kappa` (0 for malformed parameters or `kappa <= 0`).
    public static func federatedSafetyBound(_ p: JSONValue?) -> Double {
        guard isRec(p), num(p?.get("bMax")), num(p?.get("kappa")) else { return 0 }
        let kappa = f(p?.get("kappa")), bMax = f(p?.get("bMax"))
        return kappa > 0 ? (bMax > 0 ? bMax : 0) / kappa : 0
    }

    // ---- 3. mutual transparency: the cross-reference linking commitment ----------------------------------------------------------

    /// The digest of a mesh action that both Guardians anchor. Throws for a value the canonical hash refuses.
    public static func meshActionDigest(_ action: JSONValue) throws -> String {
        guard let h = IV.strictHash(.object(["v": s(ACTION_DIGEST_DOMAIN), "action": action])) else { throw PCAProducerError("meshActionDigest: the action is outside the canonical profile") }
        return h
    }

    /// The commitment binding `{action_digest, fromGuardian, toGuardian, nonce, at}`. Throws when a member is missing or the canonical hash refuses a value.
    public static func crossReferenceCommit(_ x: JSONValue) throws -> String {
        guard let digest = x.get("action_digest"), let from = x.get("fromGuardian"), let to = x.get("toGuardian"), let nonce = x.get("nonce"), let at = x.get("at"),
              let h = IV.strictHash(.object(["v": s("atlas-pca/mesh-xref/v1"), "action_digest": digest, "from": from, "to": to, "nonce": nonce, "at": at])) else {
            throw PCAProducerError("crossReferenceCommit: a member is missing or outside the canonical profile")
        }
        return h
    }

    /// A Guardian's signed anchor of a commitment at position `seq` of its own log: `{domain, commit, seq, sig}`.
    public static func anchorCrossReference(domain: PCAEdKey, commit: JSONValue, seq: JSONValue) throws -> JSONValue {
        guard let m = msg(XANCHOR_DOMAIN, .object(["commit": commit, "seq": seq])) else { throw PCAProducerError("anchorCrossReference: the anchor is outside the canonical profile") }
        return .object(["domain": s(domain.id), "commit": commit, "seq": seq, "sig": s(Base64URLStrict.encode(try domain.sign(m)))])
    }

    private static func validAnchor(_ a: JSONValue?) -> Bool { isRec(a) && isStr(a?.get("domain")) && isStr(a?.get("commit")) && nat(a?.get("seq")) && isStr(a?.get("sig")) }

    /// Both Guardians anchored the SAME commitment of this cross-reference, each under its own key: `{ok: true, commit}` or `{ok: false, reason}`.
    public static func verifyCrossReference(_ x: JSONValue?, _ anchors: JSONValue?) -> JSONValue {
        guard let xr = x, isRec(xr), isStr(xr.get("action_digest")), let from = xr.get("fromGuardian")?.asString, let to = xr.get("toGuardian")?.asString, isStr(xr.get("nonce")),
              num(xr.get("at")) else { return refuse("malformed cross-reference") }
        guard isRec(anchors), let af = anchors?.get("from"), validAnchor(af), let at = anchors?.get("to"), validAnchor(at) else { return refuse("malformed anchors") }
        if IV.same(from, to) { return refuse("cross-reference must span two distinct domains") }
        guard let expected = try? crossReferenceCommit(xr) else { return refuse("malformed cross-reference") }
        if !IV.same(af.get("domain")?.asString, from) { return refuse("source anchor domain does not match the cross-reference") }
        if !IV.same(at.get("domain")?.asString, to) { return refuse("target anchor domain does not match the cross-reference") }
        if !IV.same(af.get("commit")?.asString, expected) { return refuse("source anchor commits a different action") }
        if !IV.same(at.get("commit")?.asString, expected) { return refuse("target anchor commits a different action") }
        func signed(_ a: JSONValue) -> Bool? {
            guard let m = msg(XANCHOR_DOMAIN, .object(["commit": a.get("commit") ?? .null, "seq": a.get("seq") ?? .null])) else { return nil }
            return Ed25519Strict.verifyB64u(a.get("domain")?.asString ?? "", m, a.get("sig")?.asString ?? "")
        }
        guard let okFrom = signed(af) else { return refuse("malformed cross-reference") }
        if !okFrom { return refuse("source anchor signature invalid") }
        guard let okTo = signed(at) else { return refuse("malformed cross-reference") }
        if !okTo { return refuse("target anchor signature invalid") }
        return .object(["ok": .bool(true), "commit": s(expected)])
    }
}
