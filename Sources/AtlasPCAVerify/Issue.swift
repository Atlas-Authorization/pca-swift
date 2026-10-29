import Foundation

/// The producer side of PCA: everything an agent or issuer needs to MAKE a proof, with the same wire as the TypeScript reference
/// (`@atlasauth/pca`): root grants, delegation, plans, PCActns, and the signed artifacts (discharges, narrow blocks, escalation answers,
/// passports, workflow commitments and step receipts, read and aggregate grants, `fresh_at` tokens). Values are `JSONValue`s.
/// Everything signed passes through the STRICT canonical form, so an out-of-profile value throws instead of producing a proof no
/// verifier would accept.
public enum PCAIssue {
    public static let DEFAULT_TTL_MS: Int64 = 20 * 60_000
    static let GOAL_DOMAIN = "atlas-pca/goal/v1\u{0}"

    static func s(_ v: String) -> JSONValue { .string(v) }
    static func opt(_ v: String?) -> JSONValue { v.map { .string($0) } ?? .null }

    static func strictDigest(_ v: JSONValue) throws -> String { Base64URLStrict.encode(Canonical.sha256(try Canonical.canonicalBytes(v))) }

    static func random(_ n: Int) -> String { Base64URLStrict.encode((0..<n).map { _ in UInt8.random(in: 0...255) }) }

    /// Re-read through the strict canonical form (throws out of profile).
    public static func norm(_ v: JSONValue) throws -> JSONValue { try StrictJSON.parse(Canonical.canonicalizeStrict(v)) }

    // ---- capability chain ----
    static func seal(issuer: String, holder: String, caveats: [JSONValue], parent: String?, holderPq: String?, signer: PCASuiteKey) throws -> JSONValue {
        var body: JObject = ["issuer": s(issuer), "holder": s(holder), "caveats": .array(caveats), "parent": opt(parent)]
        if let hp = holderPq { body["holder_pq"] = s(hp) }
        if signer.alg != "ed25519" { body["alg"] = s(signer.alg); body["pq_pk"] = opt(signer.pqPk) }
        let digest = try strictDigest(.object(body))
        guard let raw = Base64URLStrict.decode(digest, length: 32) else { throw PCAProducerError("digest") }
        let sg = try signer.sign(Capability.CAP_DOMAIN + raw)
        var cap: JObject = ["id": s(digest), "issuer": s(issuer), "holder": s(holder), "caveats": .array(caveats), "body_digest": s(digest), "sig": s(sg.sig)]
        if let p = parent { cap["parent"] = s(p) }
        if let hp = holderPq { cap["holder_pq"] = s(hp) }
        if signer.alg != "ed25519" {
            cap["alg"] = s(signer.alg); cap["pq_pk"] = opt(signer.pqPk)
            if let q = sg.pqSig { cap["pq_sig"] = s(q) }
        }
        return .object(cap)
    }

    /// A root capability signed by the principal. `holderPqPk` (b64u) is the holder's ML-DSA public key, committed as `holder_pq`.
    public static func mintRoot(principal: PCASuiteKey, holder: String, holderPqPk: String? = nil, caveats: [JSONValue]) throws -> JSONValue {
        guard let ed = principal.ed else { throw PCAProducerError("a root issuer needs an Ed25519 identity") }
        guard case let .array(c) = try norm(.array(caveats)) else { throw PCAProducerError("caveats") }
        return try seal(issuer: ed.id, holder: holder, caveats: c, parent: nil, holderPq: holderPqPk.map { Capability.holderPqCommitment($0) }, signer: principal)
    }

    /// The salted goal commitment: `b64u(sha256(canonical({d, goal, salt})))`.
    public static func goalCommit(goal: String, salt: String) throws -> String { try strictDigest(.object(["d": s(GOAL_DOMAIN), "goal": s(goal), "salt": s(salt)])) }

    /// A root intent grant: a root capability whose first caveat is the `envelope` (`predicates`, `caveats`, `risk_policy` required;
    /// `agent_binding` defaults to `{}`; the optional members pass through). Only the salted hash of `goal` goes in the grant.
    public static func mintGrant(principal: PCASuiteKey, holder: String, holderPqPk: String? = nil, envelope: JObject, goal: String, salt: String? = nil)
        throws -> (grant: JSONValue, goalCommit: String, goalSalt: String) {
        if goal.isEmpty { throw PCAProducerError("mintGrant: goal required") }
        for k in ["predicates", "caveats", "risk_policy"] where envelope[JKey(k)] == nil { throw PCAProducerError("mintGrant: envelope.\(k) is required") }
        let st = salt ?? random(16)
        let commit = try goalCommit(goal: goal, salt: st)
        var env: JObject = ["type": s("envelope"), "goal_commit": s(commit)]
        for (k, v) in envelope where k.s != "goal_commit" && k.s != "type" { env[k] = v }
        if env["agent_binding"] == nil { env["agent_binding"] = .object([:]) }
        return (try mintRoot(principal: principal, holder: holder, holderPqPk: holderPqPk, caveats: [.object(env)]), commit, st)
    }

    /// Child capability: the parent's caveats followed by `added` (append-only), signed by the parent's holder.
    public static func delegate(parent: JSONValue, toHolder: String, added: [JSONValue], signer: PCASuiteKey, holderPqPk: String? = nil) throws -> JSONValue {
        guard let p = parent.asObject, let ph = p["holder"]?.asString else { throw PCAProducerError("delegate: malformed parent") }
        guard case let .array(cav) = try norm(.array((p["caveats"]?.asArray ?? []) + added)) else { throw PCAProducerError("caveats") }
        let hp = holderPqPk.map { Capability.holderPqCommitment($0) } ?? (toHolder == ph ? p["holder_pq"]?.asString : nil)
        return try seal(issuer: ph, holder: toHolder, caveats: cav, parent: Capability.capHash(parent), holderPq: hp, signer: signer)
    }

    // ---- plans ----
    static func conditionsDigest(_ pre: JSONValue?, _ post: JSONValue?) throws -> String { try strictDigest(.object(["pre": pre ?? .null, "post": post ?? .null])) }

    /// A committed plan: node objects `{id, verb, resource, params_digest?, reversibility_class?, pre?, post?}`.
    public struct Plan {
        public let root: String
        public let nodes: [JObject]
        let leaves: [[UInt8]]

        public func proofFor(_ id: String) throws -> JSONValue {
            guard let i = nodes.firstIndex(where: { $0["id"]?.asString == id }) else { throw PCAProducerError("commitPlan: unknown node \(id)") }
            var path: [JSONValue] = []
            Plan.prove(leaves, i, &path)
            return .object(["index": .int(Int64(i)), "size": .int(Int64(leaves.count)), "path": .array(path)])
        }

        static func prove(_ hs: [[UInt8]], _ idx: Int, _ out: inout [JSONValue]) {
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
    }

    public static func commitPlan(_ nodes: [JObject]) throws -> Plan {
        var ids = Set<String>()
        var leaves: [[UInt8]] = []
        for n in nodes {
            guard let id = n["id"]?.asString, ids.insert(id).inserted else { throw PCAProducerError("commitPlan: missing or duplicate node id") }
            guard let leaf = Merkle.planLeaf(.string(id), n, try conditionsDigest(n["pre"], n["post"])) else { throw PCAProducerError("commitPlan: bad node") }
            leaves.append(Merkle.leafHash(leaf))
        }
        if leaves.isEmpty { throw PCAProducerError("commitPlan: empty plan") }
        return Plan(root: Base64URLStrict.encode(Merkle.build(leaves)), nodes: nodes, leaves: leaves)
    }

    // ---- PCActn ----
    /// Inputs of `buildPCActn`. `extras` carries the optional signed members (nonce, caution, rationale_commitment, tool_binding, fresh_at, intent, ...).
    public struct ActSpec {
        public var grant: JSONValue
        public var chain: [JSONValue]
        public var plan: Plan
        public var nodeId: String
        public var params: JSONValue?
        public var counter: Int64
        public var signer: PCASuiteKey
        public var aud: String
        public var iat: Int64
        public var exp: Int64?
        public var ttlMs: Int64?
        public var extras: JObject = [:]
        public init(grant: JSONValue, chain: [JSONValue], plan: Plan, nodeId: String, params: JSONValue? = nil, counter: Int64, signer: PCASuiteKey, aud: String,
                    iat: Int64, exp: Int64? = nil, ttlMs: Int64? = nil, extras: JObject = [:]) {
            self.grant = grant; self.chain = chain; self.plan = plan; self.nodeId = nodeId; self.params = params; self.counter = counter
            self.signer = signer; self.aud = aud; self.iat = iat; self.exp = exp; self.ttlMs = ttlMs; self.extras = extras
        }
    }

    public static func buildPCActn(_ a: ActSpec) throws -> JSONValue {
        if a.aud.isEmpty { throw PCAProducerError("buildPCActn: aud (audience) is required") }
        guard let node = a.plan.nodes.first(where: { $0["id"]?.asString == a.nodeId }) else { throw PCAProducerError("buildPCActn: unknown plan node \(a.nodeId)") }
        let digest = try strictDigest(a.params.flatMap { $0.isNull ? nil : $0 } ?? .object([:]))
        if let pd = node["params_digest"]?.asString, pd != digest { throw PCAProducerError("buildPCActn: params do not match plan node \(a.nodeId)'s params_digest") }
        var body: JObject = [
            "ver": .int(PCA.WIRE_VERSION),
            "action": .object(["verb": node["verb"] ?? .null, "resource": node["resource"] ?? .null, "params_digest": s(digest),
                               "reversibility_class": node["reversibility_class"] ?? s(Merkle.DEFAULT_REVERSIBILITY_CLASS)]),
            "grant_ref": a.grant.get("id") ?? .null,
            "cap_chain": .array(a.chain),
            "plan": .object(["root": s(a.plan.root), "inclusion_proof": try a.plan.proofFor(a.nodeId), "node_id": s(a.nodeId),
                             "conditions_digest": s(try conditionsDigest(node["pre"], node["post"]))]),
            "attestation": .object(["quote_digest": s(""), "epoch": .int(0), "model_id": s("unattested"), "measurement": s(""), "operator": s("unattested")]),
            "provenance": .object(["causal_hash": s(""), "taint_level": .int(0), "trusted_refs": .array([])]),
            "freshness": .object(["beacon_ref": s(""), "epoch": .int(0), "accumulator_witness": s("")]),
            "counter": .int(a.counter),
            "risk_claim": .object(["r": .int(0), "inputs": .object([:])]),
            "aud": s(a.aud), "iat": .int(a.iat), "exp": .int(a.exp ?? a.iat + (a.ttlMs ?? DEFAULT_TTL_MS)),
        ]
        for (k, v) in a.extras { body[k] = v }
        if a.signer.alg != "ed25519" { body["alg"] = s(a.signer.alg); body["pq_pk"] = opt(a.signer.pqPk) }
        let sg = try a.signer.sign(try PCA.thresholdMessage(body))
        body["sig"] = s(sg.sig)
        if let q = sg.pqSig { body["pq_sig"] = s(q) }
        return .object(body)
    }

    /// The canonical JSON text of a PCActn (what is sent).
    public static func encode(_ pcactn: JSONValue) -> String { Canonical.canonicalize(pcactn) }

    /// The `PCA-Action` header value: the unpadded base64url of the PCActn JSON.
    public static func header(_ pcactn: JSONValue) -> String { Base64URLStrict.encode(Canonical.utf8(encode(pcactn))) }

    // ---- signed artifacts ----
    /// Sign an artifact body under a suite: covers `utf8(domain) || strictCanonical(body)`; a non-default suite adds `alg` and `pq_pk` to the SIGNED body.
    public static func signArtifact(domain: String, body: JSONValue, signer: PCASuiteKey) throws -> JObject {
        guard case var .object(full) = try norm(body) else { throw PCAProducerError("artifact body must be an object") }
        if signer.alg != "ed25519" { full["alg"] = s(signer.alg); full["pq_pk"] = opt(signer.pqPk) }
        guard let msg = IntentWB.artifactMessage(domain, full) else { throw PCAProducerError("artifact is outside the strict JSON profile") }
        let sg = try signer.sign(msg)
        full["sig"] = s(sg.sig)
        if let q = sg.pqSig { full["pq_sig"] = s(q) }
        return full
    }

    static func checked(_ what: String, _ o: JObject, _ err: String?) throws -> JSONValue {
        if let e = err { throw PCAProducerError("\(what): \(e)") }
        return .object(o)
    }

    public static func signDischarge(_ body: JSONValue, issuer: PCASuiteKey) throws -> JSONValue {
        let o = try signArtifact(domain: PCA.DISCHARGE_DOMAIN, body: body, signer: issuer)
        return try checked("signDischarge", o, PCA.dischargeShapeError(.object(o)))
    }

    public static func signNarrow(_ body: JSONValue, holder: PCASuiteKey) throws -> JSONValue {
        let o = try signArtifact(domain: PCA.NARROW_DOMAIN, body: body, signer: holder)
        return try checked("signNarrow", o, PCA.narrowShapeError(.object(o)))
    }

    public static func signEscalationAnswer(_ body: JSONValue, principal: PCASuiteKey) throws -> JSONValue {
        let o = try signArtifact(domain: PCA.ESCALATION_ANSWER_DOMAIN, body: body, signer: principal)
        return try checked("signEscalationAnswer", o, PCA.escalationAnswerShapeError(.object(o)))
    }

    /// Answer an escalation, bound to exactly this grant (policy), this PCActn (action) and this history head.
    public static func escalationAnswer(principal: PCASuiteKey, grant: JSONValue, pcactn: JSONValue, lastCounter: Int64?, allow: Bool, iat: Int64, expiresAt: Int64,
                                        renderDigest: String? = nil) throws -> JSONValue {
        guard let ed = principal.ed, let pol = PCA.escalationPolicyDigest(grant: grant), let act = PCA.escalationActionDigest(pcactn: pcactn),
              let head = PCA.escalationHistoryHead(lastCounter: lastCounter) else { throw PCAProducerError("escalationAnswer: input outside the strict JSON profile") }
        var b: JObject = ["v": .int(1), "kind": s("pca-escalation-answer"), "principal": s(ed.id), "policy_digest": s(pol), "action_digest": s(act), "history_head": s(head),
                          "decision": s(allow ? "allow" : "deny"), "iat": .int(iat), "expires_at": .int(expiresAt), "nonce": s(random(16))]
        if let r = renderDigest { b["render_digest"] = s(r) }
        return try signEscalationAnswer(.object(b), principal: principal)
    }

    // ---- Ed25519 body signatures ----
    public static func signBody(_ key: PCAEdKey, domain: String, body: JSONValue) throws -> String {
        Base64URLStrict.encode(try key.sign(Canonical.utf8(domain) + (try Canonical.canonicalBytes(body))))
    }

    public static func signWorkflow(principal: PCAEdKey, body: JSONValue) throws -> JSONValue {
        let b = try norm(body)
        guard let w = WfBody.parse(b), w.dagOk() else { throw PCAProducerError("signWorkflow: malformed workflow") }
        if w.principal != principal.id { throw PCAProducerError("signWorkflow: principal is not the signer") }
        return .object(["body": b, "sig": s(try signBody(principal, domain: Workflow.WORKFLOW_DOMAIN, body: b))])
    }

    /// Sign a step receipt (resource server). `prev` is the previous receipt of the same workflow, nil for the first.
    public static func signStepReceipt(rs: PCAEdKey, workflow: JSONValue, step: String, outcome: String, paramsDigest: String, outputs: JSONValue, issuedAt: Int64,
                                       prev: JSONValue? = nil) throws -> JSONValue {
        guard let wf = Workflow.workflowDigest(workflow) else { throw PCAProducerError("signStepReceipt: workflow outside the strict JSON profile") }
        var prevRef: JSONValue = .null
        var seq: Int64 = 0
        if let p = prev, !p.isNull {
            guard let r = Workflow.receiptRef(p), let ps = p.get("seq")?.safeInt else { throw PCAProducerError("signStepReceipt: malformed prev") }
            prevRef = s(r); seq = ps + 1
        }
        guard case var .object(b) = try norm(.object(["v": .int(1), "wf": s(wf), "step": s(step), "seq": .int(seq), "prev": prevRef, "outcome": s(outcome),
                                                       "params_digest": s(paramsDigest), "outputs": outputs, "issued_at": .int(issuedAt), "signer": s(rs.id)])) else { throw PCAProducerError("receipt") }
        b["sig"] = s(try signBody(rs, domain: Workflow.WF_RECEIPT_DOMAIN, body: .object(b)))
        return .object(b)
    }

    public static func signReadGrant(principal: PCAEdKey, body: JSONValue) throws -> JSONValue {
        let b = try norm(body)
        guard let g = ReadSide.parseGrant(b), g.principal == principal.id else { throw PCAProducerError("signReadGrant: malformed grant") }
        return .object(["body": b, "sig": s(try signBody(principal, domain: ReadSide.READ_GRANT_DOMAIN, body: b))])
    }

    public static func signAggregateGrant(principal: PCAEdKey, body: JSONValue) throws -> JSONValue {
        let b = try norm(body)
        guard let g = ReadVault.parseAggGrant(b), g.principal == principal.id else { throw PCAProducerError("signAggregateGrant: malformed grant") }
        return .object(["body": b, "sig": s(try signBody(principal, domain: ReadVault.AGGREGATE_DOMAIN, body: b))])
    }

    /// A signed consistency token (`fresh_at`): `state` holds revocation_epoch, ledger_tree_size, budget_version, policy_revision, policy_digest.
    public static func signFreshAt(rs: PCAEdKey, scope: String, state: JObject, issuedAt: Int64) throws -> JSONValue {
        var b: JObject = ["v": .int(1), "scope": s(scope)]
        for k in ["revocation_epoch", "ledger_tree_size", "budget_version", "policy_revision", "policy_digest"] { b[JKey(k)] = state[JKey(k)] ?? .null }
        b["issued_at"] = .int(issuedAt); b["signer"] = s(rs.id)
        guard case var .object(n) = try norm(.object(b)) else { throw PCAProducerError("fresh_at") }
        n["sig"] = s(try signBody(rs, domain: FreshAt.DOMAIN, body: .object(n)))
        return .object(n)
    }

    // ---- passports ----
    public static func passportFingerprint(_ p: JObject) throws -> String {
        func g(_ k: String) -> JSONValue { p[JKey(k)] ?? .null }
        return try strictDigest(.object(["d": s("atlas-pca/passport/v1"), "model_id": g("model_id"), "weights_digest": g("weights_digest"), "system_prompt_digest": g("system_prompt_digest"),
                                         "tool_manifest_digest": g("tool_manifest_digest"), "runtime_measurement": g("runtime_measurement"), "operator": g("operator"), "hardware_rooted": g("hardware_rooted")]))
    }

    /// Fill `id` from the fingerprint of the identity fields.
    public static func issuePassport(_ identity: JObject) throws -> JObject {
        var p = identity
        p["id"] = s(try passportFingerprint(identity))
        return p
    }

    /// Sign a passport for `subject` (the agent's Ed25519 key id). `evidence` is required for a hardware-rooted passport.
    public static func signPassport(_ passport: JObject, issuer: PCASuiteKey, subject: String, iat: Int64, nbf: Int64? = nil, exp: Int64, evidence: JObject? = nil) throws -> JSONValue {
        guard let ed = issuer.ed else { throw PCAProducerError("signPassport: an issuer needs an Ed25519 identity") }
        if passport["id"]?.asString != (try passportFingerprint(passport)) { throw PCAProducerError("signPassport: passport.id is not the fingerprint of its identity (use issuePassport)") }
        if passport["hardware_rooted"] == .bool(true) && evidence == nil { throw PCAProducerError("signPassport: hardware_rooted requires attestation evidence (fail closed)") }
        let nb = nbf ?? iat
        if exp <= nb { throw PCAProducerError("signPassport: exp must be after nbf") }
        var body: JObject = ["typ": s("atlas-pca/passport"), "ver": .int(1), "passport": .object(passport), "iss": s(ed.id), "sub": s(subject), "iat": .int(iat), "nbf": .int(nb), "exp": .int(exp)]
        if var ev = evidence {
            if ev["at"] == nil { ev["at"] = .int(iat) }
            body["evidence"] = .object(ev)
        }
        if issuer.alg != "ed25519" { body["alg"] = s(issuer.alg); body["pq_pk"] = opt(issuer.pqPk) }
        guard case var .object(n) = try norm(.object(body)) else { throw PCAProducerError("passport") }
        let sg = try issuer.sign(Canonical.utf8("atlas-pca/passport-sig/v1") + [0x00] + (try Canonical.canonicalBytes(.object(n))))
        n["sig"] = s(sg.sig)
        if let q = sg.pqSig { n["pq_sig"] = s(q) }
        return .object(n)
    }
}
