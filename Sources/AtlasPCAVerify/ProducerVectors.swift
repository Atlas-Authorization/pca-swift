import Foundation

// Reproduces one case of the producer conformance vectors (producer-vectors.json and producer-pq-vectors.json): the signing side of
// this SDK must emit exactly what the TypeScript reference emits. One entry point serves the tests and the conformance driver.
// Test keys come only from the fixed seeds in the vector files; Ed25519 signs through the RFC 8032 deterministic signer so the bytes
// match on every platform.

public enum PCAProducerVectors {
    /// The post-quantum families of producer-pq-vectors.json this SDK signs: ML-DSA only (SLH-DSA and FN-DSA are refused as
    /// `unsupported_suite: <family>`).
    static let families: [String: PCAMLDSALevel] = ["ml-dsa-65": .mlDsa65, "ml-dsa-87": .mlDsa87]

    struct Args {
        let m: JObject
        let keys: JObject
        let pq: JObject

        static func bad(_ what: String) -> PCAProducerError { PCAProducerError("produce: " + what) }
        static func s(_ m: JObject, _ k: String) throws -> String { guard let v = m[JKey(k)]?.asString else { throw bad("\(k) must be a string") }; return v }
        static func optS(_ m: JObject, _ k: String) throws -> String? {
            switch m[JKey(k)] {
            case nil, .null?: return nil
            case let .string(v)?: return v
            default: throw bad("\(k) must be a string")
            }
        }
        static func n(_ m: JObject, _ k: String) throws -> Int64 { guard let v = m[JKey(k)]?.safeInt else { throw bad("\(k) must be an integer") }; return v }
        static func o(_ m: JObject, _ k: String) throws -> JObject { guard let v = m[JKey(k)]?.asObject else { throw bad("\(k) must be an object") }; return v }
        static func optO(_ m: JObject, _ k: String) throws -> JObject? {
            switch m[JKey(k)] {
            case nil, .null?: return nil
            case let .object(v)?: return v
            default: throw bad("\(k) must be an object")
            }
        }
        static func l(_ m: JObject, _ k: String) throws -> [JSONValue] { guard let v = m[JKey(k)]?.asArray else { throw bad("\(k) must be an array") }; return v }
        static func objs(_ m: JObject, _ k: String) throws -> [JObject] {
            try l(m, k).map { guard let o = $0.asObject else { throw bad("\(k) must be an array of objects") }; return o }
        }
        static func strs(_ m: JObject, _ k: String) throws -> [String] {
            try l(m, k).map { guard let s = $0.asString else { throw bad("\(k) must be an array of strings") }; return s }
        }

        func seed(_ m: JObject, _ k: String) throws -> [UInt8] {
            let name = try Args.s(m, k)
            guard let s = keys[JKey(name)]?.get("seed")?.asString, let b = Base64URLStrict.decode(s, length: 32) else { throw Args.bad("no Ed25519 key '\(name)'") }
            return b
        }
        func ed(_ m: JObject, _ k: String) throws -> PCAEdKey { try Ed25519Deterministic.key(seed: try seed(m, k)) }
        func suite(_ m: JObject, _ k: String) throws -> PCASuiteKey { .ed25519(try ed(m, k)) }

        /// The PQ key a member names (nil: none).
        func pqKeyOf(_ m: JObject, _ k: String) throws -> PCAPQKey? {
            guard let name = try Args.optS(m, k) else { return nil }
            guard let e = pq[JKey(name)]?.asObject else { throw Args.bad("no post-quantum key '\(name)'") }
            return try PCAProducerVectors.keyGen(try Args.s(e, "family"), try Args.s(e, "seed"))
        }
    }

    static func keyGen(_ family: String, _ seed: String) throws -> PCAPQKey {
        guard let level = families[family] else { throw PCAProducerError("unsupported_suite: \(family)") }
        guard let bytes = Base64URLStrict.decode(seed, length: 32) else { throw PCAProducerError("produce: the \(family) seed must be canonical base64url of 32 bytes") }
        return try PCAPQKey.fromSeed(level, seed: bytes)
    }

    static func epoch(_ b: JObject) throws -> RevocationEpochBody {
        RevocationEpochBody(instanceId: try Args.s(b, "instance_id"), grantRef: try Args.s(b, "grant_ref"), epoch: try Args.n(b, "epoch"), setSize: try Args.n(b, "set_size"),
                            root: try Args.s(b, "root"), issuedAt: try Args.n(b, "issued_at"), notAfter: try Args.n(b, "not_after"))
    }

    /// Run one vector case: `op` and its `args`, with the file's Ed25519 `keys` (`{name: {seed, public}}`) and, for the post-quantum file,
    /// its `pqKeys`. `keyOrders` gives the member order of objects in the vector's JSON text, keyed by JSON pointer relative to `args`
    /// (`"/permissions"`; see `objectKeyOrders`): the reference iterates `permissions` in that order, which fixes the order of the
    /// compiled predicates. Returns the JSON output; throws with the refusal text. An op this SDK does not produce throws
    /// `unsupported_op: <op>`; a suite it does not sign throws `unsupported_suite: <alg>`.
    public static func produce(op: String, args: JSONValue, keys: JSONValue, pqKeys: JSONValue? = nil, keyOrders: [String: [String]] = [:]) throws -> JSONValue {
        guard let a = args.asObject else { throw PCAProducerError("produce: args must be an object") }
        return try run(op, Args(m: a, keys: keys.asObject ?? [:], pq: pqKeys?.asObject ?? [:]), keyOrders)
    }

    static func run(_ op: String, _ v: Args, _ orders: [String: [String]]) throws -> JSONValue {
        let a = v.m
        func body() throws -> JSONValue { guard let b = a["body"], b.asObject != nil else { throw Args.bad("body must be an object") }; return b }
        func val(_ k: String) throws -> JSONValue { guard let x = a[JKey(k)], !x.isNull else { throw Args.bad("\(k) is required") }; return x }
        // the post-quantum file: `alg` names the suite, `pq` the signer's PQ key, `holder_pq` the holder's committed PQ key
        func suiteOf(_ edMember: String) throws -> PCASuiteKey {
            guard let alg = try Args.optS(a, "alg") else { return try v.suite(a, edMember) }
            let pq = try v.pqKeyOf(a, "pq")
            var ed: PCAEdKey?
            if try Args.optS(a, edMember) != nil { ed = try v.ed(a, edMember) }
            return try PCASuiteKey(alg: alg, ed: ed, pq: pq)
        }
        func holderPq() throws -> String? { try v.pqKeyOf(a, "holder_pq")?.pkB64u }
        func toHolder(_ parent: JSONValue) throws -> String {
            if try Args.optS(a, "to_holder") == nil {
                guard let h = parent.get("holder")?.asString else { throw Args.bad("parent.holder must be a string") }
                return h
            }
            return try v.ed(a, "to_holder").id
        }
        func b64(_ k: String) throws -> [UInt8] { guard let b = Base64URLStrict.decode(try Args.s(a, k)) else { throw Args.bad("\(k) must be canonical base64url") }; return b }
        func sig(_ s: String) -> JSONValue { .object(["sig": .string(s)]) }

        switch op {
        // ---- producer-vectors.json ----------------------------------------------------------------------------------------------
        case "ed25519_sign":
            guard let seed = Base64URLStrict.decode(try Args.s(a, "seed"), length: 32) else { throw Args.bad("seed must be 32 bytes") }
            let k = try Ed25519Deterministic.key(seed: seed)
            return .object(["public": .string(k.id), "sig": .string(Base64URLStrict.encode(try k.sign(Canonical.utf8(try Args.s(a, "message_utf8")))))])
        case "goal_commit": return .object(["commit": .string(try PCAIssue.goalCommit(goal: try Args.s(a, "goal"), salt: try Args.s(a, "salt")))])
        case "params_digest": return .object(["digest": .string(Merkle.paramsDigest(a["params"]))])
        case "plan_commit":
            let nodes = try Args.objs(a, "nodes")
            let p = try PCAIssue.commitPlan(nodes)
            var proofs: JObject = [:]
            for n in nodes { let id = try Args.s(n, "id"); proofs[JKey(id)] = try p.proofFor(id) }
            return .object(["root": .string(p.root), "proofs": .object(proofs)])
        case "mint_grant":
            let g = try PCAIssue.mintGrant(principal: try v.suite(a, "principal"), holder: try v.ed(a, "holder").id, envelope: try Args.o(a, "envelope"),
                                           goal: try Args.s(a, "goal"), salt: try Args.s(a, "salt"))
            return .object(["grant": g.grant, "goal_commit": .string(g.goalCommit), "goal_salt": .string(g.goalSalt)])
        case "delegate":
            let parent = JSONValue.object(try Args.o(a, "parent"))
            return try PCAIssue.delegate(parent: parent, toHolder: try toHolder(parent), added: try Args.l(a, "added_caveats"), signer: try v.suite(a, "signer"))
        case "act":
            var extras: JObject = [:]
            for k in ["nonce", "caution", "rationale_commitment", "tool_binding", "fresh_at"] { if let x = a[JKey(k)], !x.isNull { extras[JKey(k)] = x } }
            let p = try PCAIssue.buildPCActn(.init(grant: .object(try Args.o(a, "grant")), chain: try Args.l(a, "chain"), plan: try PCAIssue.commitPlan(try Args.objs(a, "plan")),
                                                   nodeId: try Args.s(a, "node_id"), params: try Args.optO(a, "params").map { .object($0) }, counter: try Args.n(a, "counter"),
                                                   signer: try v.suite(a, "signer"), aud: try Args.s(a, "aud"), iat: try Args.n(a, "iat"), exp: try Args.n(a, "exp"), extras: extras))
            return .object(["pcactn": p, "threshold_message": .string(Base64URLStrict.encode(try PCA.thresholdMessage(p.asObject ?? [:]))),
                            "header": .string(PCAIssue.header(p))])
        case "fresh_at":
            return try PCAIssue.signFreshAt(rs: try v.ed(a, "signer"), scope: try Args.s(a, "scope"), state: try Args.o(a, "state"), issuedAt: try Args.n(a, "issued_at"))
        case "escalation_digests":
            var last: Int64?
            if let x = a["last_counter"], !x.isNull { last = try Args.n(a, "last_counter") }
            guard let pol = PCA.escalationPolicyDigest(grant: try val("grant")), let act = PCA.escalationActionDigest(pcactn: try val("pcactn")),
                  let head = PCA.escalationHistoryHead(lastCounter: last) else { throw Args.bad("escalation input outside the strict JSON profile") }
            return .object(["policy_digest": .string(pol), "action_digest": .string(act), "history_head": .string(head)])
        case "sign_escalation_answer": return try PCAIssue.signEscalationAnswer(try body(), principal: try v.suite(a, "signer"))
        case "sign_discharge": return try PCAIssue.signDischarge(try body(), issuer: try v.suite(a, "signer"))
        case "discharge_digest":
            guard let d = PCA.dischargeDigest(try val("discharge")) else { throw Args.bad("discharge outside the strict JSON profile") }
            return .object(["digest": .string(d)])
        case "sign_narrow": return try PCAIssue.signNarrow(try body(), holder: try v.suite(a, "signer"))
        case "sign_passport":
            let identity = try Args.o(a, "identity")
            let pp = try PCAIssue.issuePassport(identity)
            let signed = try PCAIssue.signPassport(pp, issuer: try v.suite(a, "issuer"), subject: try v.ed(a, "subject").id, iat: try Args.n(identity, "issued_at"),
                                                   exp: try Args.n(a, "exp"))
            return .object(["passport": .object(pp), "signed": signed])
        case "sign_workflow": return try PCAIssue.signWorkflow(principal: try v.ed(a, "signer"), body: try body())
        case "sign_step_receipt":
            return try PCAIssue.signStepReceipt(rs: try v.ed(a, "signer"), workflow: .object(try Args.o(a, "workflow")), step: try Args.s(a, "step"),
                                                outcome: try Args.s(a, "outcome"), paramsDigest: try Args.s(a, "params_digest"), outputs: .object(try Args.o(a, "outputs")),
                                                issuedAt: try Args.n(a, "issued_at"), prev: try Args.optO(a, "prev").map { .object($0) })
        case "sign_read_grant": return try PCAIssue.signReadGrant(principal: try v.ed(a, "signer"), body: try body())
        case "sign_aggregate_grant": return try PCAIssue.signAggregateGrant(principal: try v.ed(a, "signer"), body: try body())
        case "sign_revocation_epoch": return try PCASigners.signRevocationEpoch(try epoch(try Args.o(a, "body")), guardian: try v.suite(a, "signer"))
        case "sign_undo_token": return try Undo.signToken(record: .object(try Args.o(a, "record")), key: try v.ed(a, "signer"))
        case "sign_undo_receipt":
            let b = try Args.o(a, "body")
            return try Undo.signReceipt(record: try Args.s(b, "record"), event: try Args.s(b, "event"), state: try Args.s(b, "state"), at: try Args.n(b, "at"),
                                        compensationDigest: try Args.s(b, "compensation_digest"), prev: try Args.s(b, "prev"), note: try Args.s(b, "note"),
                                        key: try v.ed(a, "signer"))
        case "sign_contract": return try Contracts.signContract(.object(try Args.o(a, "contract")), principal: try v.ed(a, "signer"))
        case "sign_contract_reset":
            let seq = try Args.n(a, "seq")
            guard seq >= 0, seq <= Int64(Int32.max) else { throw Args.bad("seq must be a non-negative integer") }
            return sig(try ContractEnforcer.signContractReset(principal: try v.ed(a, "signer"), contractId: try Args.s(a, "contract_id"), seq: Int(seq)))
        case "sign_constitution": return try Prohibitions.signConstitution(.object(try Args.o(a, "constitution")), principal: try v.ed(a, "signer"))
        case "sign_safety_evidence":
            let k = try v.ed(a, "signer")
            return try Prohibitions.signSafetyEvidence(try val("evidence"), signer: k, signerPublic: k.id)
        case "sign_threshold_share":
            // every t reaches shareMessage (missing or non-integer as 0, clamped into Int), which refuses all but 1, 2 and 3 with the reference's text
            let t = Int(clamping: a["t"]?.safeInt ?? 0)
            return try PCASigners.signThresholdShare(role: try Args.s(a, "role"), key: try v.suite(a, "signer"), message: try b64("message"),
                                                     signerSet: try Args.l(a, "signer_set"), t: t)
        case "sign_prepared_share":
            return try PCASigners.signPreparedShare(role: try Args.s(a, "role"), key: try v.suite(a, "signer"), prepared: try b64("prepared"))
        case "sign_pq_binding":
            // a non-integer epoch is refused by the signer, with the reference's text
            return try PCASigners.signPqBinding(ed: try v.ed(a, "signer"), pqPk: try Args.s(a, "pq_pk"), epoch: a["epoch"]?.safeInt ?? 0, aud: try Args.optS(a, "aud") ?? "")
        case "sign_caution": return try PCASigners.signCaution(try body(), holder: try v.ed(a, "signer"))
        case "sign_heartbeat": return try PCASigners.signHeartbeat(try body(), holder: try v.ed(a, "signer"))
        case "prov_recorder": return try recorder(v)
        case "sign_mesh_action":
            return sig(try PCASigners.signMeshAction(chain: try Args.objs(a, "chain").map { .object($0) }, action: .object(try Args.o(a, "action")), leaf: try v.ed(a, "signer")))
        case "sign_session_root": return try PCASigners.signSessionRoot(try body(), principal: try v.suite(a, "signer"))
        case "mint_session_grant":
            let g = try PCASigners.mintSessionGrant(principal: try v.suite(a, "principal"), holder: try v.ed(a, "holder").id, session: try Args.s(a, "session"),
                                                    seq: try Args.n(a, "seq"), root: try Args.s(a, "root"), mapDigest: try Args.s(a, "map_digest"),
                                                    predicates: try Args.l(a, "predicates"), prev: try Args.optS(a, "prev"), mapForm: try Args.optS(a, "map_form"),
                                                    caveats: a["caveats"]?.asArray ?? [], salt: try Args.optS(a, "salt"))
            return .object(["grant": g.grant, "goal_salt": .string(g.goalSalt)])
        case "sign_action_schema": return try PCASigners.signActionSchema(.object(try Args.o(a, "doc")), kid: try Args.s(a, "kid"), site: try v.suite(a, "signer"))
        case "sign_intent_required": return try PCASigners.signIntentRequired(try body(), kid: try Args.s(a, "kid"), site: try v.suite(a, "signer"))
        case "sign_progress_step": return try PCASigners.signProgressStep(.object(try Args.o(a, "step")), holder: try v.ed(a, "signer"))
        case "sign_labels": return try PCASigners.signLabels(try body(), key: try v.suite(a, "signer"))
        case "sign_fact": return try PCASigners.signFact(try body(), key: try v.suite(a, "signer"))
        case "sign_offer_set": return try PCASigners.signOfferSet(try body(), key: try v.suite(a, "signer"))
        case "sign_read_receipt":
            return try PCASigners.signReadReceipt(rs: try v.ed(a, "signer"), grant: .object(try Args.o(a, "grant")), verb: try Args.s(a, "verb"),
                                                  resource: try Args.s(a, "resource"), purpose: try Args.s(a, "purpose"), fields: .object(try Args.o(a, "fields")),
                                                  labels: try Args.strs(a, "labels"), issuedAt: try Args.n(a, "issued_at"), prev: try Args.optO(a, "prev").map { .object($0) })
        case "sign_template": return try PCASigners.signTemplate(.object(try Args.o(a, "def")), principal: try v.ed(a, "signer"))
        case "sign_tighten": return try PCASigners.signTighten(.object(try Args.o(a, "overlay")), principal: try v.ed(a, "signer"))
        case "parse_limit": return try PCAFacade.parseLimit(a["limit"]?.asString ?? "").json
        case "compile_policy":
            return try PCAFacade.compilePolicy(permissions: try permissions(a, orders), limits: limits(a), budgetModel: try Args.optS(a, "budget_model"),
                                               now: try Args.n(a, "now")).json
        case "facade_act": return try facadeAct(v, orders)

        // ---- producer-pq-vectors.json -------------------------------------------------------------------------------------------
        case "pq_keygen": return .object(["public": .string(try keyGen(try Args.s(a, "family"), try Args.s(a, "seed")).pkB64u)])
        case "suite_sign":
            let sg = try suiteOf("ed").sign(Canonical.utf8(try Args.s(a, "message_utf8")))
            var r: JObject = ["sig": .string(sg.sig)]
            if let q = sg.pqSig { r["pq_sig"] = .string(q) }
            return .object(r)
        case "mint_root_suite":
            return try PCAIssue.mintRoot(principal: try suiteOf("principal"), holder: try v.ed(a, "holder").id, holderPqPk: try holderPq(), caveats: try Args.l(a, "caveats"))
        case "delegate_suite":
            let parent = JSONValue.object(try Args.o(a, "parent"))
            return try PCAIssue.delegate(parent: parent, toHolder: try toHolder(parent), added: a["added_caveats"]?.asArray ?? [], signer: try suiteOf("signer"),
                                         holderPqPk: try holderPq())
        case "sign_pcactn_suite": return .object(["pcactn": try PCAIssue.signPCActn(try body(), signer: try suiteOf("signer"))])
        case "sign_artifact_suite":
            switch try Args.s(a, "kind") {
            case "escalation_answer": return try PCAIssue.signEscalationAnswer(try body(), principal: try suiteOf("signer"))
            case "revocation_epoch": return try PCASigners.signRevocationEpoch(try epoch(try Args.o(a, "body")), guardian: try suiteOf("signer"))
            case let k: throw Args.bad("unknown artifact kind '\(k)'")
            }
        default: throw PCAProducerError("unsupported_op: " + op)
        }
    }

    /// The vector's permissions in the order of its JSON text (JavaScript's own-key order: integer-like keys first, ascending).
    static func permissions(_ a: JObject, _ orders: [String: [String]]) throws -> [(String, [String])] {
        guard let p = a["permissions"]?.asObject else { throw PCAProducerError("compilePolicy: permissions must be an object") }
        let names = p.keys.map { $0.s }
        var ordered = (orders["/permissions"] ?? []).filter { n in names.contains { IV.same($0, n) } }
        // members the text order does not name (no order given) follow in code-unit order: deterministic, never dropped
        ordered += names.filter { n in !ordered.contains { IV.same($0, n) } }.sorted { Array($0.utf16).lexicographicallyPrecedes(Array($1.utf16)) }
        return try jsKeyOrder(ordered).map { c in
            guard let acts = p[JKey(c)]?.asArray?.compactMap({ $0.asString }), acts.count == p[JKey(c)]?.asArray?.count else {
                throw PCAProducerError("compilePolicy: permissions.\(c) must be an array of action names")
            }
            return (c, acts)
        }
    }

    /// The vector's limits (a non-string limit reads as empty, which parseLimit refuses, as the reference does).
    static func limits(_ a: JObject) -> [String: String]? {
        guard let l = a["limits"]?.asObject else { return nil }
        var out: [String: String] = [:]
        for (k, x) in l { out[k.s] = x.asString ?? "" }
        return out
    }

    /// A provenance recorder on the vector's clock (each reading takes the next tick; the last one repeats).
    static func recorder(_ v: Args) throws -> JSONValue {
        let a = v.m
        let clock = try Args.l(a, "clock").map { (x: JSONValue) -> Int64 in guard let i = x.safeInt else { throw Args.bad("clock must hold integers") }; return i }
        if clock.isEmpty { throw Args.bad("clock must not be empty") }
        let tick = Tick(clock)
        let r = try ProvenanceRecorder(mediator: try Args.s(a, "mediator"), kid: try Args.s(a, "kid"), signer: try v.suite(a, "key"), session: try Args.s(a, "session"),
                                       now: tick.next)
        var outs: [JSONValue] = []
        for s in try Args.objs(a, "steps") {
            switch s["kind"]?.asString {
            case "principal": outs.append(try r.principal(try Args.s(s, "text")))
            case "tool": outs.append(try r.tool(try Args.s(s, "name"), textOf(s["output"])))
            case "retrieval": outs.append(try r.retrieval(try Args.s(s, "source"), textOf(s["content"])))
            case "web": outs.append(try r.web(try Args.s(s, "url"), textOf(s["content"])))
            default:
                let op = try Args.o(s, "op")
                outs.append(try r.forAction(PCA.Operation(verb: try Args.s(op, "verb"), resource: try Args.s(op, "resource"),
                                                          params: .object(try Args.optO(op, "params") ?? [:]))))
            }
        }
        guard let bundle = outs.last else { throw Args.bad("no recorder steps") }
        return .object(["pin": r.pin, "receipts": .array(Array(outs.dropLast())), "bundle": bundle])
    }

    /// Recorded content: a string as is, anything else as its canonical JSON (the reference's adapters do the same).
    static func textOf(_ x: JSONValue?) -> String {
        if let s = x?.asString { return s }
        return Canonical.canonicalize(x ?? .null)
    }

    final class Tick: @unchecked Sendable {
        let clock: [Int64]
        var i = 0
        let lock = PCALock()
        init(_ c: [Int64]) { clock = c }
        func next() -> Int64 {
            lock.lock()
            defer { lock.unlock() }
            let x = clock[min(i, clock.count - 1)]
            i += 1
            return x
        }
    }

    /// The facade end to end: compile, mint, record the principal's messages, optionally hop to a sub-agent, then act.
    static func facadeAct(_ v: Args, _ orders: [String: [String]]) throws -> JSONValue {
        let a = v.m
        let now = try Args.n(a, "now")
        var ag = try PCAAgent.fromPrincipal(PCAAgentOptions(
            principal: try v.suite(a, "principal"), goal: try Args.s(a, "goal"), permissions: try permissions(a, orders), limits: limits(a),
            holder: try v.suite(a, "holder"), aud: try Args.s(a, "aud"), now: now,
            provenance: PCAProvenanceOptions(signer: try v.suite(a, "recorder_key"), session: try Args.s(a, "session"), now: { now }),
            goalSalt: try Args.s(a, "goal_salt")))
        if a["principal_messages"] != nil { for m in try Args.strs(a, "principal_messages") { try ag.provenance.principal(m) } }
        if let sa = try Args.optO(a, "sub_agent") {
            ag = try ag.subAgent(holder: try v.suite(sa, "holder"), addedCaveats: sa["added_caveats"]?.asArray ?? [])
        }
        let act = try Args.o(a, "act")
        let r = try ag.act(verb: try Args.s(act, "verb"), resource: try Args.s(act, "resource"), params: try Args.optO(act, "params").map { .object($0) },
                           options: PCAActOptions(counter: try Args.n(act, "counter"), now: try Args.n(act, "now"), nonce: try Args.optS(act, "nonce")))
        return .object(["grant": ag.grant, "goal_commit": .string(ag.goalCommit), "chain": .array(ag.chain), "pcactn": r.pcactn, "encoded": .string(r.encoded),
                        "provenance": r.provenance])
    }

    // ---- member order --------------------------------------------------------------------------------------------------------

    /// JavaScript's own-property order of `keys` given in insertion order: array-index keys (canonical decimal integers below 2^32 - 1)
    /// first, ascending, then the rest in insertion order.
    public static func jsKeyOrder(_ keys: [String]) -> [String] {
        func index(_ k: String) -> UInt64? {
            guard !k.isEmpty, k.utf8.allSatisfy({ $0 >= 48 && $0 <= 57 }), k == "0" || !k.hasPrefix("0"), k.utf8.count <= 10, let n = UInt64(k), n < 4_294_967_295 else { return nil }
            return n
        }
        let idx = keys.compactMap { k in index(k).map { (k, $0) } }.sorted { $0.1 < $1.1 }.map { $0.0 }
        return idx + keys.filter { index($0) == nil }
    }

    /// The member order of every object in a JSON text, keyed by JSON pointer (`""` the root, `"/args/permissions"`, `"/cases/3/args"`),
    /// members in text order. `JSONValue` objects are unordered; this recovers the order where the reference's output depends on it.
    /// Returns `[:]` for text that is not well-formed JSON.
    public static func objectKeyOrders(_ text: String) -> [String: [String]] {
        var sc = KeyScanner(Array(text.utf8))
        var out: [String: [String]] = [:]
        guard (try? sc.value("", &out)) != nil else { return [:] }
        return out
    }

    /// The orders under `prefix` (a JSON pointer), re-keyed relative to it.
    public static func keyOrders(_ all: [String: [String]], under prefix: String) -> [String: [String]] {
        var out: [String: [String]] = [:]
        for (k, v) in all where k == prefix || k.hasPrefix(prefix + "/") { out[String(k.dropFirst(prefix.count))] = v }
        return out
    }

    struct KeyScanner {
        struct Bad: Error {}
        let b: [UInt8]
        var i = 0
        init(_ b: [UInt8]) { self.b = b }

        mutating func ws() { while i < b.count, b[i] == 0x20 || b[i] == 0x09 || b[i] == 0x0A || b[i] == 0x0D { i += 1 } }
        static func esc(_ s: String) -> String { s.replacingOccurrences(of: "~", with: "~0").replacingOccurrences(of: "/", with: "~1") }

        mutating func string() throws -> String {
            guard i < b.count, b[i] == 0x22 else { throw Bad() }
            let start = i
            i += 1
            while i < b.count, b[i] != 0x22 { i += b[i] == 0x5C ? 2 : 1 }
            guard i < b.count else { throw Bad() }
            i += 1
            guard let lit = String(bytes: b[start..<i], encoding: .utf8), case let .string(s) = try StrictJSON.parseLenient(lit) else { throw Bad() }
            return s
        }

        mutating func value(_ path: String, _ out: inout [String: [String]]) throws {
            ws()
            guard i < b.count else { throw Bad() }
            switch b[i] {
            case 0x7B: // {
                i += 1
                var keys: [String] = []
                ws()
                if i < b.count, b[i] == 0x7D { i += 1; out[path] = keys; return }
                while true {
                    ws()
                    let k = try string()
                    keys.append(k)
                    ws()
                    guard i < b.count, b[i] == 0x3A else { throw Bad() }
                    i += 1
                    try value(path + "/" + KeyScanner.esc(k), &out)
                    ws()
                    guard i < b.count else { throw Bad() }
                    if b[i] == 0x2C { i += 1; continue }
                    guard b[i] == 0x7D else { throw Bad() }
                    i += 1
                    break
                }
                out[path] = keys
            case 0x5B: // [
                i += 1
                ws()
                if i < b.count, b[i] == 0x5D { i += 1; return }
                var n = 0
                while true {
                    try value(path + "/" + String(n), &out)
                    n += 1
                    ws()
                    guard i < b.count else { throw Bad() }
                    if b[i] == 0x2C { i += 1; continue }
                    guard b[i] == 0x5D else { throw Bad() }
                    i += 1
                    break
                }
            case 0x22: _ = try string()
            default: // number, true, false, null: up to the next delimiter
                let start = i
                while i < b.count, ![0x2C, 0x7D, 0x5D, 0x20, 0x09, 0x0A, 0x0D].contains(b[i]) { i += 1 }
                if i == start { throw Bad() }
            }
        }
    }
}
