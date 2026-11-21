import Foundation

/// More producers, byte for byte the reference's: threshold shares, PQ key bindings, caution claims, lease heartbeats, progress steps,
/// read receipts, mesh actions and proofs, intent session roots and session grants, action schemas, intent-required bodies, label
/// receipts, facts, offer sets, policy templates and tighten overlays, and revocation epochs under any suite this SDK signs. Each runs
/// the reference's checks before signing and throws on a malformed input (a signer never emits an artifact a verifier would refuse).
/// A suite this SDK cannot sign is refused with `unsupported_suite: <alg>` when its key is built (`PCASuiteKey`).
/// Where a body has several problems the reported one follows sorted key order (a Swift dictionary carries no insertion order).
public enum PCASigners {
    public static let PQ_BINDING_DOMAIN = "atlas-pca/pq-binding/v2\u{0}"
    public static let CAUTION_DOMAIN = "atlas-pca/caution/v1"
    public static let HEARTBEAT_DOMAIN = "atlas-pca/lease-hb/v2"
    public static let PROGRESS_SIG_DOMAIN = "atlas-pca/progress-step/v2"
    public static let INTENT_REQUIRED_DOMAIN = "atlas-pca/intent-required/v1\u{0}"
    public static let MAX_CAUTION_REASON_LENGTH = 64

    static func s(_ v: String) -> JSONValue { .string(v) }

    /// `canonical({d: domain, b: body})`, the agent-native message form.
    static func msgOf(_ domain: String, _ body: JSONValue) throws -> [UInt8] {
        try Canonical.canonicalBytes(.object(["d": s(domain), "b": body]))
    }

    static func object(_ v: JSONValue, _ what: String) throws -> JObject {
        guard case let .object(o) = try PCAIssue.norm(v) else { throw PCAProducerError("\(what): not an object") }
        return o
    }

    static func nonEmpty(_ v: JSONValue?) -> Bool { !(v?.asString ?? "").isEmpty }

    // ---- threshold shares ----

    /// The bytes a role's threshold share signs: `"atlas-pca/share/<role>\0" || sha256(message) || signerSetHash(signerSet) || t`, plus
    /// the suite tag for a non-ed25519 suite. `t` is 1, 2 or 3.
    public static func shareMessage(role: String, message: [UInt8], signerSet: [JSONValue], t: Int, alg: String = "ed25519") throws -> [UInt8] {
        guard Threshold.isValidT(t) else { throw PCAProducerError("shareMessage: t must be 1, 2 or 3") }
        guard case let .array(set) = try PCAIssue.norm(.array(signerSet)), let ssh = Threshold.signerSetHashJSON(set) else {
            throw PCAProducerError("shareMessage: malformed signer set")
        }
        var out: [UInt8] = Canonical.utf8("atlas-pca/share/\(role)")
        out.append(0x00)
        out += Canonical.sha256(message)
        out += ssh
        out.append(UInt8(t))
        out += Threshold.shareSuiteTag(alg)
        return out
    }

    /// A role's threshold share over `message` (a PCActn's threshold message), bound to the signer set and `t` it is for, so it cannot be
    /// replayed into another set or threshold. Under a PQ suite the role's PQ key must be the `pq_pk` the signer set registers for it.
    public static func signThresholdShare(role: String, key: PCASuiteKey, message: [UInt8], signerSet: [JSONValue], t: Int) throws -> JSONValue {
        try signPreparedShare(role: role, key: key, prepared: try shareMessage(role: role, message: message, signerSet: signerSet, t: t, alg: key.alg))
    }

    /// Sign share bytes computed elsewhere (the `share_message` a step-up hands a principal device): `{role, publicKey, sig}`, plus `alg`
    /// (and `pq_sig` for a hybrid) under a PQ suite.
    public static func signPreparedShare(role: String, key: PCASuiteKey, prepared: [UInt8]) throws -> JSONValue {
        guard let id = key.id else { throw PCAProducerError("signPreparedShare: a share needs the role's Ed25519 identity") }
        let sg = try key.sign(prepared)
        var share: JObject = ["role": s(role), "publicKey": s(id), "sig": s(sg.sig)]
        if key.alg != "ed25519" {
            share["alg"] = s(key.alg)
            if let q = sg.pqSig { share["pq_sig"] = s(q) }
        }
        return .object(share)
    }

    // ---- PQ key binding ----

    /// An identity's signed statement that `pqPk` is its PQ key as of `epoch` (a positive integer raised on every rotation) for the
    /// audience `aud`: `{ed, pq, epoch, aud, sig}`.
    public static func signPqBinding(ed: PCAEdKey, pqPk: String, epoch: Int64, aud: String) throws -> JSONValue {
        if epoch < 1 || epoch > Canonical.MAX_SAFE { throw PCAProducerError("signPqBinding: epoch must be a positive safe integer") }
        if aud.isEmpty { throw PCAProducerError("signPqBinding: aud (the instance/audience id) is required") }
        let msg = Canonical.utf8(PQ_BINDING_DOMAIN) + Canonical.utf8("\(ed.id)\u{0}\(pqPk)\u{0}\(epoch)\u{0}\(aud)")
        return .object(["ed": s(ed.id), "pq": s(pqPk), "epoch": .int(epoch), "aud": s(aud), "sig": s(Base64URLStrict.encode(try ed.sign(msg)))])
    }

    // ---- caution claim, lease heartbeat, progress step ----

    static func reasonOK(_ r: String) -> Bool {
        !r.isEmpty && r.utf16.count <= MAX_CAUTION_REASON_LENGTH
            && r.unicodeScalars.allSatisfy { c in c.isASCII && (CharacterSet.alphanumerics.contains(c) || "_.:-".unicodeScalars.contains(c)) }
    }

    /// nil for a well-formed caution claim body, else the problem.
    public static func cautionBodyError(_ b: JObject) -> String? {
        if !nonEmpty(b["action_digest"]) { return "action_digest required" }
        if !nonEmpty(b["holder"]) { return "holder required" }
        guard let c = IV.num(b["caution"]), c.isFinite, c >= 0, c <= 1 else { return "caution must be a finite number in [0,1]" }
        if let r = b["reason"], !(r.asString.map(reasonOK) ?? false) { return "invalid reason" }
        return nil
    }

    /// A holder's signed caution claim `{action_digest, caution in [0,1], reason?, holder}`: bound to one action, it can only raise the
    /// server's risk. Other members of `body` are dropped.
    public static func signCaution(_ body: JSONValue, holder: PCAEdKey) throws -> JSONValue {
        guard case let .object(b) = body else { throw PCAProducerError("signCaution: not an object") }
        if let e = cautionBodyError(b) { throw PCAProducerError("signCaution: \(e)") }
        var clean: JObject = ["action_digest": b["action_digest"]!, "caution": b["caution"]!, "holder": b["holder"]!]
        if let r = b["reason"] { clean["reason"] = r }
        clean = try object(.object(clean), "signCaution")
        clean["sig"] = s(Base64URLStrict.encode(try holder.sign(try msgOf(CAUTION_DOMAIN, .object(clean)))))
        return .object(clean)
    }

    /// A lease holder's signed heartbeat `{cap_id, seq, at, holder, lease_issued_at}` (other members dropped).
    public static func signHeartbeat(_ body: JSONValue, holder: PCAEdKey) throws -> JSONValue {
        let b = try object(body, "signHeartbeat")
        var clean: JObject = [:]
        for k in ["cap_id", "seq", "at", "holder", "lease_issued_at"] {
            guard let v = b[JKey(k)] else { throw PCAProducerError("signHeartbeat: \(k) is required") }
            clean[JKey(k)] = v
        }
        clean["sig"] = s(Base64URLStrict.encode(try holder.sign(try msgOf(HEARTBEAT_DOMAIN, .object(clean)))))
        return .object(clean)
    }

    /// The holder's signed progress step `{step, holder, sig}`: the signature binds the step to the holder, goal, action, before / after
    /// state, sequence, chain link and step digest.
    public static func signProgressStep(_ step: JSONValue, holder: PCAEdKey) throws -> JSONValue {
        let st = try object(step, "signProgressStep")
        func m(_ k: String) throws -> JSONValue {
            guard let v = st[JKey(k)] else { throw PCAProducerError("signProgressStep: step.\(k) is required") }
            return v
        }
        let b: JObject = ["holder": s(holder.id), "goal_commitment": try m("goal_commitment"), "action_digest": try m("action_digest"),
                          "before_digest": try m("before_digest"), "after_digest": try m("after_digest"), "seq": try m("seq"), "prev": try m("prev"),
                          "step_digest": try m("digest")]
        return .object(["step": .object(st), "holder": s(holder.id), "sig": s(Base64URLStrict.encode(try holder.sign(try msgOf(PROGRESS_SIG_DOMAIN, .object(b)))))])
    }

    // ---- read receipt ----

    /// The resource server's receipt of one redacted read under `grant` (the read grant BODY): `fields` and `labels` are what
    /// `ReadSide.redactRead` reported; `prev` is the previous receipt of the chain (nil: the first, seq 0).
    public static func signReadReceipt(rs: PCAEdKey, grant: JSONValue, verb: String, resource: String, purpose: String, fields: JSONValue, labels: [String],
                                       issuedAt: Int64, prev: JSONValue? = nil) throws -> JSONValue {
        var seq: Int64 = 0
        var ref: JSONValue = .null
        if let p = prev, !p.isNull {
            let pn = try PCAIssue.norm(p)
            guard let ps = IV.int(pn.get("seq")), let r = ReadSide.readReceiptRef(pn) else { throw PCAProducerError("signReadReceipt: malformed previous receipt") }
            seq = ps + 1
            ref = s(r)
        }
        guard let gd = ReadSide.readGrantDigest(try PCAIssue.norm(grant)) else { throw PCAProducerError("signReadReceipt: grant outside the strict JSON profile") }
        var b = try object(.object(["v": .int(1), "grant": s(gd), "verb": s(verb), "resource": s(resource), "purpose": s(purpose), "seq": .int(seq), "prev": ref,
                                    "fields": fields, "labels": .array(labels.map { s($0) }), "issued_at": .int(issuedAt), "signer": s(rs.id)]), "signReadReceipt")
        b["sig"] = s(try PCAIssue.signBody(rs, domain: ReadSide.READ_RECEIPT_DOMAIN, body: .object(b)))
        return .object(b)
    }

    // ---- mesh ----

    /// The leaf holder's signature over the action bound to the chain tip: Ed25519 over
    /// `"atlas-pca/mesh-action/v1\0" || canonical({action, tip: capHash(tip)})`.
    public static func signMeshAction(chain: [JSONValue], action: JSONValue, leaf: PCAEdKey) throws -> String {
        guard let last = chain.last else { throw PCAProducerError("signMeshAction: empty chain") }
        let tip = Capability.capHash(try PCAIssue.norm(last))
        guard let msg = IV.message(Mesh.ACTION_DOMAIN, .object(["action": try PCAIssue.norm(action), "tip": s(tip)])) else {
            throw PCAProducerError("signMeshAction: the action is outside the strict JSON profile")
        }
        return Base64URLStrict.encode(try leaf.sign(msg))
    }

    /// The compact mesh proof: hops issued against the same head share one `heads` entry (their witness cosignatures merged), identical
    /// revocation bracketing leaves are carried once, and the leaf signs the action. `hops` are the per-hop evidence
    /// `{domain, head: {head, sig, cosigs}, inclusion, revocation: {cap, issuer_key}, binding?}`. Heads and leaves are keyed by canonical
    /// JSON, as in the reference. Cosignatures merge by `witness` (a non-object or witness-less one keys as "no witness", an explicit
    /// null witness is its own key); a null cosignature in a merged head is refused. A falsy `lo` / `hi` / `binding` is left out.
    public static func assembleMeshProof(chain: [JSONValue], hops: [JSONValue], action: JSONValue, leaf: PCAEdKey, pinProofs: [JSONValue] = []) throws -> JSONValue {
        var heads: [JObject] = []
        var headIdx: [String: Int] = [:]
        var leaves: [JSONValue] = []
        var leafIdx: [String: Int] = [:]
        func leafOf(_ l: JSONValue) -> Int64 {
            let k = Canonical.canonicalize(l)
            if let i = leafIdx[k] { return Int64(i) }
            leaves.append(l)
            leafIdx[k] = leaves.count - 1
            return Int64(leaves.count - 1)
        }
        func compact(_ nv: JSONValue?) throws -> JSONValue {
            guard case let .object(n)? = nv else { throw PCAProducerError("assembleMeshProof: malformed revocation evidence") }
            var o: JObject = [:]
            if let sz = n["size"] { o["size"] = sz } // an absent size stays absent (undefined in the reference), never null
            for side in ["lo", "hi"] { if let l = n[JKey(side)], Mesh.truthy(l) { o[JKey(side)] = .int(leafOf(l)) } }
            return .object(o)
        }
        // the reference's `c.witness`: reading it off a null cosignature throws there
        func witness(_ c: JSONValue) throws -> JSONValue? {
            if c.isNull { throw PCAProducerError("assembleMeshProof: a cosignature is null") }
            return c.get("witness")
        }
        var outHops: [JSONValue] = []
        for raw in hops {
            let ev = try object(raw, "assembleMeshProof")
            guard case let .object(h)? = ev["head"] else { throw PCAProducerError("assembleMeshProof: hop evidence needs a cosigned head") }
            let cosigs = h["cosigs"]?.asArray ?? []
            let key = (h["sig"]?.asString ?? "") + "|" + Canonical.canonicalize(h["head"] ?? .null)
            let i: Int
            if let at = headIdx[key] {
                i = at
                var have = heads[at]["cosigs"]?.asArray ?? []
                let seen = try have.map(witness)
                for c in cosigs {
                    let w = try witness(c)
                    if !seen.contains(w) { have.append(c) }
                }
                heads[at]["cosigs"] = .array(have)
            } else {
                i = heads.count
                heads.append(["head": h["head"] ?? .null, "sig": h["sig"] ?? .null, "cosigs": .array(cosigs)])
                headIdx[key] = i
            }
            guard case let .object(rev)? = ev["revocation"] else { throw PCAProducerError("assembleMeshProof: hop evidence needs its revocation bracketing") }
            var o: JObject = ["domain": ev["domain"] ?? .null, "head": .int(Int64(i)), "inclusion": ev["inclusion"] ?? .null,
                              "revocation": .object(["cap": try compact(rev["cap"]), "issuer_key": try compact(rev["issuer_key"])])]
            if let bd = ev["binding"], Mesh.truthy(bd) { o["binding"] = bd }
            outHops.append(.object(o))
        }
        var proof: JObject = ["chain": .array(chain), "heads": .array(heads.map { .object($0) }), "rev_leaves": .array(leaves), "hops": .array(outHops),
                              "action": action, "action_sig": s(try signMeshAction(chain: chain, action: action, leaf: leaf))]
        if !pinProofs.isEmpty { proof["pin_proofs"] = .array(pinProofs) }
        return try PCAIssue.norm(.object(proof))
    }

    // ---- intent session root and session grants ----

    static let SESSION_ROOT_UNSIGNED_KEYS = ["v", "kind", "session", "principals", "intent_ref", "schema", "layers", "accumulators", "monitors", "question_uri",
                                             "revocation", "flows", "expires_at"]

    /// Sign the session root S as one of its principals (the signer's Ed25519 identity must be listed in `principals`). A non-ed25519
    /// suite binds `alg` and `pq_pk` into the signed body.
    public static func signSessionRoot(_ body: JSONValue, principal: PCASuiteKey) throws -> JSONValue {
        guard let signer = principal.id else { throw PCAProducerError("signSessionRoot: the signer needs an Ed25519 identity") }
        let b = try object(body, "signSessionRoot")
        for k in b.keys.sorted() where !SESSION_ROOT_UNSIGNED_KEYS.contains(k.s) { throw PCAProducerError("signSessionRoot: session root: unknown member '\(k.s)'") }
        var base: JObject = [:]
        for k in SESSION_ROOT_UNSIGNED_KEYS { if let v = b[JKey(k)] { base[JKey(k)] = v } }
        base["signer"] = s(signer)
        // the signed shape, checked before signing: the body plus the suite fields and a placeholder signature
        var probe = base
        if principal.alg != "ed25519" { probe["alg"] = s(principal.alg); probe["pq_pk"] = PCAIssue.opt(principal.pqPk) }
        probe["sig"] = s("")
        if let bad = IntentSession.shapeError(.object(probe)) {
            if bad == "signer is not one of the session principals" { throw PCAProducerError("signSessionRoot: the signer is not one of the session principals") }
            throw PCAProducerError("signSessionRoot: \(bad)")
        }
        return .object(try PCAIssue.signArtifact(domain: IntentSession.SIG_DOMAIN, body: .object(base), signer: principal))
    }

    /// Mint a session grant: G_0 (`seq` 0) or a delta grant D_k, a principal-signed root capability whose caveats are the envelope (goal
    /// `pca-intent:v2:<session>:<mapDigest>`, or `v2c` over a committed map when `mapForm` is "commit") and the `intent_session`
    /// caveat. `prev` is required exactly when seq > 0. The result's goal salt goes in the PCActn's `intent.goal_salt`.
    public static func mintSessionGrant(principal: PCASuiteKey, holder: String, session: String, seq: Int64, root: String, mapDigest: String,
                                        predicates: [JSONValue], prev: String? = nil, mapForm: String? = nil, caveats: [JSONValue] = [],
                                        agentBinding: JObject = [:], riskPolicy: JObject? = nil, salt: String? = nil, holderPqPk: String? = nil)
        throws -> (grant: JSONValue, goalCommit: String, goalSalt: String) {
        var sc: JObject = ["type": s(IntentSession.CAVEAT), "session": s(session), "seq": .int(seq), "root": s(root)]
        if let p = prev { sc["prev"] = s(p) }
        if let bad = IntentSession.caveatError(.object(sc)) { throw PCAProducerError("mintSessionGrant: \(bad)") }
        if IV.digest(.string(mapDigest)) == nil { throw PCAProducerError("mintSessionGrant: mapDigest must be canonical base64url (32 bytes)") }
        let st = salt ?? PCAIssue.random(16)
        let prefix = mapForm == "commit" ? IntentSession.GOAL_V2C_PREFIX : IntentSession.GOAL_V2_PREFIX
        let commit = try PCAIssue.goalCommit(goal: prefix + session + ":" + mapDigest, salt: st)
        let env: JObject = ["type": s("envelope"), "goal_commit": s(commit), "predicates": .array(predicates), "caveats": .array(caveats),
                            "agent_binding": .object(agentBinding), "risk_policy": .object(riskPolicy ?? PCAFacade.DEFAULT_RISK_POLICY)]
        return (try PCAIssue.mintRoot(principal: principal, holder: holder, holderPqPk: holderPqPk, caveats: [.object(env), .object(sc)]), commit, st)
    }

    // ---- site and oracle artifacts ----

    static func siteSig(_ site: PCASuiteKey, _ kid: String, _ msg: [UInt8]) throws -> JSONValue {
        let sg = try site.sign(msg)
        var o: JObject = ["alg": s(site.alg), "kid": s(kid), "value": s(sg.sig)]
        if let q = sg.pqSig { o["pq_value"] = s(q) }
        return .object(o)
    }

    /// Sign an action schema as the site: `kid` names the discovery key entry. The signature covers
    /// `"atlas-pca/action-schema/v1\0" || canonical(doc)` and lands in `sig: {alg, kid, value, pq_value?}`.
    public static func signActionSchema(_ doc: JSONValue, kid: String, site: PCASuiteKey) throws -> JSONValue {
        var d = try object(doc, "signActionSchema")
        if let bad = ActionSchema.shapeError(.object(d), signed: false) { throw PCAProducerError("signActionSchema: \(bad)") }
        guard let msg = ActionSchema.message(d) else { throw PCAProducerError("signActionSchema: the schema is outside the strict JSON profile") }
        d["sig"] = try siteSig(site, kid, msg)
        return .object(d)
    }

    /// The discovery key entry `{kid, alg, pk, pq_pk?}` a verifier pins for a site signer.
    public static func actionSchemaKeyOf(kid: String, site: PCASuiteKey) throws -> JSONValue {
        guard let id = site.id else { throw PCAProducerError("a site key needs an Ed25519 identity") }
        var k: JObject = ["kid": s(kid), "alg": s(site.alg), "pk": s(id)]
        if let q = site.pqPk { k["pq_pk"] = s(q) }
        return .object(k)
    }

    static let INTENT_REQUIRED_KEYS = ["v", "kind", "session", "map_digest", "schema", "pcactn_digest", "action_digest", "cell", "reason", "question_id",
                                       "friction", "delivered_to", "expires_at", "sig"]

    /// The coordinates of a map cell: 1..64 dimensions, each an index range `[lo, hi]` (0 <= lo <= hi) or a set of 1..256 distinct strings.
    /// nil when well formed.
    public static func cellCoordsError(_ c: JSONValue?) -> String? {
        guard case let .object(m)? = c, !m.isEmpty, m.count <= 64 else { return "coords must be an object of 1..64 dimensions" }
        for k in m.keys.sorted() {
            let v = m[k]!
            if k.s.utf16.isEmpty || k.s.utf16.count > 256 { return "a coordinate path must be 1..256 characters" }
            if case let .array(r) = v, r.count == 2, let lo = IV.int(r[0]), let hi = IV.int(r[1]) {
                if !(lo >= 0 && lo <= hi) { return "coords '\(k.s)': need 0 <= lo <= hi" }
            } else if case let .array(set) = v, (1...256).contains(set.count), set.allSatisfy({ $0.asString != nil }) {
                if Set(set.map { JKey($0.asString!) }).count != set.count { return "coords '\(k.s)': values must be distinct" }
            } else {
                return "coords '\(k.s)': an index range [lo, hi] or a value set"
            }
        }
        return nil
    }

    static func questionIdOK(_ q: String) -> Bool {
        let u = Array(q.unicodeScalars)
        return (1...64).contains(u.count) && u.allSatisfy { $0.isASCII && (CharacterSet.alphanumerics.contains($0) || $0 == "_" || $0 == "-") }
    }

    /// The shape check of an UNSIGNED `pca-intent-required` v1 body (what the signer checks first). nil when well formed.
    public static func intentRequiredShapeError(_ bv: JSONValue) -> String? {
        guard case let .object(b) = bv else { return "not an object" }
        for k in b.keys.sorted() where !INTENT_REQUIRED_KEYS.contains(k.s) { return "unknown member '\(k.s)'" }
        if IV.num(b["v"]) != 1 || !IV.same(b["kind"]?.asString, "pca-intent-required") { return "not a pca-intent-required v1" }
        for k in ["session", "map_digest", "schema", "pcactn_digest", "action_digest"] where IV.digest(b[JKey(k)]) == nil {
            return "\(k) must be canonical base64url (32 bytes)"
        }
        guard case let .object(cell)? = b["cell"], cell.count == 2, cell["coords"] != nil, nonEmpty(cell["verb"]) else { return "cell must be {verb, coords}" }
        if let ce = cellCoordsError(cell["coords"]) { return ce }
        if !IV.same(b["reason"]?.asString, "uncertain") { return "reason must be 'uncertain'" }
        guard let q = b["question_id"]?.asString, questionIdOK(q) else { return "question_id must match [A-Za-z0-9_-]{1,64}" }
        if !IV.contains(["tap", "hold", "typed", "device"], b["friction"]?.asString ?? "") { return "unknown friction tier" }
        if !IV.contains(["wallet", "agent"], b["delivered_to"]?.asString ?? "") { return "delivered_to must be 'wallet' or 'agent'" }
        if IV.nonNeg(b["expires_at"]) == nil { return "expires_at must be a non-negative safe integer" }
        if b["sig"] != nil { return "an unsigned body must not carry sig" }
        return nil
    }

    /// The site's signed `pca-intent-required` v1 body: `sig = {alg, kid, value, pq_value?}` over
    /// `"atlas-pca/intent-required/v1\0" || canonical(body)`, pinned by the same discovery key entry as the action schema.
    public static func signIntentRequired(_ body: JSONValue, kid: String, site: PCASuiteKey) throws -> JSONValue {
        var b = try object(body, "signIntentRequired")
        if let bad = intentRequiredShapeError(.object(b)) { throw PCAProducerError("signIntentRequired: \(bad)") }
        guard let msg = IV.message(INTENT_REQUIRED_DOMAIN, .object(b)) else { throw PCAProducerError("signIntentRequired: the body is outside the strict JSON profile") }
        b["sig"] = try siteSig(site, kid, msg)
        return .object(b)
    }

    static func kinded(_ kind: String, _ body: JSONValue, _ what: String) throws -> JSONValue {
        var full: JObject = ["v": .int(1), "kind": s(kind)]
        for (k, v) in try object(body, what) { full[k] = v } // body members win, as in the reference's spread
        return .object(full)
    }

    /// A site's signed label receipt: `{v: 1, kind: "pca-labels", ...body}` under the signer's suite.
    public static func signLabels(_ body: JSONValue, key: PCASuiteKey) throws -> JSONValue {
        .object(try PCAIssue.signArtifact(domain: IntentWB.LABELS_DOMAIN, body: try kinded("pca-labels", body, "signLabels"), signer: key))
    }

    /// An oracle's signed fact: `{v: 1, kind: "pca-fact", ...body}` under the signer's suite.
    public static func signFact(_ body: JSONValue, key: PCASuiteKey) throws -> JSONValue {
        .object(try PCAIssue.signArtifact(domain: IntentWB.FACT_DOMAIN, body: try kinded("pca-fact", body, "signFact"), signer: key))
    }

    /// A site's signed offer set under the signer's suite.
    public static func signOfferSet(_ body: JSONValue, key: PCASuiteKey) throws -> JSONValue {
        .object(try PCAIssue.signArtifact(domain: IntentWB.OFFER_SET_DOMAIN, body: body, signer: key))
    }

    // ---- policy templates and tighten overlays ----

    /// The principal's signed template `{def, signer, sig}`; the signature covers the template domain and the digest of the definition.
    public static func signTemplate(_ def: JSONValue, principal: PCAEdKey) throws -> JSONValue {
        let d = try PCAIssue.norm(def)
        if let e = PCA.templateDefError(d) { throw PCAProducerError("signTemplate: \(e)") }
        guard let digest = PCA.templateDigest(d) else { throw PCAProducerError("signTemplate: the template is outside the strict JSON profile") }
        let sig = Base64URLStrict.encode(try principal.sign(PCA.templateMessage(PCA.templateSigDomain, digest)))
        return .object(["def": d, "signer": s(principal.id), "sig": s(sig)])
    }

    /// The principal's signed tighten overlay `{overlay, signer, sig}` (an overlay can only add where conditions and caveats).
    public static func signTighten(_ overlay: JSONValue, principal: PCAEdKey) throws -> JSONValue {
        let o = try PCAIssue.norm(overlay)
        if let e = PCA.tightenOverlayError(o) { throw PCAProducerError("signTighten: \(e)") }
        let digest = Base64URLStrict.encode(Canonical.sha256(try Canonical.canonicalBytes(o)))
        let sig = Base64URLStrict.encode(try principal.sign(PCA.templateMessage(PCA.tightenSigDomain, digest)))
        return .object(["overlay": o, "signer": s(principal.id), "sig": s(sig)])
    }

    // ---- revocation epoch ----

    /// A guardian's revocation epoch under its suite: the body's members plus `guardian`, `sig` (and for a non-ed25519 suite `alg`,
    /// `pq_pk`, signed, and `pq_sig` for a hybrid), in the wire form `checkRevocationEpoch` verifies.
    public static func signRevocationEpoch(_ b: RevocationEpochBody, guardian: PCASuiteKey) throws -> JSONValue {
        guard let id = guardian.id else { throw PCAProducerError("signRevocationEpoch: the guardian needs an Ed25519 identity") }
        var body: JObject = ["instance_id": s(b.instanceId), "grant_ref": s(b.grantRef), "epoch": .int(b.epoch), "set_size": .int(b.setSize),
                             "root": s(b.root), "issued_at": .int(b.issuedAt), "not_after": .int(b.notAfter)]
        if guardian.alg != "ed25519" { body["alg"] = s(guardian.alg); body["pq_pk"] = PCAIssue.opt(guardian.pqPk) }
        guard let msg = IV.message(PCA.REVEPOCH_DOMAIN, .object(body)) else { throw PCAProducerError("signRevocationEpoch: the body is outside the strict JSON profile") }
        let sg = try guardian.sign(msg)
        body["guardian"] = s(id)
        body["sig"] = s(sg.sig)
        if let q = sg.pqSig { body["pq_sig"] = s(q) }
        return .object(body)
    }
}
