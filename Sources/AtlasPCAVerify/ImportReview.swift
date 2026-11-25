import Foundation

private func u16less(_ a: String, _ b: String) -> Bool { Array(a.utf16).lexicographicallyPrecedes(Array(b.utf16)) }

/// The confirmation flow and signed review attestations. This is the ONE non-monotone step in the system: a def WITHOUT a valid attestation has the top of
/// the registry as its effective traits, and a valid one sets them to exactly what the reviewer signed. It counts only when a key pinned with the
/// `reviewer` role has signed this exact def digest. Any change to the def or to the trait registry the reviewer saw makes the attestation stale and the
/// def reverts to unconfirmed. Defs, pins and verdicts are JSON trees.
public enum ImportReview {
    private static let TRAIT_ID = "[a-z][a-z0-9_]{0,31}\\.[a-z][a-z0-9_]{0,63}"

    private static func fail(_ reason: String, _ detail: String) -> JObject { Jx.obj(["ok": .bool(false), "reason": .string(reason), "detail": .string(detail)]) }

    private static func strings(_ v: JSONValue?) -> Bool { if case let .array(a)? = v { return a.allSatisfy { $0.asString != nil } }; return false }

    private static func sortUniq(_ xs: JSONValue?) -> [String] { Jx.sortUniq(Jx.a(xs).compactMap { $0.asString }) }

    /// Is this def's confirmation valid? True only if: state is `confirmed`; the attestation covers THIS def digest and an accepted registry digest; its
    /// final traits are the def's declared traits; the signer is pinned with the `reviewer` role and the timestamp is inside the key's validity; the
    /// signature verifies. Never throws. Returns `{ok: true, kid}` or `{ok: false, reason, detail}`.
    public static func verifyAttestation(_ def: JObject, _ pins: JObject, _ registry: TraitRegistry) -> JObject {
        if let pe = ActionConfirmation.reviewerPinsError(.object(pins)) { return fail("bad_pins", pe) }
        let review = def[JKey("review")]
        if Jx.get(review, "state") != .string("confirmed") { return fail("not_confirmed", "review.state is not confirmed") }
        if !Jx.has(review, "attestation") { return fail("no_attestation", "a confirmed def carries an attestation") }
        let ao = Jx.get(review, "attestation")
        if ao == .null { return fail("malformed", "Cannot read properties of null (reading 'sig')") }
        let a = AK.o(ao)
        guard case .string? = a[JKey("sig")] else { return fail("no_signature", "the attestation is unsigned") }
        guard case .string? = a[JKey("facts_digest")] else { return fail("malformed", "the attestation facts_digest must be a string") }
        // shape before meaning: a missing / null / "" final_traits must not read as "no traits" for a read def
        var dismissedOk = a[JKey("dismissed")]?.asArray != nil
        if dismissedOk { for d in Jx.a(a[JKey("dismissed")]) where d.get("trait")?.asString == nil || d.get("reason")?.asString == nil { dismissedOk = false; break } }
        if !strings(a[JKey("final_traits")]) || !dismissedOk || !Jx.isInt(a[JKey("ts")]) || a[JKey("reviewer_kid")]?.asString == nil {
            return fail("malformed", "the attestation final_traits, dismissed, ts or reviewer_kid is malformed")
        }
        // the reference's try / catch around the whole verdict: a def that has no digest is "malformed" with the thrown message
        let defDigest: String
        do { defDigest = try Actions.defDigest(def) } catch { return fail("malformed", (error as? JSError)?.message ?? "\(error)") }
        if .string(defDigest) != a[JKey("def_digest")] ?? .null { return fail("digest_mismatch", "the def changed after it was reviewed") }
        var accepted: [JSONValue] = [.string(Actions.traitsDigest(registry))]
        accepted += Jx.a(pins[JKey("traits_digests")])
        if !accepted.contains(a[JKey("traits_digest")] ?? .null) { return fail("traits_digest_mismatch", "the trait registry changed since the review") }
        if sortUniq(a[JKey("final_traits")]) != sortUniq(def[JKey("traits")]) { return fail("final_traits_mismatch", "the attested final traits are not the def's declared traits") }
        let fin = Jx.a(a[JKey("final_traits")])
        for d in Jx.a(a[JKey("dismissed")]) where fin.contains(d.get("trait") ?? .null) || ActionConfirmation.blankReason(d.get("reason")?.asString ?? "") {
            return fail("dismissed_conflict", "a dismissed trait is also final, or has no reason")
        }
        let kid = a[JKey("reviewer_kid")] ?? .null
        guard let key = Jx.a(pins[JKey("keys")]).first(where: { kid == ($0.get("kid") ?? .null) })?.asObject else { return fail("unknown_reviewer", "no pinned key '\(Jx.str(kid))'") }
        if !Jx.a(key[JKey("roles")]).contains(.string("reviewer")) { return fail("not_a_reviewer", "key '\(Jx.str(key[JKey("kid")]))' does not hold the reviewer role") }
        let ts = IV.num(a[JKey("ts")]) ?? 0
        if (key[JKey("not_before")] != nil && ts < (IV.num(key[JKey("not_before")]) ?? 0)) || (key[JKey("not_after")] != nil && ts > (IV.num(key[JKey("not_after")]) ?? 0)) {
            return fail("outside_validity", "the attestation time is outside the key validity")
        }
        var body = a
        body[JKey("sig")] = nil
        guard let msg = try? ActionConfirmation.reviewMessage(body) else { return fail("malformed", "the review body is malformed") }
        if let pk = key[JKey("pk")]?.asString, let sig = a[JKey("sig")]?.asString, Ed25519Strict.verifyB64u(pk, msg, sig) { return Jx.obj(["ok": .bool(true), "kid": key[JKey("kid")] ?? .null]) }
        return fail("bad_signature", "the attestation signature is invalid")
    }

    /// The state that counts: a `confirmed` def with an invalid attestation is `stale` (it behaves as unreviewed).
    public static func reviewStatus(_ def: JObject, _ pins: JObject, _ registry: TraitRegistry) throws -> JSONValue? {
        guard let rv = JS.present(def[JKey("review")]) else { throw JSError("Cannot read properties of undefined (reading 'state')") }
        let st = Jx.get(rv, "state")
        if st != .string("confirmed") { return st }
        return verifyAttestation(def, pins, registry)[JKey("ok")] == .bool(true) ? .string("confirmed") : .string("stale")
    }

    /// Defs whose confirmation no longer holds go back to `unreviewed` (the attestation is dropped). Others are returned as they are.
    public static func revertStale(_ def: JObject, _ pins: JObject, _ registry: TraitRegistry) throws -> JObject {
        if try reviewStatus(def, pins, registry) != .string("stale") { return def }
        var review = AK.o(def[JKey("review")])
        review[o: "attestation"] = nil
        review[o: "state"] = .string("unreviewed")
        var out = def
        out[o: "review"] = .object(review)
        return out
    }

    // ---- review view and confirm ----

    private static let SUSPECT = ["pca.money_moving", "pca.privilege_change", "pca.code_execution", "pca.destructive", "pca.external_communication"]
    private static let NEXT = ["pca.credential_access", "pca.data_export", "pca.regulated_data", "pca.public_exposure", "pca.infra_mutation", "pca.legal_binding", "pca.impersonation", "pca.persistence"]

    /// The profile the def would have once reviewed (its own facts and traits, without the review marker that every unreviewed def shares).
    private static func intrinsic(_ def: JObject, _ registry: TraitRegistry) throws -> JObject { AK.o(try ActionEffective.effective(def, registry, nil)[JKey("hint")]) }

    /// Review queue priority: 0 = a core suspect trait, 1 = other risky, 2 = the rest. Lower first.
    public static func reviewPriority(_ def: JObject, _ registry: TraitRegistry) throws -> Int {
        let cl = Jx.a(try intrinsic(def, registry)[JKey("closure")])
        if SUSPECT.contains(where: { cl.contains(.string($0)) }) { return 0 }
        if NEXT.contains(where: { cl.contains(.string($0)) }) { return 1 }
        return 2
    }

    /// Defs in review order: suspect traits first, then by risk (highest first), then by verb. Deterministic.
    public static func reviewQueueOrder(_ defs: [JObject], _ registry: TraitRegistry) throws -> [JObject] {
        var rows: [(def: JObject, prio: Int, risk: Double, idx: Int)] = []
        for (i, d) in defs.enumerated() { rows.append((d, try reviewPriority(d, registry), IV.num(AK.o(try intrinsic(d, registry)[JKey("eff")])[JKey("risk")]) ?? 0, i)) }
        // stable, like the reference sort
        return rows.sorted { x, y in
            if x.prio != y.prio { return x.prio < y.prio }
            if x.risk != y.risk { return x.risk > y.risk }
            let a = Jx.str(x.def[JKey("verb")]), b = Jx.str(y.def[JKey("verb")])
            if a != b { return u16less(a, b) }
            return x.idx < y.idx
        }.map { $0.def }
    }

    /// Traits implied by the def's own facts (effects, roles, tags, scope, reversibility).
    public static func impliedTraits(_ def: JObject) throws -> [String] {
        let n = try Actions.normalize(def)
        let np = AK.o(n[JKey("params")])
        let ps = JS.keyOrder(np).map { AK.o(np[$0]) }
        return try Actions.impliedFromFacts(effects: AK.arr(n[JKey("effects")]), params: ps, scope: AK.o(n[JKey("resource")])[JKey("scope")]?.asString,
                                            worstRev: Actions.worstReversibility(n[JKey("reversibility")] ?? .null, np))
    }

    private static func strip(_ d: JObject) -> JObject { var o = d; for k in ["review", "examples", "source", "since"] { o[JKey(k)] = nil }; return o }

    /// The reviewer's view of a def: facts, implied and suggested traits, the effective profile, the policy card, what changed since `previous`.
    public static func prepareReview(_ def: JObject, _ registry: TraitRegistry, _ previous: JObject? = nil) throws -> JObject {
        let eff = try ActionEffective.effective(def, registry, nil)
        // the card shows what the reviewer would be signing (the hint), not the all-traits view that applies until they sign
        var shown = eff
        for (k, v) in AK.o(eff[JKey("hint")]) { shown[k] = v }
        shown[o: "confirmed"] = .bool(true)
        let added = Jx.get(Jx.get(def[JKey("review")], "suggested_by"), "added")
        var changes: [JSONValue] = []
        if let p = previous {
            let a = strip(p), b = strip(def)
            for k in Set(a.keys).union(b.keys).map({ $0.s }).sorted(by: u16less) where !AK.sameMember(a, b, k) { changes.append(.string(k)) }
        }
        return Jx.obj(["verb": def[JKey("verb")] ?? .null, "def_digest": .string(try Actions.defDigest(def)), "state": Jx.get(def[JKey("review")], "state") ?? .null,
                       "declared_traits": Jx.strs(sortUniq(def[JKey("traits")])), "implied_traits": Jx.strs(try impliedTraits(def)),
                       "suggested": JS.present(added) ?? .object(Jx.obj(["traits": .array([]), "roles": .object([:]), "tags": .object([:])])),
                       "effective": .object(eff), "card": try ActionDerive.cardOf(def, shown, registry), "changes": .array(changes), "priority": .int(Int64(try reviewPriority(def, registry)))])
    }

    /// Review one def: validates the decision, writes the final traits, signs an attestation over the resulting digest and returns the confirmed def.
    /// Throws ActionKitError (`bad_confirm`, `undismissed_suggestion`, `not_reviewer`) rather than guessing. `pins`: when not nil, the reviewer must be
    /// pinned with the `reviewer` role under this key. `finalTraits`: the final DECLARED trait set. `dismissed`: `[{trait, reason}]` or nil. `ts`: seconds.
    public static func confirmDef(_ def: JObject, _ registry: TraitRegistry, _ reviewerKid: String, _ key: PCAEdKey, _ pins: JObject?, _ finalTraits: [JSONValue],
                                  _ dismissed: [JSONValue]?, _ ts: JSONValue?) throws -> JObject {
        func bad(_ m: String) -> ActionKitError { ActionKitError(code: "bad_confirm", message: m) }
        guard Jx.isInt(ts), (IV.num(ts) ?? -1) >= 0 else { throw bad("ts must be a non-negative integer") }
        guard finalTraits.allSatisfy({ $0.asString != nil }) else { throw JSError("a final trait is not a string") }
        let fin = Jx.sortUniq(finalTraits.compactMap { $0.asString })
        if fin.count != finalTraits.count { throw bad("final traits must be distinct") }
        for t in fin {
            if !Actions.fullMatch(TRAIT_ID, t) || registry.traits[JKey(t)] == nil { throw bad("unknown trait '\(t)'") }
            if t == "pca.unreviewed" { throw bad("'pca.unreviewed' is the review marker, not a final trait") }
        }
        // copied: a batch shares one dismissal list across defs
        let dis: [JSONValue] = (dismissed ?? []).map { AK.obj(["trait": $0.get("trait") ?? .null, "reason": $0.get("reason") ?? .null]) }
        var dset: [JSONValue] = []
        for d in dis {
            let reason = d.get("reason"), trait = d.get("trait") ?? .null
            guard let rs = reason?.asString, !Jx.jsTrim(rs).isEmpty, rs.utf16.count <= 256 else { throw bad("dismissed trait '\(Jx.str(trait))' needs a reason (1..256 characters)") }
            if dset.contains(trait) { throw bad("trait '\(Jx.str(trait))' is dismissed twice") }
            dset.append(trait)
            if fin.contains(trait.asString ?? "\u{0}\u{0}") { throw bad("trait '\(Jx.str(trait))' is both final and dismissed") }
        }
        // what the reviewer was shown: the importer's and the suggesters' traits, plus what the def already declares
        let sbAdded = Jx.get(Jx.get(def[JKey("review")], "suggested_by"), "added")
        var shownAll = Jx.a(def[JKey("traits")])
        shownAll += Jx.a(Jx.get(sbAdded, "traits"))
        guard shownAll.allSatisfy({ $0.asString != nil }) else { throw JSError("a trait is not a string") }
        let shown = Jx.sortUniq(shownAll.compactMap { $0.asString })
        let seed = fin + (try impliedTraits(def))
        let covered = Set(try Actions.closure(registry, Jx.sortUniq(seed)))
        for t in shown {
            if fin.contains(t) || covered.contains(t) { continue }
            if !dset.contains(.string(t)) { throw ActionKitError(code: "undismissed_suggestion", message: "trait '\(t)' was suggested and is not in the final set: record it as dismissed with a reason") }
        }
        for t in dset where !shown.contains(t.asString ?? "\u{0}\u{0}") { throw bad("trait '\(Jx.str(t))' was never suggested; nothing to dismiss") }
        if let p = pins {
            if let pe = ActionConfirmation.reviewerPinsError(.object(p)) { throw bad(pe) }
            guard let k = Jx.a(p[JKey("keys")]).first(where: { .string(reviewerKid) == ($0.get("kid") ?? .null) })?.asObject, Jx.a(k[JKey("roles")]).contains(.string("reviewer")) else {
                throw ActionKitError(code: "not_reviewer", message: "key '\(reviewerKid)' is not pinned with the reviewer role")
            }
            if .string(Base64URLStrict.encode(key.pub)) != (k[JKey("pk")] ?? .null) { throw ActionKitError(code: "not_reviewer", message: "the secret does not belong to the pinned key '\(reviewerKid)'") }
        }
        var body = def
        if fin.isEmpty { body[o: "traits"] = nil } else { body[o: "traits"] = Jx.strs(fin) }
        let digest = try Actions.defDigest(body)
        // the facts of the verb this definition publishes: the verifier will recompute them from the schema and compare
        let verb = AK.o(AK.o(try ActionDerive.toSchemaVerb(body, registry, nil))[JKey("verb")])
        let att = try ActionConfirmation.signReview(Jx.obj(["def_digest": .string(digest), "traits_digest": .string(Actions.traitsDigest(registry)), "facts_digest": .string(ActionConfirmation.factsDigest(verb)),
                                                            "final_traits": Jx.strs(fin), "dismissed": .array(dis), "reviewer_kid": .string(reviewerKid), "ts": ts ?? .null]), key)
        var review = AK.o(def[JKey("review")])
        review[o: "state"] = .string("confirmed")
        review[o: "attestation"] = att
        var out = body
        out[o: "review"] = .object(review)
        if let b = Actions.validateDef(.object(out)) { throw bad("the confirmed def is invalid: \(b)") }
        return out
    }
}
