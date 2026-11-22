import Foundation

/// Class verdicts of the intent layer: the signed verdict of a judge key about a piece of content, the policy that names the allowlisted judges, labels and
/// quorum, and the decision that turns committed verdicts into the action's classes. Fail closed everywhere: a verdict that is not committed, not allowlisted,
/// not signed, about other content or another session decides nothing, and a label needs the full quorum.
public enum PCAIntentClassifier {
    public static let INTENT_CLASSIFIER_DOMAIN = IntentWB.CLASSIFIER_DOMAIN
    public static let INTENT_CLASSIFIER_REF_DOMAIN = IntentWB.CLASSIFIER_REF_DOMAIN
    public static let MAX_COMMITTED_CLASSES = 8
    public static let MAX_CLASSIFIER_LABELS = 32

    public static func validateClassifierVerdictWire(_ v: JSONValue?) -> String? { IntentWB.verdictWireError(v) }

    /// base64url(sha256(strict canonical value)); throws outside the strict profile.
    public static func classifierContentDigest(_ value: JSONValue) throws -> String {
        if let e = IV.strictCanonError(value) { throw JSError(e) }
        guard let h = IV.strictHash(value) else { throw JSError("canonicalize: value out of profile") }
        return h
    }

    /// The signed verdict of the judge whose key is `secret`: `{v: 1, kind, ...body, judge}` under the artifact signature of the suite.
    public static func signClassifierVerdict(_ body: JSONValue, key: PCASuiteKey, secret: [UInt8]) throws -> JSONValue {
        guard case let .object(b) = body else { throw JSError("body must be an object") }
        var full: JObject = ["v": .int(1), "kind": .string("pca-intent-classification")]
        for (k, v) in b { full[k] = v }
        full["judge"] = .string(PCAIntentArtifacts.publicKeyB64u(secret))
        return try PCAIntentArtifacts.signArtifact(INTENT_CLASSIFIER_DOMAIN, .object(full), key: key)
    }

    public static func classifierVerdictRef(_ v: JSONValue) throws -> String { try PCAIntentArtifacts.artifactRef(INTENT_CLASSIFIER_REF_DOMAIN, "c", v) }

    public static func validateClassifierPolicy(_ p: JSONValue?) -> String? {
        guard let p = p else { return "classifier policy needs a classifiers list" }
        return IntentWB.classifierPolicyError(p)
    }

    /// Whether the check has anything to do: a committed verdict or a declared classifier.
    public static func classifierCheckActive(_ input: JSONValue?) -> Bool {
        guard case .object? = input else { return false }
        return IntentWB.nonEmptyArray(input?.get("committed")) || IntentWB.nonEmptyArray(input?.get("policy")?.get("classifiers"))
    }

    /// `{ok: true, classes, votes}` or `{ok: false, reason: "classes: ..."}`.
    public static func decideClassifierDimensions(_ input: JSONValue?) -> JSONValue {
        func fail(_ r: String) -> JSONValue { .object(["ok": .bool(false), "reason": .string("classes: \(r)")]) }
        guard case let .object(inp)? = input else { return fail("input must be an object") }
        let policy = inp["policy"]
        if let pe = validateClassifierPolicy(policy) { return fail("policy misconfigured (fail closed): \(pe)") }
        guard let committed = IntentWB.list(inp["committed"]), committed.count <= MAX_COMMITTED_CLASSES else {
            return fail("committed verdicts must be a list of at most \(MAX_COMMITTED_CLASSES) digests")
        }
        var seen = Set<JKey>(), digests: [String] = []
        for d in committed {
            guard case let .string(s) = d, PCAIntentArtifacts.isDigest(d), seen.insert(JKey(s)).inserted else { return fail("committed verdicts must be distinct canonical 32-byte digests") }
            digests.append(s)
        }
        guard let supplied = IntentWB.list(inp["verdicts"]) else { return fail("verdicts must be an array") }
        guard case let .object(action)? = inp["action"] else { return fail("action must be an object") }
        let params = action["params"] ?? .object([:])
        guard params.isObject else { return fail("action.params must be an object") }
        var byRef: [JKey: JSONValue] = [:]
        for v in supplied where validateClassifierVerdictWire(v) == nil {
            if let r = try? classifierVerdictRef(v) { byRef[JKey(r)] = v }
        }
        let classifiers = (policy?.get("classifiers")?.asArray ?? []).compactMap { $0.asObject }
        var votes: [(id: String, tally: [(label: String, n: Int)])] = []
        var pairs = Set<JKey>()
        do {
            for d in digests {
                guard let vv = byRef[JKey(d)], case let .object(v) = vv else { return fail("a committed verdict was not supplied (or is malformed)") }
                if let se = PCAIntentArtifacts.artifactSuiteError(vv) { return fail("verdict signature suite: \(se)") }
                let cid = v["classifier"]?.asString ?? "", judge = v["judge"]?.asString ?? "", label = v["label"]?.asString ?? ""
                guard let c = classifiers.first(where: { IV.same($0["id"]?.asString, cid) }) else { return fail("verdict for undeclared classifier '\(cid)'") }
                let cid2 = c["id"]?.asString ?? cid
                if !(c["keys"]?.asArray ?? []).contains(where: { IV.same($0.asString, judge) }) { return fail("classifier '\(cid2)': judge key is not on the allowlist") }
                var pin: JObject = ["pk": .string(judge)]
                if let pq = c["pq_keys"]?.asObject?[JKey(judge)] { pin["pq_pk"] = pq }
                if !PCAIntentArtifacts.verifyArtifactSig(INTENT_CLASSIFIER_DOMAIN, vv, pin: .object(pin)) { return fail("classifier '\(cid2)': bad verdict signature") }
                if !IV.same(v["session"]?.asString, inp["session"]?.asString) { return fail("classifier '\(cid2)': verdict bound to another session") }
                let param = c["param"]?.asString ?? ""
                let content = PCAIntentArtifacts.resolveParamPath(params, .string(param))
                guard content.found else { return fail("classifier '\(cid2)': the action carries no '\(param)'") }
                if try classifierContentDigest(content.value ?? .null) != (v["content_digest"]?.asString ?? "\u{0}") { return fail("classifier '\(cid2)': verdict is about other content") }
                if !(c["labels"]?.asArray ?? []).contains(where: { IV.same($0.asString, label) }) { return fail("classifier '\(cid2)': label '\(label)' is not in its label set") }
                if let ms = c["measurements"]?.asArray, !ms.contains(where: { IV.same($0.asString, v["measurement"]?.asString) }) { return fail("classifier '\(cid2)': measurement is not pinned") }
                if !pairs.insert(JKey(cid2 + "\u{0}" + judge)).inserted { return fail("classifier '\(cid2)': two verdicts from one judge") }
                let ci = votes.firstIndex { IV.same($0.id, cid2) } ?? { votes.append((cid2, [])); return votes.count - 1 }()
                if let li = votes[ci].tally.firstIndex(where: { IV.same($0.label, label) }) { votes[ci].tally[li].n += 1 } else { votes[ci].tally.append((label, 1)) }
            }
            var classes: JObject = [:]
            for c in classifiers {
                let id = c["id"]?.asString ?? "", k = IV.int(c["k"]) ?? 0
                let t = votes.first { IV.same($0.id, id) }?.tally ?? []
                let winners = (c["labels"]?.asArray ?? []).compactMap { $0.asString }.filter { l in Int64(t.first { IV.same($0.label, l) }?.n ?? 0) >= k }
                if winners.isEmpty { return fail("classifier '\(id)': no label reaches the quorum \(k)") }
                if winners.count > 1 { return fail("classifier '\(id)': ambiguous, \(winners.count) labels reach the quorum") }
                classes[JKey(id)] = .string(winners[0])
            }
            var voteOut: JObject = [:]
            for (id, t) in votes { var r: JObject = [:]; for (l, n) in t { r[JKey(l)] = .int(Int64(n)) }; voteOut[JKey(id)] = .object(r) }
            return .object(["ok": .bool(true), "classes": .object(classes), "votes": .object(voteOut)])
        } catch {
            return fail("evaluation error (fail closed): \(error)")
        }
    }

    /// Binds a verdict's signed measurement to a verified hardware attestation (`{ok, reason?, measured?}`).
    public static func verifyClassifierAttestation(_ v: JSONValue?, _ attestation: JSONValue?, _ approved: JSONValue? = nil) -> JSONValue {
        guard case .object? = v else { return .object(["ok": .bool(false), "reason": .string("verdict must be an object")]) }
        return PCAIntentSemantic.verifyJudgeAttestation(v?.get("measurement"), attestation, approved)
    }
}
