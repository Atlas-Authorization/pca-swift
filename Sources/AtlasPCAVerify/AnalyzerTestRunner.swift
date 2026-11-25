import Foundation

/// The policy-as-code test runner: boundary-test generation, running a test document against a policy, and signed test documents.
/// A test document names the policy it was confirmed against by digest and lists actions with the decision (and optionally the
/// deciding clause) the author expects. Documents and policies are plain JSON trees (`JSONValue`).
extension PCAAnalyzer {
    public static let POLICY_TESTS_KIND = "pca-policy-tests"
    public static let POLICY_TESTS_SIG_DOMAIN = "atlas-pca/policy-tests/v1\u{0}"

    static func policyTestsDoc(_ policy: V?, _ cases: V?) throws -> V {
        obj([("v", .int(1)), ("kind", .string(POLICY_TESTS_KIND)), ("policy_digest", .string(try policyDigestOf(try toModel(policy)))), ("cases", cases)])
    }

    /// Run a document against a policy. With `requireDigest` a changed policy fails even if every case still passes.
    static func runPolicyTests(_ policy: V?, _ doc: V?, _ opts: V? = nil) throws -> V {
        let model = try toModel(policy)
        let o: V = opts ?? .object([:])
        var failures: [V] = []
        let cases = try cvList(try rd(doc, "cases"), "doc.cases")
        for c in cases {
            let w = try clauseWitness(model, try rd(c, "action"))
            let expectedBy = mem(c, "decidedBy")
            if !cvSeq(.string(w.decision), mem(c, "expect")) || (expectedBy != nil && !cvSeq(expectedBy, w.id)) {
                failures.append(obj([("name", mem(c, "name")), ("expected", mem(c, "expect")), ("got", .string(w.decision)), ("decidedBy", w.id), ("expectedDecidedBy", expectedBy)]))
            }
        }
        let digestMatch = cvSeq(mem(doc, "policy_digest"), .string(try policyDigestOf(model)))
        let requireDigest = try rd(o, "requireDigest") == .bool(true)
        return obj([("total", .int(Int64(cases.count))), ("passed", .int(Int64(cases.count - failures.count))), ("failures", .array(failures)), ("digestMatch", .bool(digestMatch)),
                    ("ok", .bool(failures.isEmpty && (!requireDigest || digestMatch)))])
    }

    /// utf8(domain) || sha256(utf8(hashCanonical(doc))): the signed message of a test document (strict canonical form; a document
    /// outside it is refused).
    static func policyTestsMessage(_ doc: V) throws -> [UInt8] {
        let h = Base64URLStrict.encode(Canonical.sha256(try Canonical.canonicalBytes(doc)))
        return Canonical.utf8(POLICY_TESTS_SIG_DOMAIN) + Canonical.sha256(Canonical.utf8(h))
    }

    /// The principal signs the confirmed examples (pinned alongside the approval).
    static func signPolicyTests(_ doc: V, _ key: PCAEdKey) throws -> V {
        let sig = try key.sign(try policyTestsMessage(doc))
        return .object(["doc": doc, "signer": .string(key.id), "sig": .string(Base64URLStrict.encode(sig))])
    }

    static func verifyPolicyTests(_ s: V?, _ expectedSigner: V?) -> Bool {
        do {
            let signer = try rd(s, "signer")
            guard cvSeq(signer, expectedSigner), let pk = signer?.asString else { return false }
            guard let doc = mem(s, "doc"), mem(doc, "kind") == .string(POLICY_TESTS_KIND), let sig = mem(s, "sig")?.asString else { return false }
            return Ed25519Strict.verifyB64u(pk, try policyTestsMessage(doc), sig)
        } catch { return false }
    }

    /// The `action.params.*` fields a predicate's conditions read (any depth, in first-seen order).
    static func trParamPaths(_ p: V?) throws -> [String] {
        var out: [String] = []
        func walk(_ c: V?) {
            guard let c = c, c.isObject || c.isArray else { return }
            if let f = mem(c, "field")?.asString, IV.startsWith(f, "action.params."), !out.contains(where: { IV.same($0, f) }) { out.append(f) }
            for k in ["all_of", "any_of"] { if let a = mem(c, k)?.asArray { for x in a { walk(x) } } }
            if let n = mem(c, "not"), JS.truthy(n) { walk(n) }
        }
        if let w = try rd(p, "where")?.asArray { for c in w { walk(c) } }
        return out
    }

    /// Boundary examples for every clause and numeric threshold of the policy; expectations are the current behaviour.
    static func generateBoundaryTests(_ policy: V?, _ o: V? = nil) throws -> V {
        let opts: V = o ?? .object([:])
        let eps = try cvOpt(try rd(opts, "epsilon"), 1, "epsilon")
        let model = try toModel(policy)
        var cases: [V] = []
        var seen = Set<JKey>()
        func add(_ name: String, _ action: V) throws {
            let key = JKey(JS.stringify(action))
            if !seen.insert(key).inserted { return }
            let w = try clauseWitness(model, action)
            cases.append(obj([("name", .string(name)), ("action", action), ("expect", .string(w.decision)), ("decidedBy", w.id == .null ? nil : w.id)]))
        }
        for (i, p) in model.predicates.enumerated() {
            let r = try alwaysDenies(obj([("predicates", .array([p])), ("caveats", .array(model.caveats)), ("vetoes", .array(model.vetoes)), ("tighten", .array(model.tighten))]), nil)
            var base = JS.present(mem(r, "witness"))
            if base == nil { base = JS.present(mem(try alwaysDenies(obj([("predicates", .array([p])), ("caveats", .array(model.caveats))]), nil), "witness")) }
            guard let b = base, JS.truthy(b) else { continue }
            try add("\(permitId(i)): minimal admitted action", b)
            for path in try trParamPaths(p) {
                let name = cvSlice(path, 14)
                for t in try thresholdsOf(try toModel(obj([("predicates", .array([p]))])), path) {
                    for (tag, v) in [("below", t - eps), ("at", t), ("above", t + eps)] {
                        var a = JSLoose.spread(b)
                        var params = JSLoose.spread(JS.present(mem(b, "params")) ?? .object([:]))
                        params[JKey(name)] = num(v)
                        a["params"] = .object(params)
                        try add("\(permitId(i)): \(name) \(tag) \(JS.toString(.double(t)))", .object(a))
                    }
                }
            }
            var a = JSLoose.spread(b)
            a["resource"] = .string(JS.toString(mem(b, "resource")) + "/__other__")
            try add("\(permitId(i)): unmentioned resource", .object(a))
        }
        // a trigger per prohibition: an action some permit would allow and this prohibition stops (so the prohibition is what is tested)
        let permitOnly = Model()
        permitOnly.predicates = model.predicates; permitOnly.caveats = model.caveats; permitOnly.vetoes = []; permitOnly.tighten = []
        permitOnly.meets = model.meets; permitOnly.caveatSat = model.caveatSat; permitOnly.caveatReason = model.caveatReason
        permitOnly.revCap = model.revCap; permitOnly.undecidable = model.undecidable
        let pr = try collectProbes(ProbeInputs(predicateSets: [try probeSet(model)], varyReversibility: model.revCap != nil))
        for v in model.vetoes {
            let hit = try collect(pr, { rep in
                if try decide(permitOnly, rep) == "deny" { return false }
                return try vetoApplies(v, try contextOfAction(repToAction(rep)))
            }, DEFAULT_MAX_COMBINATIONS, 1).hits.first
            if let h = hit { try add("\(JS.toString(try rd(v, "id"))): trigger", repToAction(h)) }
        }
        return try policyTestsDoc(policy, .array(cases))
    }

    /// Decision of every case of a document under `policy` (for a table in a PR comment).
    static func decideAll(_ policy: V?, _ doc: V?) throws -> V {
        let model = try toModel(policy)
        return strs(try cvList(try rd(doc, "cases"), "doc.cases").map { try decideAction(model, try rd($0, "action")) })
    }
}
