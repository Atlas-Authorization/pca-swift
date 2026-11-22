import Foundation

// Fraud proofs and one-shot dispute adjudication for bonded optimistic claims: `verifyFraudProof` RE-RUNS the policy VM on the server-held frozen open-time
// snapshot under the grant the verifier trusts, and `adjudicateDispute` re-adjudicates with an objective oracle's authoritative value substituted for the
// single disputed input. A slash is never authorized by a challenger's assertion. Both are total (never throw) and FAIL CLOSED. Snapshots are decide inputs
// (see `PCAPolicyVm`).

/// An objective oracle: `resolve(input, snapshot)` answers `{input, value?, class?, valid, reason?}`.
public typealias PCADisputeOracle = (_ input: String, _ snapshot: JSONValue) throws -> JSONValue

public enum PCAOptimisticAdjudication {
    public static let DEFAULT_R_MARGIN = 1e-9
    static let INPUTS = ["reversibility_class", "reversibility", "blastRadius", "semanticDistance"]

    private static func withGrant(_ snap: JSONValue, _ grant: JSONValue?) -> JSONValue {
        var o = snap.asObject ?? [:]
        o["grant"] = grant ?? .null
        return .object(o)
    }

    private static func summarize(_ d: JSONValue) -> (release: Bool, r: Double, optimistic: Bool) {
        (d.get("releaseGuardianShare") == .bool(true), IV.num(d.get("r")) ?? .nan, d.get("requiredThreshold")?.get("optimisticAllowed") == .bool(true))
    }

    private static func summaryJSON(_ s: (release: Bool, r: Double, optimistic: Bool)) -> JSONValue {
        .object(["releaseGuardianShare": .bool(s.release), "r": StoreJ.num(s.r), "optimisticAllowed": .bool(s.optimistic)])
    }

    private static func fixed3(_ x: Double) -> String { PCAStoreConformance.toFixed3(x) }

    /// Independently verify a fraud proof against a bonded claim: `{fraudulent, slashBondRef?, reason}`.
    public static func verifyFraudProof(_ claim: JSONValue, _ proof: JSONValue?, _ grant: JSONValue?, _ openSnapshot: JSONValue?) -> JSONValue {
        func no(_ why: String) -> JSONValue { .object(["fraudulent": .bool(false), "reason": .string(why)]) }
        guard let proof = proof, proof.isObject else { return no("malformed fraud proof") }
        if !StoreJ.same(proof.get("pcactn_digest"), claim.get("pcactn_digest")) { return no("fraud proof targets a different PCActn than the claim") }
        if !StoreJ.same(proof.get("bond_ref"), claim.get("bond_ref")) { return no("fraud proof names a different bond than the claim") }
        guard let snap = openSnapshot, snap.isObject else { return no("no frozen open-time snapshot supplied; cannot judge the claim") }
        do {
            let rec = try PCAPolicyVm.decide(withGrant(snap, grant))
            let s = summarize(rec)
            let d = proof.get("decision")?.isObject == true ? proof.get("decision") : nil
            guard let dd = d else { throw JSError("Cannot read properties of undefined (reading 'releaseGuardianShare')") }
            // a missing or non-numeric asserted r is NaN here, which never matches: the comparison below is the negation of "within 1e-9"
            let dr = IV.num(dd.get("r")) ?? .nan
            if d?.get("releaseGuardianShare") != .bool(s.release) || d?.get("optimisticAllowed") != .bool(s.optimistic) || !(abs(s.r - dr) <= 1e-9) {
                return no("proof decision does not match an independent recomputation")
            }
            let margin = StoreJ.fin(proof.get("r_margin")).map { Swift.max(0, $0) } ?? DEFAULT_R_MARGIN
            let snapClass = snap.get("action")?.get("action")?.get("reversibility_class")?.asString
            let irreversible = claim.get("reversibility_class")?.asString == Optimistic.IRREVERSIBLE || snapClass == Optimistic.IRREVERSIBLE
            let ref = claim.get("bond_ref") ?? .null
            func fraud(_ why: String) -> JSONValue { .object(["fraudulent": .bool(true), "slashBondRef": ref, "reason": .string(why)]) }
            if irreversible { return fraud("irreversible action is ineligible for the optimistic path") }
            if !s.release {
                let reasons = (rec.get("reasons")?.asArray ?? []).map { JS.toString($0) }.joined(separator: "; ")
                return fraud("Policy VM denies the action: \(reasons.isEmpty ? "not compliant" : reasons)")
            }
            if !s.optimistic { return fraud("optimistic path not allowed at real r=\(fixed3(s.r))") }
            guard let claimed = IV.num(claim.get("claimed_r")) else { throw JSError("'claimed_r'") }
            if s.r > claimed + margin { return fraud("risk understated: claimed \(JS.number(claimed)), real \(fixed3(s.r))") }
            return no("claim is compliant under independent recomputation; bond stands")
        } catch {
            let t = PCAStoreError.text(error)
            return no("fraud-proof verification error: \(t.isEmpty ? "unknown" : t)")
        }
    }

    private static func snapshotValue(_ snap: JSONValue, _ input: String) -> JSONValue? {
        if input == "reversibility_class" {
            if let v = snap.get("caveatContext")?.get("reversibilityClass"), !v.isNull { return v }
            return snap.get("action")?.get("action")?.get("reversibility_class")
        }
        return snap.get("risk")?.get(input)
    }

    private static func substitute(_ snap: JSONValue, _ res: JSONValue) throws -> JSONValue {
        var out = snap.asObject ?? [:]
        let input = res.get("input")?.asString ?? ""
        if input == "reversibility_class" {
            guard let c = res.get("class")?.asString, !c.isEmpty else { throw JSError("oracle reversibility_class resolution carries no class") }
            var act = snap.get("action")?.asObject ?? [:]
            var inner = act["action"]?.asObject ?? [:]
            inner["reversibility_class"] = .string(c)
            act["action"] = .object(inner)
            out["action"] = .object(act)
            if var cc = snap.get("caveatContext")?.asObject, let cur = cc["reversibilityClass"], !cur.isNull {
                cc["reversibilityClass"] = .string(c)
                out["caveatContext"] = .object(cc)
            }
            return .object(out)
        }
        guard StoreJ.fin(res.get("value")) != nil, let v = res.get("value") else { throw JSError("oracle \(input) resolution carries no finite value") }
        var risk = snap.get("risk")?.asObject ?? [:]
        risk[JKey(input)] = v
        out["risk"] = .object(risk)
        if input == "blastRadius", var cc = snap.get("caveatContext")?.asObject, let cur = cc["blastRadius"], !cur.isNull {
            cc["blastRadius"] = v
            out["caveatContext"] = .object(cc)
        }
        return .object(out)
    }

    private static func js(_ v: JSONValue?) -> String { v.map { Canonical.canonicalize($0) } ?? "undefined" }

    /// Adjudicate a contestable dispute: RE-RUN the policy VM on the frozen open-time snapshot with the ORACLE's authoritative value substituted for the single
    /// disputed input. `outcome`: `agent-fraud` (slash the agent's bond), `claim-upheld` (slash the challenger's counter-bond) or `indeterminate` (slash neither).
    /// The challenger's asserted value is never read for the verdict.
    public static func adjudicateDispute(_ claim: JSONValue, _ dispute: JSONValue?, _ grant: JSONValue?, _ openSnapshot: JSONValue?, _ oracle: PCADisputeOracle?,
                                         rMargin: JSONValue? = nil) -> JSONValue {
        let margin = StoreJ.fin(rMargin).map { Swift.max(0, $0) } ?? DEFAULT_R_MARGIN
        let worst: JSONValue = .object(["releaseGuardianShare": .bool(false), "r": .int(1), "optimisticAllowed": .bool(false)])
        func indeterminate(_ input: String, _ reason: String, baseline: JSONValue? = nil, agentValue: JSONValue? = nil) -> JSONValue {
            .object(["outcome": .string("indeterminate"), "fraudulent": .bool(false), "slashCounterBond": .bool(false), "input": .string(input), "agentValue": agentValue ?? .null,
                     "oracleValue": .null, "baseline": baseline ?? worst, "adjudicated": worst, "reason": .string(reason)])
        }
        guard let dispute = dispute, dispute.isObject else { return indeterminate("reversibility_class", "malformed dispute") }
        guard let input = dispute.get("input")?.asString, INPUTS.contains(input) else {
            return indeterminate("reversibility_class", "unknown disputed input: \(dispute.get("input").map { JS.toString($0) } ?? "undefined")")
        }
        do {
            if !StoreJ.same(dispute.get("pcactn_digest"), claim.get("pcactn_digest")) { return indeterminate(input, "dispute targets a different PCActn than the claim") }
            if !StoreJ.same(dispute.get("bond_ref"), claim.get("bond_ref")) { return indeterminate(input, "dispute names a different bond than the claim") }
            guard let open = openSnapshot, open.isObject else { return indeterminate(input, "no frozen open-time snapshot supplied; cannot adjudicate") }
            guard let oracle = oracle else { return indeterminate(input, "no objective oracle supplied") }
            let snap = withGrant(open, grant)
            let base = summarize(try PCAPolicyVm.decide(snap))
            let baseline = summaryJSON(base)
            let agentValue = snapshotValue(snap, input)
            let res = try oracle(input, snap)
            guard res.isObject, res.get("input")?.asString == input, StoreJ.truthy(res.get("valid")) else {
                let why = StoreJ.truthy(res.get("reason")) ? ": \(JS.toString(res.get("reason")))" : ""
                return indeterminate(input, "objective oracle could not authoritatively resolve \(input)\(why)", baseline: baseline, agentValue: agentValue)
            }
            let oracleValue: JSONValue? = (res.get("class").map { !$0.isNull } ?? false) ? res.get("class") : res.get("value")
            let adj = summarize(try PCAPolicyVm.decide(try substitute(snap, res)))
            guard let claimed = IV.num(claim.get("claimed_r")) else { throw JSError("'claimed_r'") }
            if !(adj.release && adj.optimistic && adj.r <= claimed + margin) {
                let why: String
                if !adj.release { why = "the Policy VM denies the action" }
                else if !adj.optimistic { why = "the optimistic path is not allowed (higher threshold) at r=\(fixed3(adj.r))" }
                else { why = "the real r=\(fixed3(adj.r)) exceeds the claimed r=\(JS.number(claimed))" }
                return .object(["outcome": .string("agent-fraud"), "fraudulent": .bool(true), "slashBondRef": claim.get("bond_ref") ?? .null, "slashCounterBond": .bool(false),
                                "input": .string(input), "agentValue": agentValue ?? .null, "oracleValue": oracleValue ?? .null, "baseline": baseline, "adjudicated": summaryJSON(adj),
                                "reason": .string("understated \(input): agent relied on \(js(agentValue)), oracle says \(js(oracleValue)) \u{2014} \(why)")])
            }
            return .object(["outcome": .string("claim-upheld"), "fraudulent": .bool(false), "slashCounterBond": .bool(true), "input": .string(input), "agentValue": agentValue ?? .null,
                            "oracleValue": oracleValue ?? .null, "baseline": baseline, "adjudicated": summaryJSON(adj),
                            "reason": .string("the objective oracle upholds the agent's \(input) (\(js(oracleValue))); fast-path admission survives \u{2014} the dispute is frivolous")])
        } catch {
            let t = PCAStoreError.text(error)
            return indeterminate(input, "dispute adjudication error (fail closed): \(t.isEmpty ? "unknown" : t)")
        }
    }

    /// A deep copy of a decide input captured at claim open (a JSON value is its own deep copy); store it with the claim.
    public static func freezeOpenSnapshot(_ input: JSONValue) -> JSONValue { input }
}
