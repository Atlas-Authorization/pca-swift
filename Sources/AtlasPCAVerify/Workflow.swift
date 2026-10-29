import Foundation

/// A hash or canonicalization the reference would throw on (out-of-profile value); every public K5 entry point turns it into its deny result.
struct K5Bail: Error {}

/// Shared strict helpers of the K5 gates (workflow admission, read-side authorization). Integers only: a JSON number counts as an
/// integer only when it is an `int` lexeme with |n| <= 2^53-1 (`1.5` and `2500.0` are not). All name patterns are ASCII, checked by byte;
/// the `(?!__proto__$)` lookahead of the reference is an explicit inequality.
enum K5 {
    static func uint(_ v: JSONValue?) -> Int64? {
        if case let .int(i)? = v, i >= 0, i <= Canonical.MAX_SAFE { return i }
        return nil
    }
    static func alnum(_ c: UInt8) -> Bool { (c >= 0x30 && c <= 0x39) || (c >= 0x41 && c <= 0x5A) || (c >= 0x61 && c <= 0x7A) }
    static func lowerDigit(_ c: UInt8) -> Bool { (c >= 0x30 && c <= 0x39) || (c >= 0x61 && c <= 0x7A) }
    static func ascii(_ s: String, _ max: Int, _ ok: (UInt8) -> Bool) -> Bool {
        let u = s.utf8
        return u.count >= 1 && u.count <= max && u.allSatisfy(ok)
    }
    /// `^(?!__proto__$)[A-Za-z0-9_.:-]{1,64}$`
    static func isId(_ s: String) -> Bool {
        let ok = ascii(s, 64) { alnum($0) || $0 == 0x5F || $0 == 0x2E || $0 == 0x3A || $0 == 0x2D }
        return ok && s != "__proto__"
    }
    /// `^(?!__proto__$)[a-z0-9_.:-]{1,64}$`
    static func isLabel(_ s: String) -> Bool {
        let ok = ascii(s, 64) { lowerDigit($0) || $0 == 0x5F || $0 == 0x2E || $0 == 0x3A || $0 == 0x2D }
        return ok && s != "__proto__"
    }
    /// `^(?!__proto__$)[A-Za-z0-9_.-]{1,64}$`
    static func isName(_ s: String) -> Bool {
        let ok = ascii(s, 64) { alnum($0) || $0 == 0x5F || $0 == 0x2E || $0 == 0x2D }
        return ok && s != "__proto__"
    }
    /// `^[A-Za-z0-9_.:-]{1,16}$`
    static func isUnit(_ s: String) -> Bool {
        ascii(s, 16) { alnum($0) || $0 == 0x5F || $0 == 0x2E || $0 == 0x3A || $0 == 0x2D }
    }

    static func idV(_ v: JSONValue?) -> String? { if let s = v?.asString, isId(s) { return s }; return nil }
    static func nameV(_ v: JSONValue?) -> String? { if let s = v?.asString, isName(s) { return s }; return nil }
    static func unitV(_ v: JSONValue?) -> String? { if let s = v?.asString, isUnit(s) { return s }; return nil }
    static func b32(_ v: JSONValue?) -> String? { IV.digest(v) }
    static func isB32(_ s: String) -> Bool { Base64URLStrict.isValid(s, length: 32) }

    /// `nullOr`: nil = invalid, `.some(nil)` = JSON null, `.some(x)` = valid x.
    static func nullable<T>(_ v: JSONValue?, _ f: (JSONValue?) -> T?) -> T?? {
        if case .null? = v { return .some(nil) }
        if let x = f(v) { return .some(x) }
        return nil
    }

    /// Strictly ascending (UTF-8 bytewise) array of strings, each passing `ok`, at most `max` long.
    static func sortedUnique(_ v: JSONValue?, _ max: Int, _ ok: (String) -> Bool) -> [String]? {
        guard let a = v?.asArray, a.count <= max else { return nil }
        var out: [String] = []
        for x in a {
            guard let s = x.asString, ok(s) else { return nil }
            if let p = out.last, !IV.utf8Less(p, s) { return nil }
            out.append(s)
        }
        return out
    }

    static func onlyKeys(_ o: JObject, _ keys: [String]) -> Bool {
        o.count == keys.count && keys.allSatisfy { o[JKey($0)] != nil }
    }

    static func isScalar(_ v: JSONValue) -> Bool {
        switch v {
        case .string, .bool: return true
        case let .int(i): return i >= -Canonical.MAX_SAFE && i <= Canonical.MAX_SAFE
        default: return false
        }
    }
    /// `isScalarMap`: an object of at most 32 NAME_RE keys holding string / boolean / safe-integer values.
    static func scalarMap(_ v: JSONValue?) -> JObject? {
        guard let o = v?.asObject, o.count <= Workflow.FIELDS, o.allSatisfy({ isName($0.key.s) && isScalar($0.value) }) else { return nil }
        return o
    }
    static func uintMap(_ v: JSONValue?, _ max: Int) -> [String: Int64]? {
        guard let o = v?.asObject, o.count <= max else { return nil }
        var out: [String: Int64] = [:]
        for (k, x) in o {
            guard isName(k.s), let n = uint(x) else { return nil }
            out[k.s] = n
        }
        return out
    }

    static func hash(_ domain: String, _ key: String, _ v: JSONValue) throws -> String {
        guard let h = K3Sig.digest(domain, key, v) else { throw K5Bail() }
        return h
    }
    /// base64url(sha256(strictCanonical({d: domain, ...fields}))) over a multi-member body; throws where the reference throws.
    static func hash(_ domain: String, _ key: String, _ v: JSONValue, full: Bool) throws -> String {
        guard full, case var .object(o) = v else { return try hash(domain, key, v) }
        o["d"] = .string(domain)
        guard let h = IV.strictHash(.object(o)) else { throw K5Bail() }
        return h
    }
    static func valueDigest(_ v: JSONValue) throws -> String { try hash(Workflow.VAL, "v", v) }
}

struct WfStep {
    let id: String, verb: String, resource: String
    let paramsDigest: String?
    let deps: [String]
    let denyLabels: [String], escalateLabels: [String]
    let freshMs: Int64?
    let cost: [String: Int64]

    static func parse(_ x: JSONValue?) -> WfStep? {
        guard let s = x?.asObject, K5.onlyKeys(s, ["id", "verb", "resource", "params_digest", "deps", "sink", "deny_labels", "escalate_labels", "fresh_ms", "cost"]),
              let id = K5.idV(s["id"]), let verb = K3Sig.str(s["verb"], 128), let resource = K3Sig.str(s["resource"], 512),
              let pd = K5.nullable(s["params_digest"], K5.b32),
              let deps = K5.sortedUnique(s["deps"], Workflow.DEPS, K5.isId),
              let _ = K5.nullable(s["sink"], K5.idV),
              let dl = K5.sortedUnique(s["deny_labels"], Workflow.LABELS, K5.isLabel),
              let el = K5.sortedUnique(s["escalate_labels"], Workflow.LABELS, K5.isLabel),
              let fm = K5.nullable(s["fresh_ms"], K5.uint),
              let cost = K5.uintMap(s["cost"], Workflow.COST) else { return nil }
        return WfStep(id: id, verb: verb, resource: resource, paramsDigest: pd, deps: deps, denyLabels: dl, escalateLabels: el, freshMs: fm, cost: cost)
    }
}

struct WfEdge {
    let fromStep: String, fromField: String, toStep: String, toParam: String
    let op: String
    let unit: String?
    let denyLabels: [String]
    let promise: String?

    static func parse(_ x: JSONValue?) -> WfEdge? {
        guard let e = x?.asObject, K5.onlyKeys(e, ["from", "to", "op", "unit", "deny_labels", "promise"]),
              let f = e["from"]?.asObject, K5.onlyKeys(f, ["step", "field"]), let fs = K5.idV(f["step"]), let ff = K5.nameV(f["field"]),
              let t = e["to"]?.asObject, K5.onlyKeys(t, ["step", "param"]), let ts = K5.idV(t["step"]), let tp = K5.nameV(t["param"]),
              let op = e["op"]?.asString, ["eq", "le", "ge", "lt", "gt"].contains(op),
              let unit = K5.nullable(e["unit"], K5.unitV),
              let dl = K5.sortedUnique(e["deny_labels"], Workflow.LABELS, K5.isLabel),
              let promise = K5.nullable(e["promise"], K5.idV) else { return nil }
        return WfEdge(fromStep: fs, fromField: ff, toStep: ts, toParam: tp, op: op, unit: unit, denyLabels: dl, promise: promise)
    }
}

struct WfBody {
    let raw: JSONValue
    let principal: String
    let goalDigest: String?, planRoot: String?
    let issuedAt: Int64, expiresAt: Int64
    let steps: [WfStep], edges: [WfEdge]
    let maxSteps: Int64
    let caps: [String: Int64]

    /// `validWorkflowBody`: nil when the body is malformed.
    static func parse(_ v: JSONValue?) -> WfBody? {
        guard let raw = v, let b = raw.asObject,
              K5.onlyKeys(b, ["v", "id", "principal", "goal_digest", "plan_root", "issued_at", "expires_at", "steps", "edges", "budget"]),
              K5.uint(b["v"]) == 1, K5.idV(b["id"]) != nil, let principal = K5.b32(b["principal"]),
              let gd = K5.nullable(b["goal_digest"], K5.b32), let pr = K5.nullable(b["plan_root"], K5.b32),
              let iat = K5.uint(b["issued_at"]), let exp = K5.uint(b["expires_at"]),
              let sa = b["steps"]?.asArray, !sa.isEmpty, sa.count <= Workflow.STEPS,
              let ea = b["edges"]?.asArray, ea.count <= Workflow.EDGES,
              let bg = b["budget"]?.asObject, K5.onlyKeys(bg, ["max_steps", "caps"]), let ms = K5.uint(bg["max_steps"]),
              let caps = K5.uintMap(bg["caps"], Workflow.COST) else { return nil }
        var steps: [WfStep] = []
        for x in sa { guard let s = WfStep.parse(x) else { return nil }; steps.append(s) }
        var edges: [WfEdge] = []
        for x in ea { guard let e = WfEdge.parse(x) else { return nil }; edges.append(e) }
        // every cost name must be capped
        for s in steps { for k in s.cost.keys where caps[k] == nil { return nil } }
        return WfBody(raw: raw, principal: principal, goalDigest: gd, planRoot: pr, issuedAt: iat, expiresAt: exp, steps: steps, edges: edges, maxSteps: ms, caps: caps)
    }

    /// step id -> the set of its transitive dependencies; nil on a cycle.
    func ancestors() -> [String: Set<String>]? {
        var byId: [String: WfStep] = [:]
        for s in steps { byId[s.id] = s }
        var out: [String: Set<String>] = [:]
        var state: [String: Int] = [:]
        func visit(_ id: String) -> Bool {
            if state[id] == 2 { return true }
            if state[id] == 1 { return false }
            state[id] = 1
            guard let s = byId[id] else { return false }
            var set = Set<String>()
            for d in s.deps {
                if !visit(d) { return false }
                set.insert(d)
                if let x = out[d] { set.formUnion(x) }
            }
            out[id] = set
            state[id] = 2
            return true
        }
        for s in steps { if !visit(s.id) { return nil } }
        return out
    }

    /// DAG semantics: unique ids, deps exist, acyclic, every edge runs from a (transitive) dependency. True when the DAG is fine.
    func dagOk() -> Bool {
        var ids = Set<String>()
        for s in steps { if !ids.insert(s.id).inserted { return false } }
        for s in steps { for d in s.deps where d == s.id || !ids.contains(d) { return false } }
        guard let anc = ancestors() else { return false }
        for e in edges {
            if !ids.contains(e.fromStep) || !ids.contains(e.toStep) || anc[e.toStep]?.contains(e.fromStep) != true { return false }
        }
        return true
    }
}

struct WfOutput {
    let digest: String
    let num: Int64?
    let unit: String?
    let labels: [String]
}

struct WfReceipt {
    let raw: JObject
    let wf: String, step: String
    let seq: Int64
    let prev: String?
    let ok: Bool
    let paramsDigest: String
    let outputs: [String: WfOutput]
    let issuedAt: Int64
    let signer: String
    let sig: String

    static func parse(_ x: JSONValue) -> WfReceipt? {
        guard let r = x.asObject, K5.onlyKeys(r, ["v", "wf", "step", "seq", "prev", "outcome", "params_digest", "outputs", "issued_at", "signer", "sig"]),
              K5.uint(r["v"]) == 1, let wf = K5.b32(r["wf"]), let step = K5.idV(r["step"]), let seq = K5.uint(r["seq"]),
              let prev = K5.nullable(r["prev"], K5.b32), (seq == 0) == (prev == nil),
              let outcome = r["outcome"]?.asString, outcome == "ok" || outcome == "failed",
              let pd = K5.b32(r["params_digest"]), let iat = K5.uint(r["issued_at"]), let signer = K5.b32(r["signer"]),
              let sig = r["sig"]?.asString,
              let o = r["outputs"]?.asObject, o.count <= Workflow.FIELDS else { return nil }
        var outs: [String: WfOutput] = [:]
        for (k, v) in o {
            guard K5.isName(k.s), let ov = v.asObject, K5.onlyKeys(ov, ["digest", "num", "unit", "labels"]), let d = K5.b32(ov["digest"]),
                  let num = K5.nullable(ov["num"], K5.uint), let unit = K5.nullable(ov["unit"], K5.unitV),
                  let labels = K5.sortedUnique(ov["labels"], Workflow.LABELS, K5.isLabel) else { return nil }
            outs[k.s] = WfOutput(digest: d, num: num, unit: unit, labels: labels)
        }
        return WfReceipt(raw: r, wf: wf, step: step, seq: seq, prev: prev, ok: outcome == "ok", paramsDigest: pd, outputs: outs, issuedAt: iat, signer: signer, sig: sig)
    }
}

public struct WfResult: Equatable {
    public let decision: String
    public let code: String?
    public let step: String?
    /// index of the offending receipt (receipt-chain failures)
    public let at: Int?
    /// edge indexes whose source receipt does not exist yet (promise pipelining)
    public let pending: [Int]

    /// The shape the shared vectors expect: {decision, code, step, at, pending}.
    public var json: JSONValue {
        .object([
            "decision": .string(decision), "code": code.map { JSONValue.string($0) } ?? .null, "step": step.map { JSONValue.string($0) } ?? .null,
            "at": at.map { JSONValue.int(Int64($0)) } ?? .null, "pending": .array(pending.map { .int(Int64($0)) }),
        ])
    }
}

/// K5 workflow (DAG) admission: a principal-signed DAG of steps, per-edge dataflow constraints, taint labels, freshness and cost budgets;
/// each step is admitted only as part of that DAG, its inputs proven from signed step receipts. Total and pure; replays
/// packages/pca/conformance/workflow-vectors.json. Port of packages/pca/src/workflow.ts, same check order.
public enum Workflow {
    public static let WORKFLOW_DOMAIN = "atlas-pca/workflow/v1\u{0}"
    public static let WF_RECEIPT_DOMAIN = "atlas-pca/wf-receipt/v1\u{0}"
    static let WF_REF = "atlas-pca/workflow-ref/v1"
    static let WR_REF = "atlas-pca/wf-receipt-ref/v1"
    static let VAL = "atlas-pca/wf-value/v1"
    static let STEPS = 64, EDGES = 256, DEPS = 16, LABELS = 16, FIELDS = 32, COST = 8

    /// Digest of a (shape-valid) workflow body; nil where the reference throws.
    public static func workflowDigest(_ body: JSONValue) -> String? { K3Sig.digest(WF_REF, "w", body) }
    /// Digest of a scalar value as it appears in step receipts; nil where the reference throws.
    public static func valueDigest(_ v: JSONValue) -> String? { K3Sig.digest(VAL, "v", v) }
    public static func receiptRef(_ r: JSONValue) -> String? { K3Sig.digest(WR_REF, "r", r) }

    static func res(_ decision: String, _ code: String?, _ step: String?, at: Int? = nil, pending: [Int] = []) -> WfResult {
        WfResult(decision: decision, code: code, step: step, at: at, pending: pending)
    }
    static func deny(_ code: String, _ step: String? = nil, at: Int? = nil) -> WfResult { res("deny", code, step, at: at) }

    /// Is `root` the Merkle plan root this signed, unexpired, pinned-principal workflow authorizes?
    public static func planRootAuthorized(workflow: JSONValue?, principal: String, now: Int64, root: String) -> Bool {
        guard let sw = workflow?.asObject, let w = WfBody.parse(sw["body"]), w.dagOk(), w.principal == principal,
              K3Sig.verifyBody(WORKFLOW_DOMAIN, w.raw, signer: principal, sig: sw["sig"]),
              now >= w.issuedAt, now < w.expiresAt, w.planRoot == root else { return false }
        return true
    }

    struct Request {
        let step: String, verb: String, resource: String
        let params: JObject
        let units: [String: String]
        let goalDigest: String?, planRoot: String?

        static func parse(_ x: JSONValue?) -> Request? {
            guard let r = x?.asObject, K5.onlyKeys(r, ["step", "verb", "resource", "params", "units", "goal_digest", "plan_root"]),
                  let step = K5.idV(r["step"]), let verb = K3Sig.str(r["verb"], 128), let resource = K3Sig.str(r["resource"], 512),
                  let params = K5.scalarMap(r["params"]), let uo = r["units"]?.asObject,
                  let gd = K5.nullable(r["goal_digest"], K5.b32), let pr = K5.nullable(r["plan_root"], K5.b32) else { return nil }
            var units: [String: String] = [:]
            for (k, v) in uo {
                guard K5.isName(k.s), let u = K5.unitV(v) else { return nil }
                units[k.s] = u
            }
            return Request(step: step, verb: verb, resource: resource, params: params, units: units, goalDigest: gd, planRoot: pr)
        }
    }

    /// Check the receipt chain against the workflow. Returns the offending index, or the parsed chain.
    static func receipts(_ w: WfBody, _ rsSigner: String, _ list: [JSONValue], _ now: Int64) throws -> (at: Int?, recs: [WfReceipt]) {
        guard let wd = workflowDigest(w.raw) else { throw K5Bail() }
        var byId: [String: WfStep] = [:]
        for s in w.steps { byId[s.id] = s }
        var index: [String: Int] = [:]
        var prev: WfReceipt? = nil
        var recs: [WfReceipt] = []
        for (i, raw) in list.enumerated() {
            guard let r = WfReceipt.parse(raw), r.signer == rsSigner, r.wf == wd, r.seq == Int64(i), r.issuedAt <= now else { return (i, recs) }
            guard let st = byId[r.step], index[r.step] == nil else { return (i, recs) }
            let linked: Bool
            if let p = prev {
                guard let ref = receiptRef(.object(p.raw)) else { throw K5Bail() }
                linked = r.prev == ref
            } else { linked = r.prev == nil }
            if !linked || !K3Sig.verifyBody(WF_RECEIPT_DOMAIN, .object(K3Sig.without(r.raw, "sig")), signer: rsSigner, sig: .string(r.sig)) { return (i, recs) }
            // a receipt may precede one of its dependencies' receipts only when every edge from that dependency is a declared promise
            for d in st.deps where index[d] == nil {
                let es = w.edges.filter { $0.fromStep == d && $0.toStep == r.step }
                if es.isEmpty || es.contains(where: { $0.promise == nil }) { return (i, recs) }
            }
            index[r.step] = i
            prev = r
            recs.append(r)
        }
        return (nil, recs)
    }

    static func evaluate(_ workflow: JSONValue?, _ principal: String, _ rsSigner: String, _ receiptList: JSONValue?, _ now: Int64, _ request: JSONValue?, bind: Bool) throws -> WfResult {
        guard let sw = workflow?.asObject, K5.onlyKeys(sw, ["body", "sig"]), let w = WfBody.parse(sw["body"]), let q = Request.parse(request),
              let list = receiptList?.asArray, K5.isB32(principal), K5.isB32(rsSigner), now >= 0, now <= Canonical.MAX_SAFE else { return deny("bad_workflow") }
        if !w.dagOk() { return deny("bad_dag", q.step) }
        if w.principal != principal || !K3Sig.verifyBody(WORKFLOW_DOMAIN, w.raw, signer: principal, sig: sw["sig"]) { return deny("bad_signature", q.step) }
        if now < w.issuedAt { return deny("not_yet", q.step) }
        if now >= w.expiresAt { return deny("expired", q.step) }
        if q.goalDigest != w.goalDigest { return deny("goal_mismatch", q.step) }
        if q.planRoot != w.planRoot { return deny("plan_root_mismatch", q.step) }
        let chain = try receipts(w, rsSigner, list, now)
        if let at = chain.at { return deny("bad_receipt", q.step, at: at) }
        var rec: [String: WfReceipt] = [:]
        for r in chain.recs { rec[r.step] = r }
        guard let step = w.steps.first(where: { $0.id == q.step }) else { return deny("unplanned_step", q.step) }
        if !IV.same(step.verb, q.verb) || !IV.same(step.resource, q.resource) { return deny("step_mismatch", q.step) }
        guard let pd = IV.strictHash(.object(q.params)) else { throw K5Bail() }
        if let spd = step.paramsDigest, spd != pd { return deny("params_mismatch", q.step) }
        let mine = rec[step.id]
        if bind {
            guard let m = mine, m.paramsDigest == pd else { return deny("params_mismatch", q.step) }
        } else {
            if mine != nil { return deny("already_done", q.step) }
            if Int64(chain.recs.count) + 1 > w.maxSteps { return deny("budget_exceeded", q.step) }
            var byId: [String: WfStep] = [:]
            for s in w.steps { byId[s.id] = s }
            for (name, cap) in w.caps {
                var spent: Int64 = step.cost[name] ?? 0
                for r in chain.recs { spent += byId[r.step]?.cost[name] ?? 0 }
                if spent > cap { return deny("budget_exceeded", q.step) }
            }
        }
        // dependencies
        var pending: [Int] = []
        var unconstrained = false
        for d in step.deps {
            guard let dr = rec[d] else {
                let es = w.edges.enumerated().filter { $0.element.fromStep == d && $0.element.toStep == step.id }
                if bind || es.isEmpty { return deny("deps_unmet", q.step) }
                if es.contains(where: { $0.element.promise == nil }) { unconstrained = true }
                continue
            }
            if !dr.ok { return deny("dep_failed", q.step) }
            if let fm = step.freshMs, now - dr.issuedAt > fm { return deny("stale_dep", q.step) }
        }
        // edge constraints
        for (i, e) in w.edges.enumerated() where e.toStep == step.id {
            guard let src = rec[e.fromStep] else { pending.append(i); continue }
            guard let out = src.outputs[e.fromField], let val = q.params[JKey(e.toParam)] else { return deny("edge_missing", q.step, at: i) }
            let qu = q.units[e.toParam]
            if out.unit != qu || out.unit != e.unit { return deny("edge_unit", q.step, at: i) }
            if e.op == "eq" {
                if try K5.valueDigest(val) != out.digest { return deny("edge_digest", q.step, at: i) }
            } else {
                guard case let .int(v) = val, let n = out.num else { return deny("edge_value", q.step, at: i) }
                let ok: Bool
                switch e.op {
                case "le": ok = v <= n
                case "ge": ok = v >= n
                case "lt": ok = v < n
                default: ok = v > n
                }
                if !ok { return deny("edge_relation", q.step, at: i) }
            }
            if out.labels.contains(where: { e.denyLabels.contains($0) }) { return deny("taint_flow", q.step, at: i) }
        }
        if bind && !pending.isEmpty { return deny("deps_unmet", q.step) }
        // taint across the DAG: every label any executed ancestor produced
        guard let anc = w.ancestors() else { return deny("bad_dag", q.step) }
        var inherited = Set<String>()
        for a in anc[step.id] ?? [] { if let r = rec[a] { for o in r.outputs.values { inherited.formUnion(o.labels) } } }
        if step.denyLabels.contains(where: { inherited.contains($0) }) { return deny("taint_flow", q.step) }
        if unconstrained { return res("escalate", "pipeline_unconstrained", q.step) }
        if step.escalateLabels.contains(where: { inherited.contains($0) }) { return res("escalate", "taint_escalate", q.step) }
        return res("allow", nil, q.step, pending: pending)
    }

    /// Admit ONE step of the committed workflow, or deny / escalate. `workflow` is `{body, sig}`; `principal` / `rsSigner` are the verifier-pinned keys.
    public static func admitStep(workflow: JSONValue?, principal: String, rsSigner: String, receipts: JSONValue?, now: Int64, request: JSONValue?) -> WfResult {
        do { return try evaluate(workflow, principal, rsSigner, receipts, now, request, bind: false) } catch { return deny("bad_workflow") }
    }
    /// Promise binding (post hoc): the step already has its receipt; its params are re-checked against every edge now that all of its dependencies' receipts exist.
    public static func bindPromises(workflow: JSONValue?, principal: String, rsSigner: String, receipts: JSONValue?, now: Int64, request: JSONValue?) -> WfResult {
        do { return try evaluate(workflow, principal, rsSigner, receipts, now, request, bind: true) } catch { return deny("bad_workflow") }
    }
}
