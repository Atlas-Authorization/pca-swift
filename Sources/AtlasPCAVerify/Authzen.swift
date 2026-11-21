import Foundation

/// PCA behind the OpenID AuthZEN Authorization API 1.0: a Policy Decision Point (Access Evaluation, the Access Evaluations
/// boxcar, the COAZ MCP-tool profile, the AARP approval-required step-up), a framework-agnostic handler over {path, body} and
/// the three Search APIs. Everything fails closed: an unresolved policy, a malformed PCActn, a verifier rejection, a policy
/// denial or any thrown error is `decision: false`.
///
/// The Policy-VM (`decide` / `deriveDecideInput`) and the static analyzer (`admitsConcrete`) default to the native ones
/// (`PCAPolicyVm`, `PCAAnalyzer`); the config can still inject a replacement. `enforce.attestation` / `enforce.taint` /
/// `enforce.freshness` in a resolved context are refused (they are not wired to this verifier's PDP path).
public struct PCAAuthzenConfig {
    /// Resolves the PCA authority for a request: {grant, chain?, policy, plan?, risk?, budget?, enforce?}; nil / null = none.
    public var resolve: (JSONValue) throws -> JSONValue?
    /// `.unset` (default) fails closed against a PCActn that carries an `aud`; `.any` is the explicit opt-out.
    public var audience: PCA.Audience = .unset
    public var authorizedPlanRoots: [String]?
    public var insecureSkipPlanRootCheck = false
    public var now: () -> Int64 = { Int64(Date().timeIntervalSince1970 * 1000) }
    /// Maps an MCP tool name to the capability it needs (default: the tool name).
    public var toolCapability: ((JSONValue) throws -> JSONValue)?
    /// Maps a request to the analyzer action (default `PCAAuthzen.defaultToAction`).
    public var toAction: ((JSONValue) throws -> JSONValue)?
    public var requireProof = true
    /// Replay / revocation authorizer: input {operation, pcactn, provenance?} -> {allow, reason?}.
    public var authorizer: ((JSONValue) throws -> JSONValue)?
    public var requireAuthorizer = true
    /// A JavaScript number (default 100); a non-number never refuses (NaN comparison).
    public var maxEvaluations: JSONValue = .int(Int64(PCAAuthzen.DEFAULT_MAX_EVALUATIONS))
    public var decide: ((JSONValue) throws -> JSONValue)?
    public var deriveDecideInput: ((JSONValue, JSONValue) throws -> JSONValue)?
    public var admitsConcrete: ((JSONValue, JSONValue) throws -> Bool)?

    public init(resolve: @escaping (JSONValue) throws -> JSONValue?) { self.resolve = resolve }
}

/// Host-supplied search provider; a nil function means that search is unsupported.
public struct PCAAuthzenSearchProvider {
    public var searchSubject: ((JSONValue) throws -> JSONValue)?
    public var searchResource: ((JSONValue) throws -> JSONValue)?
    public var searchAction: ((JSONValue) throws -> JSONValue)?
    public init(searchSubject: ((JSONValue) throws -> JSONValue)? = nil, searchResource: ((JSONValue) throws -> JSONValue)? = nil,
                searchAction: ((JSONValue) throws -> JSONValue)? = nil) {
        self.searchSubject = searchSubject
        self.searchResource = searchResource
        self.searchAction = searchAction
    }
}

public enum PCAAuthzen {
    public static let PCA_APPROVAL_KEY = "pca_approval"
    public static let PCA_ACTION_KEY = "pca_action"
    public static let PCA_PROVENANCE_KEY = "pca_provenance"
    public static let DEFAULT_MAX_EVALUATIONS = 100
    public static let EVALUATION_PATH = "/access/v1/evaluation"
    public static let EVALUATIONS_PATH = "/access/v1/evaluations"
    public static let COAZ_TOOL_PATH = "/access/v1/mcp/tool/evaluation"
    public static let SEARCH_SUBJECT_PATH = "/access/v1/search/subject"
    public static let SEARCH_RESOURCE_PATH = "/access/v1/search/resource"
    public static let SEARCH_ACTION_PATH = "/access/v1/search/action"
    public static let MAX_SEARCH_LIMIT = 1000

    // MARK: helpers

    static func obj(_ d: [String: JSONValue?]) -> JSONValue {
        var o: JObject = [:]
        for (k, v) in d { if let v = v { o[JKey(k)] = v } }
        return .object(o)
    }

    static func rec(_ x: JSONValue?) -> Bool { x?.isObject ?? false }
    static func str(_ x: JSONValue?) -> Bool { x?.asString != nil }
    static func nonEmpty(_ x: JSONValue?) -> Bool { !(x?.asString ?? "").isEmpty }
    static func num(_ x: JSONValue?) -> Double? {
        switch x {
        case let .int(i)?: return Double(i)
        case let .double(d)?: return d.isFinite ? d : nil
        default: return nil
        }
    }
    static func has(_ x: JSONValue?, _ k: String) -> Bool { x?.get(k) != nil }

    /// `x.k` in JavaScript: null / undefined throw, any other non-object has no member.
    static func prop(_ x: JSONValue?, _ k: String) throws -> JSONValue? {
        switch x {
        case nil: throw JSError("Cannot read properties of undefined (reading '\(k)')")
        case .null?: throw JSError("Cannot read properties of null (reading '\(k)')")
        default: return x?.get(k)
        }
    }

    /// `${o.k}`: an absent member renders as undefined.
    static func js(_ o: JSONValue?, _ k: String) -> String { JS.toString(o?.get(k)) }

    static func message(_ e: Error) -> String {
        let m = (e as? JSError)?.message ?? "\(e)"
        return m.isEmpty ? "unknown" : m
    }

    // MARK: guards

    public static func isAuthzenSubject(_ x: JSONValue?) -> Bool { rec(x) && str(x?.get("type")) && str(x?.get("id")) }
    public static func isAuthzenAction(_ x: JSONValue?) -> Bool { rec(x) && str(x?.get("name")) }
    public static func isAuthzenResource(_ x: JSONValue?) -> Bool { isAuthzenSubject(x) }
    public static func isAccessEvaluationRequest(_ x: JSONValue?) -> Bool {
        rec(x) && isAuthzenSubject(x?.get("subject")) && isAuthzenAction(x?.get("action")) && isAuthzenResource(x?.get("resource"))
            && (!has(x, "context") || rec(x?.get("context")))
    }
    public static func isAccessEvaluationsRequest(_ x: JSONValue?) -> Bool { rec(x) && x?.get("evaluations")?.isArray == true }
    public static func isCoazToolAuthorizationRequest(_ x: JSONValue?) -> Bool {
        rec(x) && isAuthzenSubject(x?.get("subject")) && rec(x?.get("tool")) && str(x?.get("tool")?.get("name"))
    }

    static func isRequiredThreshold(_ x: JSONValue?) -> Bool {
        guard rec(x), let t = num(x?.get("t")), t == 1 || t == 2 || t == 3, str(x?.get("proof")) else { return false }
        if case .bool(_)? = x?.get("optimisticAllowed") { return true }
        return false
    }

    // MARK: AARP

    /// The AARP pending-approval reference of a decision, or nil. Throws where the reference throws (a null response or context).
    public static func approvalOf(_ resp: JSONValue?) throws -> JSONValue? {
        guard has(resp, "context") else { _ = try prop(resp, "context"); return nil }
        guard let p = try prop(try prop(resp, "context"), PCA_APPROVAL_KEY), rec(p), p.get("approval_required") == .bool(true), str(p.get("auth_req_id")) else { return nil }
        let tier: Int64 = num(p.get("tier")) == 3 ? 3 : 2
        let rt = p.get("required_threshold")
        return obj([
            "approval_required": .bool(true),
            "auth_req_id": p.get("auth_req_id"),
            "tier": .int(tier),
            "required_threshold": isRequiredThreshold(rt) ? rt : JSONValue?.some(obj(["t": .int(tier), "proof": .string(tier == 3 ? "strong" : "standard"), "optimisticAllowed": .bool(false)])),
            "goal_commit": str(p.get("goal_commit")) ? p.get("goal_commit") : JSONValue.string(""),
            "risk": num(p.get("risk")) != nil ? p.get("risk") : JSONValue.int(1),
            "reason": str(p.get("reason")) ? p.get("reason") : JSONValue.string("approval required"),
            "requested_at": num(p.get("requested_at")) != nil ? p.get("requested_at") : JSONValue.int(0),
        ])
    }

    public static func isApprovalRequired(_ resp: JSONValue?) throws -> Bool { try approvalOf(resp) != nil }

    // MARK: mapping

    static func deny(_ reason: String, id: String? = nil, status: Int64? = nil) -> JSONValue {
        obj(["decision": .bool(false), "context": denyContext(reason, id: id, status: status)])
    }

    static func denyContext(_ reason: String, id: String? = nil, status: Int64? = nil) -> JSONValue {
        obj([
            "reason_admin": obj(["denied": .bool(true), "reason": .string(reason)]),
            "reason_user": obj(["message": .string(reason)]),
            "error": status.map { obj(["status": .int($0), "message": .string(reason)]) },
            "id": id.map { JSONValue.string($0) },
        ])
    }

    static func permit(_ reason: String) -> JSONValue {
        obj(["decision": .bool(true), "context": obj(["reason_admin": obj(["reason": .string(reason)])])])
    }

    /// verb = action.name; resource = "type:id" (just the type when id is empty); params = resource.properties overlaid by
    /// action.properties; subject = subject.properties; env = context minus the PCA keys.
    public static func defaultToAction(_ req: JSONValue) throws -> JSONValue {
        let res = req.get("resource")
        let act = req.get("action")
        let idv = try prop(res, "id")
        // `id.length > 0`: only a string (or array) has a length; undefined throws
        guard let id = idv else { throw JSError("Cannot read properties of undefined (reading 'length')") }
        if case .null = id { throw JSError("Cannot read properties of null (reading 'length')") }
        let hasLen: Bool
        switch id {
        case let .string(s): hasLen = !s.isEmpty
        case let .array(a): hasLen = !a.isEmpty
        default: hasLen = false
        }
        let type = res?.get("type")
        let resource: JSONValue? = hasLen ? .string(JS.toString(type) + ":" + JS.toString(id)) : type
        var params: JObject = [:]
        let actProps = try prop(act, "properties")
        for props in [res?.get("properties"), actProps] {
            if case let .object(o)? = props { for (k, v) in o { params[k] = v } }
        }
        var out: JObject = [:]
        out["verb"] = act?.get("name")
        out["resource"] = resource
        out["params"] = .object(params)
        let fromAction = actProps, ctx = req.get("context")
        if rec(fromAction), let r = fromAction?.get("reversibility_class"), str(r) {
            out["reversibilityClass"] = r
        } else if rec(ctx), let r = ctx?.get("reversibility_class"), str(r) {
            out["reversibilityClass"] = r
        }
        if let sp = try prop(req.get("subject"), "properties"), rec(sp) { out["subject"] = sp }
        if case let .object(c)? = ctx {
            var env: JObject = [:]
            for (k, v) in c where k.s != PCA_ACTION_KEY && k.s != PCA_APPROVAL_KEY { env[k] = v }
            if !env.isEmpty { out["env"] = .object(env) }
        }
        return .object(out)
    }

    enum Carried { case none, malformed, value(JSONValue) }

    /// The forwarded PCActn (compact JSON text in the context), absent, or malformed.
    static func pcactnFromContext(_ context: JSONValue?) -> Carried {
        guard rec(context), let raw = JS.present(context?.get(PCA_ACTION_KEY)) else { return .none }
        guard let s = raw.asString, s.utf8.count <= PCA.MAX_ARTIFACT_BYTES, let v = try? StrictJSON.parse(s), v.isObject else { return .malformed }
        return .value(v)
    }

    static func freshBudget(_ grant: JSONValue?, _ now: Int64) -> JSONValue {
        let bMax = grant.flatMap { PCA.readEnvelope($0) }?.get("risk_policy")?.get("bMax")
        return obj(["B": num(bMax) != nil ? bMax : JSONValue.int(0), "tau": .int(now), "asOf": .int(now)])
    }

    static func approvalRequired(_ p: JSONValue, _ decision: JSONValue, _ grant: JSONValue?, _ now: Int64) -> JSONValue {
        let rt = decision.get("requiredThreshold")
        let tier: Int64 = (num(rt?.get("t")) ?? 0) >= 3 ? 3 : 2
        let reasons = decision.get("reasons")
        let reason: JSONValue = reasons?.asArray?.first ?? JSONValue.string("requires tier-\(tier) co-sign")
        let act = p.get("action")
        let id = Canonical.hashCanonical(obj([
            "d": .string("atlas-pca/authzen/aarp/v1"), "verb": act?.get("verb"), "resource": act?.get("resource"),
            "params_digest": act?.get("params_digest"), "at": .int(now), "counter": p.get("counter"),
        ]))
        let env = grant.flatMap { PCA.readEnvelope($0) }
        return obj(["decision": .bool(false), "context": obj([
            "id": .string(id),
            "reason_admin": obj(["stage": .string("step_up"), "risk": decision.get("r"), "threshold": rt, "reasons": reasons]),
            "reason_user": obj(["message": .string("approval required before this action can proceed")]),
            PCA_APPROVAL_KEY: obj(["approval_required": .bool(true), "auth_req_id": .string(id), "tier": .int(tier), "required_threshold": rt,
                                   "goal_commit": env?.get("goal_commit") ?? .string(""), "risk": decision.get("r"), "reason": reason,
                                   "requested_at": .int(now)]),
        ])])
    }

    static func mergeEvaluation(_ defaults: JSONValue, _ item: JSONValue) throws -> JSONValue? {
        if item == .null { throw JSError("Cannot read properties of null (reading 'subject')") }
        func pick(_ k: String) -> JSONValue? { JS.present(item.get(k)) ?? defaults.get(k) }
        let s = pick("subject"), a = pick("action"), r = pick("resource")
        guard isAuthzenSubject(s), isAuthzenAction(a), isAuthzenResource(r) else { return nil }
        var ctx: JSONValue?
        if let c = JS.present(item.get("context")) { ctx = c } else if has(defaults, "context") { ctx = defaults.get("context") }
        return obj(["subject": s, "action": a, "resource": r, "context": ctx])
    }

    static func missing(_ name: String) -> JSError { JSError("authzen: config.\(name) is not provided (fail closed)") }

    // MARK: PDP

    /// One Access Evaluation.
    public static func evaluate(_ c: PCAAuthzenConfig, _ reqIn: JSONValue?) -> JSONValue {
        let now = c.now()
        let req = reqIn ?? .null
        do {
            guard let ctx = JS.present(try c.resolve(req)) else { return deny("no PCA authority resolved for this request") }
            let mapped = try (c.toAction ?? defaultToAction)(req)
            let carried = pcactnFromContext(req.get("context"))
            let p: JSONValue
            switch carried {
            case .malformed: return deny("context carries a malformed PCActn")
            case .none:
                if c.requireProof { return deny("a signed PCActn is required (requireProof)") }
                let admits = c.admitsConcrete ?? { try PCAAnalyzer.admitsConcrete($0, $1) }
                return try admits(ctx.get("policy") ?? .null, mapped) ? permit("statically admissible under the declared authority")
                    : deny("action is not admissible under the declared authority")
            case let .value(v): p = v
            }
            if c.requireAuthorizer && c.authorizer == nil { return deny("no replay/revocation authorizer is configured (requireAuthorizer)") }
            // the proof must be FOR this request: verb + resource, and the attributes must hash to the signed params_digest
            _ = try prop(p.get("action"), "verb") // a missing or null action throws like the reference
            let act = p.get("action")!
            guard let verb = act.get("verb"), verb == mapped.get("verb"), let resource = act.get("resource"), resource == mapped.get("resource") else {
                return deny("the PCActn authorizes \(js(act, "verb")) on \(js(act, "resource")), not the requested \(js(mapped, "verb")) on \(js(mapped, "resource"))")
            }
            let reqParams: JSONValue = rec(mapped.get("params")) ? mapped.get("params")! : .object([:])
            guard let pd = act.get("params_digest"), pd == .string(Merkle.paramsDigest(reqParams)) else {
                return deny("the request attributes do not match the PCActn's signed params_digest")
            }
            let enforce = ctx.get("enforce")
            for k in ["attestation", "taint", "freshness"] where JS.present(enforce?.get(k)) != nil {
                throw JSError("authzen: enforce.\(k) is not supported by this verifier (fail closed)")
            }
            let verify = PCA.verify(pcactn: p, grant: ctx.get("grant") ?? .null, now: now, audience: c.audience, authorizedPlanRoots: c.authorizedPlanRoots,
                                    insecureSkipPlanRootCheck: c.insecureSkipPlanRootCheck)
            guard verify.allow else {
                var checks: JObject = [:]
                for (k, v) in verify.checks { checks[JKey(k)] = .bool(v) }
                return obj(["decision": .bool(false), "context": obj([
                    "reason_admin": obj(["denied": .bool(true), "stage": .string("verify"), "checks": .object(checks),
                                         "reason": .string(verify.reason.isEmpty ? "PCActn verification failed" : verify.reason)]),
                    "reason_user": obj(["message": .string("the proof-carrying action did not verify")])])])
            }
            let grant = ctx.get("grant")
            var dctx: [String: JSONValue?] = [
                "grant": grant, "chain": JS.present(ctx.get("chain")) ?? p.get("cap_chain"), "params": reqParams,
                "risk": JS.present(ctx.get("risk")) ?? .object([:]), "budget": JS.present(ctx.get("budget")) ?? freshBudget(grant, now), "now": .int(now),
            ]
            if let v = JS.present(ctx.get("plan")) { dctx["plan"] = v }
            if let v = JS.present(mapped.get("subject")) { dctx["subject"] = v }
            if let v = JS.present(mapped.get("env")) { dctx["env"] = v }
            let derive = c.deriveDecideInput ?? { try PCAPolicyVm.deriveDecideInput($0, $1) }
            let decideFn = c.decide ?? { try PCAPolicyVm.decide($0) }
            let decision = try decideFn(try derive(p, obj(dctx)))
            guard JS.truthy(decision.get("releaseGuardianShare")) else {
                return obj(["decision": .bool(false), "context": obj([
                    "reason_admin": obj(["denied": .bool(true), "stage": .string("policy"), "reasons": decision.get("reasons"), "risk": decision.get("r")]),
                    "reason_user": obj(["message": .string("the policy does not permit this action")])])])
            }
            guard JS.truthy(decision.get("admit")) else { return approvalRequired(p, decision, grant, now) }
            if let authorizer = c.authorizer {
                var ain: [String: JSONValue?] = ["operation": obj(["verb": mapped.get("verb"), "resource": mapped.get("resource"), "params": reqParams]), "pcactn": p]
                if let rc = req.get("context"), rec(rc), let prov = rc.get(PCA_PROVENANCE_KEY) { ain["provenance"] = prov }
                let az = try authorizer(obj(ain))
                if !JS.truthy(az.get("allow")) {
                    return obj(["decision": .bool(false), "context": obj([
                        "reason_admin": obj(["denied": .bool(true), "stage": .string("authorize"), "reason": az.get("reason")]),
                        "reason_user": obj(["message": .string("the proof-carrying action was not authorized")])])])
                }
            }
            return obj(["decision": .bool(true), "context": obj(["reason_admin": obj(["stage": .string("policy"), "risk": decision.get("r"), "threshold": decision.get("requiredThreshold")])])])
        } catch { // fail closed
            return deny("evaluation error (fail closed): \(message(error))", status: 500)
        }
    }

    /// The Access Evaluations boxcar (execute_all, deny_on_first_deny, permit_on_first_permit). Throws where the reference throws
    /// (a null request, a null item).
    public static func evaluations(_ c: PCAAuthzenConfig, _ req: JSONValue?) throws -> JSONValue {
        guard let items = try prop(req, "evaluations")?.asArray else { return obj(["evaluations": .array([])]) }
        let opts = try prop(req, "options")
        let semantic = JS.present(rec(opts) ? opts?.get("evaluations_semantic") : nil) ?? .string("execute_all")
        func refuse(_ reason: String) -> JSONValue { obj(["evaluations": .array(items.map { _ in deny(reason, status: 400) })]) }
        guard let sem = semantic.asString, ["execute_all", "deny_on_first_deny", "permit_on_first_permit"].contains(sem) else { return refuse("unsupported evaluations_semantic") }
        let mx = c.maxEvaluations
        if let m = num(mx), Double(items.count) > m { return refuse("too many evaluations (limit \(JS.toString(mx)))") }
        let reqV = req ?? .null
        let merged = try items.map { try mergeEvaluation(reqV, $0) }
        var out: [JSONValue] = []
        for m in merged {
            let r = m.map { evaluate(c, $0) } ?? deny("incomplete evaluation (missing subject/action/resource)", status: 400)
            out.append(r)
            let d = r.get("decision")
            if (sem == "deny_on_first_deny" && d == .bool(false)) || (sem == "permit_on_first_permit" && d == .bool(true)) { break }
        }
        return obj(["evaluations": .array(out)])
    }

    /// The COAZ MCP-tool profile: the tool maps to a capability (config `toolCapability`, default the tool name).
    public static func evaluateTool(_ c: PCAAuthzenConfig, _ req: JSONValue?) throws -> JSONValue {
        let tool = try prop(req, "tool")
        let name = try prop(tool, "name")
        let capability: JSONValue?
        do { capability = try c.toolCapability.map { try $0(name ?? .null) } ?? name } catch { // fail closed
            return obj(["decision": .bool(false), "tool": name, "required_capability": .string(""),
                        "context": denyContext("evaluation error (fail closed): \(message(error))", status: 500)])
        }
        let mapped = obj([
            "subject": req?.get("subject"),
            "action": obj(["name": capability, "properties": has(tool, "arguments") ? tool?.get("arguments") : nil]),
            "resource": obj(["type": .string("mcp_tool"), "id": name]),
            "context": has(req, "context") ? req?.get("context") : nil,
        ])
        let resp = evaluate(c, mapped)
        return obj(["decision": resp.get("decision"), "tool": name, "required_capability": capability, "context": resp.get("context")])
    }

    // MARK: handler

    /// handler({path, body}) -> {status, body}. A malformed body is a 400; any thrown error is a 500 with no detail.
    public static func handler(_ c: PCAAuthzenConfig) -> (JSONValue?) -> JSONValue {
        return { req in
            func out(_ status: Int64, _ body: JSONValue) -> JSONValue { obj(["status": .int(status), "body": body]) }
            func bad(_ m: String) -> JSONValue { out(400, obj(["error": .string(m)])) }
            do {
                let path = try prop(req, "path"), body = req?.get("body")
                if path == .string(EVALUATION_PATH) {
                    return isAccessEvaluationRequest(body) ? out(200, evaluate(c, body)) : bad("invalid AuthZEN Access Evaluation request")
                }
                if path == .string(EVALUATIONS_PATH) {
                    // an absent or empty `evaluations` array is a plain single Access Evaluation
                    if rec(body), !has(body, "evaluations") || body?.get("evaluations") == .array([]) {
                        return isAccessEvaluationRequest(body) ? out(200, evaluate(c, body)) : bad("invalid AuthZEN Access Evaluations request")
                    }
                    return isAccessEvaluationsRequest(body) ? out(200, try evaluations(c, body)) : bad("invalid AuthZEN Access Evaluations request")
                }
                if path == .string(COAZ_TOOL_PATH) {
                    return isCoazToolAuthorizationRequest(body) ? out(200, try evaluateTool(c, body)) : bad("invalid COAZ MCP-tool authorization request")
                }
                return out(404, obj(["error": .string("unknown AuthZEN path: " + js(req, "path"))]))
            } catch { // a PEP treats non-200 as a deny; never leak internals
                return out(500, obj(["error": .string("internal error")]))
            }
        }
    }

    // MARK: search

    static func entity(_ x: JSONValue?, _ needId: Bool) -> Bool {
        rec(x) && nonEmpty(x?.get("type")) && (!needId || nonEmpty(x?.get("id"))) && (!has(x, "properties") || rec(x?.get("properties")))
    }

    static func action(_ x: JSONValue?) -> Bool { rec(x) && nonEmpty(x?.get("name")) && (!has(x, "properties") || rec(x?.get("properties"))) }

    static func pageOk(_ b: JSONValue?) -> Bool {
        guard has(b, "page") else { return true }
        let p = b?.get("page")
        guard rec(p) else { return false }
        if has(p, "token"), !str(p?.get("token")) { return false }
        if has(p, "limit") {
            guard let l = p?.get("limit"), l.safeInt.map({ $0 >= 0 }) == true else { return false }
            if case let .double(d) = l, d == 0, d.sign == .minus { return false }
        }
        return !has(p, "properties") || rec(p?.get("properties"))
    }

    static func base(_ b: JSONValue?) -> Bool { (!has(b, "context") || rec(b?.get("context"))) && pageOk(b) }

    public static func isSubjectSearch(_ b: JSONValue?) -> Bool {
        rec(b) && base(b) && entity(b?.get("subject"), false) && action(b?.get("action")) && entity(b?.get("resource"), true)
    }
    public static func isResourceSearch(_ b: JSONValue?) -> Bool {
        rec(b) && base(b) && entity(b?.get("subject"), true) && action(b?.get("action")) && entity(b?.get("resource"), false)
    }
    public static func isActionSearch(_ b: JSONValue?) -> Bool {
        rec(b) && base(b) && !has(b, "action") && entity(b?.get("subject"), true) && entity(b?.get("resource"), true)
    }

    /// Fragment for `/.well-known/authzen-configuration`; a missing endpoint means that search is unsupported.
    public static func searchMetadata(_ base: String, _ p: PCAAuthzenSearchProvider) -> JSONValue {
        obj(["search_subject_endpoint": p.searchSubject == nil ? nil : .string(base + SEARCH_SUBJECT_PATH),
             "search_resource_endpoint": p.searchResource == nil ? nil : .string(base + SEARCH_RESOURCE_PATH),
             "search_action_endpoint": p.searchAction == nil ? nil : .string(base + SEARCH_ACTION_PATH)])
    }

    /// The queried entity's `id` is ignored if present (spec); strip it so a provider cannot be steered by it.
    static func stripId(_ req: JSONValue, _ key: String) -> JSONValue {
        guard case var .object(o) = req else { return req }
        var e = req.get(key)?.asObject ?? [:]
        e["id"] = nil
        o[JKey(key)] = .object(e)
        return .object(o)
    }

    static func shape(_ r: JSONValue?, _ limit: JSONValue?, _ typeOk: (JSONValue) throws -> Bool) throws -> JSONValue {
        guard let input = try prop(r, "results")?.asArray else { throw JSError("results.filter is not a function") }
        var seen = Set<String>()
        var results: [JSONValue] = []
        for t in input {
            guard try typeOk(t) else { continue }
            guard seen.insert(JS.stringify(t)).inserted else { continue }
            results.append(t)
        }
        let capped: [JSONValue]
        if let l = num(limit), l > 0 { capped = Array(results.prefix(l >= Double(results.count) ? results.count : Int(l))) } else { capped = results }
        // a provider that ignores the limit would hide results behind a page marker we cannot resume: fail closed
        if capped.count < results.count { throw JSError("provider returned more than the page limit") }
        var out: JObject = [:]
        if let pg = r?.get("page"), JS.truthy(pg) {
            out["page"] = obj(["next_token": pg.get("next_token"), "count": .int(Int64(capped.count)), "total": pg.get("total"),
                               "properties": JS.truthy(pg.get("properties")) ? pg.get("properties") : nil])
        }
        if let cx = r?.get("context"), JS.truthy(cx) { out["context"] = cx }
        out["results"] = .array(capped)
        return .object(out)
    }

    /// The search handler; nil for a path that is not a search path (so it chains after `handler`).
    public static func searchHandler(_ p: PCAAuthzenSearchProvider) -> (JSONValue?) -> JSONValue? {
        return { req in
            func out(_ status: Int64, _ body: JSONValue) -> JSONValue { obj(["status": .int(status), "body": body]) }
            do {
                let path = try prop(req, "path"), body = req?.get("body")
                let routes: [(String, String?, ((JSONValue) throws -> JSONValue)?, (JSONValue?) -> Bool)] = [
                    (SEARCH_SUBJECT_PATH, "subject", p.searchSubject, isSubjectSearch),
                    (SEARCH_RESOURCE_PATH, "resource", p.searchResource, isResourceSearch),
                    (SEARCH_ACTION_PATH, nil, p.searchAction, isActionSearch),
                ]
                for (route, key, fn, valid) in routes where path == .string(route) {
                    let what = key ?? "action"
                    guard let provFn = fn else { return out(404, obj(["error": .string("\(what) search is not supported")])) }
                    guard valid(body), let b = body else { return out(400, obj(["error": .string("invalid AuthZEN \(what) search request")])) }
                    let res = try provFn(key.map { stripId(b, $0) } ?? b)
                    let limit = has(b, "page") ? b.get("page")?.get("limit") : nil
                    let want = key.flatMap { b.get($0)?.get("type") }
                    return out(200, try shape(res, limit) { e in
                        if key == nil { return true }
                        return try prop(e, "type") == want
                    })
                }
                return nil
            } catch {
                return out(500, obj(["error": .string("internal error")]))
            }
        }
    }
}
