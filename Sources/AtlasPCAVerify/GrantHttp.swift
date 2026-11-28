import Foundation

/// Framework-neutral HTTP binding of the grant management resource (pca-grants http.ts): plain request and response values, no server dependency.
public enum GrantHttp {
    public static let GRANTS_PATH = "/pca/grants"
    public static let NEEDS_PATH = "/pca/needs"

    /// `path` is the full request path (for example `/pca/grants/g_1/amend`); `body` is a parsed JSON value or nil.
    public struct Request {
        public var method: String
        public var path: String
        public var query: [String: String]
        public var body: JSONValue?
        public init(method: String, path: String, query: [String: String] = [:], body: JSONValue? = nil) { self.method = method; self.path = path; self.query = query; self.body = body }
    }

    public struct Response {
        public var status: Int
        public var body: JSONValue
        public init(_ status: Int, _ body: JSONValue) { self.status = status; self.body = body }
    }

    /// Who is calling, as the host authenticated them. `principal` limits every read and write to that principal's grants.
    public struct Caller {
        public var principal: String?
        public var admin: Bool
        public init(principal: String?, admin: Bool) { self.principal = principal; self.admin = admin }
    }

    public typealias Authenticate = (Request) throws -> Caller?
    public typealias Handler = (Request) -> Response

    static let STATUS: [String: Int] = [
        "not_found": 404, "conflict": 409, "bad_request": 400, "not_narrower": 422,
        "signature_required": 401, "bad_signature": 401, "step_up_required": 403, "not_active": 409,
        "need_not_lowered_only": 422, "need_not_adjustable": 422, "forbidden": 403,
    ]

    static func err(_ e: Error) -> Response {
        if let g = e as? GrantResource.GrantError {
            var m: JObject = ["error": .string(g.code)]
            if let msg = g.message { m["message"] = .string(msg) }
            return Response(STATUS[g.code] ?? 500, .object(m))
        }
        return Response(500, .object(["error": .string("server_error")]))
    }

    static func notFound() -> Response { Response(404, .object(["error": .string("not_found")])) }

    /// Discovery fragment for `/.well-known/pca-configuration`.
    public static func grantManagementMetadata(_ base: String) -> JSONValue {
        .object(["grant_management": .object(["grants_endpoint": .string(base + GRANTS_PATH), "needs_endpoint": .string(base + NEEDS_PATH),
                                              "amend_actions": .array(["narrow", "merge", "replace"].map { .string($0) }),
                                              "revoke_scopes": .array(["grant", "agent", "subtree"].map { .string($0) }),
                                              "widening": .string("new_grant_id_with_supersedes")])])
    }

    static func segments(_ path: String) -> [String] { IV.split(path, "/").filter { !$0.isEmpty } }

    private static func has(_ s: String?) -> Bool { !(s ?? "").isEmpty }

    public static func grantResourceHandler(_ svc: GrantResource.GrantService, authenticate: @escaping Authenticate) -> Handler {
        return { req in
            do {
                guard let who = try authenticate(req), who.admin || has(who.principal) else { return Response(401, .object(["error": .string("unauthenticated")])) }
                let seg = segments(req.path)
                let q = req.query
                let b: JObject = req.body?.asObject ?? [:]
                if seg.isEmpty || seg[0] != "pca" { return notFound() }
                let s1 = seg.count > 1 ? seg[1] : nil, s2 = seg.count > 2 ? seg[2] : nil, s3 = seg.count > 3 ? seg[3] : nil
                if s1 == "grants" {
                    if seg.count == 2 && req.method == "GET" {
                        let status = q["status"]
                        if let s = status, s != "active", s != "revoked", s != "superseded" { throw GrantResource.GrantError("bad_request", "bad status") }
                        let principal = who.admin ? q["principal"] : who.principal
                        var limit: Int64?
                        if let l = q["limit"] {
                            let d = IV.jsNumber(l)
                            if d.isFinite { limit = d >= 9.2e18 ? Int64.max : d <= -9.2e18 ? Int64.min : Int64(d) } // truncates toward zero
                        }
                        let f = GrantResource.ListFilter(principal: has(principal) ? principal : nil, agent: has(q["agent"]) ? q["agent"] : nil,
                                                         status: has(status) ? status : nil, limit: limit, cursor: has(q["cursor"]) ? q["cursor"] : nil)
                        return Response(200, .object(try svc.list(f)))
                    }
                    guard let id = s2 else { return notFound() }
                    let g = try svc.inspect(id)
                    if !who.admin && g["principal"]?.asString != who.principal { throw GrantResource.GrantError("not_found", "no such grant") }
                    if seg.count == 3 && req.method == "GET" { return Response(200, .object(g)) }
                    if seg.count == 3 && req.method == "DELETE" {
                        let scope = q["scope"] ?? "grant"
                        let sig = b["sig"]?.asString
                        // A principal-scoped caller must still sign; only an admin may revoke without a principal signature.
                        let adminNoSig = who.admin && !has(sig)
                        return Response(200, .object(try svc.revoke(id, scope: scope, sig: adminNoSig ? nil : (sig ?? ""), admin: adminNoSig)))
                    }
                    if seg.count == 4 && s3 == "amend" && req.method == "POST" {
                        let r = try svc.amend(id, b)
                        return Response(r["created"] == .bool(true) ? 201 : 200, r["grant"] ?? .null)
                    }
                    if seg.count == 4 && s3 == "needs" && req.method == "POST" { return Response(201, .object(try svc.requestNeeds(id, b["needs"]))) }
                }
                if s1 == "needs", let id = s2, s3 == "approve", req.method == "POST" {
                    try ownNeed(svc, who, id)
                    guard let sig = b["sig"]?.asString, let approved = b["approved"], approved.isArray else { throw GrantResource.GrantError("bad_request", "sig and approved are required") }
                    let r = try svc.approveNeeds(id, approved: approved, sig: sig, stepUpRef: b["step_up_ref"]?.asString)
                    return Response(201, r["grant"] ?? .null)
                }
                if s1 == "needs", let id = s2, s3 == "deny", req.method == "POST" {
                    try ownNeed(svc, who, id)
                    try svc.denyNeeds(id)
                    return Response(200, .object(["status": .string("denied")]))
                }
                return notFound()
            } catch {
                return err(error)
            }
        }
    }

    private static func ownNeed(_ svc: GrantResource.GrantService, _ who: Caller, _ needId: String) throws {
        let g = try svc.inspect(try svc.needGrantId(needId))
        if !who.admin && g["principal"]?.asString != who.principal { throw GrantResource.GrantError("not_found", "no such grant") }
    }
}

/// Hosted lease routes (framework-neutral, same shape as the grant resource; pca-grants lease-http.ts). The server only stores records the lease
/// authority already signed; it never mints one, so a compromised host cannot extend a lease.
///
///     POST /pca/leases             body {lease, chain?}   issue (seq 1) or renew (seq n+1)
///     GET  /pca/leases/:id                                the newest record and its renewal ledger
///     POST /pca/leases/:id/check   body {lease}           is this record a live lease
///     POST /pca/leases/revoke      body {revocation}      a signed revoke by lease, prefix or grant
public enum LeaseHttp {
    public static let LEASES_PATH = "/pca/leases"

    /// Who is calling; a non-admin sees and checks only leases it holds.
    public struct Caller {
        public var admin: Bool
        public var principal: String?
        public init(admin: Bool, principal: String?) { self.admin = admin; self.principal = principal }
    }

    public typealias Authenticate = (GrantHttp.Request) throws -> Caller?

    static let STATUS: [String: Int] = [
        "bad_record": 400, "bad_seq": 409, "stale_seq": 409, "lease_fork": 409, "renewal_mismatch": 422,
        "over_max_ttl": 422, "ttl_ceiling": 422, "not_extending": 422, "stale_justification": 422,
        "expired_lease": 409, "revoked": 409, "sod": 403, "unknown_authority": 403, "store_unreachable": 503,
    ]

    public static func leaseManagementMetadata(_ base: String) -> JSONValue {
        .object(["leases": .object(["leases_endpoint": .string(base + LEASES_PATH), "revoke_targets": .array(["lease", "prefix", "grant"].map { .string($0) })])])
    }

    // a lease belongs to its holder: a non-admin sees and checks only leases it holds
    private static func visible(_ who: Caller, _ lease: JObject) -> Bool { who.admin || who.principal == lease["holder"]?.asString }

    private static func historyJson(_ reg: Lease.Registry, _ id: String) -> JSONValue {
        .array(reg.history(id).map { h in
            .object(["seq": .int(h.seq), "renewed_at": .int(h.renewedAt), "expires_at": .int(h.expiresAt), "justification_digest": .string(h.justificationDigest)])
        })
    }

    private static func obj(_ s: String) -> JSONValue { .object(["error": .string(s)]) }

    /// The lease routes over `reg`. A refused accept carries the registry's own `message` (for `sod` the separation-of-duties rule that failed).
    public static func leaseResourceHandler(_ reg: Lease.Registry, authenticate: @escaping Authenticate, now: (() -> Int64)? = nil) -> GrantHttp.Handler {
        let clock: () -> Int64 = now ?? { Int64(Date().timeIntervalSince1970 * 1000) }
        return { req in
            do {
                guard let who = try authenticate(req), who.admin || !(who.principal ?? "").isEmpty else { return GrantHttp.Response(401, obj("unauthenticated")) }
                let seg = GrantHttp.segments(req.path)
                let b: JObject = req.body?.asObject ?? [:]
                if seg.count < 2 || seg[0] != "pca" || seg[1] != "leases" { return GrantHttp.notFound() }
                if seg.count == 2 && req.method == "POST" {
                    if !who.admin { return GrantHttp.Response(403, obj("forbidden")) }
                    var chain: [String] = []
                    if let c = b["chain"]?.asArray, c.allSatisfy({ $0.asString != nil }) { chain = c.compactMap { $0.asString } }
                    let r = reg.accept(b["lease"], chain: chain)
                    guard let code = r.code else { return GrantHttp.Response(r.replaced ? 201 : 200, .object(["ok": .bool(true), "replaced": .bool(r.replaced), "seq": .int(r.seq)])) }
                    var e: JObject = ["error": .string(code)]
                    if let m = r.reason, !m.isEmpty { e["message"] = .string(m) }
                    return GrantHttp.Response(STATUS[code] ?? 400, .object(e))
                }
                if seg.count == 3 && seg[2] == "revoke" && req.method == "POST" {
                    if !who.admin { return GrantHttp.Response(403, obj("forbidden")) }
                    let r = reg.revoke(b["revocation"])
                    guard let code = r.code else { return GrantHttp.Response(200, .object(["ok": .bool(true), "revoked": .int(Int64(r.revoked))])) }
                    return GrantHttp.Response(code == "store_unreachable" ? 503 : code == "unknown_authority" ? 403 : 400, obj(code))
                }
                guard seg.count > 2 else { return GrantHttp.notFound() }
                let id = seg[2]
                if seg.count == 3 && req.method == "GET" {
                    guard let cur = reg.get(id), visible(who, cur) else { return GrantHttp.notFound() }
                    return GrantHttp.Response(200, .object(["lease": .object(cur), "history": historyJson(reg, id)]))
                }
                if seg.count == 4 && seg[3] == "check" && req.method == "POST" {
                    guard let cur = reg.get(id), visible(who, cur) else { return GrantHttp.notFound() }
                    let d = Lease.checkLease(b["lease"], registry: reg, now: .int(clock()))
                    var body: JObject = ["decision": .string(d.decision)]
                    if let c = d.code { body["code"] = .string(c) }
                    if let l = d.leaseId { body["lease_id"] = .string(l) }
                    if let e = d.expiresAt { body["expires_at"] = .int(e) }
                    return GrantHttp.Response(d.decision == "allow" ? 200 : 403, .object(body))
                }
                return GrantHttp.notFound()
            } catch {
                return GrantHttp.Response(500, obj("server_error"))
            }
        }
    }
}

/// Authority-side lease operations (pca-grants lease.ts renewLease). Verification, the registry and the live check are `Lease`; signing is
/// `PCAGrants.signLease`.
public enum Leases {
    /// Renewal options. `veto` can only REFUSE a renewal, never lengthen the lease. nil members are absent.
    public struct RenewOptions {
        public var now: JSONValue?
        /// Advisory increment from now; the new expiry is capped at issued_at + max_ttl.
        public var increment: JSONValue?
        public var justificationDigest: String?
        public var approvers: JSONValue?
        public var veto: ((JObject) -> Bool)?
        public var chain: [String]?
        public init(now: JSONValue? = nil, increment: JSONValue? = nil, justificationDigest: String? = nil, approvers: JSONValue? = nil,
                    veto: ((JObject) -> Bool)? = nil, chain: [String]? = nil) {
            self.now = now; self.increment = increment; self.justificationDigest = justificationDigest; self.approvers = approvers; self.veto = veto; self.chain = chain
        }
    }

    private static func res(_ ok: Bool, _ code: String?, _ record: JSONValue? = nil) -> JSONValue {
        ok ? .object(["ok": .bool(true), "record": record ?? .null]) : .object(["ok": .bool(false), "code": .string(code ?? "")])
    }

    /// Sign and register the next record of a lease. Returns `{ok: true, record}` or `{ok: false, code}`.
    public static func renewLease(_ secret: PCAEdKey, _ registry: Lease.Registry, _ id: String, _ o: RenewOptions) -> JSONValue {
        guard let now = K3Sig.safeInt(o.now), let inc = K3Sig.safeInt(o.increment), inc >= 1 else { return res(false, "bad_input") }
        guard let cur = registry.get(id) else { return res(false, "unknown_lease") }
        if let v = o.veto, v(cur) { return res(false, "vetoed") }
        let cap = Lease.num(cur, "issued_at") + Lease.num(cur, "max_ttl")
        let expires = min(now + inc, cap)
        var rest = cur
        for k in ["v", "sig", "authority"] { rest[JKey(k)] = nil }
        rest["seq"] = .int(Lease.num(cur, "seq") + 1)
        rest["renewed_at"] = .int(now)
        rest["expires_at"] = .int(expires)
        rest["justification_digest"] = o.justificationDigest.map { .string($0) }
        rest["approvers"] = o.approvers ?? cur["approvers"]
        let record: JSONValue
        do { record = try PCAGrants.signLease(secret, rest) } catch { return res(false, expires <= now ? "expired_lease" : "bad_input") }
        let r = registry.accept(record, chain: o.chain ?? [])
        return r.code == nil ? res(true, nil, record) : res(false, r.code)
    }
}
