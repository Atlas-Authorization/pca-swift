import Foundation

/// Grant management resource of `pca-grants` (grant-resource.ts): list / inspect / amend / revoke and incremental authorization for principals.
/// Nothing widens in place: a widening merge or replace needs a fresh principal signature and a satisfied step-up and creates a NEW grant id with
/// `supersedes`. The pure decisions (`K3.verifyAmendment`, `K3.verifyRevokeSignature`, `K3.verifyNeedApproval`, `K3.compareAuthority`,
/// `K3.authorityDigest`) are carried by `K3`; this enum holds the message builders, the store and the service. A grant record is
/// `{id, principal, agent, parent?, status, authority, rev, chain_digest, supersedes?, superseded_by?, adjustable?, created_at, history[]}`; a need
/// request is `{id, grant_id, needs[], status, created_at, result_grant_id?}`.
public enum GrantResource {
    public static let GRANT_AMEND_DOMAIN = K3.GRANT_AMEND_DOMAIN
    public static let GRANT_REVOKE_DOMAIN = K3.GRANT_REVOKE_DOMAIN
    public static let NEED_APPROVE_DOMAIN = K3.NEED_APPROVE_DOMAIN
    public static let NEED_REQUEST_DOMAIN = "atlas-pca/need-request/v1\u{0}"
    public static let GRANT_STEPUP_DOMAIN = "atlas-pca/grant-stepup/v1\u{0}"

    // ---- signed messages ----

    /// The body an amendment signature covers: `{grant, rev, action, authority: digest}`.
    public static func amendMessage(_ g: JObject, action: String, authority: JSONValue?) throws -> JSONValue {
        guard let d = K3.authorityDigest(authority) else { throw PCAProducerError("amendMessage: malformed authority") }
        var m: JObject = ["action": .string(action), "authority": .string(d)]
        if let id = g["id"] { m["grant"] = id }
        if let r = g["rev"] { m["rev"] = r }
        return .object(m)
    }

    public static func needRequestMessage(_ grantId: String, rev: JSONValue?, needs: JSONValue?) -> JSONValue {
        var m: JObject = ["grant": .string(grantId)]
        if let r = rev { m["rev"] = r }
        if let n = needs { m["needs"] = n }
        return .object(m)
    }

    public static func stepUpMessage(_ grantId: String, challengeId: String, nonce: String) -> JSONValue {
        .object(["grant": .string(grantId), "challenge": .string(challengeId), "nonce": .string(nonce)])
    }

    public static func grantRevokeMessage(_ id: String, scope: String) -> JSONValue { .object(["grant": .string(id), "scope": .string(scope)]) }

    public static func needApproveMessage(_ nr: JObject, rev: JSONValue?, approved: JSONValue?) -> JSONValue {
        var m: JObject = [:]
        if let id = nr["id"] { m["need"] = id }
        if let g = nr["grant_id"] { m["grant"] = g }
        if let r = rev { m["rev"] = r }
        if let a = approved { m["approved"] = a }
        return .object(m)
    }

    public static func signGrantBody(_ domain: String, _ body: JSONValue, _ secret: PCAEdKey) throws -> String { try PCAGrants.signBody(domain, body, secret) }

    public struct GrantError: Error, CustomStringConvertible {
        /// not_found conflict bad_request not_narrower signature_required bad_signature step_up_required not_active need_not_lowered_only need_not_adjustable forbidden
        public let code: String
        public let message: String?
        public var description: String { message ?? code }
        public init(_ code: String, _ message: String?) { self.code = code; self.message = message }
    }

    /// Persistence of grants and need requests. Records are values: what a caller gets back is its own copy.
    public protocol GrantStore: Sendable {
        func get(_ id: String) throws -> JObject?
        func put(_ g: JObject) throws
        func list() throws -> [JObject]
        func getNeed(_ id: String) throws -> JObject?
        func putNeed(_ n: JObject) throws
        func listNeeds(_ grantId: String) throws -> [JObject]
    }

    /// A deep copy through the strict canonical form (numbers normalized like the reference's structuredClone of parsed JSON).
    static func norm(_ o: JObject) throws -> JObject {
        guard let c = IV.strictCanon(.object(o)), let p = try? StrictJSON.parseLenient(c), let r = p.asObject else { throw PCAProducerError("grant record is not strict-canonical JSON") }
        return r
    }

    public final class MemoryGrantStore: GrantStore, @unchecked Sendable {
        private var g: [(String, JObject)] = []
        private var n: [(String, JObject)] = []
        private let lock = PCALock()
        public init() {}

        private func upsert(_ l: inout [(String, JObject)], _ id: String, _ v: JObject) {
            if let i = l.firstIndex(where: { IV.same($0.0, id) }) { l[i].1 = v } else { l.append((id, v)) }
        }

        public func get(_ id: String) throws -> JObject? { lock.lock(); defer { lock.unlock() }; return try g.first { IV.same($0.0, id) }.map { try GrantResource.norm($0.1) } }
        public func put(_ rec: JObject) throws {
            guard let id = rec["id"]?.asString else { throw GrantError("bad_request", "a grant needs an id") }
            let c = try GrantResource.norm(rec)
            lock.lock(); defer { lock.unlock() }
            upsert(&g, id, c)
        }
        public func list() throws -> [JObject] { lock.lock(); defer { lock.unlock() }; return try g.map { try GrantResource.norm($0.1) } }
        public func getNeed(_ id: String) throws -> JObject? { lock.lock(); defer { lock.unlock() }; return try n.first { IV.same($0.0, id) }.map { try GrantResource.norm($0.1) } }
        public func putNeed(_ rec: JObject) throws {
            guard let id = rec["id"]?.asString else { throw GrantError("bad_request", "a need request needs an id") }
            let c = try GrantResource.norm(rec)
            lock.lock(); defer { lock.unlock() }
            upsert(&n, id, c)
        }
        public func listNeeds(_ grantId: String) throws -> [JObject] {
            lock.lock(); defer { lock.unlock() }
            return try n.filter { $0.1["grant_id"]?.asString.map { IV.same($0, grantId) } ?? false }.map { try GrantResource.norm($0.1) }
        }
    }

    /// Hooks and providers. Every member except `store`, `now` and `newId` may be nil.
    public struct Options {
        public var store: GrantStore
        public var now: () -> Int64
        /// kind is `grant` or `need`.
        public var newId: (String) -> String
        public var usage: ((JObject) -> JSONValue?)?
        public var remainingBudget: ((JObject) -> JSONValue?)?
        public var policyCard: ((JObject) -> JSONValue?)?
        public var residual: ((JObject) -> JSONValue?)?
        /// Confirms a satisfied step-up for a widening change. Absent: widening is refused (fail closed).
        public var verifyStepUp: ((String, JObject) -> Bool)?
        public var onRevoke: (([String], String, JObject) -> Void)?
        /// kind: amend | revoke | supersede | need.
        public var onChange: ((String, JObject) -> Void)?
        /// Typed validation of a need: an error string refuses.
        public var validateNeed: ((JObject) -> String?)?
        public init(store: GrantStore, now: @escaping () -> Int64, newId: @escaping (String) -> String) { self.store = store; self.now = now; self.newId = newId }
    }

    static let FAIL_MESSAGE: [String: String] = [
        "not_found": "no such grant",
        "conflict": "conflict",
        "bad_request": "malformed request",
        "not_narrower": "a narrow amendment must be strictly narrower",
        "signature_required": "the amendment is signed (by the principal when it widens)",
        "bad_signature": "the signature does not verify for this grant revision",
        "step_up_required": "widening needs a satisfied step-up",
        "not_active": "grant is not active",
        "need_not_lowered_only": "an approval may only lower amounts of the requested needs",
        "need_not_adjustable": "the need is not adjustable",
        "forbidden": "not authorised",
    ]

    /// List filter: any member may be nil.
    public struct ListFilter {
        public var principal: String?, agent: String?, status: String?, limit: Int64?, cursor: String?
        public init(principal: String? = nil, agent: String? = nil, status: String? = nil, limit: Int64? = nil, cursor: String? = nil) {
            self.principal = principal; self.agent = agent; self.status = status; self.limit = limit; self.cursor = cursor
        }
    }

    private static func less(_ a: String, _ b: String) -> Bool { a.utf16.lexicographicallyPrecedes(b.utf16) }

    public final class GrantService: @unchecked Sendable {
        private let o: Options
        public init(_ options: Options) { self.o = options }

        private func hist(_ rev: Int64, _ authority: JSONValue?, _ at: Int64, _ action: String?) throws -> JSONValue {
            guard let d = K3.authorityDigest(authority) else { throw GrantError("bad_request", "malformed authority") }
            var m: JObject = ["rev": .int(rev), "authority_digest": .string(d), "at": .int(at)]
            if let a = action { m["action"] = .string(a) }
            return .object(m)
        }

        private func checkAuthority(_ a: JSONValue?) throws {
            guard K3.Authority(a) != nil else { throw GrantError("bad_request", "malformed authority") }
        }

        private func must(_ id: String) throws -> JObject {
            guard let g = try o.store.get(id) else { throw GrantError("not_found", "no such grant") }
            return g
        }

        private func pushHistory(_ g: inout JObject, _ h: JSONValue) {
            g["history"] = .array((g["history"]?.asArray ?? []) + [h])
        }

        /// Create a grant record: `{id, principal, agent, parent?, authority, chain_digest, ...}` (status optional, default active).
        @discardableResult
        public func register(_ g: JObject) throws -> JObject {
            try checkAuthority(g["authority"])
            guard let id = g["id"]?.asString else { throw GrantError("bad_request", "a grant needs an id") }
            if try o.store.get(id) != nil { throw GrantError("conflict", "grant id exists") }
            let now = o.now()
            var rec = g
            if let s = g["status"], !s.isNull { rec["status"] = s } else { rec["status"] = .string("active") }
            rec["rev"] = .int(1)
            rec["created_at"] = .int(now)
            rec["history"] = .array([try hist(1, g["authority"], now, "create")])
            try o.store.put(rec)
            return rec
        }

        public func list(_ f: ListFilter = ListFilter()) throws -> JObject {
            let limit = min(max(f.limit ?? 50, 1), 200)
            let all = try o.store.list().filter { g in
                (f.principal == nil || K3Sig.eq(g["principal"]?.asString, f.principal!)) && (f.agent == nil || K3Sig.eq(g["agent"]?.asString, f.agent!))
                    && (f.status == nil || K3Sig.eq(g["status"]?.asString, f.status!))
            }.sorted { less($0["id"]?.asString ?? "", $1["id"]?.asString ?? "") }
            let filtered = all.filter { f.cursor == nil || less(f.cursor!, $0["id"]?.asString ?? "") }
            let page = Array(filtered.prefix(Int(limit)))
            var out: JObject = ["grants": .array(try page.map { .object(try view($0, rich: false)) })]
            if Int64(filtered.count) > limit, let last = page.last?["id"] { out["next_cursor"] = last }
            return out
        }

        public func inspect(_ id: String) throws -> JObject { try view(try must(id), rich: true) }

        private func view(_ g: JObject, rich: Bool) throws -> JObject {
            var v = g
            v["history"] = nil
            v["authority_digest"] = .string(K3.authorityDigest(g["authority"]) ?? "")
            let id = g["id"]?.asString ?? ""
            v["pending_needs"] = .array(try o.store.listNeeds(id).filter { $0["status"]?.asString == "pending" }.compactMap { $0["id"] })
            if rich {
                if let r = o.usage?(g) { v["usage"] = r }
                if let r = o.remainingBudget?(g) { v["remaining_budget"] = r }
                if let r = o.policyCard?(g) { v["policy_card"] = r }
                if let r = o.residual?(g) { v["residual"] = r }
            }
            return v
        }

        /// The grant that replaces `cur` for a widening change: a fresh id, `supersedes` set, history restarted. The caller stores it and the
        /// superseded `cur`.
        private func superseding(_ cur: inout JObject, _ nid: String, _ authority: JSONValue, _ now: Int64, _ action: String) throws -> JObject {
            var fresh = cur
            fresh["id"] = .string(nid)
            fresh["authority"] = authority
            fresh["rev"] = .int(1)
            fresh["status"] = .string("active")
            fresh["supersedes"] = cur["id"]
            fresh["created_at"] = .int(now)
            fresh["history"] = .array([try hist(1, authority, now, action)])
            fresh["superseded_by"] = nil
            cur["status"] = .string("superseded")
            cur["superseded_by"] = .string(nid)
            return fresh
        }

        /// Amend; returns `{grant, created}`. `req` = `{action, authority, sig?, signed_by?, step_up_ref?}`.
        public func amend(_ id: String, _ req: JObject) throws -> JObject {
            var cur = try must(id)
            var v = K3.verifyAmendment(.object(cur), .object(req), stepUpOk: false)
            // Evaluate the (possibly consuming) step-up only when everything else already passed.
            if !v.ok, v.code == "step_up_required", let ref = req["step_up_ref"], JS.truthy(ref), let su = o.verifyStepUp, su(JS.toString(ref), cur) {
                v = K3.verifyAmendment(.object(cur), .object(req), stepUpOk: true)
            }
            if !v.ok { throw GrantError(v.code, Self.msg(v.code)) }
            // The verdict carries the digest of the resulting authority; rebuild it and refuse on any disagreement.
            guard let reqAuth = req["authority"], let ra = K3.Authority(reqAuth), let ca = K3.Authority(cur["authority"]) else { throw GrantError("bad_request", Self.msg("bad_request")) }
            let next: JSONValue = req["action"]?.asString == "merge" ? K3.mergeAuthority(ca, ra).json : reqAuth
            if K3.authorityDigest(next) != v.digest { throw GrantError("bad_request", Self.msg("bad_request")) }
            let now = o.now()
            let action = req["action"]?.asString
            if !v.widens {
                cur["authority"] = next
                let rev = (cur["rev"]?.safeInt ?? 0) + 1
                cur["rev"] = .int(rev)
                pushHistory(&cur, try hist(rev, next, now, action))
                try o.store.put(cur)
                o.onChange?("amend", cur)
                return ["grant": .object(try view(cur, rich: true)), "created": .bool(false)]
            }
            let nid = o.newId("grant")
            let fresh = try superseding(&cur, nid, next, now, "supersedes:" + (cur["id"]?.asString ?? ""))
            try o.store.put(fresh)
            try o.store.put(cur)
            o.onChange?("supersede", fresh)
            return ["grant": .object(try view(fresh, rich: true)), "created": .bool(true)]
        }

        static func msg(_ code: String) -> String? { FAIL_MESSAGE[code] }

        /// Revoke, authorised by the principal's signature over `{grant id, scope}` (`sig` non-nil) or by a host-authenticated admin (`sig` nil and
        /// `admin` true). Returns `{revoked: [ids]}`.
        public func revoke(_ id: String, scope: String, sig: String?, admin: Bool) throws -> JObject {
            guard scope == "grant" || scope == "agent" || scope == "subtree" else { throw GrantError("bad_request", "unknown scope") }
            let root = try must(id)
            if let s = sig {
                let rv = K3.verifyRevokeSignature(.object(root), scope: .string(scope), sig: .string(s))
                if !rv.ok { throw GrantError(rv.code, Self.msg(rv.code)) }
            } else if !admin { throw GrantError("forbidden", "not authorised") }
            let all = try o.store.list()
            var hit: [JObject] = []
            if scope == "grant" {
                hit = [root]
            } else if scope == "agent" {
                hit = all.filter { $0["agent"] == root["agent"] && $0["principal"] == root["principal"] }
            } else {
                var ids: [JSONValue] = [.string(id)]
                var grew = true
                while grew {
                    grew = false
                    for g in all {
                        if let p = g["parent"], !p.isNull, ids.contains(p), let gid = g["id"], !ids.contains(gid) { ids.append(gid); grew = true }
                    }
                }
                hit = all.filter { g in g["id"].map { ids.contains($0) } ?? false }
            }
            var revoked: [String] = []
            for var g in hit {
                if g["status"]?.asString == "revoked" { continue }
                g["status"] = .string("revoked")
                pushHistory(&g, try hist(g["rev"]?.safeInt ?? 0, g["authority"], o.now(), "revoke:" + scope))
                try o.store.put(g)
                if let gid = g["id"]?.asString { revoked.append(gid) }
            }
            o.onRevoke?(revoked, scope, root)
            o.onChange?("revoke", root)
            return ["revoked": .array(revoked.map { .string($0) })]
        }

        private static func limitsOk(_ l: JSONValue?) -> Bool {
            guard let o = l?.asObject else { return false }
            return o.values.allSatisfy { v in IV.num(v).map { $0.isFinite && $0 >= 0 } ?? false }
        }

        /// Agent side: ask for more. Typed needs only; no authority changes until the principal approves.
        public func requestNeeds(_ grantId: String, _ needs: JSONValue?) throws -> JObject {
            let g = try must(grantId)
            if g["status"]?.asString != "active" { throw GrantError("not_active", "grant is \(JS.toString(g["status"]))") }
            guard let list = needs?.asArray, list.count >= 1, list.count <= 32 else { throw GrantError("bad_request", "1..32 needs") }
            for no in list {
                guard let nd = no.asObject, K3Sig.str(nd["verb"], 128) != nil, K3Sig.str(nd["resource"], 512) != nil,
                      nd["limits"] == nil || Self.limitsOk(nd["limits"]) else { throw GrantError("bad_request", "malformed need") }
                if let e = o.validateNeed?(nd), !e.isEmpty { throw GrantError("bad_request", e) }
            }
            let nr: JObject = ["id": .string(o.newId("need")), "grant_id": .string(grantId), "needs": needs ?? .null, "status": .string("pending"), "created_at": .int(o.now())]
            try o.store.putNeed(nr)
            o.onChange?("need", g)
            return nr
        }

        /// The authority a verified approval yields: the grant's authority merged with the approved delta (limits default to 0, never absent).
        private func approvedAuthority(_ g: JObject, _ approved: JSONValue?) throws -> JSONValue {
            var verbs: [String] = [], resources: [String] = []
            var limits: [JKey: Double] = [:]
            for a0 in approved?.asArray ?? [] {
                guard let a = a0.asObject else { continue }
                if let v = a["verb"]?.asString { verbs.append(v) }
                if let r = a["resource"]?.asString { resources.append(r) }
                for (k, v) in a["limits"]?.asObject ?? [:] {
                    if let d = IV.num(v) { limits[k] = max(limits[k] ?? 0, d) }
                }
            }
            guard let ga = K3.Authority(g["authority"]) else { throw GrantError("bad_request", Self.msg("bad_request")) }
            return K3.mergeAuthority(ga, K3.Authority(verbs: verbs, resources: resources, limits: limits, expiresAt: nil)).json
        }

        /// Principal side: approve the delta (a widening merge). Returns `{grant, created}`.
        public func approveNeeds(_ needId: String, approved: JSONValue?, sig: String?, stepUpRef: String? = nil) throws -> JObject {
            guard var nr = try o.store.getNeed(needId) else { throw GrantError("not_found", "no such need request") }
            if nr["status"]?.asString != "pending" { throw GrantError("conflict", "need request is \(JS.toString(nr["status"]))") }
            var g = try must(nr["grant_id"]?.asString ?? "")
            let sigV: JSONValue? = sig.map { .string($0) }
            var v = K3.verifyNeedApproval(.object(nr), grant: .object(g), approved: approved, sig: sigV, stepUpOk: false)
            if !v.ok, v.code == "step_up_required", let ref = stepUpRef, !ref.isEmpty, let su = o.verifyStepUp, su(ref, g) {
                v = K3.verifyNeedApproval(.object(nr), grant: .object(g), approved: approved, sig: sigV, stepUpOk: true)
            }
            if !v.ok { throw GrantError(v.code, Self.msg(v.code)) }
            let authority = try approvedAuthority(g, approved)
            if K3.authorityDigest(authority) != v.digest { throw GrantError("bad_request", Self.msg("bad_request")) }
            let nid = o.newId("grant")
            let now = o.now()
            let fresh = try superseding(&g, nid, authority, now, "needs:" + needId)
            nr["status"] = .string("approved")
            nr["result_grant_id"] = .string(nid)
            try o.store.put(fresh)
            try o.store.put(g)
            try o.store.putNeed(nr)
            o.onChange?("supersede", fresh)
            return ["grant": .object(try view(fresh, rich: true)), "created": .bool(true)]
        }

        /// The grant a need request belongs to.
        public func needGrantId(_ needId: String) throws -> String {
            guard let nr = try o.store.getNeed(needId) else { throw GrantError("not_found", "no such need request") }
            return nr["grant_id"]?.asString ?? ""
        }

        public func denyNeeds(_ needId: String) throws {
            guard var nr = try o.store.getNeed(needId) else { throw GrantError("not_found", "no such need request") }
            if nr["status"]?.asString != "pending" { throw GrantError("conflict", "need request is \(JS.toString(nr["status"]))") }
            nr["status"] = .string("denied")
            try o.store.putNeed(nr)
        }
    }
}
