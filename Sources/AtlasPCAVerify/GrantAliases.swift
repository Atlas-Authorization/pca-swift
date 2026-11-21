import Foundation

/// The TypeScript export names of `pca-grants` that this SDK carries under another type or module name, so an import by the TS name resolves.
extension PCAGrants {
    public static let DEFAULT_LEASE_SHARDS = Lease.DEFAULT_SHARDS
    public static let MAX_LEASE_SHARDS = Lease.MAX_SHARDS
    public static let GRANT_STEPUP_DOMAIN = GrantResource.GRANT_STEPUP_DOMAIN
    public static let NEED_REQUEST_DOMAIN = GrantResource.NEED_REQUEST_DOMAIN
    public static let MAX_PAGE_LIMIT = ListAuthorized.MAX_PAGE_LIMIT
    public static let GRANTS_PATH = GrantHttp.GRANTS_PATH
    public static let NEEDS_PATH = GrantHttp.NEEDS_PATH
    public static let LEASES_PATH = LeaseHttp.LEASES_PATH

    public typealias ShadowLog = Shadow.ShadowLog
    public typealias GrantService = GrantResource.GrantService
    public typealias MemoryGrantStore = GrantResource.MemoryGrantStore
    public typealias WindowReadAccumulator = ListAuthorized.WindowReadAccumulator
    public typealias ListError = ListAuthorized.ListError

    /// `signDomainBody` / `verifyDomainBody`: the domain-separated body signature under their package-index names.
    public static func signDomainBody(_ domain: String, _ body: JSONValue, _ secret: PCAEdKey) throws -> String { try signBody(domain, body, secret) }
    public static func verifyDomainBody(_ domain: String, _ body: JSONValue, _ signer: String, _ sig: JSONValue?) -> Bool { verifyBody(domain, body, signer, sig) }
    public static func signGrantBody(_ domain: String, _ body: JSONValue, _ secret: PCAEdKey) throws -> String { try signBody(domain, body, secret) }

    public static func renewLease(_ secret: PCAEdKey, _ registry: Lease.Registry, _ id: String, _ o: Leases.RenewOptions) -> JSONValue { Leases.renewLease(secret, registry, id, o) }
    public static func runLeaseStoreConformance(_ kit: LeaseStoreConformance.Kit) throws -> [String] { try LeaseStoreConformance.runLeaseStoreConformance(kit) }

    public static func runShadow(_ input: JSONValue, enforced: (JSONValue) throws -> String?, candidates: [Shadow.Candidate]) rethrows -> Shadow.Run {
        try Shadow.runShadow(input, enforced: enforced, candidates: candidates)
    }
    public static func promotionGate(_ log: Shadow.ShadowLog, _ o: JObject) -> JObject { Shadow.promotionGate(log, o) }
    public static func promoteShadow(_ enforced: JObject, _ candidate: JObject, _ gate: JObject, now: JSONValue?) throws -> JObject { try Shadow.promoteShadow(enforced, candidate, gate, now: now) }
    public static func verifyShadowDiff(_ d: JSONValue?, signer: String? = nil) -> Bool { Shadow.verifyShadowDiff(d, signer: signer) }
    public static func signPromotionApproval(_ secret: PCAEdKey, _ a: JObject) throws -> JSONValue { try Shadow.signPromotionApproval(secret, a) }
    public static func signWideningExplanation(_ secret: PCAEdKey, _ e: JObject) throws -> JSONValue { try Shadow.signWideningExplanation(secret, e) }
    public static func listAuthorized(_ a: ListAuthorized.Args) throws -> ListAuthorized.Result { try ListAuthorized.listAuthorized(a) }
    public static func candidatesFromRelation(_ rel: ListAuthorized.RelationSource, subject: String, relation: String) throws -> ListAuthorized.CandidateSource {
        try ListAuthorized.candidatesFromRelation(rel, subject: subject, relation: relation)
    }

    public static func grantRevokeMessage(_ id: String, scope: String) -> JSONValue { GrantResource.grantRevokeMessage(id, scope: scope) }
    public static func needApproveMessage(_ nr: JObject, rev: JSONValue?, approved: JSONValue?) -> JSONValue { GrantResource.needApproveMessage(nr, rev: rev, approved: approved) }
    public static func amendMessage(_ g: JObject, action: String, authority: JSONValue?) throws -> JSONValue { try GrantResource.amendMessage(g, action: action, authority: authority) }
    public static func needRequestMessage(_ grantId: String, rev: JSONValue?, needs: JSONValue?) -> JSONValue { GrantResource.needRequestMessage(grantId, rev: rev, needs: needs) }
    public static func stepUpMessage(_ grantId: String, challengeId: String, nonce: String) -> JSONValue { GrantResource.stepUpMessage(grantId, challengeId: challengeId, nonce: nonce) }
    public static func grantResourceHandler(_ svc: GrantResource.GrantService, authenticate: @escaping GrantHttp.Authenticate) -> GrantHttp.Handler { GrantHttp.grantResourceHandler(svc, authenticate: authenticate) }
    public static func leaseResourceHandler(_ reg: Lease.Registry, authenticate: @escaping LeaseHttp.Authenticate, now: (() -> Int64)? = nil) -> GrantHttp.Handler {
        LeaseHttp.leaseResourceHandler(reg, authenticate: authenticate, now: now)
    }
    public static func grantManagementMetadata(_ base: String) -> JSONValue { GrantHttp.grantManagementMetadata(base) }
    public static func leaseManagementMetadata(_ base: String) -> JSONValue { LeaseHttp.leaseManagementMetadata(base) }

    /// `checkBlueprints`: the group gate over a delegation chain (`Blueprint.check`).
    public static func checkBlueprints(chain: JSONValue?, registry: Blueprint.Registry, now: JSONValue?, mode: String, minEpoch: Int64? = nil,
                                       admitted: ((String, JObject) throws -> Bool)? = nil) -> Blueprint.Decision {
        Blueprint.check(chain: chain, registry: registry, now: now, mode: mode, minEpoch: minEpoch, admitted: admitted)
    }
}
