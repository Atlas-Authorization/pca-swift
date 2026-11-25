import Foundation

/// "Which objects of this type may this agent touch?" (pca-grants list-authorized.ts). Authority = capability AND relationship: the capability
/// (`permits`) decides and a relation source can only NARROW. Every page is charged to a read accumulator (scanned and returned objects), pages
/// are bound by a signed cursor and the result carries a signed receipt. Verification of receipts and cursors is `K3.verifyListReceipt` /
/// `K3.verifyListCursor`.
public enum ListAuthorized {
    public static let MAX_PAGE_LIMIT = 500

    /// One page of candidate objects; `next` nil or empty ends the scan.
    public struct CandidatePage {
        public let objects: [String]
        public let next: String?
        public init(objects: [String], next: String? = nil) { self.objects = objects; self.next = next }
    }

    /// `(type, cursor, limit)` to one page of candidates.
    public typealias CandidateSource = (String, String?, Int) throws -> CandidatePage

    public protocol RelationSource {
        /// May `subject` have `relation` on `obj`? Only ever narrows.
        func check(_ subject: String, _ relation: String, _ obj: String) throws -> Bool
        /// Whether `listObjects` is implemented.
        var supportsListObjects: Bool { get }
        func listObjects(_ subject: String, _ relation: String, _ type: String, _ cursor: String?, _ limit: Int) throws -> CandidatePage
    }

    /// Adapt a relation source's list-objects into a candidate source for one subject + relation.
    public static func candidatesFromRelation(_ rel: RelationSource, subject: String, relation: String) throws -> CandidateSource {
        guard rel.supportsListObjects else { throw PCAProducerError("candidatesFromRelation: the relation source has no listObjects") }
        return { type, cursor, limit in try rel.listObjects(subject, relation, type, cursor, limit) }
    }

    /// Charges reads against a budget keyed by (subject, type). False when the charge would exceed the cap.
    public protocol ReadAccumulator {
        func charge(_ key: String, _ units: Int64, _ now: Int64) throws -> Bool
    }

    /// Reference accumulator: `cap` units per `windowMs` fixed window per key.
    public final class WindowReadAccumulator: ReadAccumulator, @unchecked Sendable {
        private var used: [String: (start: Int64, units: Int64)] = [:]
        private let cap: Int64, windowMs: Int64
        private let lock = PCALock()
        public init(cap: Int64, windowMs: Int64) { self.cap = cap; self.windowMs = windowMs }

        public func charge(_ key: String, _ units: Int64, _ now: Int64) -> Bool {
            lock.lock(); defer { lock.unlock() }
            var cur: (start: Int64, units: Int64) = (start: now, units: 0)
            if let e = used[key], now - e.start < windowMs { cur = e }
            if cur.units + units > cap { return false }
            cur.units += units
            used[key] = cur
            return true
        }
    }

    public static func objectsDigest(_ objects: [JSONValue]) -> String? { K3.objectsDigest(objects) }
    public static func verifyListReceipt(_ r: JSONValue?, signer: String, objects: [JSONValue]? = nil) -> Bool { K3.verifyListReceipt(r, signer: signer, objects: objects) }

    public struct ListError: Error, CustomStringConvertible {
        /// read_budget_exhausted | bad_cursor | bad_limit
        public let code: String
        public let message: String
        public var description: String { message }
    }

    /// Arguments of `listAuthorized`; fields mirror the reference.
    public struct Args {
        public var subject: String
        public var resourceType: String
        /// The capability: true iff the grant permits the object.
        public var permits: (String) -> Bool
        public var candidates: CandidateSource
        public var filterId: String
        public var policyDigest: String
        public var freshAtDigest: String
        public var limit: Int64
        public var reads: ReadAccumulator
        public var now: Int64
        public var signingSecret: PCAEdKey
        public var relationSource: RelationSource?
        /// The relation name; nil when no relation filter is used.
        public var relation: String?
        public var cursor: String?
        /// Max candidates scanned per call; nil means 4x limit. At most 1000 either way.
        public var maxScan: Int64?

        public init(subject: String, resourceType: String, permits: @escaping (String) -> Bool, candidates: @escaping CandidateSource, filterId: String,
                    policyDigest: String, freshAtDigest: String, limit: Int64, reads: ReadAccumulator, now: Int64, signingSecret: PCAEdKey,
                    relationSource: RelationSource? = nil, relation: String? = nil, cursor: String? = nil, maxScan: Int64? = nil) {
            self.subject = subject; self.resourceType = resourceType; self.permits = permits; self.candidates = candidates; self.filterId = filterId
            self.policyDigest = policyDigest; self.freshAtDigest = freshAtDigest; self.limit = limit; self.reads = reads; self.now = now
            self.signingSecret = signingSecret; self.relationSource = relationSource; self.relation = relation; self.cursor = cursor; self.maxScan = maxScan
        }
    }

    /// `{objects, next_cursor?, receipt}`.
    public struct Result {
        public let objects: [String]
        public let nextCursor: String?
        public let receipt: JSONValue
        public var json: JSONValue {
            var m: JObject = ["objects": .array(objects.map { .string($0) }), "receipt": receipt]
            if let n = nextCursor { m["next_cursor"] = .string(n) }
            return .object(m)
        }
    }

    private static func bindInputs(_ a: Args) -> JSONValue {
        var m: JObject = ["subject": .string(a.subject), "resourceType": .string(a.resourceType), "filterId": .string(a.filterId),
                          "policyDigest": .string(a.policyDigest), "limit": .int(a.limit)]
        if let r = a.relation { m["relation"] = .object(["relation": .string(r)]) }
        return .object(m)
    }

    /// What a cursor is bound to: `{subject, resourceType, filterId, policyDigest, relation?: {relation}, limit}`.
    public static func listBind(_ a: JSONValue?) -> String? { K3.listBind(a) }

    /// Verify a page cursor (never throws); `bind` nil skips the binding check.
    public static func verifyListCursor(_ tok: JSONValue?, signer: String, bind: JSONValue? = nil) -> K3.CursorVerdict { K3.verifyListCursor(tok, signer: signer, bind: bind) }

    private static func encCursor(_ inner: String?, _ skip: Int64, _ bind: String, _ signer: String, _ secret: PCAEdKey) throws -> String {
        var c: JObject = ["v": .int(1), "skip": .int(skip), "bind": .string(bind), "signer": .string(signer)]
        if let i = inner { c["inner"] = .string(i) }
        // Member order is the reference's JSON.stringify order (v, inner?, skip, bind, signer); the signature covers the canonical form.
        let text = JS.stringify(.object(c), order: ["v", "inner", "skip", "bind", "signer"])
        return Base64URLStrict.encode(Canonical.utf8(text)) + "." + (try PCAGrants.signBody(K3.LIST_CURSOR_DOMAIN, .object(c), secret))
    }

    public static func listAuthorized(_ a: Args) throws -> Result {
        if a.limit < 1 || a.limit > Int64(MAX_PAGE_LIMIT) { throw ListError(code: "bad_limit", message: "limit must be 1..\(MAX_PAGE_LIMIT)") }
        let limit = Int(a.limit)
        let signer = PCAGrants.signerOf(a.signingSecret)
        let bi = bindInputs(a)
        guard let bind = K3.listBind(bi) else { throw PCAProducerError("listAuthorized: not strict-canonical") }
        var inner: String?
        var skipIn: Int64 = 0
        if let cur = a.cursor {
            let c = K3.verifyListCursor(.string(cur), signer: signer, bind: bi)
            if !c.ok { throw ListError(code: "bad_cursor", message: c.reason == "bind" ? "subject, type, filter, policy or limit changed between pages" : "the page cursor is malformed, forged or from another signer") }
            inner = c.inner
            skipIn = c.skip
        }
        let maxScan = min(a.maxScan ?? a.limit * 4, 1000)
        let key = Canonical.hashCanonical(.object(["s": .string(a.subject), "t": .string(a.resourceType)]))
        var out: [String] = []
        var scanned: Int64 = 0
        var pageStart = inner
        var skip = skipIn
        var resume: (inner: String?, skip: Int64)?
        while true {
            let pg = try a.candidates(a.resourceType, pageStart, limit)
            let objs = pg.objects.count > limit ? Array(pg.objects[..<limit]) : pg.objects
            // Charge what was SCANNED before anything is returned: enumeration by filter-heavy scans is the attack.
            if !(try a.reads.charge(key, max(Int64(objs.count) - skip, 1), a.now)) { throw ListError(code: "read_budget_exhausted", message: "the read budget for this subject and type is exhausted") }
            var i = Int(min(skip, Int64(Int32.max)))
            while i < objs.count && out.count < limit {
                scanned += 1
                let o = objs[i]
                i += 1
                if !a.permits(o) { continue }
                if let r = a.relation {
                    guard let src = a.relationSource else { throw PCAProducerError("listAuthorized: a relation without a relation source") }
                    if !(try src.check(a.subject, r, o)) { continue }
                }
                out.append(o)
            }
            if i < objs.count { resume = (pageStart, Int64(i)); break }
            guard let nx = pg.next, !nx.isEmpty, !objs.isEmpty else { break }
            pageStart = nx
            skip = 0
            if out.count >= limit || scanned >= maxScan { resume = (nx, 0); break }
        }
        let receipt: JObject = ["v": .int(1), "subject": .string(a.subject), "resource_type": .string(a.resourceType), "policy_digest": .string(a.policyDigest),
                                "fresh_at": .string(a.freshAtDigest), "filter_digest": .string(a.filterId), "count": .int(Int64(out.count)),
                                "objects_digest": .string(K3.objectsDigest(out.map { .string($0) }) ?? ""), "issued_at": .int(a.now), "signer": .string(signer)]
        var signed = receipt
        signed["sig"] = .string(try PCAGrants.signBody(K3.LIST_RECEIPT_DOMAIN, .object(receipt), a.signingSecret))
        let next = try resume.map { try encCursor($0.inner, $0.skip, bind, signer, a.signingSecret) }
        return Result(objects: out, nextCursor: next, receipt: .object(signed))
    }
}
