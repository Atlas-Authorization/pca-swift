import Foundation

/// Verification of the K3 operational-plane artifacts, ported from `packages/pca-grants` (`bundle.ts`, `list-authorized.ts`,
/// `grant-resource.ts`): signed policy bundles, the Merkle-committed decision log, list receipts and page cursors, and the
/// grant-management signatures. Every signature is Ed25519 (strict) over `domain || strictCanonical(body)`. Verification
/// only, and every function is total: malformed input returns the failure value, it never traps.
public enum K3 {
    public static let BUNDLE_DOMAIN = "atlas-pca/policy-bundle/v1\u{0}"
    public static let BUNDLE_REF_DOMAIN = "atlas-pca/policy-bundle-ref/v1"
    public static let RECORD_DOMAIN = "atlas-pca/decision-record/v1"
    public static let LOG_HEAD_DOMAIN = "atlas-pca/decision-log-head/v1\u{0}"
    public static let LIST_RECEIPT_DOMAIN = "atlas-pca/list-receipt/v1\u{0}"
    public static let LIST_CURSOR_DOMAIN = "atlas-pca/list-cursor/v1\u{0}"
    public static let OBJECTS_DOMAIN = "atlas-pca/list-objects/v1"
    public static let GRANT_AMEND_DOMAIN = "atlas-pca/grant-amend/v1\u{0}"
    public static let GRANT_REVOKE_DOMAIN = "atlas-pca/grant-revoke/v1\u{0}"
    public static let NEED_APPROVE_DOMAIN = "atlas-pca/need-approve/v1\u{0}"
    public static let AUTHORITY_DOMAIN = "atlas-pca/authority/v1"

    // ---- policy bundles ----------------------------------------------------------------------------------------------

    /// base64url(sha256(strictCanonical({d, b: bundle without `sigs`}))); nil when the bundle is not an object or not strict-canonical.
    public static func bundleDigest(_ b: JSONValue?) -> String? {
        guard let o = b?.asObject else { return nil }
        return K3Sig.digest(BUNDLE_REF_DOMAIN, "b", .object(K3Sig.without(o, "sigs")))
    }

    /// `^\d{1,6}(\.\d{1,6}){0,3}$` (ASCII digits only).
    static func validVersion(_ s: String) -> Bool {
        let parts = s.utf8.split(separator: UInt8(ascii: "."), omittingEmptySubsequences: false)
        if parts.isEmpty || parts.count > 4 { return false }
        return parts.allSatisfy { !$0.isEmpty && $0.count <= 6 && $0.allSatisfy { $0 >= 48 && $0 <= 57 } }
    }

    /// JS `Number(s)` for the dotted-version parts. shortcut: only plain ASCII digits (and "") are numbers, every other lexeme is NaN; upgrade if a verifier version ever carries whitespace or an exponent.
    static func jsNumber(_ s: String) -> Double {
        if s.isEmpty { return 0 }
        guard s.utf8.allSatisfy({ $0 >= 48 && $0 <= 57 }) else { return Double.nan }
        return Double(s) ?? Double.nan
    }

    /// `d{1,6}(.d{1,6}){0,3}` in ASCII digits; anything else is too old for a bundle, never newer (fail closed).
    static func versionOk(_ s: String) -> Bool {
        let parts = s.split(separator: ".", omittingEmptySubsequences: false)
        return (1...4).contains(parts.count) && parts.allSatisfy { (1...6).contains($0.utf8.count) && $0.utf8.allSatisfy { $0 >= 48 && $0 <= 57 } }
    }

    /// -1, 0 or 1 (dotted numeric versions; a missing part is 0, a non-numeric part compares greater, as the reference's NaN).
    public static func compareVersion(_ a: String, _ b: String) -> Int {
        let pa = IV.split(a, ".").map(jsNumber)
        let pb = IV.split(b, ".").map(jsNumber)
        for i in 0..<max(pa.count, pb.count) {
            let d = (i < pa.count ? pa[i] : 0) - (i < pb.count ? pb[i] : 0)
            if d != 0 { return d < 0 ? -1 : 1 }
        }
        return 0
    }

    static func bundleShapeError(_ v: JSONValue?) -> String? {
        guard let b = v?.asObject, b["v"]?.safeInt == 1, b["kind"]?.asString == "pca-policy-bundle" else { return "not a policy bundle" }
        guard let rev = K3Sig.safeInt(b["revision"]), rev >= 1, K3Sig.safeInt(b["issued_at"]) != nil else { return "bad revision or time" }
        let prevOk = rev == 1 ? (b["prev"] == nil) : (K3Sig.str(b["prev"], 128) != nil)
        if !prevOk { return "prev must be absent at revision 1 and present after" }
        for k in ["grants", "template_digests"] {
            guard let a = b[JKey(k)]?.asArray, a.count <= 4096, a.allSatisfy({ K3Sig.str($0, 128) != nil }) else { return "bad \(k)" }
        }
        for k in ["schema_digest", "constitution_digest", "flow_rules_digest"] where b[JKey(k)] != nil && K3Sig.str(b[JKey(k)], 128) == nil {
            return "bad \(k)"
        }
        guard let mv = b["min_verifier_version"]?.asString, validVersion(mv) else { return "bad min_verifier_version" }
        return nil
    }

    public struct BundleOptions {
        /// The pinned signer set (base64url public keys); signatures by anyone else are ignored.
        public var signers: [String]
        /// nil when the caller's threshold is not a safe integer (malformed).
        public var threshold: Int64?
        public var verifierVersion: String
        /// Newest accepted revision and digest so far (rollback / chain checks).
        public var last: (revision: Int64, digest: String)?

        public init(signers: [String], threshold: Int64?, verifierVersion: String, last: (revision: Int64, digest: String)? = nil) {
            self.signers = signers
            self.threshold = threshold
            self.verifierVersion = verifierVersion
            self.last = last
        }
    }

    public struct BundleVerdict: Equatable {
        public let ok: Bool
        public let revision: Int64
        public let digest: String
        public let signers: [String]
        /// `malformed`, `below_threshold`, `rollback`, `broken_chain` or `verifier_too_old` when `ok` is false.
        public let code: String
        public let reason: String

        static func fail(_ code: String, _ reason: String) -> BundleVerdict {
            BundleVerdict(ok: false, revision: 0, digest: "", signers: [], code: code, reason: reason)
        }
    }

    public static func verifyBundle(_ bv: JSONValue?, _ o: BundleOptions) -> BundleVerdict {
        if let e = bundleShapeError(bv) { return .fail("malformed", e) }
        guard let b = bv?.asObject, let sigs = b["sigs"]?.asArray, sigs.count <= 64, let threshold = o.threshold, threshold >= 1 else {
            return .fail("malformed", "bad sigs or threshold")
        }
        let body = JSONValue.object(K3Sig.without(b, "sigs"))
        let pinned = Set(o.signers.map { JKey($0) })
        var good: [String] = []
        var seen = Set<JKey>()
        for s in sigs {
            guard let so = s.asObject, let signer = so["signer"]?.asString, pinned.contains(JKey(signer)),
                  K3Sig.verifyBody(BUNDLE_DOMAIN, body, signer: signer, sig: so["sig"]) else { continue }
            if seen.insert(JKey(signer)).inserted { good.append(signer) }
        }
        if Int64(good.count) < threshold { return .fail("below_threshold", "\(good.count) valid pinned signature(s), need \(threshold)") }
        guard let mv = b["min_verifier_version"]?.asString, let revision = K3Sig.safeInt(b["revision"]) else { return .fail("malformed", "not a policy bundle") }
        if !versionOk(o.verifierVersion) || compareVersion(o.verifierVersion, mv) < 0 { return .fail("verifier_too_old", "needs verifier >= \(mv)") }
        guard let digest = bundleDigest(bv) else { return .fail("malformed", "the bundle is not strict canonical JSON") }
        if let last = o.last {
            if revision < last.revision { return .fail("rollback", "revision \(revision) < accepted \(last.revision)") }
            if revision == last.revision && !IV.same(digest, last.digest) { return .fail("broken_chain", "same revision, different content") }
            if revision == last.revision + 1 && !K3Sig.eq(b["prev"]?.asString, last.digest) {
                return .fail("broken_chain", "prev does not chain to the accepted revision")
            }
        }
        return BundleVerdict(ok: true, revision: revision, digest: digest, signers: good, code: "", reason: "")
    }

    // ---- decision log ------------------------------------------------------------------------------------------------

    /// The commit of one decision record (the Merkle leaf is the canonical bytes of this string); nil where the reference throws.
    public static func recordCommit(_ r: JSONValue?) -> String? {
        guard let r = r else { return nil }
        return K3Sig.digest(RECORD_DOMAIN, "r", r)
    }

    /// A signed log head: well formed, and signed by the pinned `signer` over every member but `sig`.
    public static func verifyLogHead(_ h: JSONValue?, signer: String) -> Bool {
        guard let o = h?.asObject, o["v"]?.safeInt == 1, K3Sig.eq(o["signer"]?.asString, signer),
              K3Sig.safeInt(o["size"]) != nil, K3Sig.safeInt(o["issued_at"]) != nil,
              o["root"]?.asString != nil, o["last_commit"]?.asString != nil else { return false }
        return K3Sig.verifyBody(LOG_HEAD_DOMAIN, .object(K3Sig.without(o, "sig")), signer: signer, sig: o["sig"])
    }

    /// Offline: this record is in the log the signed head commits to, and the head is by the pinned signer.
    public static func verifyRecordInclusion(_ rec: JSONValue?, proof: JSONValue?, head: JSONValue?, signer: String) -> Bool {
        guard verifyLogHead(head, signer: signer), let root = head?.get("root")?.asString, let commit = recordCommit(rec) else { return false }
        return Merkle.verifyInclusion(root, proof?.asObject, .string(commit))
    }

    public struct BatchVerdict: Equatable {
        public let ok: Bool
        public let next: Int64
        public let lastCommit: String
        public let reason: String

        static func fail(_ reason: String) -> BatchVerdict { BatchVerdict(ok: false, next: 0, lastCommit: "", reason: reason) }
    }

    private static func number(_ v: JSONValue?) -> String {
        guard let d = IV.num(v) else { return "undefined" }
        return Canonical.numberString(d)
    }

    /// Receiver side of the decision stream: contiguous sequence, an intact hash chain from the receiver's `state`
    /// (`{next, lastCommit}`) and, when the batch reaches the head, the head's last commit and size.
    public static func verifyBatch(_ b: JSONValue?, state: JSONValue?, signer: String) -> BatchVerdict {
        let malformed = BatchVerdict.fail("malformed batch")
        guard let bo = b?.asObject, let st = state?.asObject, let expected = K3Sig.safeInt(st["next"]),
              var last = st["lastCommit"]?.asString, let from = IV.safe(bo["from"]) else { return malformed }
        if Int64(from) != expected { return .fail("gap or replay: batch starts at \(number(bo["from"])), expected \(expected)") }
        guard let head = bo["head"]?.asObject, verifyLogHead(bo["head"], signer: signer) else {
            return .fail("head not signed by the pinned log signer")
        }
        guard let records = bo["records"]?.asArray, let size = K3Sig.safeInt(head["size"]), let headLast = head["last_commit"]?.asString else { return malformed }
        var n = expected
        for rv in records {
            guard let r = rv.asObject else { return malformed }
            guard let seq = IV.safe(r["seq"]), Int64(seq) == n, K3Sig.eq(r["prev"]?.asString, last) else {
                return .fail("chain broken at seq \(number(r["seq"]))")
            }
            guard let commit = recordCommit(rv) else { return malformed }
            last = commit
            n += 1
        }
        if n > size { return .fail("batch is longer than the signed head") }
        if n == size && !IV.same(last, headLast) { return .fail("batch end does not match the signed head") }
        return BatchVerdict(ok: true, next: n, lastCommit: last, reason: "")
    }

    // ---- list-authorized ---------------------------------------------------------------------------------------------

    /// Digest of the returned object ids, in order; nil where the reference throws.
    public static func objectsDigest(_ objects: [JSONValue]) -> String? {
        K3Sig.digest(OBJECTS_DOMAIN, "o", .array(objects))
    }

    /// A signed list receipt: well formed, signed by `signer`, and (when `objects` is given) it covers exactly those objects.
    public static func verifyListReceipt(_ r: JSONValue?, signer: String, objects: [JSONValue]? = nil) -> Bool {
        guard let o = r?.asObject, o["v"]?.safeInt == 1, K3Sig.eq(o["signer"]?.asString, signer),
              K3Sig.str(o["subject"]) != nil, K3Sig.str(o["resource_type"]) != nil,
              let count = K3Sig.safeInt(o["count"]), K3Sig.safeInt(o["issued_at"]) != nil else { return false }
        guard K3Sig.verifyBody(LIST_RECEIPT_DOMAIN, .object(K3Sig.without(o, "sig")), signer: signer, sig: o["sig"]) else { return false }
        guard let objs = objects else { return true }
        guard Int64(objs.count) == count, let d = objectsDigest(objs) else { return false }
        return K3Sig.eq(o["objects_digest"]?.asString, d)
    }

    /// What a page cursor is bound to (`{subject, resourceType, filterId, policyDigest, limit, relation?: {relation}}`);
    /// changing any of these between pages is refused.
    public static func listBind(_ a: JSONValue?) -> String? {
        guard let o = a?.asObject else { return nil }
        var m: JObject = [:]
        if let v = o["subject"] { m["s"] = v }
        if let v = o["resourceType"] { m["t"] = v }
        if let v = o["filterId"] { m["f"] = v }
        if let v = o["policyDigest"] { m["p"] = v }
        m["r"] = o["relation"]?.get("relation") ?? .null
        if let v = o["limit"] { m["l"] = v }
        return IV.strictHash(.object(m))
    }

    public struct CursorVerdict: Equatable {
        public let ok: Bool
        public let inner: String?
        public let skip: Int64
        /// `malformed`, `signature` or `bind` when `ok` is false.
        public let reason: String
    }

    /// Verify a page cursor: shape, signature by `signer`, and (when `bind` is given) that it was issued for exactly those inputs.
    public static func verifyListCursor(_ tok: JSONValue?, signer: String, bind: JSONValue? = nil) -> CursorVerdict {
        func bad(_ r: String) -> CursorVerdict { CursorVerdict(ok: false, inner: nil, skip: 0, reason: r) }
        guard let t = tok?.asString else { return bad("malformed") }
        let parts = IV.split(t, ".")
        guard parts.count == 2, !parts[0].isEmpty, !parts[1].isEmpty, let raw = Base64URLStrict.decode(parts[0]),
              let c = try? StrictJSON.parseLenient(String(decoding: raw, as: UTF8.self)), let co = c.asObject,
              co["v"]?.safeInt == 1, let cbind = co["bind"]?.asString, let skip = K3Sig.safeInt(co["skip"]) else { return bad("malformed") }
        if let iv = co["inner"], iv.asString == nil { return bad("malformed") }
        guard K3Sig.eq(co["signer"]?.asString, signer),
              K3Sig.verifyBody(LIST_CURSOR_DOMAIN, c, signer: signer, sig: .string(parts[1])) else { return bad("signature") }
        if let bind = bind {
            guard let want = listBind(bind), IV.same(cbind, want) else { return bad("bind") }
        }
        return CursorVerdict(ok: true, inner: co["inner"]?.asString, skip: skip, reason: "")
    }

    // ---- grant management --------------------------------------------------------------------------------------------

    /// The comparable shape of a grant's authority.
    struct Authority {
        var verbs: [String]
        var resources: [String]
        var limits: [JKey: Double]
        var expiresAt: Double?

        init(verbs: [String], resources: [String], limits: [JKey: Double], expiresAt: Double?) {
            self.verbs = verbs
            self.resources = resources
            self.limits = limits
            self.expiresAt = expiresAt
        }

        /// `checkAuthority`: nil unless the value is a well-formed authority.
        init?(_ v: JSONValue?) {
            guard let o = v?.asObject, let vs = o["verbs"]?.asArray, vs.count <= 256, let rs = o["resources"]?.asArray, rs.count <= 1024 else { return nil }
            let verbs = vs.compactMap { K3Sig.str($0, 128) }
            let resources = rs.compactMap { K3Sig.str($0, 512) }
            if verbs.count != vs.count || resources.count != rs.count { return nil }
            var limits: [JKey: Double] = [:]
            if let l = o["limits"] {
                guard let lo = l.asObject else { return nil }
                for (k, x) in lo {
                    guard let d = IV.num(x), d.isFinite, d >= 0 else { return nil }
                    limits[k] = d
                }
            }
            var expiresAt: Double?
            if let e = o["expires_at"] {
                guard let d = IV.safe(e), d >= 0 else { return nil }
                expiresAt = d
            }
            self.init(verbs: verbs, resources: resources, limits: limits, expiresAt: expiresAt)
        }

        var json: JSONValue {
            var m: JObject = ["verbs": .array(verbs.map { JSONValue.string($0) }), "resources": .array(resources.map { JSONValue.string($0) })]
            if !limits.isEmpty { m["limits"] = .object(limits.mapValues { JSONValue.double($0) }) }
            if let e = expiresAt { m["expires_at"] = .double(e) }
            return .object(m)
        }
    }

    private static func resCovers(_ p: String, _ r: String) -> Bool {
        IV.endsWith(p, "*") ? IV.startsWith(r, IV.text(p.unicodeScalars.dropLast())) : IV.same(p, r)
    }

    private static func resSubset(_ small: [String], _ big: [String]) -> Bool {
        small.allSatisfy { s in
            big.contains { b in resCovers(b, s) && (IV.endsWith(s, "*") ? (IV.endsWith(b, "*") || IV.same(b, s)) : true) }
        }
    }

    private static func verbSubset(_ small: [String], _ big: [String]) -> Bool {
        small.allSatisfy { s in big.contains { IV.same($0, s) } }
    }

    /// everything `a` allows, `b` allows
    private static func le(_ a: Authority, _ b: Authority) -> Bool {
        if !verbSubset(a.verbs, b.verbs) || !resSubset(a.resources, b.resources) { return false }
        for (k, v) in a.limits { if let bv = b.limits[k], !(v <= bv) { return false } }
        for k in b.limits.keys where a.limits[k] == nil { return false }
        return (a.expiresAt ?? Double.infinity) <= (b.expiresAt ?? Double.infinity)
    }

    static func order(_ o: Authority, _ n: Authority) -> String {
        let nle = le(n, o)
        let ole = le(o, n)
        return nle && ole ? "equal" : nle ? "narrower" : ole ? "wider" : "incomparable"
    }

    /// `narrower`, `equal`, `wider` or `incomparable`; an authority that is not well formed is `incomparable` (treated as wider).
    public static func compareAuthority(_ old: JSONValue?, _ new: JSONValue?) -> String {
        guard let o = Authority(old), let n = Authority(new) else { return "incomparable" }
        return order(o, n)
    }

    /// Digest of an authority (verbs and resources sorted); nil where the reference throws.
    public static func authorityDigest(_ v: JSONValue?) -> String? {
        guard var o = v?.asObject else { return nil }
        for k in ["verbs", "resources"] {
            guard let a = o[JKey(k)]?.asArray else { return nil }
            let strs = a.compactMap { $0.asString }
            if strs.count != a.count { return nil }
            o[JKey(k)] = .array(strs.sorted { $0.utf16.lexicographicallyPrecedes($1.utf16) }.map { JSONValue.string($0) })
        }
        return K3Sig.digest(AUTHORITY_DOMAIN, "a", .object(o))
    }

    private static func union(_ a: [String], _ b: [String]) -> [String] {
        var seen = Set<JKey>()
        var out: [String] = []
        for s in a + b where seen.insert(JKey(s)).inserted { out.append(s) }
        return out
    }

    /// Union. A ceiling or expiry is only ever RAISED by the delta; one the delta omits is kept.
    static func mergeAuthority(_ a: Authority, _ d: Authority) -> Authority {
        var limits: [JKey: Double] = [:]
        for (k, v) in a.limits { limits[k] = max(v, d.limits[k] ?? v) }
        let exp = a.expiresAt.map { max($0, d.expiresAt ?? $0) }
        return Authority(verbs: union(a.verbs, d.verbs), resources: union(a.resources, d.resources), limits: limits, expiresAt: exp)
    }

    public struct GrantVerdict: Equatable {
        public let ok: Bool
        /// `bad_request`, `not_active`, `not_narrower`, `signature_required`, `bad_signature`, `step_up_required`, `conflict`,
        /// `need_not_lowered_only` or `need_not_adjustable` when `ok` is false.
        public let code: String
        public let widens: Bool
        /// Amendment: digest of the resulting authority. Need approval: digest of the merged authority.
        public let digest: String
        /// Revocation: the verified scope.
        public let scope: String

        static func fail(_ code: String) -> GrantVerdict { GrantVerdict(ok: false, code: code, widens: false, digest: "", scope: "") }
    }

    /// Decide an amendment against the current grant facts `{id, rev, principal, agent, status, authority}`. Order: request shape,
    /// authority shape, grant active, classification, signature (the PRINCIPAL when it widens), step-up for a widening.
    /// `stepUpOk` is the already-evaluated step-up verdict.
    public static func verifyAmendment(_ cur: JSONValue?, _ req: JSONValue?, stepUpOk: Bool) -> GrantVerdict {
        guard let r = req?.asObject, let action = r["action"]?.asString, ["narrow", "merge", "replace"].contains(where: { IV.same($0, action) }),
              let reqAuth = Authority(r["authority"]) else { return .fail("bad_request") }
        guard let c = cur?.asObject else { return .fail("bad_request") }
        if !K3Sig.eq(c["status"]?.asString, "active") { return .fail("not_active") }
        guard let curAuth = Authority(c["authority"]) else { return .fail("bad_request") }
        let nextAuth = action == "merge" ? mergeAuthority(curAuth, reqAuth) : reqAuth
        let nextJSON = action == "merge" ? nextAuth.json : (r["authority"] ?? .null)
        let ord = order(curAuth, nextAuth)
        let widens = ord == "wider" || ord == "incomparable"
        if !widens && action == "narrow" && ord == "equal" { return .fail("not_narrower") }
        if widens && action == "narrow" { return .fail("not_narrower") }
        guard let sig = r["sig"]?.asString, let by = r["signed_by"]?.asString, by == "holder" || by == "principal" else { return .fail("signature_required") }
        if widens && by != "principal" { return .fail("signature_required") }
        guard let signer = (by == "principal" ? c["principal"] : c["agent"])?.asString, let ad = authorityDigest(r["authority"]) else { return .fail("bad_signature") }
        var msg: JObject = ["action": .string(action), "authority": .string(ad)]
        if let id = c["id"] { msg["grant"] = id }
        if let rev = c["rev"] { msg["rev"] = rev }
        guard K3Sig.verifyBody(GRANT_AMEND_DOMAIN, .object(msg), signer: signer, sig: .string(sig)) else { return .fail("bad_signature") }
        if widens && !stepUpOk { return .fail("step_up_required") }
        guard let nd = authorityDigest(nextJSON) else { return .fail("bad_request") }
        return GrantVerdict(ok: true, code: "", widens: widens, digest: nd, scope: "")
    }

    /// Decide a revocation's authority: the principal's signature over (grant id, scope).
    public static func verifyRevokeSignature(_ root: JSONValue?, scope: JSONValue?, sig: JSONValue?) -> GrantVerdict {
        guard let sc = scope?.asString, sc == "grant" || sc == "agent" || sc == "subtree" else { return .fail("bad_request") }
        guard let ro = root?.asObject, let principal = ro["principal"]?.asString else { return .fail("bad_signature") }
        var msg: JObject = ["scope": .string(sc)]
        if let id = ro["id"] { msg["grant"] = id }
        guard K3Sig.verifyBody(GRANT_REVOKE_DOMAIN, .object(msg), signer: principal, sig: sig) else { return .fail("bad_signature") }
        return GrantVerdict(ok: true, code: "", widens: false, digest: "", scope: sc)
    }

    /// Decide a needs approval: principal signature over (need, grant, rev, approved), same count, each approved need names the
    /// same verb and resource with amounts only LOWERED (and only when `adjustable`), then step-up. Yields the merged authority's digest.
    public static func verifyNeedApproval(_ nr: JSONValue?, grant g: JSONValue?, approved: JSONValue?, sig: JSONValue?, stepUpOk: Bool) -> GrantVerdict {
        guard let n = nr?.asObject, let go = g?.asObject else { return .fail("bad_request") }
        if n["status"]?.asString != "pending" { return .fail("conflict") }
        guard let principal = go["principal"]?.asString else { return .fail("bad_signature") }
        var msg: JObject = [:]
        if let id = n["id"] { msg["need"] = id }
        if let gid = n["grant_id"] { msg["grant"] = gid }
        if let rev = go["rev"] { msg["rev"] = rev }
        if let ap = approved { msg["approved"] = ap }
        guard K3Sig.verifyBody(NEED_APPROVE_DOMAIN, .object(msg), signer: principal, sig: sig) else { return .fail("bad_signature") }
        guard let ap = approved?.asArray, let needs = n["needs"]?.asArray, ap.count == needs.count else { return .fail("need_not_lowered_only") }
        var verbs: [String] = []
        var resources: [String] = []
        var limits: [JKey: Double] = [:]
        for i in 0..<ap.count {
            guard let a = ap[i].asObject, let want = needs[i].asObject, let av = a["verb"]?.asString, let ar = a["resource"]?.asString,
                  K3Sig.eq(want["verb"]?.asString, av), K3Sig.eq(want["resource"]?.asString, ar) else { return .fail("need_not_lowered_only") }
            let wantLimits = want["limits"]?.asObject
            let given = a["limits"]?.asObject ?? [:]
            for k in given.keys.sorted() {
                var w: Double?
                if let wl = wantLimits, let wx = wl[k] { w = IV.num(wx) }
                guard let v = IV.num(given[k]), let wv = w, v <= wv else { return .fail("need_not_lowered_only") }
                if v < wv && want["adjustable"] != .bool(true) { return .fail("need_not_adjustable") }
                // a limit the need names but the principal omitted is not granted at all (omission is the lowest amount)
                limits[k] = max(limits[k] ?? 0, v)
            }
            verbs.append(av)
            resources.append(ar)
        }
        if !stepUpOk { return .fail("step_up_required") }
        guard let ga = Authority(go["authority"]) else { return .fail("bad_request") }
        let merged = mergeAuthority(ga, Authority(verbs: verbs, resources: resources, limits: limits, expiresAt: nil))
        guard let d = authorityDigest(merged.json) else { return .fail("bad_request") }
        return GrantVerdict(ok: true, code: "", widens: true, digest: d, scope: "")
    }
}
