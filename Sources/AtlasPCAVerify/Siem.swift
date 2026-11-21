import Foundation

/// SIEM export for PCA authorization decisions: one decision record (the signed action, the core verify result, the Policy-VM
/// decision) becomes an OCSF 1.1 Authorize Session event, an ArcSight CEF line or an Elastic Common Schema event, each citing the
/// cryptographic proof digest and the full delegation chain. Pure over the record; shipping never throws into the caller's
/// authorization path (sinks return a result, `exportBatch` reports through `onError`).
///
/// A record is the JSON object {pcactn, verify, decision?, now?, session?} (any member of any shape is tolerated, like the reference).
/// shortcut: the insertion order of the `checks` object is not kept by a parsed `JSONValue`, so checks are listed index keys first,
/// then the normative check order (wire ... replay, threshold), then any other key sorted; the reference lists them as inserted.
/// shortcut: the HTTP sink takes an injected `fetch` (no bundled URLSession default, which needs FoundationNetworking on Linux).
public enum PCASiem {
    public struct Options {
        /// `full`, `prefix` (default, 16 characters), `omit`; any other value means prefix.
        public var signature: String?
        public init(signature: String? = nil) { self.signature = signature }
    }

    public struct Event {
        public let format: String
        public let object: JSONValue?
        public let line: String
        public func toMap() -> JSONValue {
            var o: JObject = ["format": .string(format), "line": .string(line)]
            if let object = object { o["object"] = object }
            return .object(o)
        }
    }

    public struct SinkResult {
        public var ok: Bool
        public var error: String?
        public init(ok: Bool, error: String? = nil) { self.ok = ok; self.error = error }
        public var json: JSONValue {
            var o: JObject = ["ok": .bool(ok)]
            if let e = error { o["error"] = .string(e) }
            return .object(o)
        }
    }

    public struct Sink {
        public let name: String
        public let format: String
        public let deliver: ([Event]) throws -> SinkResult
        public init(name: String, format: String, deliver: @escaping ([Event]) throws -> SinkResult) {
            self.name = name; self.format = format; self.deliver = deliver
        }
    }

    public struct ExportOptions {
        /// (scrubbed message, sink name, event count); a throw from it is swallowed.
        public var onError: ((String, String, Int) throws -> Void)?
        public var serialize: Options?
        public init(onError: ((String, String, Int) throws -> Void)? = nil, serialize: Options? = nil) { self.onError = onError; self.serialize = serialize }
    }

    public struct ExportResult {
        public var ok: Bool
        public var delivered: Int
        public var format: String
        public var error: String?
        public var skipped: Int?
        public var json: JSONValue {
            var o: JObject = ["ok": .bool(ok), "delivered": .int(Int64(delivered)), "format": .string(format)]
            if let e = error { o["error"] = .string(e) }
            if let s = skipped { o["skipped"] = .int(Int64(s)) }
            return .object(o)
        }
    }

    // MARK: ordered JSON (the line is JSON.stringify of an object whose keys are in the producer's order)

    indirect enum OJ {
        case v(JSONValue)
        case obj([(String, OJ?)])
        case arr([OJ])

        static func of(_ p: KeyValuePairs<String, OJ?>) -> OJ { .obj(p.map { ($0.key, $0.value) }) }

        var json: JSONValue {
            switch self {
            case let .v(x): return x
            case let .arr(a): return .array(a.map { $0.json })
            case let .obj(m):
                var o = JObject()
                for (k, v) in m { if let v = v { o[JKey(k)] = v.json } }
                return .object(o)
            }
        }

        var text: String {
            switch self {
            case let .v(x): return JS.stringify(x)
            case let .arr(a): return "[" + a.map { $0.text }.joined(separator: ",") + "]"
            case let .obj(m):
                var parts: [String] = []
                for (k, v) in m { if let v = v { parts.append(Canonical.canonicalize(.string(k)) + ":" + v.text) } }
                return "{" + parts.joined(separator: ",") + "}"
            }
        }
    }

    fileprivate static func oS(_ s: String) -> OJ { .v(.string(s)) }
    fileprivate static func oI(_ i: Int) -> OJ { .v(.int(Int64(i))) }
    fileprivate static func oB(_ b: Bool) -> OJ { .v(.bool(b)) }
    fileprivate static func oD(_ d: Double) -> OJ {
        .v(d == d.rounded() && abs(d) < 9_007_199_254_740_992 ? .int(Int64(d)) : .double(d))
    }
    fileprivate static func oSA(_ a: [String]) -> OJ { .arr(a.map { oS($0) }) }
    fileprivate static func oV(_ v: JSONValue?) -> OJ? { v.map { .v($0) } }

    /// The key order of a parsed object: index keys ascending, then the normative check names, then the rest in code-unit order.
    public static let checkOrder = ["wire", "version", "audience", "validity", "cap_chain", "plan_inclusion", "leaf_signature", "counter_format", "replay", "threshold"]
    static func orderedKeys(_ o: JObject) -> [String] {
        let all = o.keys.map { $0.s }
        let idx = all.compactMap { k in JS.indexKey(k).map { (k, $0) } }.sorted { $0.1 < $1.1 }.map { $0.0 }
        let known = checkOrder.filter { k in o[JKey(k)] != nil && JS.indexKey(k) == nil }
        let rest = all.filter { JS.indexKey($0) == nil && !checkOrder.contains($0) }.sorted { $0.utf16.lexicographicallyPrecedes($1.utf16) }
        return idx + known + rest
    }

    fileprivate static func checksOJ(_ v: JSONValue) -> OJ {
        guard case let .object(o) = v else { return .v(v) }
        return .obj(orderedKeys(o).map { (k: String) -> (String, OJ?) in (k, OJ.v(o[JKey(k)]!)) })
    }

    /// `Object.entries(v)` for the shapes `checks` can take.
    static func entries(_ v: JSONValue) -> [(String, JSONValue)] {
        switch v {
        case let .object(o): return orderedKeys(o).map { ($0, o[JKey($0)]!) }
        case let .array(a): return a.enumerated().map { (String($0.offset), $0.element) }
        case let .string(s): return s.utf16.enumerated().map { (String($0.offset), .string(String(utf16CodeUnits: [$0.element], count: 1))) }
        default: return []
        }
    }

    // MARK: normalization

    struct Sev { let id: Int; let name: String; let cef: Int }
    static let SEV_INFO = Sev(id: 1, name: "Informational", cef: 1)
    static let SEV_LOW = Sev(id: 2, name: "Low", cef: 3)
    static let SEV_MEDIUM = Sev(id: 3, name: "Medium", cef: 5)
    static let SEV_HIGH = Sev(id: 4, name: "High", cef: 8)
    static let SECURITY_CHECKS = ["wire", "version", "audience", "validity", "cap_chain", "plan_inclusion", "leaf_signature", "counter_format", "replay"]

    struct Hop { let index: Int; let isRoot: Bool; let issuer: String; let holder: String; let added: Int }

    struct Normalized {
        var now = 0.0
        var outcome = "deny"
        var reason = ""
        var verifiable = false
        var checks: JSONValue = .object([:])
        var agentHolder = "(none)"
        var principal: String?
        var session = ""
        var hops: [Hop] = []
        var depth = 0
        var chainString = ""
        var verb = "", resource = "", paramsDigest = "", reversibilityClass = "", grantRef = ""
        var counter = -1.0
        var nonce: String?
        var planRoot = "", signatureSuite = "", leafSignature = "", proofDigest = ""
        var riskScore: Double?
        var tier: JSONValue?
        var proofStrength: JSONValue?
        var caution: Double?
        var bondRef: String?
        var humanApproved = false
        var approvers: [String] = []
        var guardians: [String] = []
        var roles: [String] = []
        var severity = PCASiem.SEV_INFO
        var iat = 0.0
        var exp = 0.0
    }

    static func prop(_ v: JSONValue?, _ k: String) -> JSONValue? { v?.get(k) }
    static func str(_ v: JSONValue?, _ fallback: String) -> String {
        if case let .string(s)? = v, !s.isEmpty { return s }
        return fallback
    }
    static func finiteNum(_ v: JSONValue?) -> Double? {
        switch v {
        case let .int(i)?: return Double(i)
        case let .double(d)?: return d.isFinite ? d : nil
        default: return nil
        }
    }
    static func msg(_ e: Error) -> String { (e as? JSError)?.message ?? "\(e)" }

    /// The first `n` UTF-16 units (a cut that would split a surrogate pair drops the lone half: a Swift String cannot hold one).
    static func cut(_ s: String, _ n: Int) -> String {
        let u = Array(s.utf16)
        if u.count <= n { return s }
        var k = n
        if k > 0, UTF16.isLeadSurrogate(u[k - 1]) { k -= 1 }
        return String(decoding: u[0..<k], as: UTF16.self)
    }

    static func shortKey(_ key: String?) -> String {
        guard let key = key, !key.isEmpty else { return "(none)" }
        return key.utf16.count <= 13 ? key : cut(key, 12) + "\u{2026}"
    }

    static func safeDigest(_ p: JSONValue?) -> String {
        guard let p = p, let b = try? Canonical.canonicalBytes(p) else { return "(undigestible)" }
        return Base64URLStrict.encode(Canonical.sha256(b))
    }

    static func firstReasonOr(_ decision: JSONValue?, _ fallback: String) -> String {
        if case let .array(rs)? = prop(decision, "reasons"), case let .string(s)? = rs.first, !s.isEmpty { return s }
        return fallback
    }

    static func resolveOutcome(_ verify: JSONValue, _ decision: JSONValue?) -> (String, String) {
        if !JS.truthy(verify) || prop(verify, "allow") != .bool(true) { return ("deny", str(prop(verify, "reason"), "proof failed verification")) }
        if !JS.truthy(decision) { return ("allow", "proof verified; no policy decision supplied") }
        if JS.truthy(prop(decision, "admit")) { return ("allow", firstReasonOr(decision, "auto-admitted within policy and budget")) }
        if JS.truthy(prop(decision, "releaseGuardianShare")) { return ("step-up", firstReasonOr(decision, "policy satisfied but a co-signature is required")) }
        return ("deny", firstReasonOr(decision, "policy did not release authority (default-deny)"))
    }

    static func buildHops(_ chain: [JSONValue]) -> [Hop] {
        var hops: [Hop] = []
        for (i, cap) in chain.enumerated() {
            if !JS.truthy(cap) { continue }
            var parentLen = 0
            if i > 0, JS.truthy(chain[i - 1]), case let .array(c)? = prop(chain[i - 1], "caveats") { parentLen = c.count }
            var ownLen = 0
            if case let .array(c)? = prop(cap, "caveats") { ownLen = c.count }
            let added = i == 0 ? ownLen : max(0, ownLen - parentLen)
            hops.append(Hop(index: i, isRoot: i == 0, issuer: str(prop(cap, "issuer"), "(none)"), holder: str(prop(cap, "holder"), "(none)"), added: added))
        }
        return hops
    }

    static func severityFor(_ outcome: String, _ checks: JSONValue, _ tier: JSONValue?) -> Sev {
        if outcome == "deny" { return SECURITY_CHECKS.contains { prop(checks, $0) == .string("fail") } ? SEV_HIGH : SEV_MEDIUM }
        if outcome == "step-up" { return SEV_MEDIUM }
        if let t = finiteNum(tier) { return t == 3 ? SEV_MEDIUM : t == 2 ? SEV_LOW : SEV_INFO }
        return SEV_INFO
    }

    static func shownSignature(_ sig: String, _ mode: String?) -> String {
        if mode == "full" { return sig }
        if mode == "omit" { return "(omitted)" }
        return sig.utf16.count <= 16 ? sig : cut(sig, 16) + "\u{2026}"
    }

    static func uniq(_ a: [String]) -> [String] {
        var out: [String] = []
        for s in a where !out.contains(where: { $0.unicodeScalars.elementsEqual(s.unicodeScalars) }) { out.append(s) }
        return out
    }

    /// One total pass over the record (never throws on shape; only a null / missing record is refused, like the reference's property read).
    static func normalize(_ record: JSONValue, _ opts: Options?) throws -> Normalized {
        if record == .null { throw JSError("Cannot read properties of null (reading 'pcactn')") }
        let p = prop(record, "pcactn")
        let verify: JSONValue = JS.present(prop(record, "verify")) ?? .object(["allow": .bool(false), "checks": .object([:])])
        let checks: JSONValue = JS.present(prop(verify, "checks")) ?? .object([:])
        let now = finiteNum(prop(record, "now")) ?? (Date().timeIntervalSince1970 * 1000).rounded(.down)
        let chain: [JSONValue] = prop(p, "cap_chain")?.asArray ?? []
        let hops = buildHops(chain)
        let decision = prop(record, "decision")
        var n = Normalized()
        n.now = now
        (n.outcome, n.reason) = resolveOutcome(verify, decision)
        let rt = prop(decision, "requiredThreshold")
        n.tier = prop(rt, "t")
        n.proofStrength = prop(rt, "proof")
        // `threshold` sits outside the signed body: its shares prove nothing until a threshold verifier passed
        if prop(checks, "threshold") == .string("pass"), case let .array(shares)? = prop(prop(p, "threshold"), "shares") {
            for s in shares {
                guard case let .string(role)? = prop(s, "role") else { continue }
                n.roles.append(role)
                if role == "principal", case let .string(k)? = prop(s, "publicKey") { n.approvers.append(k) }
                if role == "guardian", case let .string(k)? = prop(s, "publicKey") { n.guardians.append(k) }
            }
            n.humanApproved = !n.approvers.isEmpty
        }
        n.grantRef = str(prop(p, "grant_ref"), "(none)")
        n.agentHolder = str(prop(chain.last, "holder"), "(none)")
        if case let .string(r)? = prop(chain.first, "issuer"), !r.isEmpty { n.principal = r }
        n.checks = checks
        n.verifiable = prop(checks, "wire") == .string("pass") && prop(checks, "leaf_signature") == .string("pass")
        n.session = str(prop(record, "session"), n.grantRef)
        n.hops = hops
        n.depth = hops.isEmpty ? 0 : hops.count - 1
        n.chainString = ([n.principal ?? "(principal?)"] + hops.map { $0.holder }).map { shortKey($0) }.joined(separator: " -> ")
        let act = prop(p, "action")
        n.verb = str(prop(act, "verb"), "(unknown verb)")
        n.resource = str(prop(act, "resource"), "(unknown resource)")
        n.paramsDigest = str(prop(act, "params_digest"), "(none)")
        n.reversibilityClass = str(prop(act, "reversibility_class"), "(unknown)")
        n.counter = finiteNum(prop(p, "counter")) ?? -1
        if case let .string(s)? = prop(p, "nonce") { n.nonce = s }
        n.planRoot = str(prop(prop(p, "plan"), "root"), "(none)")
        n.signatureSuite = str(prop(p, "alg"), "ed25519")
        n.leafSignature = shownSignature(str(prop(p, "sig"), "(unsigned)"), opts?.signature)
        n.proofDigest = safeDigest(p)
        n.riskScore = finiteNum(prop(decision, "r"))
        n.caution = finiteNum(prop(p, "caution"))
        if case let .string(s)? = prop(p, "bond_ref") { n.bondRef = s }
        n.severity = severityFor(n.outcome, checks, n.tier)
        n.iat = finiteNum(prop(p, "iat")) ?? now
        n.exp = finiteNum(prop(p, "exp")) ?? now
        return n
    }

    fileprivate static func humanOverride(_ n: Normalized) -> OJ? {
        guard n.humanApproved else { return nil }
        return OJ.of(["human_approved": oB(true), "approvers": oSA(n.approvers), "guardian_cosigners": oSA(n.guardians), "roles": oSA(n.roles)])
    }

    fileprivate static func pcaExtensions(_ n: Normalized) -> OJ {
        let chain: OJ = .arr(n.hops.map { h in
            OJ.of(["index": oI(h.index), "is_root": oB(h.isRoot), "issuer": oS(h.issuer), "holder": oS(h.holder), "added_caveats": oI(h.added)])
        })
        var m: [(String, OJ?)] = []
        m.append(("proof_digest", oS(n.proofDigest)))
        m.append(("leaf_signature", oS(n.leafSignature)))
        m.append(("signature_suite", oS(n.signatureSuite)))
        m.append(("cryptographically_verifiable", oB(n.verifiable)))
        m.append(("plan_root", oS(n.planRoot)))
        m.append(("params_digest", oS(n.paramsDigest)))
        m.append(("grant_ref", oS(n.grantRef)))
        m.append(("counter", oD(n.counter)))
        m.append(("nonce", n.nonce.map { oS($0) }))
        m.append(("reversibility_class", oS(n.reversibilityClass)))
        m.append(("risk_score", n.riskScore.map { oD($0) }))
        m.append(("risk_tier", oV(n.tier)))
        m.append(("required_proof", oV(n.proofStrength)))
        m.append(("caution", n.caution.map { oD($0) }))
        m.append(("bond_ref", n.bondRef.map { oS($0) }))
        m.append(("delegation_depth", oI(n.depth)))
        m.append(("delegation_chain", chain))
        m.append(("checks", checksOJ(n.checks)))
        m.append(("human_override", humanOverride(n)))
        return .obj(m)
    }

    static func narrative(_ n: Normalized) -> String {
        let word = n.outcome == "allow" ? "ALLOWED" : n.outcome == "deny" ? "DENIED" : "STEP-UP"
        return "Agent \(shortKey(n.agentHolder)) \(word) to \(n.verb) on \(n.resource) "
            + "(\(n.hops.count)-hop chain rooted at principal \(shortKey(n.principal)); "
            + (n.verifiable ? "cryptographically verifiable proof" : "proof not cryptographically verifiable")
            + (n.humanApproved ? "; human-signed step-up" : "")
            + "). \(n.reason)"
    }

    // MARK: OCSF

    static func ocsfOJ(_ record: JSONValue, _ opts: Options?) throws -> OJ {
        let n = try normalize(record, opts)
        let activity: (Int, String) = n.outcome == "allow" ? (1, "Allow") : n.outcome == "deny" ? (2, "Deny") : (3, "Step-Up")
        let action: (Int, String) = n.outcome == "allow" ? (1, "Allowed") : n.outcome == "deny" ? (2, "Denied") : (99, "Other")
        let status: (Int, String, String) = n.outcome == "allow" ? (1, "Success", n.reason)
            : n.outcome == "deny" ? (2, "Failure", n.reason) : (99, "Other", "step-up / co-signature required: \(n.reason)")
        let principalUid = n.principal ?? "(none)"
        let actorUser = OJ.of(["type_id": oI(99), "type": oS("Agent"), "uid": oS(n.agentHolder), "name": oS(shortKey(n.agentHolder))])
        let actorSession = OJ.of(["uid": oS(n.session), "issuer": n.principal.map { oS($0) }])
        let actor = OJ.of(["user": actorUser, "invoked_by": oS(principalUid), "session": actorSession, "app_name": oS("PCA")])
        let user = OJ.of(["type_id": oI(1), "type": oS("User"), "uid": oS(principalUid), "name": oS(shortKey(n.principal))])
        let resources: OJ = .arr([OJ.of(["type": oS("pca.resource"), "name": oS(n.resource), "uid": oS(n.resource)])])
        let api = OJ.of(["operation": oS(n.verb), "service": OJ.of(["name": oS("PCA")])])
        let product = OJ.of(["name": oS("PCA"), "vendor_name": oS("Atlas"), "version": oS("1.1.0")])
        let metadata = OJ.of(["version": oS("1.1.0"), "product": product, "logged_time": oD(n.now), "uid": oS(n.proofDigest),
                              "labels": oSA(["pca", "outcome:\(n.outcome)", "suite:\(n.signatureSuite)"])])
        let observables: OJ = .arr([
            OJ.of(["name": oS("actor.user.uid"), "type": oS("User Name"), "type_id": oI(4), "value": oS(n.agentHolder)]),
            OJ.of(["name": oS("pca.proof.digest"), "type": oS("Hash"), "type_id": oI(8), "value": oS(n.proofDigest)]),
            OJ.of(["name": oS("resources.uid"), "type": oS("Resource UID"), "type_id": oI(10), "value": oS(n.resource)]),
        ])
        var m: [(String, OJ?)] = []
        m.append(("activity_id", oI(activity.0)))
        m.append(("activity_name", oS(activity.1)))
        m.append(("category_uid", oI(3)))
        m.append(("category_name", oS("Identity & Access Management")))
        m.append(("class_uid", oI(3003)))
        m.append(("class_name", oS("Authorize Session")))
        m.append(("type_uid", oI(3003 * 100 + activity.0)))
        m.append(("type_name", oS("Authorize Session: \(activity.1)")))
        m.append(("action_id", oI(action.0)))
        m.append(("action", oS(action.1)))
        m.append(("severity_id", oI(n.severity.id)))
        m.append(("severity", oS(n.severity.name)))
        m.append(("status_id", oI(status.0)))
        m.append(("status", oS(status.1)))
        m.append(("status_detail", oS(status.2)))
        m.append(("time", oD(n.iat)))
        m.append(("actor", actor))
        m.append(("user", user))
        m.append(("resources", resources))
        m.append(("api", api))
        m.append(("metadata", metadata))
        m.append(("observables", observables))
        m.append(("count", oI(1)))
        m.append(("message", oS(narrative(n))))
        m.append(("unmapped", pcaExtensions(n)))
        return .obj(m)
    }

    public static func toOcsfEvent(_ record: JSONValue, _ opts: Options? = nil) throws -> JSONValue { try ocsfOJ(record, opts).json }

    // MARK: CEF

    /// Header field: backslash and pipe escaped, line breaks folded to a space.
    static func cefHeaderEscape(_ s: String) -> String {
        var out = String.UnicodeScalarView()
        var inBreak = false
        for u in s.unicodeScalars {
            if u == "\r" || u == "\n" {
                if !inBreak { out.append(" ") }
                inBreak = true
                continue
            }
            inBreak = false
            if u == "\\" { out.append("\\"); out.append("\\") } else if u == "|" { out.append("\\"); out.append("|") } else { out.append(u) }
        }
        return String(out)
    }

    /// Extension value: backslash and equals escaped, CRLF / CR / LF written as the two characters `\n`.
    static func cefExtValueEscape(_ s: String) -> String {
        var out = String.UnicodeScalarView()
        let u = Array(s.unicodeScalars)
        var i = 0
        while i < u.count {
            let c = u[i]
            if c == "\\" { out.append("\\"); out.append("\\") }
            else if c == "=" { out.append("\\"); out.append("=") }
            else if c == "\r" || c == "\n" {
                if c == "\r", i + 1 < u.count, u[i + 1] == "\n" { i += 1 }
                out.append("\\"); out.append("n")
            } else { out.append(c) }
            i += 1
        }
        return String(out)
    }

    static func num(_ d: Double) -> String { JS.number(d) }

    static func cefLine(_ record: JSONValue, _ opts: Options?) throws -> String {
        let n = try normalize(record, opts)
        let ver = finiteNum(prop(prop(record, "pcactn"), "ver")).map { num($0) } ?? "2"
        let header = ["CEF:0", cefHeaderEscape("Atlas"), cefHeaderEscape("PCA"), cefHeaderEscape(ver), cefHeaderEscape("pca-authz-\(n.outcome)"),
                      cefHeaderEscape("PCA authorization \(n.outcome): \(n.verb) on \(n.resource)"), String(n.severity.cef)].joined(separator: "|")
        let proof: String = { if let p = n.proofStrength, p != .null { return JS.toString(p) }; return "n/a" }()
        let tier: String = { if let t = n.tier, t != .null { return JS.toString(t) }; return "" }()
        let checks = entries(n.checks).map { "\($0.0):\(JS.toString($0.1))" }.joined(separator: ";")
        let pairs: [(String, String)] = [
            ("act", n.outcome), ("outcome", n.outcome),
            ("suser", n.principal ?? "(none)"), ("suid", n.principal ?? "(none)"),
            ("duser", n.agentHolder), ("duid", n.agentHolder),
            ("destinationServiceName", n.verb),
            ("rt", num(n.now)), ("start", num(n.iat)), ("end", num(n.exp)),
            ("externalId", n.nonce ?? num(n.counter)),
            ("request", n.resource), ("requestMethod", n.verb),
            ("cs1Label", "pcaProofDigest"), ("cs1", n.proofDigest),
            ("cs2Label", "pcaDelegationChain"), ("cs2", n.chainString),
            ("cs3Label", "pcaProofStrength"), ("cs3", proof),
            ("cs4Label", "pcaSignatureSuite"), ("cs4", n.signatureSuite),
            ("cs5Label", "pcaVerifyChecks"), ("cs5", checks),
            ("cs6Label", "pcaGrantRef"), ("cs6", n.grantRef),
            ("cn1Label", "pcaRiskScore"), ("cn1", n.riskScore.map { num($0) } ?? ""),
            ("cn2Label", "pcaDelegationDepth"), ("cn2", String(n.depth)),
            ("cn3Label", "pcaRiskTier"), ("cn3", tier),
            ("flexString1Label", "pcaHumanApproved"), ("flexString1", n.humanApproved ? "true" : "false"),
            ("cat", "authorization"), ("msg", n.reason),
        ]
        return header + "|" + pairs.map { "\($0.0)=\(cefExtValueEscape($0.1))" }.joined(separator: " ")
    }

    public static func toCef(_ record: JSONValue, _ opts: Options? = nil) throws -> String { try cefLine(record, opts) }

    // MARK: ECS

    /// `new Date(ms).toISOString()`; a value the Date constructor cannot represent reads as the epoch.
    static func isoOf(_ ms: Double) -> String { isoString(ms) ?? "1970-01-01T00:00:00.000Z" }

    /// `new Date(ms).toISOString()`; nil where the Date constructor yields an invalid date (a RangeError in the reference).
    static func isoString(_ ms: Double) -> String? {
        guard ms.isFinite else { return nil }
        let t = ms.rounded(.towardZero)
        guard abs(t) <= 8.64e15 else { return nil }
        let tv = Int64(t)
        let day = Int64((Double(tv) / 86_400_000).rounded(.down))
        let rem = tv - day * 86_400_000
        let z = day + 719_468
        let era = (z >= 0 ? z : z - 146_096) / 146_097
        let doe = z - era * 146_097
        let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146_096) / 365
        let doy = doe - (365 * yoe + yoe / 4 - yoe / 100)
        let mp = (5 * doy + 2) / 153
        let d = doy - (153 * mp + 2) / 5 + 1
        let m = mp < 10 ? mp + 3 : mp - 9
        let y = yoe + era * 400 + (m <= 2 ? 1 : 0)
        let ys = (0...9999).contains(y) ? String(format: "%04d", Int(y)) : (y < 0 ? "-" : "+") + String(format: "%06d", Int(abs(y)))
        return ys + "-" + String(format: "%02d-%02dT%02d:%02d:%02d.%03dZ", Int(m), Int(d), Int(rem / 3_600_000), Int(rem / 60_000 % 60), Int(rem / 1000 % 60), Int(rem % 1000))
    }

    static func ecsOJ(_ record: JSONValue, _ opts: Options?) throws -> OJ {
        let n = try normalize(record, opts)
        let relatedUsers = uniq([n.agentHolder] + (n.principal.map { [$0] } ?? []) + n.approvers)
        let relatedHashes = uniq([n.proofDigest, n.leafSignature])
        let type = n.outcome == "allow" ? "allowed" : n.outcome == "deny" ? "denied" : "info"
        let outcome = n.outcome == "allow" ? "success" : n.outcome == "deny" ? "failure" : "unknown"
        let event = OJ.of(["kind": oS("event"), "category": oSA(["iam"]), "type": oSA([type]), "action": oS(n.verb), "outcome": oS(outcome),
                           "module": oS("pca"), "dataset": oS("pca.authorization"), "provider": oS("pca"), "id": oS(n.proofDigest),
                           "severity": oI(n.severity.cef), "reason": oS(n.reason), "risk_score": n.riskScore.map { oD($0) }])
        let user = OJ.of(["id": oS(n.agentHolder), "name": oS(shortKey(n.agentHolder)), "roles": oSA(["agent"]),
                          "effective": OJ.of(["id": oS(n.principal ?? "(none)"), "name": oS(shortKey(n.principal))])])
        let proof = OJ.of(["digest": oS(n.proofDigest), "leaf_signature": oS(n.leafSignature), "signature_suite": oS(n.signatureSuite),
                           "cryptographically_verifiable": oB(n.verifiable), "plan_root": oS(n.planRoot), "params_digest": oS(n.paramsDigest)])
        let risk = OJ.of(["score": n.riskScore.map { oD($0) }, "tier": oV(n.tier), "required_proof": oV(n.proofStrength), "caution": n.caution.map { oD($0) }])
        let hops: OJ = .arr(n.hops.map { h in
            OJ.of(["index": oI(h.index), "isRoot": oB(h.isRoot), "issuer": oS(h.issuer), "holder": oS(h.holder), "addedCaveats": oI(h.added)])
        })
        let delegation = OJ.of(["depth": oI(n.depth), "chain": oS(n.chainString), "hops": hops])
        var pca: [(String, OJ?)] = []
        pca.append(("outcome", oS(n.outcome)))
        pca.append(("proof", proof))
        pca.append(("risk", risk))
        pca.append(("delegation", delegation))
        pca.append(("grant_ref", oS(n.grantRef)))
        pca.append(("counter", oD(n.counter)))
        pca.append(("nonce", n.nonce.map { oS($0) }))
        pca.append(("reversibility_class", oS(n.reversibilityClass)))
        pca.append(("bond_ref", n.bondRef.map { oS($0) }))
        pca.append(("checks", checksOJ(n.checks)))
        pca.append(("human_override", humanOverride(n)))
        var m: [(String, OJ?)] = []
        m.append(("@timestamp", oS(isoOf(n.iat))))
        m.append(("ecs.version", oS("8.11.0")))
        m.append(("event", event))
        m.append(("user", user))
        m.append(("service", OJ.of(["name": oS("pca"), "type": oS("authorization")])))
        m.append(("related", OJ.of(["user": oSA(relatedUsers), "hash": oSA(relatedHashes)])))
        m.append(("message", oS(narrative(n))))
        m.append(("pca", .obj(pca)))
        return .obj(m)
    }

    public static func toEcs(_ record: JSONValue, _ opts: Options? = nil) throws -> JSONValue { try ecsOJ(record, opts).json }

    // MARK: sinks

    /// Serializes a record: `cef` is the CEF line; `ocsf` the OCSF object (NDJSON line); anything else the ECS object.
    public static func formatDecision(_ record: JSONValue, _ format: String, _ opts: Options? = nil) throws -> Event {
        if format == "cef" { return Event(format: format, object: nil, line: try cefLine(record, opts)) }
        let o = format == "ocsf" ? try ocsfOJ(record, opts) : try ecsOJ(record, opts)
        return Event(format: format, object: o.json, line: o.text)
    }

    static func contentType(_ format: String) -> String? {
        switch format {
        case "ocsf", "ecs": return "application/x-ndjson"
        case "cef": return "text/plain; charset=utf-8"
        default: return nil
        }
    }

    // JavaScript's regular-expression flavour (no `u` flag): `\w` / `\b` are ASCII, `\s` is the ECMAScript white-space set, `i` folds ASCII only.
    private static let notAfterWord = "(?<![A-Za-z0-9_])"
    private static let spaceSet = #"\t\n\u000B\u000C\r    -     　﻿"#
    private static let S = "[" + spaceSet + "]"
    private static func ci(_ w: String) -> String {
        w.map { c in c.isASCII && c.isLetter ? "[\(c.lowercased())\(c.uppercased())]" : String(c) }.joined()
    }
    private static func re(_ p: String) -> NSRegularExpression { try! NSRegularExpression(pattern: p) }

    private static let userinfo = re("([A-Za-z][A-Za-z0-9+.-]*://)[^" + spaceSet + "/@]*:[^" + spaceSet + "/@]*@")
    private static let authorization = re(notAfterWord + "(" + ci("authorization") + "[\"']?" + S + "*[:=]" + S + "*)[^\\n\"']*")
    private static let scheme = re(notAfterWord + "(" + ["Bearer", "Basic", "Splunk", "Token"].map(ci).joined(separator: "|") + ")" + S + "+[A-Za-z0-9_.~+/=-]{6,}")
    private static let pair = re(notAfterWord + "((?:" + ["token", "secret", "password", "passwd", "pwd"].map(ci).joined(separator: "|")
        + "|" + ci("api") + "[_-]?" + ci("key") + "|" + ci("dd-api-key") + "|" + ["key", "signature", "sig", "credential"].map(ci).joined(separator: "|")
        + ")[\"']?" + S + "*[:=]" + S + "*)(\"[^\"]*\"|'[^']*'|[^" + spaceSet + "\"'&,;]+)")
    private static let longRun = re("[A-Za-z0-9_-]{32,}")

    private static func sub(_ s: String, _ r: NSRegularExpression, _ f: (NSTextCheckingResult, NSString) -> String) -> String {
        let ns = s as NSString
        var out = "", last = 0
        for m in r.matches(in: s, range: NSRange(location: 0, length: ns.length)) {
            out += ns.substring(with: NSRange(location: last, length: m.range.location - last))
            out += f(m, ns)
            last = m.range.location + m.range.length
        }
        return out + ns.substring(from: last)
    }

    /// Removes credentials from an error message before it is returned or reported: URL userinfo, authorization values, bearer / basic /
    /// splunk / token credentials, `token=` style pairs and long token-like runs; cut to 300 UTF-16 units.
    public static func scrubError(_ message: String) -> String {
        var t = sub(message, userinfo) { m, ns in ns.substring(with: m.range(at: 1)) + "[redacted]@" }
        t = sub(t, authorization) { m, ns in ns.substring(with: m.range(at: 1)) + "[redacted]" }
        t = sub(t, scheme) { m, ns in ns.substring(with: m.range(at: 1)) + " [redacted]" }
        t = sub(t, pair) { m, ns in ns.substring(with: m.range(at: 1)) + "[redacted]" }
        t = sub(t, longRun) { _, _ in "[redacted]" }
        return t.utf16.count > 300 ? cut(t, 300) + "..." : t
    }

    public struct HttpRequest {
        public let url: String
        public let method: String
        public let headers: [String: String]
        public let body: String
        /// The delivery timeout the fetch must enforce (a hung collector must not hold the caller).
        public let timeoutMs: Double
    }
    public struct FetchResponse {
        public let ok: Bool
        public let status: Int
        public let statusText: String?
        public init(ok: Bool, status: Int, statusText: String? = nil) { self.ok = ok; self.status = status; self.statusText = statusText }
    }
    /// Thrown by a fetch that gave up at its timeout.
    public struct FetchTimeout: Error { public init() {} }

    public struct HttpSinkOptions {
        public var format: String
        public var headers: [String: String]?
        public var fetch: ((HttpRequest) throws -> FetchResponse)?
        public var contentType: String?
        public var name: String?
        public var timeoutMs: Double?
        public init(format: String, headers: [String: String]? = nil, fetch: ((HttpRequest) throws -> FetchResponse)? = nil,
                    contentType: String? = nil, name: String? = nil, timeoutMs: Double? = nil) {
            self.format = format; self.headers = headers; self.fetch = fetch; self.contentType = contentType; self.name = name; self.timeoutMs = timeoutMs
        }
    }

    /// One POST per batch: NDJSON for OCSF / ECS, the CEF lines for CEF. Delivery never throws: a failure is `{ok: false, error}` (scrubbed).
    public static func httpSink(_ url: String, _ options: HttpSinkOptions) -> Sink {
        let format = options.format
        return Sink(name: options.name ?? "http:\(format)", format: format) { events in
            do {
                guard let doFetch = options.fetch else { return SinkResult(ok: false, error: "no fetch implementation available (pass options.fetch)") }
                var headers: [String: String] = [:]
                if let ct = options.contentType ?? contentType(format) { headers["content-type"] = ct }
                for (k, v) in options.headers ?? [:] { headers[k] = v }
                let t = options.timeoutMs ?? 10_000
                let req = HttpRequest(url: url, method: "POST", headers: headers, body: events.map { $0.line }.joined(separator: "\n"),
                                      timeoutMs: t.isFinite && t > 0 ? t : 10_000)
                let res = try doFetch(req)
                if res.ok { return SinkResult(ok: true) }
                let text = (res.statusText?.isEmpty ?? true) ? "" : " " + res.statusText!
                return SinkResult(ok: false, error: scrubError("HTTP \(res.status)\(text)"))
            } catch is FetchTimeout {
                return SinkResult(ok: false, error: "delivery timed out")
            } catch {
                return SinkResult(ok: false, error: scrubError(msg(error)))
            }
        }
    }

    /// A sink that writes each event's line to a logger (default `print`). Never throws.
    public static func consoleSink(format: String? = nil, logger: ((String) throws -> Void)? = nil, name: String? = nil) -> Sink {
        let f = format ?? "ocsf"
        let log = logger ?? { print($0) }
        return Sink(name: name ?? "console:\(f)", format: f) { events in
            do {
                for e in events { try log(e.line) }
                return SinkResult(ok: true)
            } catch {
                return SinkResult(ok: false, error: scrubError(msg(error)))
            }
        }
    }

    // MARK: export orchestration (fail-safe: nothing here throws into the caller)

    static func safeOnError(_ options: ExportOptions?, _ message: String, _ sink: String, _ count: Int) {
        guard let cb = options?.onError else { return }
        do { try cb(message, sink, count) } catch {}
    }

    public static func exportDecision(_ record: JSONValue, _ sink: Sink, _ options: ExportOptions? = nil) -> ExportResult {
        exportBatch([record], sink, options)
    }

    /// One delivery for a batch. A record that cannot be serialized is reported and left out; a delivery failure is reported and returned.
    public static func exportBatch(_ records: [JSONValue], _ sink: Sink, _ options: ExportOptions? = nil) -> ExportResult {
        let format = sink.format
        var count = 0
        do {
            var events: [Event] = []
            var skipped = 0
            for r in records {
                do { events.append(try formatDecision(r, format, options?.serialize)) } catch {
                    skipped += 1
                    safeOnError(options, scrubError("record could not be serialized: \(msg(error))"), sink.name, 1)
                }
            }
            count = events.count
            if events.isEmpty && skipped > 0 {
                return ExportResult(ok: false, delivered: 0, format: format, error: "no record could be serialized", skipped: skipped)
            }
            let res = try sink.deliver(events)
            if res.ok { return ExportResult(ok: true, delivered: events.count, format: format, error: nil, skipped: skipped > 0 ? skipped : nil) }
            let m = scrubError(res.error ?? "sink reported a delivery failure")
            safeOnError(options, m, sink.name, events.count)
            return ExportResult(ok: false, delivered: 0, format: format, error: m, skipped: skipped > 0 ? skipped : nil)
        } catch {
            let m = scrubError(msg(error))
            safeOnError(options, m, sink.name, count)
            return ExportResult(ok: false, delivered: 0, format: format, error: m, skipped: nil)
        }
    }
}
