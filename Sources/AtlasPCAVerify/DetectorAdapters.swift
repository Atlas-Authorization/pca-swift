import Foundation

/// Detector receipts: what a PINNED detector gateway saw (Lakera Guard, Prompt Security, a home-grown classifier), bound to the exact
/// content. `{v:1, kind:"pca-detector-receipt", detector, version, input_digest, verdict, categories, iat, session?, calibration_ref?,
/// sig}` signed under domain `atlas-pca/detector-receipt/v1\0`. Tighten-only by construction: `suspicious` may lower a decision,
/// `no_finding` is exactly no receipt at all.
public enum PCADetectorReceipt {
    public static let DOMAIN = "atlas-pca/detector-receipt/v1\u{0}"
    public static let REF_DOMAIN = "atlas-pca/detector-receipt-ref/v1"
    public static let VERDICTS = ["suspicious", "no_finding"]

    /// `^[a-z][a-z0-9_]{0,63}$`.
    static func idOk(_ s: String) -> Bool {
        let u = Array(s.unicodeScalars)
        guard u.count >= 1, u.count <= 64, u[0].value >= 97, u[0].value <= 122 else { return false }
        return u.dropFirst().allSatisfy { ($0.value >= 97 && $0.value <= 122) || ($0.value >= 48 && $0.value <= 57) || $0 == "_" }
    }

    /// b64u(sha256(strictCanonical({d: "atlas-pca/detector-input/v1", content}))): the digest a receipt binds. Any JSON value.
    public static func inputDigest(_ content: JSONValue) throws -> String {
        guard let h = IV.strictHash(.object(["d": .string("atlas-pca/detector-input/v1"), "content": content])) else {
            throw JSError("detectorInputDigest: the content is outside the strict JSON profile")
        }
        return h
    }

    /// The content address of a receipt (signature included).
    public static func ref(_ r: JSONValue) throws -> String {
        guard let h = IV.strictHash(.object(["d": .string(REF_DOMAIN), "receipt": r])) else { throw JSError("detectorReceiptRef: outside the strict JSON profile") }
        return h
    }

    /// nil when the receipt is well-formed, else the reference's reason.
    public static func shapeError(_ r: JSONValue?) -> String? {
        guard case let .object(o)? = r else { return "receipt must be an object" }
        if let e = IntentWB.closedMembersError(o, ["v", "kind", "detector", "version", "input_digest", "verdict", "categories", "iat", "sig"],
                                               ["session", "calibration_ref", "alg", "pq_pk", "pq_sig"], "receipt") { return e }
        if !(o["v"].flatMap { IV.num($0) } == 1 && IV.same(o["kind"]?.asString, "pca-detector-receipt")) { return "not a pca-detector-receipt v1" }
        guard let det = o["detector"]?.asString, idOk(det) else { return "detector id is malformed" }
        if IV.bounded(o["version"], 64) == nil { return "version must be 1..64 bytes" }
        if IV.digest(o["input_digest"]) == nil { return "input_digest must be a b64u 32-byte digest" }
        guard let verdict = o["verdict"]?.asString, VERDICTS.contains(where: { IV.same($0, verdict) }) else { return "verdict must be 'suspicious' or 'no_finding'" }
        guard case let .array(c)? = o["categories"], c.count <= 8, c.allSatisfy({ $0.asString.map(idOk) ?? false }) else { return "categories must be 0..8 ids" }
        let cs = c.map { $0.asString! }
        for i in cs.indices.dropFirst() where !cs[i - 1].utf16.lexicographicallyPrecedes(cs[i].utf16) { return "categories must be sorted and distinct" }
        if IV.same(verdict, "no_finding") && !cs.isEmpty { return "a no_finding receipt carries no categories" }
        guard let iat = IV.int(o["iat"]), iat >= 0 else { return "iat must be a non-negative integer" }
        _ = iat
        if let s = o["session"], IV.digest(s) == nil { return "session must be a b64u 32-byte id" }
        if let s = o["calibration_ref"], IV.bounded(s, 256) == nil { return "calibration_ref must be 1..256 bytes" }
        if o["sig"]?.asString == nil { return "sig must be a string" }
        return IntentWB.artifactSuiteError(o)
    }

    /// Sign a receipt (the detector gateway's key). Throws on a malformed body.
    public static func sign(_ body: JSONValue, signer: PCASuiteKey) throws -> JSONValue {
        let o = JSONValue.object(try PCAIssue.signArtifact(domain: DOMAIN, body: body, signer: signer))
        if let e = shapeError(o) { throw JSError("signDetectorReceipt: \(e)") }
        return o
    }
}

/// Detector adapters: vendor guardrail responses to signed, tighten-only receipts. Deliberately one-sided: a response is
/// `no_finding` only when it is well-formed AND says nothing was detected. Anything malformed, unexpected or ambiguous becomes
/// `suspicious` with category `detector_error`, so a broken integration adds friction instead of looking clean.
///
/// Response shapes: Lakera Guard `POST /v2/guard` `{flagged, breakdown?: [{detector_type, detected}]}`; Prompt Security
/// `/api/protect` (both published integration shapes: `result.action` and `result.prompt.{action, violations}`); generic
/// `{flagged, categories?}`.
public enum PCADetectors {
    public struct Context {
        /// Policy id of the detector (`^[a-z][a-z0-9_]{0,63}$`).
        public var detector: String
        /// Model / ruleset version reported by the vendor or configured (1..64 bytes).
        public var version: String
        /// The exact content sent to the detector.
        public var content: JSONValue
        /// The gateway's signing key.
        public var signer: PCASuiteKey
        /// Epoch ms.
        public var now: Double
        /// Carried as given: a present value that is not a b64u 32-byte id is refused by the receipt shape check.
        public var session: JSONValue?
        public var calibrationRef: JSONValue?

        public init(detector: String, version: String, content: JSONValue, signer: PCASuiteKey, now: Double, session: JSONValue? = nil, calibrationRef: JSONValue? = nil) {
            self.detector = detector; self.version = version; self.content = content; self.signer = signer; self.now = now
            self.session = session; self.calibrationRef = calibrationRef
        }
    }

    static func isObj(_ v: JSONValue?) -> Bool { v?.isObject ?? false }

    /// Vendor category text to a receipt category id (lowercase, non-alphanumerics to `_`); unusable text becomes `other`.
    public static func categoryId(_ s: JSONValue?) -> String {
        guard case let .string(text)? = s else { return "other" }
        var out: [Unicode.Scalar] = []
        var gap = false
        for u in text.lowercased().unicodeScalars {
            if (u.value >= 97 && u.value <= 122) || (u.value >= 48 && u.value <= 57) {
                if gap { out.append("_"); gap = false }
                out.append(u)
            } else { gap = true }
        }
        if gap { out.append("_") }
        while out.first == "_" { out.removeFirst() }
        while out.last == "_" { out.removeLast() }
        if let f = out.first, f.value >= 48, f.value <= 57 { out.insert(contentsOf: ["c", "_"], at: 0) }
        let c = String(String.UnicodeScalarView(out.prefix(64)))
        return PCADetectorReceipt.idOk(c) ? c : "other"
    }

    static func iat(_ now: Double) -> JSONValue {
        if now.isFinite, now == now.rounded(), abs(now) <= Double(Canonical.MAX_SAFE), !(now == 0 && now.sign == .minus) { return .int(Int64(now)) }
        return .double(now)
    }

    static func receipt(_ ctx: Context, _ suspicious: Bool, _ categories: [String]) throws -> JSONValue {
        let cats = suspicious ? Array(PCADataflow.jsSorted(PCADataflow.distinct(categories)).prefix(8)) : []
        var body: JObject = [
            "v": .int(1), "kind": .string("pca-detector-receipt"), "detector": .string(ctx.detector), "version": .string(ctx.version),
            "input_digest": .string(try PCADetectorReceipt.inputDigest(ctx.content)), "verdict": .string(suspicious ? "suspicious" : "no_finding"),
            "categories": PCADataflow.strs(cats), "iat": iat(ctx.now),
        ]
        if let s = ctx.session { body["session"] = s }
        if let c = ctx.calibrationRef { body["calibration_ref"] = c }
        return try PCADetectorReceipt.sign(.object(body), signer: ctx.signer)
    }

    static func errorReceipt(_ ctx: Context) throws -> JSONValue { try receipt(ctx, true, ["detector_error"]) }

    /// Lakera Guard v2 `/guard` response.
    public static func lakeraReceipt(_ response: JSONValue?, _ ctx: Context) throws -> JSONValue {
        guard case let .object(o)? = response, case .bool(let flagged)? = o["flagged"] else { return try errorReceipt(ctx) }
        var cats: [String] = []
        if let bd = o["breakdown"] {
            guard case let .array(items) = bd else { return try errorReceipt(ctx) }
            for b in items {
                guard case let .object(bo) = b, case .bool(let detected)? = bo["detected"] else { return try errorReceipt(ctx) }
                if detected { cats.append(categoryId(bo["detector_type"])) }
            }
        }
        cats = PCADataflow.distinct(cats)
        let suspicious = flagged || !cats.isEmpty
        if suspicious && cats.isEmpty { cats.append("flagged") }
        return try receipt(ctx, suspicious, cats)
    }

    /// Prompt Security `/api/protect` response (both integration shapes accepted).
    public static func promptSecurityReceipt(_ response: JSONValue?, _ ctx: Context) throws -> JSONValue {
        guard case let .object(top)? = response, case let .object(r)? = top["result"] else { return try errorReceipt(ctx) }
        let p = r["prompt"]
        if p != nil && !isObj(p) { return try errorReceipt(ctx) }
        let actions = [r["action"], isObj(p) ? p?.asObject?["action"] : nil].compactMap { $0 }
        if actions.isEmpty || !actions.allSatisfy({ $0.asString != nil }) { return try errorReceipt(ctx) }
        let violations = isObj(p) ? p?.asObject?["violations"] : nil
        if violations != nil && !(violations?.isArray ?? false) { return try errorReceipt(ctx) }
        var cats = (violations?.asArray ?? []).map { categoryId($0) }
        if actions.contains(where: { IV.same($0.asString, "block") }) { cats.append("blocked") }
        if actions.contains(where: { IV.same($0.asString, "modify") }) { cats.append("modified") }
        cats = PCADataflow.distinct(cats)
        return try receipt(ctx, !cats.isEmpty, cats)
    }

    /// Any detector that answers `{flagged, categories?}`.
    public static func genericReceipt(_ response: JSONValue?, _ ctx: Context) throws -> JSONValue {
        guard case let .object(o)? = response, case .bool(let flagged)? = o["flagged"] else { return try errorReceipt(ctx) }
        var cats: [String] = []
        if let c = o["categories"] {
            guard case let .array(items) = c else { return try errorReceipt(ctx) }
            cats = PCADataflow.distinct(items.map { categoryId($0) })
        }
        if !flagged && !cats.isEmpty { return try errorReceipt(ctx) } // categories on a clean answer: ambiguous
        if flagged && cats.isEmpty { cats.append("flagged") }
        return try receipt(ctx, flagged, cats)
    }
}
