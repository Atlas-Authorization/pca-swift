import Foundation

/// Signed, versioned, expiring measurement-allowlist manifests: verification (issuer keys, suite, validity window, lifetime, version floor, rollback and
/// conflict against a last-seen record), durable verification (the version high-water mark in an atomic key/value store, append-only), creation, signing,
/// revocation, the projection to per-vendor policy fields (Azure MAA, Intel DCAP, SEV-SNP, GCP Confidential Space, NVIDIA) and the driver-version slot
/// encoding. Manifests, bodies and projections are the language-neutral JSON of the wire; every failure is closed.
public enum PCAAttestAllowlist {
    public static let ALLOWLIST_KINDS = ["tdx-mrtd", "tdx-rtmr", "sev-snp-measurement", "gcp-image-digest", "nvidia-measurement", "nvidia-driver-version", "maa-signing-spki",
                                         "maa-chain-root-spki", "maa-chain-intermediate-spki", "attest-corroboration"]
    static let DOMAIN = "pca-attest-allowlist/v1\n"
    private static let MAX_ENTRIES = 10_000
    private static let BODY_KEYS = ["version", "issuedAt", "notBefore", "expiresAt", "entries"]
    private static let ENTRY_KEYS = ["kind", "value", "label", "notAfter", "revoked"]
    private static let MANIFEST_KEYS = ["body", "issuer", "alg", "sig", "pq_sig"]

    // MARK: the value profiles (the reference's regular expressions, spelled out over scalars: no line-terminator surprises)

    private static func lowerHex(_ s: String, _ n: Int) -> Bool {
        let u = Array(s.unicodeScalars)
        return u.count == n && u.allSatisfy { ($0.value >= 48 && $0.value <= 57) || ($0.value >= 97 && $0.value <= 102) }
    }
    private static func digits<S: Sequence>(_ u: S) -> Bool where S.Element == Unicode.Scalar { u.allSatisfy { $0.value >= 48 && $0.value <= 57 } }
    private static func imageDigest(_ s: String) -> Bool { s.unicodeScalars.starts(with: "sha256:".unicodeScalars) && lowerHex(String(s.dropFirst(7)), 64) }
    /// `^[0-9]{1,6}(\.[0-9]{1,6}){1,3}$`
    private static func driverVersion(_ s: String) -> Bool {
        let parts = s.unicodeScalars.split(separator: ".", omittingEmptySubsequences: false)
        return (2...4).contains(parts.count) && parts.allSatisfy { (1...6).contains($0.count) && digits($0) }
    }
    /// `^vantages=[1-9][0-9]{0,2};method=[\x20-\x7e]{1,150}$`
    private static func corroborationLabel(_ s: String) -> Bool {
        let u = Array(s.unicodeScalars)
        let head = Array("vantages=".unicodeScalars)
        guard u.count > head.count, Array(u[0..<head.count]) == head else { return false }
        var i = head.count
        let start = i
        while i < u.count, u[i].value >= 48 && u[i].value <= 57 { i += 1 }
        guard (1...3).contains(i - start), u[start].value != 48 else { return false }
        let mid = Array(";method=".unicodeScalars)
        guard i + mid.count < u.count, Array(u[i..<(i + mid.count)]) == mid else { return false }
        let rest = u[(i + mid.count)...]
        return (1...150).contains(rest.count) && rest.allSatisfy { $0.value >= 0x20 && $0.value <= 0x7e }
    }
    /// `^https:\/\/[a-z0-9]([a-z0-9.-]*[a-z0-9])?(:[0-9]{1,5})?$`
    private static func issuerUrl(_ s: String) -> Bool {
        guard s.unicodeScalars.starts(with: "https://".unicodeScalars) else { return false }
        let rest = Array(s.unicodeScalars.dropFirst(8))
        func alnum(_ c: Unicode.Scalar) -> Bool { (c.value >= 48 && c.value <= 57) || (c.value >= 97 && c.value <= 122) }
        var i = 0
        while i < rest.count, alnum(rest[i]) || rest[i] == "." || rest[i] == "-" { i += 1 }
        let host = rest[0..<i]
        guard let f = host.first, let l = host.last, alnum(f), alnum(l) else { return false }
        let tail = rest[i...]
        if tail.isEmpty { return true }
        return tail.first == ":" && (1...5).contains(tail.count - 1) && digits(tail.dropFirst())
    }

    private static func valueError(_ kind: String, _ value: String, _ label: String) -> String? {
        switch kind {
        case "tdx-mrtd", "tdx-rtmr", "sev-snp-measurement", "nvidia-measurement": return lowerHex(value, 96) ? nil : "\(kind) must be 96 lowercase hex chars"
        case "gcp-image-digest": return imageDigest(value) ? nil : "gcp-image-digest must be sha256:<64 lowercase hex>"
        case "nvidia-driver-version": return driverVersion(value) && value.utf16.count <= 16 ? nil : "nvidia-driver-version must be a dotted version of at most 16 chars"
        case "maa-signing-spki":
            if !lowerHex(value, 64) { return "maa-signing-spki must be 64 lowercase hex chars" }
            return issuerUrl(label) ? nil : "maa-signing-spki label must be the https issuer URL (no path, no trailing slash)"
        case "maa-chain-root-spki", "maa-chain-intermediate-spki": return lowerHex(value, 64) ? nil : "\(kind) must be 64 lowercase hex chars"
        default:
            if !lowerHex(value, 64) { return "attest-corroboration must be a 64 lowercase hex evidence digest" }
            return corroborationLabel(label) ? nil : "attest-corroboration label must be vantages=<n>;method=<text>"
        }
    }

    private static func isEpoch(_ v: JSONValue?) -> Double? {
        guard let d = IV.num(v), d.isFinite, d.rounded() == d, abs(d) <= IV.MAX_SAFE, d >= 0, !(d == 0 && d.sign == .minus) else { return nil }
        return d
    }

    private static func tErr(_ m: String) -> JSError { JSError(m) }

    /// The body of a manifest, validated: exactly version / issuedAt / notBefore / expiresAt / entries; entries bounded, each of a known kind with a value
    /// of the kind's profile, a printable label, an optional integer `notAfter` and `revoked: true`, without duplicates. Throws on any violation.
    static func parseBody(_ x: JSONValue?) throws -> JSONValue {
        guard let b = x?.asObject, b.keys.allSatisfy({ BODY_KEYS.contains($0.s) }) else { throw tErr("body must be an object with exactly version/issuedAt/notBefore/expiresAt/entries") }
        guard let version = IV.num(b["version"]), version.isFinite, version.rounded() == version, abs(version) <= IV.MAX_SAFE, version >= 1 else { throw tErr("version must be a positive integer") }
        guard let issuedAt = isEpoch(b["issuedAt"]), let notBefore = isEpoch(b["notBefore"]), let expiresAt = isEpoch(b["expiresAt"]) else { throw tErr("issuedAt/notBefore/expiresAt must be integer epoch ms") }
        guard notBefore < expiresAt else { throw tErr("notBefore must be before expiresAt") }
        guard issuedAt <= expiresAt else { throw tErr("issuedAt must not be after expiresAt") }
        guard case let .array(entries)? = b["entries"], entries.count <= MAX_ENTRIES else { throw tErr("entries must be an array (bounded)") }
        var seen = Set<[UInt16]>()
        var out: [JSONValue] = []
        for (i, e) in entries.enumerated() {
            guard let r = e.asObject, r.keys.allSatisfy({ ENTRY_KEYS.contains($0.s) }) else { throw tErr("entry \(i): unexpected shape") }
            guard case let .string(kind)? = r["kind"], ALLOWLIST_KINDS.contains(kind) else { throw tErr("entry \(i): unknown kind") }
            guard case let .string(value)? = r["value"], case let .string(label)? = r["label"] else { throw tErr("entry \(i): value and label must be strings") }
            let n = label.utf16.count
            if n < 1 || n > 200 || label.utf16.contains(where: { $0 <= 0x1f || $0 == 0x7f }) { throw tErr("entry \(i): label must be 1..200 printable chars") }
            if let ve = valueError(kind, value, label) { throw tErr("entry \(i): \(ve)") }
            if let na = r["notAfter"], isEpoch(na) == nil { throw tErr("entry \(i): notAfter must be integer epoch ms") }
            if let rv = r["revoked"], rv != .bool(true) { throw tErr("entry \(i): revoked, when present, must be true") }
            let dup = kind + "\u{0}" + (kind == "maa-signing-spki" ? label + "\u{0}" : "") + value
            if !seen.insert(Array(dup.utf16)).inserted { throw tErr("entry \(i): duplicate \(kind) value") }
            var o: JObject = ["kind": .string(kind), "value": .string(value), "label": .string(label)]
            if let na = r["notAfter"] { o["notAfter"] = na }
            if r["revoked"] == .bool(true) { o["revoked"] = .bool(true) }
            out.append(.object(o))
        }
        return .object(["version": b["version"]!, "issuedAt": b["issuedAt"]!, "notBefore": b["notBefore"]!, "expiresAt": b["expiresAt"]!, "entries": .array(out)])
    }

    static func signedBytes(_ body: JSONValue) throws -> [UInt8] { try PCAIntentKit.message(DOMAIN, body) }
    private static func hashStrict(_ v: JSONValue) throws -> String { Base64URLStrict.encode(Canonical.sha256(try Canonical.canonicalBytes(v))) }

    // MARK: verification

    public struct VerifyOptions {
        /// `{<issuer id>: {alg, keys: {edPub?, mlDsaPub?, slhDsaPub?, mlDsa87Pub?, slhDsa256sPub?, ...}, notAfter?}}` (public keys, base64url).
        public var issuerKeys: JSONValue
        public var nowMs: Double
        public var minVersion: JSONValue?
        public var lastSeenVersion: JSONValue?
        public var lastSeenDigest: JSONValue?
        public var clockSkewMs: JSONValue?
        public var maxLifetimeMs: JSONValue?
        public init(issuerKeys: JSONValue, nowMs: Double, minVersion: JSONValue? = nil, lastSeenVersion: JSONValue? = nil, lastSeenDigest: JSONValue? = nil,
                    clockSkewMs: JSONValue? = nil, maxLifetimeMs: JSONValue? = nil) {
            self.issuerKeys = issuerKeys; self.nowMs = nowMs; self.minVersion = minVersion; self.lastSeenVersion = lastSeenVersion; self.lastSeenDigest = lastSeenDigest
            self.clockSkewMs = clockSkewMs; self.maxLifetimeMs = maxLifetimeMs
        }
    }

    private static func fail(_ code: String, _ reason: String) -> JSONValue { .object(["ok": .bool(false), "code": .string(code), "reason": .string(reason)]) }

    /// The public key material of an issuer's suite: the Ed25519 key for the classical half, the post-quantum key by suite.
    private static func pqKey(_ suite: PQ.Suite, _ k: JSONValue?) -> JSONValue? {
        let name: String
        if suite.pq == .mlDsa65 { name = "mlDsaPub" } else if suite.pq == .mlDsa87 { name = "mlDsa87Pub" } else if suite.slh == "SLH-DSA-SHA2-128f" { name = "slhDsaPub" }
        else if suite.slh == "SLH-DSA-SHA2-256s" { name = "slhDsa256sPub" } else if suite.fnDsa == "fn-dsa-512" { name = "fnDsa512Pub" } else if suite.fnDsa == "fn-dsa-1024" { name = "fnDsa1024Pub" }
        else if suite.lessCat1 { name = "lessCat1Pub" } else { return nil }
        return k?.get(name)
    }

    private static func finite(_ v: JSONValue?) -> Bool { IV.num(v).map { $0.isFinite } ?? false }
    private static func safeInteger(_ v: JSONValue?) -> Bool { IV.num(v).map { $0.isFinite && $0.rounded() == $0 && abs($0) <= IV.MAX_SAFE } ?? false }

    /// Verifies a signed manifest `{body, issuer, alg, sig, pq_sig?}` and returns `{ok: true, body, issuer, alg, version, digest}` or `{ok: false, code,
    /// reason}`. The checks and their order: the shape; the clock; the issuer, suite and signature fields; the body; the registered issuer, its suite and
    /// expiry; the signature (a post-quantum half verifies only under the registered key); the option types; the validity window and lifetime; the
    /// minimum version; the rollback floor and the same-version conflict. Never throws.
    public static func verifyAllowlistManifest(_ manifest: JSONValue?, _ opts: VerifyOptions) -> JSONValue {
        do {
            guard let m = manifest?.asObject, m.keys.allSatisfy({ MANIFEST_KEYS.contains($0.s) }) else { return fail("malformed", "manifest has an unexpected shape") }
            guard opts.nowMs.isFinite, opts.nowMs.rounded() == opts.nowMs, abs(opts.nowMs) <= IV.MAX_SAFE else { return fail("malformed", "nowMs must be an integer") }
            guard case let .string(issuer)? = m["issuer"], !issuer.isEmpty, issuer.utf16.count <= 200 else { return fail("malformed", "issuer must be a string") }
            guard case let .string(alg)? = m["alg"], let suite = PQ.resolve(alg) else { return fail("malformed", "unknown signature alg") }
            guard case .string? = m["sig"] else { return fail("malformed", "sig must be a string") }
            let pqSig = m["pq_sig"]
            if let p = pqSig, p.asString == nil { return fail("malformed", "pq_sig must be a string") }
            if !suite.needsPqSig != (pqSig == nil) { return fail("malformed", "pq_sig presence does not match the suite") }
            let body: JSONValue
            do { body = try parseBody(m["body"]) } catch { return fail("malformed", (error as? JSError)?.message ?? "invalid body") }
            guard let reg = opts.issuerKeys.get(issuer), opts.issuerKeys.asObject?.keys.contains(where: { IV.same($0.s, issuer) }) == true else {
                return fail("unknown-issuer", "issuer '\(issuer)' is not registered")
            }
            if !(reg.get("alg")?.asString.map { IV.same($0, alg) } ?? false) { return fail("alg-mismatch", "issuer is registered for '\(JS.toString(reg.get("alg")))', manifest claims '\(alg)'") }
            if let na = reg.get("notAfter"), !(opts.nowMs <= PCAAttestation.toNumber(na)) { return fail("issuer-expired", "issuer key is past its notAfter") }
            let keys = reg.get("keys")
            let pk = suite.needsPqPk ? pqKey(suite, keys) : nil
            let pkS = pk?.asString
            let ok = IV.verifyPinned(alg: .string(alg), identity: keys?.get("edPub")?.asString ?? "", artifactPqPk: pkS.map { .string($0) }, msg: try signedBytes(body), sig: m["sig"],
                                     pqSig: pqSig, pin: pkS) == .valid
            if !ok { return fail("bad-signature", "signature does not verify under the registered issuer key") }
            if let s = opts.clockSkewMs, !finite(s) { return fail("malformed", "clockSkewMs must be a finite number") }
            if let s = opts.maxLifetimeMs, !finite(s) { return fail("malformed", "maxLifetimeMs must be a finite number") }
            if let s = opts.minVersion, !safeInteger(s) { return fail("malformed", "minVersion must be an integer") }
            if let s = opts.lastSeenVersion, !safeInteger(s) { return fail("malformed", "lastSeenVersion must be an integer") }
            let skew = Swift.max(0, IV.num(opts.clockSkewMs) ?? 0)
            let version = IV.num(body.get("version"))!, notBefore = IV.num(body.get("notBefore"))!, expiresAt = IV.num(body.get("expiresAt"))!
            if !(opts.nowMs + skew >= notBefore) { return fail("not-yet-valid", "manifest is not yet valid") }
            if !(opts.nowMs - skew <= expiresAt) { return fail("expired", "manifest has expired") }
            if let ml = IV.num(opts.maxLifetimeMs), !(expiresAt - notBefore <= ml) { return fail("lifetime-too-long", "manifest lifetime exceeds maxLifetimeMs") }
            if let mv = IV.num(opts.minVersion), version < mv { return fail("below-min-version", "version \(JS.number(version)) < minVersion \(JS.number(mv))") }
            let digest = try hashStrict(body)
            if let ls = IV.num(opts.lastSeenVersion) {
                if version < ls { return fail("rollback", "version \(JS.number(version)) is older than last seen \(JS.number(ls))") }
                if version == ls, let d = opts.lastSeenDigest, !(d.asString.map { IV.same($0, digest) } ?? false) { return fail("conflict", "same version as last seen but a different body") }
            }
            return .object(["ok": .bool(true), "body": body, "issuer": .string(issuer), "alg": .string(alg), "version": body.get("version")!, "digest": .string(digest)])
        } catch {
            return fail("malformed", (error as? JSError)?.message ?? "verification error")
        }
    }

    // MARK: durable verification

    private static func parseMark(_ v: JSONValue?) -> (version: Double, digest: String)? {
        guard let o = v?.asObject, let ver = IV.num(o["version"]), ver.isFinite, ver.rounded() == ver, abs(ver) <= IV.MAX_SAFE, !(ver == 0 && ver.sign == .minus),
              case let .string(d)? = o["digest"], d.unicodeScalars.count == 43, d.unicodeScalars.allSatisfy({ ($0.value >= 48 && $0.value <= 57) || ($0.value >= 65 && $0.value <= 90) || ($0.value >= 97 && $0.value <= 122) || $0.value == 45 || $0.value == 95 }) else { return nil }
        return (ver, d)
    }

    /// Verifies a manifest against the version high-water mark held in `kv` (key `allowlist/<issuer>` = `{version, digest}`), and records an accepted
    /// manifest atomically. Versions are append-only: a record at or above the manifest's version is kept as stored; an older manifest is a `rollback`, the
    /// same version with another body a `conflict`; a corrupt record is `malformed`; a refused manifest never advances the mark.
    public static func verifyAllowlistDurable(_ manifest: JSONValue?, _ opts: VerifyOptions, _ kv: AtomicKV) -> JSONValue {
        do {
            guard let issuer = manifest?.get("issuer")?.asString, issuer.utf16.count <= 200 else { return fail("malformed", "issuer must be a string") }
            let key = "allowlist/" + issuer
            let raw = try kv.get(key)
            let prior = raw.flatMap { parseMark($0) }
            if raw != nil, prior == nil { return fail("malformed", "persisted allowlist high-water mark is corrupt") }
            var o = opts
            if let p = prior { o.lastSeenVersion = .int(Int64(p.version)); o.lastSeenDigest = .string(p.digest) }
            let v = verifyAllowlistManifest(manifest, o)
            if v.get("ok") != .bool(true) { return v }
            let ver = IV.num(v.get("version"))!, dig = v.get("digest")!.asString!
            var now: (version: Double, digest: String)?
            var nowCorrupt = false
            try kv.update(key) { cur in
                if let c = cur { if let p = parseMark(c) { now = p } else { nowCorrupt = true } }
                // the append-only update: a corrupt record is left alone, a record at or above this version is kept
                if nowCorrupt { return nil }
                if let n = now, n.version >= ver { return nil }
                return .object(["version": v.get("version")!, "digest": .string(dig)])
            }
            if nowCorrupt { return fail("rollback", "a newer manifest was accepted concurrently") }
            let after: (version: Double, digest: String) = (now.map { $0.version >= ver } ?? false) ? now! : (ver, dig)
            if after.version > ver { return fail("rollback", "a newer manifest was accepted concurrently") }
            if after.version == ver, !IV.same(after.digest, dig) { return fail("conflict", "same version as the stored high-water mark but a different body") }
            return v
        } catch {
            return fail("malformed", (error as? JSError)?.message ?? "durable verification error")
        }
    }

    // MARK: creation, signing, revocation

    /// The validated body (throws on any violation).
    public static func createAllowlistManifest(_ input: JSONValue?) throws -> JSONValue { try parseBody(input) }

    /// Signs the validated body as `key` (the suite and its keys): `{body, issuer, alg, sig, pq_sig?}`.
    public static func signAllowlistManifest(_ body: JSONValue?, issuer: String, key: PCASuiteKey) throws -> JSONValue {
        let clean = try parseBody(body)
        let parts = try key.sign(try signedBytes(clean))
        var o: JObject = ["body": clean, "issuer": .string(issuer), "alg": .string(key.alg), "sig": .string(parts.sig)]
        if let q = parts.pqSig { o["pq_sig"] = .string(q) }
        return .object(o)
    }

    /// The next version of `prev` with one entry revoked (or a revocation entry added): `rev = {kind, value, label?}`, `times = {issuedAt, notBefore,
    /// expiresAt}`. A `maa-signing-spki` entry is matched by its label too.
    public static func revokeAllowlistEntry(_ prev: JSONValue?, _ rev: JSONValue?, _ times: JSONValue?) throws -> JSONValue {
        guard case let .array(es)? = prev?.get("entries") else { throw tErr("Cannot read properties of undefined (reading 'map')") }
        var entries = es
        let kind = rev?.get("kind"), value = rev?.get("value"), label = rev?.get("label")
        let hit = entries.firstIndex { e in
            strictEq(e.get("kind"), kind) && strictEq(e.get("value"), value) && (kind?.asString != "maa-signing-spki" || strictEq(e.get("label"), label))
        }
        if let h = hit, case var .object(o) = entries[h] { o["revoked"] = .bool(true); entries[h] = .object(o) }
        else {
            var o: JObject = ["label": JS.present(label) ?? .string("revoked"), "revoked": .bool(true)]
            if let k = kind { o["kind"] = k }
            if let v = value { o["value"] = v }
            entries.append(.object(o))
        }
        // `prev.version + 1`: a number, null (0) or a boolean adds; anything else concatenates or is NaN, and the body check refuses it
        let next: Double
        switch prev?.get("version") {
        case let .int(i)?: next = Double(i) + 1
        case let .double(d)?: next = d + 1
        case .null?: next = 1
        case let .bool(b)?: next = (b ? 1 : 0) + 1
        default: throw tErr("version must be a positive integer")
        }
        var body: JObject = [:]
        for (k, v) in times?.asObject ?? [:] { body[k] = v }
        body["version"] = StoreJ.num(next)
        body["entries"] = .array(entries)
        return try parseBody(.object(body))
    }

    /// JavaScript `===` on JSON values (objects and arrays are never identical; two absent values are).
    private static func strictEq(_ a: JSONValue?, _ b: JSONValue?) -> Bool {
        switch (a, b) {
        case (nil, nil): return true
        case let (x?, y?):
            switch (x, y) {
            case let (.string(p), .string(q)): return IV.same(p, q)
            case (.null, .null): return true
            case let (.bool(p), .bool(q)): return p == q
            default: if let p = IV.num(x), let q = IV.num(y) { return p == q }; return false
            }
        default: return false
        }
    }

    /// The NVIDIA CC driver-version slot: the ASCII hex of the version, right-padded with `0` to 32 characters. Throws on a malformed version.
    public static func driverVersionSlotHex(_ version: JSONValue?) throws -> String {
        guard case let .string(v)? = version, driverVersion(v), v.utf16.count <= 16 else { throw tErr("invalid driver version") }
        let h = ACrypto.hex(Array(v.utf8))
        return h + String(repeating: "0", count: Swift.max(0, 32 - h.count))
    }

    // MARK: projection

    /// The per-vendor view of a verified manifest at `nowMs`: revoked entries (and every entry of a revoked kind and value) are denied, entries past their
    /// `notAfter` are listed as expired, the rest are sorted into the vendor lists.
    public static func projectAllowlist(_ verified: JSONValue, nowMs: Double) throws -> JSONValue {
        guard let body = verified.get("body"), case let .array(entries)? = body.get("entries") else { throw tErr("Cannot read properties of undefined (reading 'entries')") }
        var lists: [String: [JSONValue]] = [:]
        var spkis: [(label: String, values: [JSONValue])] = []
        var revoked: [JSONValue] = [], expired: [JSONValue] = []
        var denied = Set<[UInt16]>()
        func tag(_ e: JSONValue) -> JSONValue { .object(["kind": e.get("kind") ?? .null, "value": e.get("value") ?? .null, "label": e.get("label") ?? .null]) }
        func dkey(_ e: JSONValue) -> [UInt16] { Array(((e.get("kind")?.asString ?? "") + "\u{0}" + (e.get("value")?.asString ?? "")).utf16) }
        for e in entries where e.get("revoked") == .bool(true) { denied.insert(dkey(e)); revoked.append(tag(e)) }
        for e in entries {
            if e.get("revoked") == .bool(true) || denied.contains(dkey(e)) { continue }
            if let na = e.get("notAfter"), !(nowMs.isFinite && nowMs <= PCAAttestation.toNumber(na)) { expired.append(tag(e)); continue }
            let v = e.get("value") ?? .null
            switch e.get("kind")?.asString {
            case "tdx-mrtd"?: lists["tdxMrtds", default: []].append(v)
            case "tdx-rtmr"?: lists["tdxRtmrs", default: []].append(v)
            case "sev-snp-measurement"?: lists["sevSnpMeasurements", default: []].append(v)
            case "gcp-image-digest"?: lists["imageDigests", default: []].append(v)
            case "nvidia-measurement"?: lists["nvidiaMeasurements", default: []].append(v)
            case "nvidia-driver-version"?:
                lists["nvidiaDriverVersions", default: []].append(v)
                lists["nvidiaCcDriverVersions", default: []].append(.string(try driverVersionSlotHex(v)))
            case "maa-signing-spki"?:
                let l = e.get("label")?.asString ?? ""
                if let i = spkis.firstIndex(where: { IV.same($0.label, l) }) { spkis[i].values.append(v) } else { spkis.append((l, [v])) }
            case "maa-chain-root-spki"?: lists["maaChainRootSpkis", default: []].append(v)
            case "maa-chain-intermediate-spki"?: lists["maaChainIntermediateSpkis", default: []].append(v)
            case "attest-corroboration"?: lists["corroboration", default: []].append(.object(["value": v, "label": e.get("label") ?? .null]))
            default: break
            }
        }
        var maa = JObject()
        for s in spkis { maa[JKey(s.label)] = .array(s.values) }
        var out: JObject = ["maaSigningSpkis": .object(maa), "revoked": .array(revoked), "expired": .array(expired), "version": body.get("version") ?? .null,
                            "manifestExpiresAt": body.get("expiresAt") ?? .null]
        for k in ["tdxMrtds", "tdxRtmrs", "sevSnpMeasurements", "imageDigests", "nvidiaMeasurements", "nvidiaDriverVersions", "nvidiaCcDriverVersions", "maaChainRootSpkis",
                  "maaChainIntermediateSpkis", "corroboration"] { out[JKey(k)] = .array(lists[k] ?? []) }
        return .object(out)
    }

    // MARK: vendor policy fields

    private static func list(_ p: JSONValue, _ k: String) -> [JSONValue] { p.get(k)?.asArray ?? [] }

    /// Azure MAA: the TDX MRTDs, SEV-SNP measurements and TDX RTMRs, each only when non-empty.
    public static func azureMaaPolicyFields(_ p: JSONValue) -> JSONValue {
        var o = JObject()
        for (k, src) in [("tdxMrtds", "tdxMrtds"), ("sevSnpMeasurements", "sevSnpMeasurements"), ("tdxRtmrs", "tdxRtmrs")] where !list(p, src).isEmpty { o[JKey(k)] = .array(list(p, src)) }
        return .object(o)
    }

    /// Intel DCAP: `{mrtds, rtmrs?}`.
    public static func intelDcapPolicyFields(_ p: JSONValue) -> JSONValue {
        var o: JObject = ["mrtds": .array(list(p, "tdxMrtds"))]
        if !list(p, "tdxRtmrs").isEmpty { o["rtmrs"] = .array(list(p, "tdxRtmrs")) }
        return .object(o)
    }

    /// AMD SEV-SNP: `{measurements}`.
    public static func sevSnpPolicyFields(_ p: JSONValue) -> JSONValue { .object(["measurements": .array(list(p, "sevSnpMeasurements"))]) }

    /// GCP Confidential Space: `{imageDigests}`.
    public static func gcpCsPolicyFields(_ p: JSONValue) -> JSONValue { .object(["imageDigests": .array(list(p, "imageDigests"))]) }

    /// NVIDIA CC: `{measurements, driverVersions?}` (the driver versions as slot hex).
    public static func nvidiaCcPolicyFields(_ p: JSONValue) -> JSONValue {
        var o: JObject = ["measurements": .array(list(p, "nvidiaMeasurements"))]
        if !list(p, "nvidiaCcDriverVersions").isEmpty { o["driverVersions"] = .array(list(p, "nvidiaCcDriverVersions")) }
        return .object(o)
    }
}
