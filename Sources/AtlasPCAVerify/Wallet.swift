import Foundation

/// The wallet side of the PCA Intent Layer v2: the principal-signed answer (wire), friction tiers scaled by harm, cell coordinates over
/// the wallet's own outcome space, the statistics behind the noise estimates, attention canaries and the approval-fatigue model. A
/// port of the TypeScript reference (@atlasauth/pca-wallet). The trusted card and clarification planning live in `WalletCard.swift`,
/// risk-priced escalation in `WalletPricing.swift`, the question channel in `WalletChannel.swift`.
///
/// Values are `JSONValue`. A reference refusal that is a thrown Error is a thrown `JSError` here. Where an object's member order
/// decides which problem is reported first, members are visited in canonical key order (a parsed object has no insertion order).
public enum PCAWallet {
    public static let INTENT_ANSWER_SIG_DOMAIN = "atlas-pca/intent-obs/v2\u{0}"
    public static let INTENT_ANSWER_REF_DOMAIN = "atlas-pca/intent-answer-ref/v1"
    public static let INTENT_TYPED_DOMAIN = "atlas-pca/intent-typed/v1"
    public static let INTENT_DEVICE_CHALLENGE_DOMAIN = "atlas-pca/intent-device/v1"
    public static let INTENT_ACTION_DOMAIN = "atlas-pca/intent-action/v1"
    public static let MIN_HOLD_MS = 2000

    // ---- friction (wire.ts, friction.ts) ----

    public static let FRICTION_ORDER = ["tap", "hold", "typed", "device"]
    public static let PROVENANCE_ORDER = ["trusted", "first_party", "tool", "web", "agent"]
    static let TAINTED = ["web", "agent"]

    public static func isFrictionTier(_ x: JSONValue?) -> Bool { x?.asString.map { IV.contains(FRICTION_ORDER, $0) } ?? false }

    public static func frictionRank(_ t: JSONValue?) -> Int {
        guard let s = t?.asString, let i = FRICTION_ORDER.firstIndex(where: { IV.same($0, s) }) else { return -1 }
        return i
    }

    /// `maxFriction(...ts)`: the strongest tier (the first of equals), "tap" for none.
    public static func maxFriction(_ ts: [JSONValue]) -> JSONValue {
        var best: JSONValue = .string("tap")
        for t in ts where frictionRank(t) > frictionRank(best) { best = t }
        return best
    }

    public static func satisfiesTier(_ given: JSONValue?, _ required: JSONValue?) -> Bool { frictionRank(given) >= frictionRank(required) }

    public static func isProvenanceLevel(_ x: JSONValue?) -> Bool { x?.asString.map { IV.contains(PROVENANCE_ORDER, $0) } ?? false }

    /// The least trusted level of a set; "agent" for an empty or unknown set (fail closed). A non-iterable value throws.
    public static func worstProvenance(_ levels: JSONValue?) throws -> String {
        var best = -1
        for l in try JS.spread(levels) {
            guard let s = l.asString, let i = PROVENANCE_ORDER.firstIndex(where: { IV.same($0, s) }) else { return "agent" }
            best = max(best, i)
        }
        return best < 0 ? "agent" : PROVENANCE_ORDER[best]
    }

    /// The decision {tier, rules} of the friction rule (the spec table); `th` = {hTap, hDevice}.
    public static func frictionFor(_ inp: JSONValue?, _ th: JSONValue? = nil) throws -> JSONValue {
        let hTap = IV.num(th?.get("hTap")) ?? (th == nil ? 5 : .nan)
        let hDevice = IV.num(th?.get("hDevice")) ?? (th == nil ? 100_000 : .nan)
        guard let harm = IV.num(inp?.get("expectedHarm")), harm.isFinite, harm >= 0 else {
            return WJ.obj([("tier", .string("device")), ("rules", .array([.string("harm-unknown")]))])
        }
        var rules: [String] = []
        var tier: JSONValue = .string("tap")
        func raise(_ t: JSONValue, _ why: String) {
            if frictionRank(t) >= frictionRank(tier) { rules.append(why) }
            tier = maxFriction([tier, t])
        }
        let rev = inp?.get("reversibility")
        if WJ.isStr(rev, "rate_limited") { raise(.string("hold"), "rate-limited") }
        if harm >= hTap { raise(.string("hold"), "harm>=h_tap") }
        if WJ.isStr(rev, "irreversible") { raise(.string("typed"), "irreversible") }
        var taintedCritical = false
        if let p = JS.present(inp?.get("provenance")) {
            guard let list = p.asArray else { throw JSError("provenance.some is not a function") }
            for e in list {
                if WJ.isStr(e.get("sensitivity"), "critical"), TAINTED.contains(try worstProvenance(e.get("levels"))) { taintedCritical = true; break }
            }
        }
        if taintedCritical { raise(.string("typed"), "tainted-critical") }
        if JS.truthy(inp?.get("widensCriticalIdentity")) && WJ.isStr(rev, "irreversible") { raise(.string("device"), "critical-irreversible") }
        if harm >= hDevice { raise(.string("device"), "harm>=h_device") }
        if JS.truthy(inp?.get("singleSource")) {
            raise(.string(FRICTION_ORDER[min(FRICTION_ORDER.count - 1, frictionRank(tier) + 1)]), "single-source")
        }
        if let m = inp?.get("siteMin") { raise(m, "site-minimum") }
        return WJ.obj([("tier", tier), ("rules", .array(rules.map { .string($0) }))])
    }

    // ---- helpers (wire.ts) ----

    public static func isObj(_ v: JSONValue?) -> Bool { v?.isObject ?? false }
    public static func isB64u32(_ v: JSONValue?) -> Bool { IV.digest(v) != nil }
    public static func coordsError(_ c: JSONValue?) -> String? { PCASigners.cellCoordsError(c) }

    /// The V3 action digest of an attempted action (what `intent_required.action_digest` and a JIT consent bind to).
    public static func pcaActionDigest(_ a: JSONValue?) throws -> String {
        var act = JObject()
        for k in ["verb", "resource"] {
            guard let v = a?.get(k) else { throw JSError("canonicalize: undefined") }
            act[JKey(k)] = v
        }
        let params = a?.get("params")
        act["params_digest"] = .string(try WJ.hash(JS.present(params) ?? .object([:])))
        guard let rc = a?.get("reversibility_class") else { throw JSError("canonicalize: undefined") }
        act["reversibility_class"] = rc
        return try WJ.hash(WJ.obj([("d", .string(INTENT_ACTION_DOMAIN)), ("action", .object(act))]))
    }

    /// The default projection of an attempted action onto Omega paths: the resource and every scalar param.
    public static func actionValuesOf(_ a: JSONValue?) throws -> JSONValue {
        var values = JObject()
        if let r = a?.get("resource") { values["action.resource"] = r }
        for (k, v) in try WJ.entries(a?.get("params")) {
            if v.asString != nil || WJ.isFiniteNumber(v) { values[JKey("action.params." + k)] = v }
        }
        var out: JObject = ["values": .object(values)]
        if let v = a?.get("verb") { out["verb"] = v }
        return .object(out)
    }

    // ---- M6: the signed answer ----

    static let ANS_KEYS = ["v", "kind", "map_digest", "session", "question_id", "verb", "cell", "y", "partial", "source", "observed_at", "ux", "signer", "alg", "sig"]
    static let UX_KEYS = ["tier", "rendered_digest", "typed_digest", "hold_ms", "webauthn", "canary", "action_digest", "consent_for_action"]
    static let WA_KEYS = ["credential_id", "authenticator_data", "client_data_json", "signature"]

    /// The members of an object in canonical key order (index keys first, as a JS object lists them).
    static func keysOf(_ o: JObject) -> [String] {
        (try? WJ.entries(.object(o)).map { $0.0 }) ?? []
    }

    static func onlyKeys(_ o: JObject, _ allowed: [String]) -> String? {
        for k in keysOf(o) where !IV.contains(allowed, k) { return "unknown member \"\(k)\"" }
        return nil
    }

    static func partialError(_ pv: JSONValue?) -> String? {
        guard case let .object(p)? = pv, let path = p["path"]?.asString, !path.isEmpty else { return "partial.path must be a non-empty string" }
        let keys = keysOf(p).filter { $0 != "path" }
        if keys.count != 1 { return "partial must carry exactly one of upTo / from / except / notFor" }
        let k = keys[0]
        let v = p[JKey(k)]
        if (k == "upTo" || k == "from") && !WJ.isInt(v) { return "partial.\(k) must be an integer" }
        if k == "except" && !(v?.asArray.map { !$0.isEmpty && $0.allSatisfy { WJ.isInt($0) } } ?? false) { return "partial.except must be a non-empty integer array" }
        if k == "notFor" && !(v?.asArray.map { !$0.isEmpty && $0.allSatisfy { !($0.asString ?? "").isEmpty } } ?? false) { return "partial.notFor must be a non-empty string array" }
        if !["upTo", "from", "except", "notFor"].contains(k) { return "unknown partial member \"\(k)\"" }
        return nil
    }

    public static func answerShapeError(_ av: JSONValue?) -> String? {
        guard case let .object(a)? = av else { return "not an object" }
        if let extra = onlyKeys(a, ANS_KEYS) { return extra }
        if !WJ.numEq(a["v"], 2) || !WJ.isStr(a["kind"], "pca-intent-observation") { return "not a pca-intent-observation v2" }
        for k in ["map_digest", "session", "signer"] where IV.digest(a[JKey(k)]) == nil { return "\(k) is not canonical base64url (32 bytes)" }
        guard let qid = a["question_id"]?.asString, PCASigners.questionIdOK(qid) else { return "question_id must match [A-Za-z0-9_-]{1,64}" }
        guard let verb = a["verb"]?.asString, !verb.isEmpty else { return "verb must be a non-empty string" }
        _ = verb
        if let ce = coordsError(a["cell"]) { return "cell: " + ce }
        let yOne = WJ.numEq(a["y"], 1)
        if !(WJ.numEq(a["y"], 0) || yOne) { return "y must be 0 or 1" }
        let hasPartial = a["partial"] != nil
        if hasPartial {
            if let pe = partialError(a["partial"]) { return pe }
            if !yOne { return "a partial answer carries y = 1 (yes for the part)" }
        }
        if !(WJ.isStr(a["source"], "elicitation") || WJ.isStr(a["source"], "clarification")) { return "source must be elicitation or clarification" }
        if IV.nonNeg(a["observed_at"]) == nil { return "observed_at must be a non-negative safe integer" }
        if !WJ.isStr(a["alg"], "ed25519") { return "alg must be ed25519" }
        guard case let .object(ux)? = a["ux"] else { return "ux must be an object" }
        if let ue = onlyKeys(ux, UX_KEYS) { return "ux: " + ue }
        if !isFrictionTier(ux["tier"]) { return "ux.tier is not a friction tier" }
        if IV.digest(ux["rendered_digest"]) == nil { return "ux.rendered_digest is not canonical base64url (32 bytes)" }
        guard case let .bool(canary)? = ux["canary"] else { return "ux.canary must be a boolean" }
        if ux["typed_digest"] != nil && IV.digest(ux["typed_digest"]) == nil { return "ux.typed_digest is not canonical base64url (32 bytes)" }
        if let h = ux["hold_ms"], !(IV.nonNeg(h) != nil) { return "ux.hold_ms must be a non-negative integer" }
        if ux["action_digest"] != nil && IV.digest(ux["action_digest"]) == nil { return "ux.action_digest is not canonical base64url (32 bytes)" }
        if let c = ux["consent_for_action"], case .bool = c {} else if ux["consent_for_action"] != nil { return "ux.consent_for_action must be a boolean" }
        let consent = ux["consent_for_action"] == .bool(true)
        if consent && (ux["action_digest"] == nil || !yOne || hasPartial) { return "consent_for_action needs action_digest and a plain yes" }
        if consent && canary { return "a canary never consents to an action" }
        if let wa = ux["webauthn"] {
            guard case let .object(w) = wa, onlyKeys(w, WA_KEYS) == nil, WA_KEYS.allSatisfy({ w[JKey($0)]?.asString != nil }) else { return "ux.webauthn is malformed" }
        }
        if yOne && !canary {
            let tier = ux["tier"]?.asString ?? ""
            if tier == "hold" && !((IV.nonNeg(ux["hold_ms"]) ?? -1) >= Int64(MIN_HOLD_MS)) { return "hold tier needs hold_ms >= \(MIN_HOLD_MS)" }
            if tier == "typed" && ux["typed_digest"] == nil { return "typed tier needs typed_digest" }
            if tier == "device" && ux["webauthn"] == nil { return "device tier needs a WebAuthn assertion" }
        }
        return nil
    }

    static let ANSWER_BODY_KEYS = ["v", "kind", "map_digest", "session", "question_id", "verb", "cell", "y", "partial", "source", "observed_at", "ux", "signer", "alg"]

    static func answerBody(_ a: JObject) -> JSONValue {
        var body = JObject()
        for k in ANSWER_BODY_KEYS { if let v = a[JKey(k)] { body[JKey(k)] = v } }
        return WJ.plain(.object(body))
    }

    /// Wallet side: sign the principal's answer with the principal key (Ed25519, domain-separated, over the canonical body).
    public static func signIntentAnswer(_ a: JSONValue?, seed: [UInt8]) throws -> JSONValue {
        guard case var .object(base)? = a else { throw JSError("signIntentAnswer: not an object") }
        base["v"] = .int(2)
        base["kind"] = .string("pca-intent-observation")
        base["signer"] = .string(Base64URLStrict.encode(Ed25519Deterministic.publicKey(seed: seed)))
        base["alg"] = .string("ed25519")
        let body = answerBody(base)
        if let bad = answerShapeError(body) { throw JSError("signIntentAnswer: " + bad) }
        var out = body.asObject!
        out["sig"] = .string(Base64URLStrict.encode(Ed25519Deterministic.sign(seed: seed, try WJ.message(INTENT_ANSWER_SIG_DOMAIN, body))))
        return .object(out)
    }

    /// Verify a signed answer; `principals` restricts the signer (the keys named in the session root). Never throws.
    public static func verifyIntentAnswer(_ a: JSONValue?, _ principals: JSONValue? = nil) -> JSONValue {
        func no(_ r: String) -> JSONValue { WJ.obj([("ok", .bool(false)), ("reason", .string(r))]) }
        if let bad = answerShapeError(a) { return no(bad) }
        guard case let .object(ans)? = a, let signer = ans["signer"]?.asString else { return no("malformed answer: not an object") }
        // A non-array principals list (a string would be a substring match) restricts to nobody.
        if let p = principals {
            guard case let .array(list) = p, list.contains(where: { IV.same($0.asString, signer) }) else { return no("signer is not a principal of the session") }
        }
        guard let sig = ans["sig"]?.asString else { return no("bad signature") }
        guard let msg = try? WJ.message(INTENT_ANSWER_SIG_DOMAIN, answerBody(ans)) else { return no("malformed answer: canonicalize failed") }
        return Ed25519Strict.verifyB64u(signer, msg, sig) ? WJ.obj([("ok", .bool(true))]) : no("bad signature")
    }

    /// Content address of a signed answer (evidence bundles and delta grants refer to it).
    public static func answerRef(_ a: JSONValue?) throws -> String {
        guard let a = a else { throw JSError("canonicalize: undefined") }
        return try WJ.hash(WJ.obj([("d", .string(INTENT_ANSWER_REF_DOMAIN)), ("a", a)]))
    }

    public static func typedDigest(_ questionId: String, _ normalizedValue: String) throws -> String {
        try WJ.hash(WJ.obj([("d", .string(INTENT_TYPED_DOMAIN)), ("q", .string(questionId)), ("v", .string(normalizedValue))]))
    }

    /// The 32-byte WebAuthn challenge of a device-tier answer: binds the question, the card the human saw, y and the action.
    public static func deviceChallenge(questionId: JSONValue?, renderedDigest: JSONValue?, y: JSONValue?, actionDigest: JSONValue?) throws -> String {
        guard let q = questionId, let r = renderedDigest, let y = y else { throw JSError("canonicalize: undefined") }
        return try WJ.hash(WJ.obj([("d", .string(INTENT_DEVICE_CHALLENGE_DOMAIN)), ("q", q), ("r", r), ("y", y), ("a", JS.present(actionDigest) ?? .null)]))
    }

    // ---- cell coordinates <-> the wallet's own Omega (box.ts) ----

    /// A category label of a coordinate path: `env.acc.<id>.post` -> `<id>`, `env.mon.<id>.state` -> `mon:<id>`, `env.prov.<p>` ->
    /// `prov:<p>`, `env.world.<name>` -> `<name>`; any other path is its own key.
    public static func coordKeyOf(_ path: String) -> String {
        let u = Array(path.unicodeScalars)
        func isId(_ s: ArraySlice<Unicode.Scalar>) -> Bool {
            !s.isEmpty && s.allSatisfy { ($0.value >= 48 && $0.value <= 57) || ($0.value >= 65 && $0.value <= 90) || ($0.value >= 97 && $0.value <= 122) || $0.value == 95 || $0.value == 46 || $0.value == 45 }
        }
        func has(_ p: String) -> Bool { IV.startsWith(path, p) }
        if has("env.acc."), IV.endsWith(path, ".post"), u.count > 13, isId(u[8..<(u.count - 5)]) { return IV.text(u[8..<(u.count - 5)]) }
        if has("env.mon."), IV.endsWith(path, ".state"), u.count > 14, isId(u[8..<(u.count - 6)]) { return "mon:" + IV.text(u[8..<(u.count - 6)]) }
        if has("env.prov."), u.count > 9, !u[9...].contains(where: { [0x0A, 0x0D, 0x2028, 0x2029].contains($0.value) }) { return "prov:" + IV.text(u[9...]) }
        if has("env.world."), isId(u[10...]) { return IV.text(u[10...]) }
        return path
    }

    public static func catLabel(_ d: WalletDim, _ i: Int) -> String { d.values[i].value }

    public struct Resolved {
        public let vs: WalletVerb
        public let box: [[Int]]
    }

    /// Resolve coordinates to a box of cells of the verb's space. Every dimension must be named exactly once; anything the wallet
    /// cannot resolve exactly is refused (returned as `.failure` with the reason); a value the reference throws on throws.
    public static func resolveCoords(_ omega: WalletOmega, _ verb: JSONValue?, _ coords: JSONValue?) throws -> Result<Resolved, WalletRefusal> {
        guard let vname = verb?.asString, let vs = omega.verb(vname) else {
            return .failure(WalletRefusal("verb \(JS.toString(verb)) is not in the wallet's outcome space"))
        }
        var byKey: [JKey: Int] = [:]
        for (k, d) in vs.dims.enumerated() { byKey[JKey(d.path)] = k; byKey[JKey(coordKeyOf(d.path))] = k }
        var named = Set<Int>()
        for (key, _) in try WJ.entries(coords) {
            guard let k = byKey[JKey(key)] else { return .failure(WalletRefusal("unknown dimension \(key)")) }
            if named.contains(k) { return .failure(WalletRefusal("dimension \(vs.dims[k].path) is named twice")) }
            named.insert(k)
        }
        var box: [[Int]] = []
        for d in vs.dims {
            var c = coords?.get(d.path)
            if c == nil || c == .null { c = coords?.get(coordKeyOf(d.path)) }
            guard let cc = c else { return .failure(WalletRefusal("coordinates leave out dimension \(d.path)")) }
            if cc == .null { throw JSError("Cannot read properties of null (reading 'length')") }
            if d.isNum {
                guard let arr = cc.asArray, arr.count == 2, WJ.isNumber(arr[0]), WJ.isNumber(arr[1]) else {
                    return .failure(WalletRefusal("dimension \(d.path) is numeric: expected an index range"))
                }
                let lo = IV.num(arr[0])!, hi = IV.num(arr[1])!
                guard WJ.isIntegral(arr[0]), WJ.isIntegral(arr[1]), !IV.isNegZero(lo), !IV.isNegZero(hi), lo >= 0, lo <= hi, hi < Double(WalletOmegaMath.numCells(d).count) else {
                    return .failure(WalletRefusal("index range of \(d.path) is out of range"))
                }
                box.append(Array(Int(lo)...Int(hi)))
            } else {
                guard let arr = cc.asArray else { throw JSError("c.every is not a function") }
                guard arr.allSatisfy({ $0.asString != nil }) else { return .failure(WalletRefusal("dimension \(d.path) is categorical: expected a value set")) }
                var ids: [Int] = []
                for label in arr.compactMap({ $0.asString }) {
                    let hits = d.values.enumerated().filter { IV.same($0.element.value, label) }.map { $0.offset }
                    if hits.isEmpty { return .failure(WalletRefusal("unknown value \(JS.stringify(.string(label))) for \(d.path)")) }
                    if hits.count > 1 { return .failure(WalletRefusal("value \(JS.stringify(.string(label))) names two cells of \(d.path)")) }
                    ids.append(hits[0])
                }
                box.append(Array(Set(ids)).sorted())
            }
        }
        return .success(Resolved(vs: vs, box: box))
    }

    /// The coordinates of a box (the inverse of `resolveCoords`; numeric sides must be contiguous).
    public static func coordsOfBox(_ vs: WalletVerb, _ box: [[Int]]) throws -> JSONValue {
        var out = JObject()
        for (k, d) in vs.dims.enumerated() {
            guard k < box.count else { throw JSError("coordsOfBox: box has too few sides") }
            let ids = box[k]
            if d.isNum {
                guard let lo = ids.min(), let hi = ids.max(), hi - lo + 1 == ids.count else { throw JSError("coordsOfBox: numeric side of \(d.path) is not contiguous") }
                out[JKey(d.path)] = WJ.arr([lo, hi])
            } else {
                out[JKey(d.path)] = .array(try ids.map { i -> JSONValue in
                    guard i >= 0 && i < d.values.count else { throw JSError("coordsOfBox: no such value") }
                    return .string(catLabel(d, i))
                })
            }
        }
        return .object(out)
    }

    public static func coordsOfCell(_ vs: WalletVerb, _ idx: [Int]) throws -> JSONValue { try coordsOfBox(vs, idx.map { [$0] }) }

    public static func cellInBox(_ box: [[Int]], _ idx: [Int]) -> Bool {
        box.count == idx.count && box.enumerated().allSatisfy { $0.element.contains(idx[$0.offset]) }
    }

    /// Every cell (per-dimension indices) of a box, in lexicographic order.
    public static func boxCells(_ box: [[Int]]) -> [[Int]] {
        var out: [[Int]] = [[]]
        for ids in box { out = out.flatMap { pre in ids.map { pre + [$0] } } }
        return out
    }

    public static func boxSize(_ box: [[Int]]) -> Int { box.reduce(1) { $0 * $1.count } }

    /// The cell of a concrete action {verb, values} in the wallet's Omega (nil outside it: fail closed).
    public static func cellOfAction(_ omega: WalletOmega, _ a: JSONValue?) throws -> (vs: WalletVerb, idx: [Int])? {
        guard let vs = a?.get("verb")?.asString.flatMap({ omega.verb($0) }) else { return nil }
        guard let values = a?.get("values"), values.isObject || values.isArray else { throw JSError("Cannot use 'in' operator to search for a path") }
        for d in vs.dims { guard case let .object(o) = values, o[JKey(d.path)] != nil else { return nil } }
        guard let idx = WalletOmegaMath.cellOf(vs, values: values) else { return nil }
        return (vs, idx)
    }

    public static func flatIndex(_ vs: WalletVerb, _ idx: [Int]) -> Int {
        var f = 0
        for (k, d) in vs.dims.enumerated() { f = f * WalletOmegaMath.cellCount(d) + idx[k] }
        return f
    }

    // ---- canaries (canary.ts) ----

    public static let EMPTY_NOISE: JSONValue = WJ.obj([("falseYes", WJ.i(0)), ("correctNo", WJ.i(0)), ("falseNo", WJ.i(0)), ("correctYes", WJ.i(0))])
    public static let NOISE_PRIOR: JSONValue = WJ.obj([("a", WJ.i(1)), ("b", WJ.i(9))])

    static func count(_ n: JSONValue?, _ k: String) -> Double { IV.num(n?.get(k)) ?? .nan }
    static func bump(_ n: JSONValue?, _ k: String) -> JSONValue { .double(count(n, k) + 1) }

    /// Fold one canary answer into the counts (pure).
    public static func recordCanary(_ n: JSONValue?, expected: JSONValue?, y: JSONValue?) throws -> JSONValue {
        guard case var .object(out)? = n else { throw JSError("Cannot read properties of undefined") }
        if WJ.numEq(expected, 0) {
            if WJ.numEq(y, 1) { out["falseYes"] = bump(n, "falseYes") } else { out["correctNo"] = bump(n, "correctNo") }
        } else if WJ.numEq(y, 0) { out["falseNo"] = bump(n, "falseNo") } else { out["correctYes"] = bump(n, "correctYes") }
        return .object(out)
    }

    public static func estimateNoise(_ n: JSONValue?, deltaC: Double = 0.05) throws -> JSONValue {
        if !(deltaC > 0 && deltaC < 1) { throw JSError("estimateNoise: deltaC must be in (0, 1)") }
        let fy = count(n, "falseYes"), cn = count(n, "correctNo"), fn = count(n, "falseNo"), cy = count(n, "correctYes")
        let ap = 1 + fy, bp = 9 + cn, an = 1 + fn, bn = 9 + cy
        let knownNo = fy + cn, knownYes = fn + cy
        let upPos = try WalletStats.betaUpperExact(deltaC, ap, bp)
        let upNeg = try WalletStats.betaUpperExact(deltaC, an, bn)
        var cpPos: JSONValue = WJ.i(1), cpNeg: JSONValue = WJ.i(1)
        if knownNo != 0 { cpPos = .double(try WalletOmegaMath.clopperPearsonUpper(.double(fy), .double(knownNo), .double(deltaC))) }
        if knownYes != 0 { cpNeg = .double(try WalletOmegaMath.clopperPearsonUpper(.double(fn), .double(knownYes), .double(deltaC))) }
        return WJ.obj([("etaPos", .double(ap / (ap + bp))), ("etaNeg", .double(an / (an + bn))), ("etaPosUpper", .double(upPos)), ("etaNegUpper", .double(upNeg)),
                       ("etaPosCP", cpPos), ("etaNegCP", cpNeg), ("asked", .double(knownNo + knownYes))])
    }

    public static func cellKey(_ verb: String, _ idx: [Int]) -> String { "\(verb)|\(idx.map { String($0) }.joined(separator: ","))" }

    /// Cells one step outside the confirmed region in exactly one dimension (deterministic order).
    public static func boundaryNeighbours(_ omega: WalletOmega, _ confirmed: [(verb: String, idx: [Int])]) -> [(verb: String, idx: [Int])] {
        var inside = Set<String>()
        for c in confirmed { inside.insert(cellKey(c.verb, c.idx)) }
        var out: [String: (verb: String, idx: [Int])] = [:]
        for c in confirmed {
            guard let vs = omega.verb(c.verb) else { continue }
            for (k, d) in vs.dims.enumerated() {
                let n = WalletOmegaMath.cellCount(d)
                let alts = d.isNum ? [c.idx[k] - 1, c.idx[k] + 1] : Array(0..<n)
                for a in alts {
                    if a < 0 || a >= n || a == c.idx[k] { continue }
                    var idx = c.idx
                    idx[k] = a
                    let key = cellKey(c.verb, idx)
                    if !inside.contains(key) { out[key] = (c.verb, idx) }
                }
            }
        }
        return out.sorted { WJ.u16Less($0.key, $1.key) }.map { $0.value }
    }

    public struct Canary {
        public let verb: String
        public let idx: [Int]
        public let expected: Int
        public let source: String
        var json: JSONValue { WJ.obj([("verb", .string(verb)), ("idx", WJ.arr(idx)), ("expected", WJ.i(expected)), ("source", .string(source))]) }
    }

    /// Decide whether to insert a canary now, and which (nil: no canary this time). `rand` draws from the injected randomness
    /// (a draw past its end throws).
    public static func pickCanary(omega: WalletOmega, confirmed: [(verb: String, idx: [Int])], knownNo: (String, [Int]) -> String?, knownYes: [(verb: String, idx: [Int])],
                           exclude: Set<String>, rand: () throws -> Double, rho rhoIn: Double?, lowHarmSession: Bool, canariesSoFar: Double) throws -> Canary? {
        let rho = rhoIn ?? 0.1
        if !(rho >= 0 && rho <= 1) { throw JSError("pickCanary: rho must be in [0, 1]") }
        if lowHarmSession && canariesSoFar >= 1 { return nil }
        if !(try rand() < rho) { return nil }
        var no: [Canary] = []
        for c in boundaryNeighbours(omega, confirmed) {
            if exclude.contains(cellKey(c.verb, c.idx)) { continue }
            if let why = knownNo(c.verb, c.idx), !why.isEmpty { no.append(Canary(verb: c.verb, idx: c.idx, expected: 0, source: why)) }
        }
        let yes = knownYes.filter { !exclude.contains(cellKey($0.verb, $0.idx)) }.map { Canary(verb: $0.verb, idx: $0.idx, expected: 1, source: "confirmed-yes") }
        if no.isEmpty && yes.isEmpty { return nil }
        let pool: [Canary]
        if !no.isEmpty && !yes.isEmpty { pool = try rand() < 0.5 ? no : yes } else { pool = no.isEmpty ? yes : no }
        let r = try rand()
        let at = (r * Double(pool.count)).rounded(.down)
        guard at.isFinite, at >= 0 else { return nil }
        return pool[min(pool.count - 1, Int(at))]
    }

    // ---- approval fatigue (fatigue.ts) ----

    public static let DEFAULT_FATIGUE: JSONValue = WJ.obj([("betaF", .double(0.005)), ("etaStop", .double(0.15)), ("deltaC", .double(0.05)),
                                                          ("freezeOn", .string("mean")), ("assumeNoiseFree", .bool(false)), ("delta", .double(0.05))])
    static let BELOW_HALF = 0.5 - 1e-9

    /// eta+ under load: base + beta_f * n_recent, capped at 1/2.
    public static func etaUnderLoad(_ base: Double, _ betaF: Double, _ nRecent: Double) throws -> Double {
        guard base >= 0, betaF >= 0, nRecent.isFinite, nRecent.rounded(.towardZero) == nRecent, nRecent >= 0 else { throw JSError("etaUnderLoad: bad arguments") }
        return min(0.5, base + betaF * nRecent)
    }

    static func modelNum(_ model: JSONValue, _ k: String) -> Double { IV.num(model.get(k)) ?? .nan }

    public static func noiseState(_ counts: JSONValue?, _ nRecent: Double, _ model: JSONValue? = nil) throws -> JSONValue {
        let m = model ?? DEFAULT_FATIGUE
        let e = try estimateNoise(counts, deltaC: m.get("deltaC") == nil ? 0.05 : modelNum(m, "deltaC"))
        let betaF = modelNum(m, "betaF")
        let etaPos = try etaUnderLoad(IV.num(e.get("etaPos"))!, betaF, nRecent)
        let etaPosBar = try etaUnderLoad(IV.num(e.get("etaPosUpper"))!, betaF, nRecent)
        let stat = WJ.isStr(m.get("freezeOn"), "mean") ? etaPos : etaPosBar
        return WJ.obj([("etaPos", .double(etaPos)), ("etaPosBar", .double(etaPosBar)), ("etaNegBar", .double(min(0.5, IV.num(e.get("etaNegUpper"))!))),
                       ("frozen", .bool(stat > modelNum(m, "etaStop")))])
    }

    public static func admissionPolicy(_ state: JSONValue?, _ model: JSONValue? = nil) throws -> JSONValue {
        let m = model ?? DEFAULT_FATIGUE
        if JS.truthy(m.get("assumeNoiseFree")) {
            return WJ.obj([("tau", WJ.i(1)), ("etaPos", WJ.i(0)), ("etaNeg", WJ.i(0)), ("doubleConfirmIrreversible", .bool(false)), ("falseAdmitBound", WJ.i(0))])
        }
        let delta = modelNum(m, "delta")
        if !(delta > 0 && delta < 1) { throw JSError("admissionPolicy: delta must be in (0, 1)") }
        let ep = min(BELOW_HALF, IV.num(state?.get("etaPosBar")) ?? .nan)
        let en = min(BELOW_HALF, IV.num(state?.get("etaNegBar")) ?? .nan)
        return WJ.obj([("tau", .double(1 - delta)), ("etaPos", .double(ep)), ("etaNeg", .double(en)), ("doubleConfirmIrreversible", .bool(ep > 0)),
                       ("falseAdmitBound", .double(ep * ep))])
    }

    /// Sliding-window question counter shared across sessions (the per-hour cap is an accumulator, so an agent cannot split around
    /// it by opening sessions). Keeps only timestamps inside the window.
    public final class SlidingWindowCounter {
        let windowMs: Double
        private var times: [Double] = []

        public init(windowMs: Double = 3_600_000) throws {
            guard windowMs.isFinite, windowMs.rounded(.towardZero) == windowMs, windowMs > 0 else { throw JSError("SlidingWindowCounter: windowMs must be a positive integer") }
            self.windowMs = windowMs
        }

        private func prune(_ now: Double) { guard now.isFinite else { return }; while let f = times.first, f <= now - windowMs { times.removeFirst() } }

        public func count(_ now: Double) -> Int { prune(now); return times.count }

        /// Record one event at `now` if the count is below `cap`; false (and nothing recorded) otherwise.
        public func tryAdd(_ now: Double, _ cap: Double) throws -> Bool {
            prune(now)
            if !(Double(times.count) < cap) { return false }
            if let l = times.last, !(now >= l) { throw JSError("SlidingWindowCounter: time went backwards") }
            if !now.isFinite { return false }
            times.append(now)
            return true
        }
    }

    /// Two "yes" answers at typed or device tier, on different screens, with at least one other screen between them.
    public static func doubleConfirmed(_ records: [(screen: Double, tier: String)]) -> Bool {
        let strong = records.filter { $0.tier == "typed" || $0.tier == "device" }.map { $0.screen }.sorted()
        for i in 0..<strong.count { for j in (i + 1)..<max(i + 1, strong.count) where strong[j] - strong[i] >= 2 { return true } }
        return false
    }
}

/// A resolved-coordinates or channel refusal: the reason the reference returns as `{ok: false, reason}`.
public struct WalletRefusal: Error {
    public let reason: String
    public init(_ r: String) { reason = r }
}
