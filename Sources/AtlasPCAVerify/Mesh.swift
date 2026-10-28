import Foundation

/// Cross-domain mesh proofs (the agent mesh, `mesh.ts` `verifyMeshProof`). A mesh proof carries a capability chain, one witnessed
/// head per issuing domain, per-hop log inclusion and revocation non-membership proofs, and a signed leaf action.
/// `verifyMeshProof` checks all of it offline and returns the reference's reason and failing hop. Everything `verifyMeshProof`
/// does is here, including RFC 9162 consistency proofs from a pinned head; the witness side (cosigning, head publication) is not.
public enum Mesh {
    static let HEAD_DOMAIN = "atlas-pca/mesh-head/v1\u{0}"
    static let COSIG_DOMAIN = "atlas-pca/mesh-cosig/v1\u{0}"
    static let BINDING_DOMAIN = "atlas-pca/mesh-binding/v1\u{0}"
    static let ACTION_DOMAIN = "atlas-pca/mesh-action/v1\u{0}"

    static let DEFAULT_MAX_HEAD_AGE_MS = 5.0 * 60_000
    static let DEFAULT_MAX_SKEW_MS = 60_000.0
    static let DEFAULT_MAX_CHAIN: Int64 = 64
    static let MAX_COSIGS = 256
    static let MAX_PATH = 128

    /// The result of `verifyMeshProof`. `hop` is -1 when no hop is named.
    public struct Verdict: Equatable, Sendable {
        public let ok: Bool
        public let reason: String
        public let hop: Int
    }

    static func fail(_ reason: String, _ hop: Int = -1) -> Verdict { Verdict(ok: false, reason: reason, hop: hop) }

    static func nat(_ x: JSONValue?) -> Bool { IV.nonNeg(x) != nil }
    static func natV(_ x: JSONValue?) -> Int64 { IV.safe(x).map { Int64($0) } ?? 0 }
    static func num(_ x: JSONValue?) -> Bool { IV.num(x).map { $0.isFinite } ?? false }
    static func f(_ x: JSONValue?) -> Double { IV.num(x) ?? .nan }

    static func msg(_ domain: String, _ body: JSONValue) -> [UInt8]? { IV.message(domain, body) }

    static func validHead(_ h: JSONValue?) -> JObject? {
        guard case let .object(m)? = h, m["domain"]?.asString != nil, let root = m["root"]?.asString, m["rev_root"]?.asString != nil,
              nat(m["size"]), nat(m["rev_size"]), num(m["timestamp"]) else { return nil }
        return (natV(m["size"]) == 0) == root.isEmpty ? m : nil
    }

    static func validConsistency(_ c: JSONValue?) -> JObject? {
        guard case let .object(m)? = c, nat(m["oldSize"]), nat(m["newSize"]), case let .array(path)? = m["path"], path.count <= MAX_PATH,
              path.allSatisfy({ $0.asString != nil }) else { return nil }
        return m
    }

    static func validInclusion(_ i: JSONValue?) -> JObject? {
        guard case let .object(m)? = i, nat(m["index"]), nat(m["size"]), case let .array(path)? = m["path"], path.count <= MAX_PATH else { return nil }
        return m
    }

    static func validAction(_ a: JSONValue?) -> JObject? {
        guard case let .object(m)? = a else { return nil }
        for k in ["type", "resource", "service_domain", "nonce"] where m[JKey(k)]?.asString == nil { return nil }
        if !num(m["at"]) { return nil }
        if let v = m["amount"], !num(v) { return nil }
        return m
    }

    // ---- effective authority ----

    struct Authority {
        var actions: [String] = []
        var hasAct = false
        var prefixes: [String] = []
        var maxAmount = 0.0
        var hasAmount = false
        var expiresAt = 0.0
        var hasExp = false
        var audience: [String] = []
        var hasAud = false
        var maxHops = 0.0
        var hasHops = false
    }

    static func intersect(_ have: Bool, _ a: [String], _ b: [String]) -> [String] {
        if !have {
            var seen = Set<JKey>()
            var out: [String] = []
            for x in b where !seen.contains(JKey(x)) {
                seen.insert(JKey(x))
                out.append(x)
            }
            return out.sorted { IV.utf8Less($0, $1) }
        }
        return a.filter { x in b.contains { IV.same($0, x) } }
    }

    static func strings(_ v: JSONValue?) -> [String]? {
        guard case let .array(arr)? = v else { return nil }
        var out: [String] = []
        for x in arr {
            guard let s = x.asString else { return nil }
            out.append(s)
        }
        return out
    }

    static func minOf(_ have: Bool, _ cur: Double, _ v: Double) -> Double { have ? Swift.min(cur, v) : v }

    /// `effectiveAuthority`: the conjunction of the caveats; an unknown or malformed caveat is an error (the reason).
    static func effective(_ caveats: JSONValue?) -> (Authority, String) {
        var e = Authority()
        guard case let .array(arr)? = caveats else { return (e, "malformed proof") }
        for cv in arr {
            guard case let .object(c) = cv else { return (e, "malformed proof") }
            let t = c["type"]?.asString ?? ""
            switch t {
            case "scope":
                guard let a = strings(c["actions"]) else { return (e, "malformed scope caveat") }
                e.actions = intersect(e.hasAct, e.actions, a)
                e.hasAct = true
            case "resource":
                guard let p = c["prefix"]?.asString else { return (e, "malformed resource caveat") }
                e.prefixes.append(p)
            case "max_amount":
                if !num(c["max"]) { return (e, "malformed max_amount caveat") }
                e.maxAmount = minOf(e.hasAmount, e.maxAmount, f(c["max"]))
                e.hasAmount = true
            case "expires":
                if !num(c["at"]) { return (e, "malformed expires caveat") }
                e.expiresAt = minOf(e.hasExp, e.expiresAt, f(c["at"]))
                e.hasExp = true
            case "audience":
                guard let d = strings(c["domains"]) else { return (e, "malformed audience caveat") }
                e.audience = intersect(e.hasAud, e.audience, d)
                e.hasAud = true
            case "max_hops":
                if !num(c["n"]) { return (e, "malformed max_hops caveat") }
                e.maxHops = minOf(e.hasHops, e.maxHops, f(c["n"]))
                e.hasHops = true
            default:
                return (e, "unknown caveat type \"\(IntentWB.jsOpt(c["type"]))\" (fail closed)")
            }
        }
        return (e, "")
    }

    static func subset(_ child: [String], _ parent: [String]) -> Bool {
        child.allSatisfy { c in parent.contains { IV.same($0, c) } }
    }

    static func narrows(_ child: Authority, _ parent: Authority) -> Bool {
        if parent.hasAct && (!child.hasAct || !subset(child.actions, parent.actions)) { return false }
        if parent.hasAud && (!child.hasAud || !subset(child.audience, parent.audience)) { return false }
        if parent.hasAmount && (!child.hasAmount || child.maxAmount > parent.maxAmount) { return false }
        if parent.hasExp && (!child.hasExp || child.expiresAt > parent.expiresAt) { return false }
        if parent.hasHops && (!child.hasHops || child.maxHops > parent.maxHops) { return false }
        return subset(parent.prefixes, child.prefixes)
    }

    static func admits(_ e: Authority, _ a: JObject, _ now: Double, _ chainLen: Int) -> String {
        let typ = a["type"]?.asString ?? "", res = a["resource"]?.asString ?? "", svc = a["service_domain"]?.asString ?? ""
        if e.hasAct && !subset([typ], e.actions) { return "action \"\(typ)\" not in scope" }
        for p in e.prefixes where !IV.startsWith(res, p) { return "resource \"\(res)\" outside prefix \"\(p)\"" }
        if e.hasAmount {
            guard let amt = a["amount"], !(f(amt) > e.maxAmount) else { return "amount exceeds ceiling \(Canonical.numberString(e.maxAmount))" }
        }
        if e.hasExp && now > e.expiresAt { return "capability expired" }
        if e.hasAud && !subset([svc], e.audience) { return "service domain not in audience" }
        if e.hasHops && Double(chainLen) > e.maxHops { return "chain exceeds max_hops \(Canonical.numberString(e.maxHops))" }
        return ""
    }

    // ---- revocation sets and Merkle proofs ----

    static func leafOK(_ root: String, _ size: Int64, _ id: String, _ proof: JObject) -> Bool {
        guard let psize = IV.safe(proof["size"]).map({ Int64($0) }), let index = IV.safe(proof["index"]).map({ Int64($0) }),
              psize == size, index >= 0, index < size else { return false }
        let sides = Merkle.pathShape(UInt64(index), UInt64(size))
        guard case let .array(path)? = proof["path"], path.count == sides.count else { return false }
        var h = Merkle.leafHash(.string(id))
        for (i, s) in path.enumerated() {
            guard case let .object(step) = s else { return false }
            let side = step["side"]?.asString ?? ""
            let hs = step["hash"]?.asString ?? ""
            if Array(side.utf8) != [sides[i]] { return false }
            guard let sib = Base64URLStrict.decode(hs, length: 32) else { return false }
            h = side == "L" ? Merkle.nodeHash(sib, h) : Merkle.nodeHash(h, sib)
        }
        guard let bound = IntentRevocation.bindRoot(.int(size), Base64URLStrict.encode(h)) else { return false }
        return IV.same(bound, root)
    }

    /// `verifyNonMembership` over an expanded proof {size, lo?, hi?}.
    static func nonMembership(_ root: String, _ nm: JObject, _ id: String) -> Bool {
        guard let size = IV.safe(nm["size"]).map({ Int64($0) }), size >= 0 else { return false }
        let lo = nm["lo"]?.asObject, hi = nm["hi"]?.asObject
        if size == 0 {
            guard let bound = IntentRevocation.bindRoot(.int(0), IntentRevocation.EMPTY_TREE) else { return false }
            return lo == nil && hi == nil && IV.same(bound, root)
        }
        if lo == nil && hi == nil { return false }
        var loIdx: Int64 = 0, hiIdx: Int64 = 0
        if let l = lo {
            let loID = l["id"]?.asString ?? ""
            guard let lp = l["proof"]?.asObject, IV.utf8Less(loID, id), leafOK(root, size, loID, lp) else { return false }
            loIdx = IV.safe(lp["index"]).map { Int64($0) } ?? 0
            if hi == nil && loIdx != size - 1 { return false }
        }
        if let h = hi {
            let hiID = h["id"]?.asString ?? ""
            guard let hp = h["proof"]?.asObject, IV.utf8Less(id, hiID), leafOK(root, size, hiID, hp) else { return false }
            hiIdx = IV.safe(hp["index"]).map { Int64($0) } ?? 0
            if lo == nil && hiIdx != 0 { return false }
        }
        if lo != nil && hi != nil && hiIdx != loIdx + 1 { return false }
        return true
    }

    /// `verifyLedgerConsistency` (RFC 9162 section 2.1.4.2) with strict 32-byte base64url hashes.
    static func consistency(_ oldRoot: String, _ newRoot: String, _ proof: JObject) -> Bool {
        guard let fi = IV.safe(proof["oldSize"]), let si = IV.safe(proof["newSize"]), fi >= 0, fi <= si else { return false }
        let first = UInt64(fi), second = UInt64(si)
        let raw = proof["path"]?.asArray ?? []
        if raw.count > MAX_PATH { return false }
        let empty = IntentRevocation.EMPTY_TREE
        if first == 0 {
            if !raw.isEmpty || !IV.same(oldRoot, empty) { return false }
            if second == 0 { return IV.same(newRoot, empty) }
            return true
        }
        if first == second { return raw.isEmpty && IV.same(oldRoot, newRoot) }
        var path: [[UInt8]] = []
        if first & (first - 1) == 0 {
            guard let o = Base64URLStrict.decode(oldRoot, length: 32) else { return false }
            path.append(o)
        }
        for p in raw {
            guard let b = Base64URLStrict.decode(p.asString ?? "", length: 32) else { return false }
            path.append(b)
        }
        if path.isEmpty { return false }
        var fn = first - 1, sn = second - 1
        while fn & 1 == 1 {
            fn >>= 1
            sn >>= 1
        }
        var fr = path[0], sr = path[0]
        for c in path.dropFirst() {
            if sn == 0 { return false }
            if fn & 1 == 1 || fn == sn {
                fr = Merkle.nodeHash(c, fr)
                sr = Merkle.nodeHash(c, sr)
                while fn & 1 == 0 && fn != 0 {
                    fn >>= 1
                    sn >>= 1
                }
            } else {
                sr = Merkle.nodeHash(sr, c)
            }
            fn >>= 1
            sn >>= 1
        }
        return sn == 0 && IV.same(Base64URLStrict.encode(fr), oldRoot) && IV.same(Base64URLStrict.encode(sr), newRoot)
    }

    // ---- heads ----

    static func checkHeadAdvance(_ prev: JSONValue?, _ next: JSONValue?, _ proof: JSONValue?) -> String {
        guard let p = validHead(prev), let n = validHead(next) else { return "malformed head" }
        if !IV.same(p["domain"]?.asString, n["domain"]?.asString) { return "head is for a different domain" }
        if natV(n["size"]) < natV(p["size"]) || natV(n["rev_size"]) < natV(p["rev_size"]) { return "head rolls back" }
        if natV(n["size"]) == natV(p["size"]) {
            if !IV.same(n["root"]?.asString, p["root"]?.asString) { return "equivocation (same size, different log)" }
        } else {
            guard let c = validConsistency(proof), natV(c["oldSize"]) == natV(p["size"]), natV(c["newSize"]) == natV(n["size"]) else {
                return "consistency proof required for a larger head"
            }
            if !consistency(p["root"]?.asString ?? "", n["root"]?.asString ?? "", c) { return "head is not consistent with the previous head (fork or rewrite)" }
        }
        if natV(n["rev_size"]) == natV(p["rev_size"]) && !IV.same(n["rev_root"]?.asString, p["rev_root"]?.asString) { return "equivocation (revocation set)" }
        return ""
    }

    struct Trust {
        var human = ""
        var witnesses = Set<JKey>()
        var threshold: Int64 = 0
        var now = 0.0
        var maxHeadAge = 0.0
        var maxSkew = 0.0
        var maxActionAge = 0.0
        var hasActionAge = false
        var maxChain: Int64 = 0
        var allowed: [String] = []
        var rootDomain = ""
        var issuerDoms: JObject?
        var pinned: JObject?
        var pqPins: [String: String] = [:]
    }

    static func opt(_ t: JObject, _ k: String, _ def: Double) -> Double? {
        guard let v = t[JKey(k)] else { return def }
        guard num(v), f(v) >= 0 else { return nil }
        return f(v)
    }

    static func validTrust(_ traw: JSONValue?) -> (Trust, String) {
        var c = Trust()
        guard case let .object(t)? = traw else { return (c, "invalid trust configuration") }
        guard let human = t["humanPrincipal"]?.asString, let ws = strings(t["witnesses"]) else { return (c, "invalid trust configuration") }
        c.human = human
        c.witnesses = Set(ws.map { JKey($0) })
        guard nat(t["threshold"]), natV(t["threshold"]) >= 1, natV(t["threshold"]) <= Int64(c.witnesses.count) else { return (c, "invalid trust configuration: threshold") }
        c.threshold = natV(t["threshold"])
        guard num(t["now"]) else { return (c, "invalid trust configuration: now") }
        c.now = f(t["now"])
        guard let mha = opt(t, "maxHeadAgeMs", DEFAULT_MAX_HEAD_AGE_MS) else { return (c, "invalid trust configuration: maxHeadAgeMs") }
        c.maxHeadAge = mha
        guard let msk = opt(t, "maxClockSkewMs", DEFAULT_MAX_SKEW_MS) else { return (c, "invalid trust configuration: maxClockSkewMs") }
        c.maxSkew = msk
        if t["maxActionAgeMs"] != nil {
            guard let maa = opt(t, "maxActionAgeMs", 0) else { return (c, "invalid trust configuration: maxActionAgeMs") }
            c.maxActionAge = maa
            c.hasActionAge = true
        }
        c.maxChain = DEFAULT_MAX_CHAIN
        if let v = t["maxChainLength"] {
            guard nat(v), natV(v) >= 1 else { return (c, "invalid trust configuration: maxChainLength") }
            c.maxChain = natV(v)
        }
        guard let ad = strings(t["allowedDomains"]), !ad.isEmpty else { return (c, "invalid trust configuration: allowedDomains is required") }
        c.allowed = ad
        guard let rd = t["rootDomain"]?.asString, subset([rd], ad) else {
            return (c, "invalid trust configuration: rootDomain is required and must be in allowedDomains")
        }
        c.rootDomain = rd
        if let v = t["issuerDomains"] {
            guard case let .object(m) = v, m.values.allSatisfy({ $0.asString != nil }) else { return (c, "invalid trust configuration: issuerDomains") }
            c.issuerDoms = m
        }
        if let v = t["pinnedHeads"] {
            guard case let .object(m) = v else { return (c, "invalid trust configuration: pinnedHeads") }
            c.pinned = m
        }
        if case let .object(m)? = t["pqPins"] {
            for (k, x) in m { if let s = x.asString { c.pqPins[k.s] = s } }
        }
        return (c, "")
    }

    /// JavaScript truthiness for a decoded JSON value.
    static func truthy(_ v: JSONValue) -> Bool {
        switch v {
        case .null: return false
        case let .bool(b): return b
        case let .string(s): return !s.isEmpty
        case let .int(i): return i != 0
        case let .double(d): return d != 0 && !d.isNaN
        default: return true
        }
    }

    static func checkCosignedHead(_ ch: JSONValue?, _ expectedDomain: String, _ t: Trust, _ pinProof: JSONValue?) -> String {
        let chm = ch?.asObject ?? [:]
        guard let h = chm["head"]?.asObject, IV.same(h["domain"]?.asString, expectedDomain) else { return "head is for a different domain" }
        if validHead(.object(h)) == nil { return "malformed head" }
        guard let sig = chm["sig"]?.asString else { return "malformed head" }
        let domain = h["domain"]?.asString ?? ""
        guard let m = msg(HEAD_DOMAIN, .object(h)), Ed25519Strict.verifyB64u(domain, m, sig) else { return "head not signed by its domain key" }
        guard case let .array(cosigs)? = chm["cosigs"], cosigs.count <= MAX_COSIGS else { return "malformed head" }
        var good = Set<JKey>()
        let cm = msg(COSIG_DOMAIN, .object(h))
        for c in cosigs {
            guard case let .object(cr) = c, let w = cr["witness"]?.asString, let s = cr["sig"]?.asString else { continue }
            if t.witnesses.contains(JKey(w)) && !good.contains(JKey(w)), let cmsg = cm, Ed25519Strict.verifyB64u(w, cmsg, s) { good.insert(JKey(w)) }
        }
        if Int64(good.count) < t.threshold { return "head has \(good.count)/\(t.threshold) trusted witness cosignatures" }
        let ts = f(h["timestamp"])
        if ts > t.now + t.maxSkew { return "head timestamp is in the future" }
        if t.now - ts > t.maxHeadAge { return "head is stale" }
        if let pinned = t.pinned, let pin = pinned[JKey(domain)], truthy(pin) {
            let why = checkHeadAdvance(pin, .object(h), pinProof)
            if !why.isEmpty { return why + " (vs pinned head)" }
        }
        return ""
    }

    static func expandNM(_ c: JSONValue?, _ leaves: [JSONValue]) -> JObject? {
        guard case let .object(m)? = c, nat(m["size"]), let size = m["size"] else { return nil }
        var out: JObject = ["size": size]
        for side in ["lo", "hi"] {
            guard let ix = m[JKey(side)] else { continue }
            guard nat(ix), natV(ix) < Int64(leaves.count) else { return nil }
            out[JKey(side)] = leaves[Int(natV(ix))]
        }
        return out
    }

    /// Verify a mesh proof end to end, offline. Both arguments are parsed JSON. Total: any malformed input is a verdict, never a trap.
    public static func verifyMeshProof(_ proof: JSONValue?, trust: JSONValue?) -> Verdict {
        let (t, bad) = validTrust(trust)
        if !bad.isEmpty { return fail(bad) }
        guard case let .object(p)? = proof else { return fail("malformed proof") }
        guard case let .array(chain)? = p["chain"], case let .array(hops)? = p["hops"], case let .array(heads)? = p["heads"],
              case let .array(revLeaves)? = p["rev_leaves"] else { return fail("malformed proof") }
        guard let actionSig = p["action_sig"]?.asString, let action = validAction(p["action"]) else { return fail("malformed action") }
        if let pp = p["pin_proofs"] {
            guard case let .array(arr) = pp, arr.count <= MAX_COSIGS else { return fail("malformed pin proofs") }
            for x in arr {
                guard case let .object(xm) = x, xm["domain"]?.asString != nil, validConsistency(xm["proof"]) != nil else { return fail("malformed pin proofs") }
            }
        }
        if chain.count < 1 || Int64(chain.count) > t.maxChain { return fail("chain length out of bounds") }
        if heads.count > chain.count || revLeaves.count > 2 * chain.count { return fail("evidence tables exceed chain size") }
        if let why = Capability.verifyChain(chain, expectedRootIssuer: t.human, allowedSuites: nil, pqPins: t.pqPins, trustedRoot: nil) { return fail("chain: " + why) }
        if hops.count != chain.count { return fail("hop evidence count does not match chain length") }
        for l in revLeaves {
            guard case let .object(lm) = l, lm["id"]?.asString != nil, validInclusion(lm["proof"]) != nil else { return fail("malformed revocation leaves") }
        }
        var used = Set<Int64>()
        for h in hops { if case let .object(ev) = h, nat(ev["head"]) { used.insert(natV(ev["head"])) } }
        if used.count != heads.count { return fail("unreferenced or missing head in evidence table") }

        var headErrs: [Int64: String] = [:]
        var headDone = Set<Int64>()
        var prev = Authority()
        var havePrev = false
        for i in 0..<chain.count {
            let cap = chain[i].asObject ?? [:]
            guard case let .object(ev) = hops[i] else { return fail("malformed hop evidence", i) }
            guard let domain = ev["domain"]?.asString, nat(ev["head"]), natV(ev["head"]) < Int64(heads.count), ev["revocation"]?.asObject != nil else {
                return fail("malformed hop evidence", i)
            }
            if !subset([domain], t.allowed) { return fail("issuing domain not allowed by policy", i) }
            if i == 0 && !IV.same(domain, t.rootDomain) { return fail("root capability must be anchored in the pinned root domain", i) }
            let issuer = cap["issuer"]?.asString ?? ""
            if i > 0, let doms = t.issuerDoms, let pin = doms[JKey(issuer)], !IV.same(pin.asString, domain) {
                return fail("issuer key is pinned to a different domain", i)
            }
            let hi = natV(ev["head"])
            let ch = heads[Int(hi)]
            if !headDone.contains(hi) {
                let dom = ch.asObject?["head"]?.asObject?["domain"]?.asString ?? ""
                var pinProof: JSONValue?
                if case let .array(pps)? = p["pin_proofs"] {
                    for x in pps {
                        if case let .object(xm) = x, IV.same(xm["domain"]?.asString, dom) {
                            pinProof = xm["proof"]
                            break
                        }
                    }
                }
                headErrs[hi] = checkCosignedHead(ch, dom, t, pinProof)
                headDone.insert(hi)
            }
            guard case let .object(chm) = ch, let hv = chm["head"], !hv.isNull else { return fail("malformed proof") } // `ch.head.domain` throws in the reference
            guard case let .object(headM) = hv, IV.same(headM["domain"]?.asString, domain) else { return fail("source-domain anchor: head is for a different domain", i) }
            if let e = headErrs[hi], !e.isEmpty { return fail("source-domain anchor: " + e, i) }

            guard let incl = validInclusion(ev["inclusion"]), natV(incl["size"]) == natV(headM["size"]) else { return fail("hop not included in the issuing domain log", i) }
            let capDigest = Capability.capHash(.object(cap))
            if !Merkle.verifyInclusion(headM["root"]?.asString ?? "", incl, .string(capDigest)) { return fail("hop not included in the issuing domain log", i) }

            if i > 0 {
                guard case let .object(b)? = ev["binding"], let role = b["role"]?.asString, let bsig = b["sig"]?.asString,
                      Ledger.same(b["agent"], cap["issuer"]), Ledger.same(b["domain"], ev["domain"]) else {
                    return fail("missing or mismatched domain binding for issuer", i)
                }
                var body: JObject = ["role": .string(role)]
                if let a = b["agent"] { body["agent"] = a }
                if let d = b["domain"] { body["domain"] = d }
                guard let m = msg(BINDING_DOMAIN, .object(body)), Ed25519Strict.verifyB64u(domain, m, bsig) else { return fail("domain binding signature invalid", i) }
            }

            let rev = ev["revocation"]?.asObject ?? [:]
            let revRoot = headM["rev_root"]?.asString ?? ""
            let id = cap["id"]?.asString ?? ""
            guard let nmCap = expandNM(rev["cap"], revLeaves), nonMembership(revRoot, nmCap, id) else { return fail("capability revoked (or revocation proof invalid)", i) }
            guard let nmKey = expandNM(rev["issuer_key"], revLeaves), nonMembership(revRoot, nmKey, "key:" + issuer) else { return fail("issuer key revoked (or revocation proof invalid)", i) }

            let (eff, why) = effective(cap["caveats"])
            if !why.isEmpty { return fail(why, i) }
            if havePrev && !narrows(eff, prev) { return fail("hop widens authority", i) }
            prev = eff
            havePrev = true
        }

        let at = f(action["at"])
        if at > t.now + t.maxSkew { return fail("action timestamp is in the future") }
        if t.hasActionAge && t.now - at > t.maxActionAge { return fail("action is stale") }
        let tip = chain[chain.count - 1].asObject ?? [:]
        let tipHash = Capability.capHash(.object(tip))
        let holder = tip["holder"]?.asString ?? ""
        guard let am = msg(ACTION_DOMAIN, .object(["action": .object(action), "tip": .string(tipHash)])), Ed25519Strict.verifyB64u(holder, am, actionSig) else {
            return fail("action not signed by the chain tip holder")
        }
        let denied = admits(prev, action, t.now, chain.count)
        if !denied.isEmpty { return fail("action not admitted: " + denied) }
        return Verdict(ok: true, reason: "", hop: -1)
    }
}
