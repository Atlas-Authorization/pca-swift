import Foundation

/// The layered intent lattice (org ceiling, site policy, standing profile, task grant: deny anywhere wins, a ceiling is never a question)
/// and the quorum of principal-signed approvals that a shared layer needs to widen. The outcome space is the wallet's verb space
/// (`WalletVerb`) and outcomes are `{verb, values}` JSON values, like the learner and the admission oracle they run against.
public enum PCAIntentLayers {
    /// The ceilings in evaluation order.
    public static let LAYER_CEILINGS: [String] = ["org", "site", "std"]
    public static let LAYER_APPROVAL_DOMAIN = "atlas-pca/intent-layer-approval/v1\u{0}"

    /// The acceptability of an outcome in [0, 1].
    public typealias Acceptability = (WalletVerb, JSONValue) throws -> Double

    /// Compiled ceilings; an absent ceiling is nil.
    public struct CeilingAdmitters {
        public let org: PCAIntentAdmitter?
        public let site: PCAIntentAdmitter?
        public let std: PCAIntentAdmitter?

        func of(_ k: String) -> PCAIntentAdmitter? { k == "org" ? org : (k == "site" ? site : std) }
    }

    /// Absent = no ceiling; a ceiling PRESENT with null (or not an object) is malformed: throws.
    public static func ceilingAdmitters(_ layers: JSONValue?) throws -> CeilingAdmitters {
        guard let lo = layers?.asObject else { throw JSError("ceilingAdmitters: layers must be an object") }
        var out: [PCAIntentAdmitter?] = [nil, nil, nil]
        for i in 0..<3 {
            let k = LAYER_CEILINGS[i]
            guard let l = lo[JKey(k)] else { continue }
            guard l.isObject else { throw JSError("ceilingAdmitters: the \(k) ceiling is malformed (null or not an object)") }
            out[i] = try PCAIntentPolicy.admitter(l)
        }
        return CeilingAdmitters(org: out[0], site: out[1], std: out[2])
    }

    /// The first ceiling that excludes the outcome, or nil when every ceiling admits it.
    public static func ceilingOf(_ c: CeilingAdmitters, _ vs: WalletVerb, _ o: JSONValue) -> String? {
        for k in LAYER_CEILINGS {
            if let a = c.of(k), !a.admits(vs, o) { return k }
        }
        return nil
    }

    private static func num(_ v: JSONValue?) throws -> Double {
        guard let d = IV.num(v) else { throw JSError("not a number") }
        return d
    }

    private static func key(_ verb: String?, _ cell: [JSONValue]) throws -> String {
        var parts: [String] = []
        for c in cell { parts.append(JS.toString(.double(try num(c)))) }
        return (verb ?? "null") + "|" + parts.joined(separator: ",")
    }

    private static func verbMember(_ v: JSONValue?) throws -> String? {
        guard let x = v, !x.isNull else { return nil }
        guard let s = x.asString else { throw JSError("not a string") }
        return s
    }

    /// A question may only be about a cell of the uncertain set (inside every ceiling). Throws otherwise.
    public static func assertAskable(_ view: JSONValue?, _ c: JSONValue?) throws {
        let k = try key(try verbMember(c?.get("verb")), try PCAIntentOmega.arr(c?.get("cell")))
        for u in try PCAIntentOmega.arr(view?.get("uncertain")) {
            guard u.isObject else { throw JSError("not an object") }
            if try key(try verbMember(u.get("verb")), try PCAIntentOmega.arr(u.get("cell"))) == k { return }
        }
        throw JSError("layers: cell \(k) is not an uncertain cell inside every ceiling (never a question)")
    }

    private static func idxOf(_ cl: [JSONValue]) throws -> [Int] {
        var out: [Int] = []
        for c in cl { out.append(PCAIntentOmega.toInt(try num(c))) }
        return out
    }

    /// Layer owner's own risk of a set of cells ({verb, cell}): sum of mass * (1 - a) * E[h | cell].
    static func ownerRisk(_ omega: WalletOmega, _ cells: [JSONValue], _ acceptability: Acceptability,
                                 _ harm: WalletOmegaMath.HarmModel = WalletOmegaMath.DEFAULT_HARM) throws -> Double {
        var r = 0.0
        for c in cells {
            guard let verb = try verbMember(c.get("verb")), let vs = omega.verb(verb) else { continue }
            let idx = try idxOf(try PCAIntentOmega.arr(c.get("cell")))
            let st = WalletOmegaMath.cellStats(vs, idx, harm)
            r += st.mass * (1 - (try acceptability(vs, WalletOmegaMath.cellRep(vs, idx)))) * st.harm
        }
        return r
    }

    /// Every cell of the space an admitter admits (the layer as a cell set).
    public static func layerCells(_ omega: WalletOmega, _ a: PCAIntentAdmitter) -> [JSONValue] {
        var out: [JSONValue] = []
        for vs in omega.verbs {
            let n = WalletOmegaMath.verbCellCount(vs)
            var f = 0
            while f < n {
                let cell = WalletOmegaMath.decodeCell(vs, f)
                if a.admits(vs, WalletOmegaMath.cellRep(vs, cell)) {
                    out.append(.object([JKey("verb"): .string(vs.verb), JKey("cell"): WJ.arr(cell)]))
                }
                f += 1
            }
        }
        return out
    }

    /// Flat key of a cell ({verb, cell}).
    public static func cellKeyOf(_ omega: WalletOmega, _ c: JSONValue?) throws -> String {
        let verb = try verbMember(c?.get("verb"))
        let cl = try PCAIntentOmega.arr(c?.get("cell"))
        guard let v = verb, let vs = omega.verb(v) else { return try key(verb, cl) }
        return v + "|" + JS.toString(.double(Double(PCAIntentLearner.encode(vs, try idxOf(cl)))))
    }

    // ---- quorum-signed layer approvals ----

    private static let STATEMENT_KEYS: [String] = ["v", "kind", "layer", "session", "seq", "map_digest", "prev"]

    private static func statementOf(_ a: JObject) -> JObject {
        var st = JObject()
        st[JKey("v")] = .int(1)
        st[JKey("kind")] = .string("pca-intent-layer-approval")
        for k in ["layer", "session", "seq", "map_digest", "prev"] {
            if let x = a[JKey(k)] { st[JKey(k)] = x }
        }
        return st
    }

    private static func approvalMessage(_ st: JObject) throws -> [UInt8] {
        return try PCAIntentKit.message(LAYER_APPROVAL_DOMAIN, .object(st))
    }

    /// Sign an approval of a shared-layer widening ({layer, session, seq, map_digest, prev}).
    public static func signLayerApproval(_ s: JSONValue?, _ secretSeed: [UInt8]) throws -> JSONValue {
        return try signLayerApproval(s, try PCAEdKey(seed: secretSeed))
    }

    /// The same under an already built key (so a test can sign with the deterministic RFC 8032 scheme).
    static func signLayerApproval(_ s: JSONValue?, _ key: PCAEdKey) throws -> JSONValue {
        var st = statementOf(try PCAIntentOmega.obj(s))
        let sig = try key.sign(try approvalMessage(st))
        st[JKey("signer")] = .string(key.id)
        st[JKey("sig")] = .string(Base64URLStrict.encode(sig))
        return .object(st)
    }

    private static func quorumResult(_ ok: Bool, _ signers: [String], _ ignored: [JSONValue]) -> JSONValue {
        return .object([JKey("ok"): .bool(ok), JKey("signers"): .array(signers.map { JSONValue.string($0) }), JKey("ignored"): .array(ignored)])
    }

    private static func ign(_ index: Int, _ reason: String?) -> JSONValue {
        return .object([JKey("index"): .int(Int64(index)), JKey("reason"): reason.map { JSONValue.string($0) } ?? JSONValue.null])
    }

    /// Verify approvals against the layer's members and rule. An approval counts iff its signer is a member, it is the FIRST from that
    /// member, its statement equals `expected` field by field and its signature verifies; the rule is the multi-principal one over
    /// member keys. Returns {ok, signers, ignored[{index, reason}]}.
    public static func verifyQuorumApprovals(_ approvals: JSONValue?, _ members: JSONValue?, _ rule: JSONValue?, _ expected: JSONValue?) -> JSONValue {
        guard let apps = approvals?.asArray, let mems = members?.asArray, let exp = expected?.asObject else {
            return quorumResult(false, [], [ign(-1, "approvals and members must be arrays and expected an object")])
        }
        var mem: [String] = []
        var bad = false
        for x in mems {
            guard let s = x.asString, Base64URLStrict.decode(s, length: 32) != nil else { bad = true; break }
            mem.append(s)
        }
        if !bad && !IV.distinct(mem) { bad = true }
        if bad { return quorumResult(false, [], [ign(-1, "members must be distinct 32-byte keys")]) }
        let n: PCAIntentMulti.NormalRule
        do {
            n = try PCAIntentMulti.normalizeRule(rule, mem)
        } catch let e as JSError {
            return quorumResult(false, [], [ign(-1, e.message)])
        } catch {
            return quorumResult(false, [], [ign(-1, "\(error)")])
        }
        let want = statementOf(exp)
        var counted: [String] = []
        var ignored: [JSONValue] = []
        for i in 0..<apps.count {
            let ao = apps[i]
            if !ao.isObject && !ao.isArray {
                ignored.append(ign(i, "not an object"))
                continue
            }
            guard let a = ao.asObject else {
                ignored.append(ign(i, "signer is not a member"))
                continue
            }
            guard let signer = a[JKey("signer")]?.asString, IV.contains(mem, signer) else {
                ignored.append(ign(i, "signer is not a member"))
                continue
            }
            if IV.contains(counted, signer) {
                ignored.append(ign(i, "second approval from the same member"))
                continue
            }
            let st = statementOf(a)
            var same = true
            for k in STATEMENT_KEYS {
                let xd = st[JKey(k)] != nil
                let yd = want[JKey(k)] != nil
                if xd != yd || (xd && !IV.strictEq(st[JKey(k)], want[JKey(k)])) { same = false }
            }
            same = same && IV.strictEq(a[JKey("v")], .int(1)) && IV.same(a[JKey("kind")]?.asString, "pca-intent-layer-approval")
            if !same {
                ignored.append(ign(i, "approval is for another (layer, session, seq, map_digest, prev)"))
                continue
            }
            var ok = false
            if let msg = try? approvalMessage(st) { ok = PCAIntentKit.verifyEd(JSONValue.string(signer), msg, a[JKey("sig")]) }
            if !ok {
                ignored.append(ign(i, "bad signature"))
                continue
            }
            counted.append(signer)
        }
        var signers: [String] = []
        var ins = [Bool](repeating: false, count: mem.count)
        for i in 0..<mem.count {
            ins[i] = IV.contains(counted, mem[i])
            if ins[i] { signers.append(mem[i]) }
        }
        return quorumResult(PCAIntentMulti.ruleAdmits(n, ins), signers, ignored)
    }
}
