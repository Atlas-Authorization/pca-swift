import XCTest
import CryptoKit
@testable import AtlasPCAVerify
@testable import AtlasPCAPairing

/// Replays the reference corpus (FAME ciphertext-policy ABE on BLS12-381, AES-256-GCM, capability attributes). The corpus carries no key
/// bytes: master and user keys are recipes ({"$abeMsk": label}, {"$abeKey": {msk, attrs, id}}, optionally edited by "$patch" / "$edits" or
/// merged by "$pool"), and every scalar is sha512("abe-oracle/" + label) mod r (1 for 0), so the keys are re-derived here as in the reference.
final class AbeTests: XCTestCase {
    static func sc(_ label: String) -> Fr {
        let v = Fr(reducing: Array(SHA512.hash(data: Data(("abe-oracle/" + label).utf8))))
        return v.isZero ? Fr(1) : v
    }

    static func seedMsk(_ label: String) -> Fame.Msk {
        func s(_ n: String) -> Fr { sc(label + "/" + n) }
        return try! Fame.setup(a: [s("a1"), s("a2")], b: [s("b1"), s("b2")], d: [s("d1"), s("d2"), s("d3")]).1
    }

    static func seedKey(_ spec: JSONValue) -> JSONValue {
        let label = spec.get("msk")?.asString ?? "", id = spec.get("id")?.asString ?? ""
        var seen = Set<JKey>()
        var names: [JKey] = []
        for a in (spec.get("attrs")?.asArray ?? []).compactMap({ $0.asString }) { let k = JKey(a); if seen.insert(k).inserted, !a.isEmpty { names.append(k) } }
        let sigmas = names.indices.map { sc(id + "/sg\($0)") }
        let key = try! Fame.keygen(seedMsk(label), attrs: names, r: [sc(id + "/r1"), sc(id + "/r2")], sigmas: sigmas, sigmaPrime: sc(id + "/sgp"))
        var am: JObject = [:]
        for n in names { am[n] = .object(["k": Abe.tri1JSON(key.attrs[n]!)]) }
        return .object(["v": Abe.v2, "curve": .string("bls12-381"), "k0": Abe.tri2JSON(key.k0), "kp": Abe.tri1JSON(key.kp), "attrs": .object(am)])
    }

    static func at(_ v: JSONValue, _ path: [JSONValue]) -> JSONValue {
        var cur = v
        for p in path {
            if let k = p.asString, let x = cur.get(k) { cur = x }
            else if case let .int(i) = p, let a = cur.asArray, Int(i) < a.count { cur = a[Int(i)] }
        }
        return cur
    }

    static func set(_ v: JSONValue, _ path: [JSONValue], _ val: JSONValue, delete: Bool) -> JSONValue {
        guard let head = path.first else { return val }
        switch v {
        case var .object(o):
            let k = JKey(head.asString ?? "")
            if path.count == 1 && delete { o[k] = nil } else { o[k] = set(o[k] ?? .null, Array(path.dropFirst()), val, delete: delete) }
            return .object(o)
        case var .array(a):
            guard case let .int(i) = head else { return v }
            let n = Int(i)
            if n == a.count { a.append(.null) }
            a[n] = set(a[n], Array(path.dropFirst()), val, delete: delete)
            return .array(a)
        default: return v
        }
    }

    /// Replaces every key recipe inside `v` by the derived key.
    static func resolve(_ v: JSONValue) -> JSONValue {
        switch v {
        case let .array(a): return .array(a.map(resolve))
        case let .object(o):
            if let l = o["$abeMsk"]?.asString { return Abe.mskJSON(seedMsk(l)) }
            if let k = o["$abeKey"] { return seedKey(k) }
            if let p = o["$pool"]?.asArray, let first = p.first {
                var base = resolve(first).asObject ?? [:]
                var attrs = base["attrs"]?.asObject ?? [:]
                for other in p.dropFirst() { for (n, c) in resolve(other).get("attrs")?.asObject ?? [:] { attrs[n] = c } }
                base["attrs"] = .object(attrs)
                return .object(base)
            }
            if let p = o["$patch"] {
                var base = resolve(p)
                let edits = o["$edits"]?.asArray ?? []
                // a $ref reads the base as it was before any edit
                let vals: [JSONValue] = edits.map { e in
                    let val = e.get("value") ?? .null
                    if let r = val.get("$ref")?.asArray { return at(base, r) }
                    return val
                }
                for (i, e) in edits.enumerated() {
                    base = set(base, e.get("path")?.asArray ?? [], vals[i], delete: vals[i].get("$undefined") != nil)
                }
                return base
            }
            return .object(o.mapValues(resolve))
        default: return v
        }
    }

    static func strs(_ v: JSONValue?) -> [String] { (v?.asArray ?? []).compactMap { $0.asString } }

    static func opts(_ v: JSONValue?) -> Abe.CapabilityOptions {
        var o = Abe.CapabilityOptions()
        if let c = v?.get("chain")?.asArray { o.chain = c }
        if let p = v?.get("principal")?.asString { o.principal = p }
        if let pins = v?.get("pqPins")?.asObject { o.pqPins = Dictionary(uniqueKeysWithValues: pins.compactMap { k, x in x.asString.map { (k.s, $0) } }) }
        return o
    }

    static func b(_ x: [UInt8]) -> JSONValue { Ref.bytesValue(x) }
    static func g1l(_ x: [G1]) -> JSONValue { .array(x.map { b($0.compressed) }) }
    static func g2l(_ x: [G2]) -> JSONValue { .array(x.map { b($0.compressed) }) }

    static func fame(_ a: [JSONValue]) -> JSONValue? {
        guard a.count == 3 else { return nil }
        // the scalars are a seed label, or (the CI-generated cases that carry private keys) an object of big-endian hex scalars
        let label = a[2].get("$seed")?.asString
        let hexScalars = a[2].asObject != nil && label == nil
        guard label != nil || hexScalars else { return nil }
        func hs(_ n: String, _ i: Int) -> Fr? {
            var v: JSONValue? = a[2].get(n)
            if n != "sigmaPrime" { let l = v?.asArray ?? []; v = i < l.count ? l[i] : nil }
            guard let h = v?.asString, let u = Ref.unhex(h) else { return nil }
            return Fr(reducing: u)
        }
        let (treeOpt, _) = AbePolicy.normalize(a[0])
        guard let tree = treeOpt else { return nil }
        let attrs = strs(a[1]).map { JKey($0) }
        func s(_ n: String) -> Fr {
            if let l = label { return sc(l + n) }
            let m = ["a1": ("a", 0), "a2": ("a", 1), "b1": ("b", 0), "b2": ("b", 1), "d1": ("d", 0), "d2": ("d", 1), "d3": ("d", 2), "r1": ("r", 0), "r2": ("r", 1),
                     "s1": ("s", 0), "s2": ("s", 1), "sgp": ("sigmaPrime", 0)]
            if let (k, i) = m[n] { return hs(k, i) ?? Fr(1) }
            return hs("sigma", Int(n.dropFirst(2)) ?? 0) ?? Fr(1)
        }
        guard let (mpk, msk) = try? Fame.setup(a: [s("a1"), s("a2")], b: [s("b1"), s("b2")], d: [s("d1"), s("d2"), s("d3")]),
              let key = try? Fame.keygen(msk, attrs: attrs, r: [s("r1"), s("r2")], sigmas: attrs.indices.map { s("sg\($0)") }, sigmaPrime: s("sgp")),
              let (ct, k) = try? Fame.encrypt(mpk, tree, s: [s("s1"), s("s2")]) else { return nil }
        var keyAttrs: JObject = [:]
        for (n, c) in key.attrs { keyAttrs[n] = g1l(c) }
        return .object(["h": .array([b(mpk.h1.compressed), b(mpk.h2.compressed)]), "t": .array([b(mpk.t1), b(mpk.t2)]), "mskg": g1l(msk.g),
                        "k0": g2l(key.k0), "kp": g1l(key.kp), "key": .object(keyAttrs), "ct0": g2l(ct.ct0),
                        "rows": .array(ct.rows.map { g1l($0) }), "k": b(k), "dec": Fame.decrypt(key, tree, ct).map { b($0) } ?? .null])
    }

    static func byteList(_ v: JSONValue?) -> [[UInt8]]? {
        guard let a = v?.asArray else { return nil }
        var out: [[UInt8]] = []
        for x in a { guard let y = Ref.bytes(x) else { return nil }; out.append(y) }
        return out
    }

    static func run(_ c: RefCase) -> JSONValue? {
        let a = c.args.map(resolve)
        func arg(_ i: Int) -> JSONValue? { i < a.count ? a[i] : nil }
        switch c.fn {
        case "fame": return fame(a)
        case "gtIsElement": return Ref.bytes(arg(0)).map { .bool(Gt.isElement($0)) }
        case "gtPow":
            guard let x = Ref.bytes(arg(0)), let h = arg(1)?.asString, var k = Ref.unhex(h) else { return nil }
            while k.count < 32 { k.insert(0, at: 0) }
            return Gt.pow(x, k).map { b($0) }
        case "gtMul":
            guard let x = Ref.bytes(arg(0)), let y = Ref.bytes(arg(1)) else { return nil }
            return Gt.mul(x, y).map { b($0) }
        case "pairingProduct":
            guard let g1s = byteList(arg(0)), let g2s = byteList(arg(1)) else { return nil }
            return Gt.pairing(g1s, g2s).map { b($0) }
        case "normalizePolicy":
            guard let p = arg(0) else { return nil }
            let (t, why) = Abe.normalizePolicy(p)
            if let t = t { return .object(["ok": .bool(true), "tree": t]) }
            return .object(["ok": .bool(false), "reason": .string(why ?? "")])
        case "satisfies": return arg(0).map { .bool(Abe.satisfies(tree: $0, attrs: strs(arg(1)))) }
        case "policyAttributes": return arg(0).flatMap { Abe.policyAttributes(tree: $0) }.map { .array($0.map { .string($0) }) }
        case "parseCiphertext": return arg(0).map { Abe.parseCiphertext($0) ?? .null }
        case "decrypt":
            guard let k = arg(0), let ct = arg(1) else { return nil }
            return Abe.decrypt(key: k, ciphertext: ct).map { b($0) } ?? .null
        case "decryptText":
            guard let k = arg(0), let ct = arg(1) else { return nil }
            return Abe.decryptText(key: k, ciphertext: ct).map { .string($0) } ?? .null
        case "decryptWithCapability":
            guard let k = arg(0), let ct = arg(1) else { return nil }
            let r = Abe.decryptWithCapability(key: k, ciphertext: ct)
            if let reason = r.reason { return .object(["ok": .bool(false), "reason": .string(reason)]) }
            return .object(["ok": .bool(true), "payload": r.payload ?? .null])
        case "encryptAccepts":
            guard let mpk = arg(0), let p = arg(1) else { return nil }
            return (try? Abe.encryptForPolicy(mpk: mpk, policy: p, plaintext: [0x78])) == nil ? nil : .bool(true)
        case "keygenForAttributes":
            guard let msk = arg(0), arg(1)?.asArray != nil, let r = try? Abe.issue(msk, strs(arg(1))) else { return nil }
            return .array(r.names.map { .string($0) })
        case "keygenForCapability":
            guard let msk = arg(0), let cap = arg(1), let r = try? Abe.keygenForCapability(msk: msk, capability: cap, extra: strs(arg(2)), opts(arg(3))) else { return nil }
            return .object(["holder": r.key.get("holder") ?? .null, "attrs": .array(r.attrs.map { .string($0) })])
        case "capabilityAttributes":
            guard let cap = arg(0) else { return nil }
            return .array(Abe.capabilityAttributes(cap, opts(arg(1))).map { .string($0) })
        default: return nil
        }
    }

    func testReplayCorpus() throws {
        let d = Ref.Diffs()
        let n = try Ref.each("ref-abe.json.gz") { c in d.add(Ref.diff(c, AbeTests.run(c))) }
        // cases carrying a lone surrogate cannot be held by a Swift String (4 in the corpus)
        XCTAssertLessThanOrEqual(Ref.lastUnparsed, 4)
        XCTAssertEqual(n + Ref.lastUnparsed, 254)
        // the 14 cases that carry private keys live in ref-abe-gen.json.gz (CI-generated): 268 in all
        if let g = Ref.secretCorpusPath("ref-abe.json.gz") {
            let m = try Ref.each(g) { c in d.add(Ref.diff(c, AbeTests.run(c))) }
            XCTAssertEqual(m + Ref.lastUnparsed, 14)
            d.finish(264)
        } else {
            d.finish(250)
        }
    }

    func testRoundTrip() throws {
        let (mpk, msk) = try Abe.setup()
        let policy: JSONValue = .object(["allOf": .array([.object(["attr": .string("a")]), .object(["attr": .string("b")])])])
        let ct = try Abe.encryptForPolicy(mpk: mpk, policy: policy, plaintext: Array("hello".utf8))
        let both = try Abe.keygenForAttributes(msk: msk, attrs: ["a", "b"])
        let one = try Abe.keygenForAttributes(msk: msk, attrs: ["a"])
        XCTAssertEqual(Abe.decrypt(key: both, ciphertext: ct), Array("hello".utf8))
        XCTAssertNil(Abe.decrypt(key: one, ciphertext: ct), "a key missing an attribute must not decrypt")
        XCTAssertEqual(Abe.decryptText(key: both, ciphertext: ct), "hello")
    }
}
