import Foundation

/// The builder side of the committed Intent Map (Merkle form, per-leaf salts derived from one session secret): the leaf layout, salts,
/// tree and Z0 disclosure that the verifier side (`IntentMap`) checks. Inputs and outputs are plain JSON trees.
public enum PCAIntentMapCommit {
    /// Informative per-leaf salt derivation tag (wallet side).
    public static let MAP_TAG_SALT = "atlas-pca/intent-map/salt/v1\u{0}"

    /// One committed leaf: its kind, its (normalised) JSON and its salt.
    public struct Leaf {
        public let kind: String
        public let leaf: JSONValue
        public let salt: [UInt8]
    }

    public final class CommittedMap {
        public let mapCommit: String
        public let size: Int
        public let leaves: [Leaf]
        let hashes: [[UInt8]]
        let full: [JObject]

        init(mapCommit: String, size: Int, leaves: [Leaf], hashes: [[UInt8]], full: [JObject]) {
            self.mapCommit = mapCommit
            self.size = size
            self.leaves = leaves
            self.hashes = hashes
            self.full = full
        }

        /// The leaves as JSON: [{kind, leaf, salt}].
        public func leavesJson() -> JSONValue {
            return .array(leaves.map { l in
                JSONValue.object(["kind": .string(l.kind), "leaf": l.leaf, "salt": .string(Base64URLStrict.encode(l.salt))])
            })
        }

        private func entry(_ i: Int) -> JSONValue {
            var out: [[UInt8]] = []
            PCAIntentMapCommit.auditPath(hashes[...], i, &out)
            return .object(["index": .int(Int64(i)), "salt": .string(Base64URLStrict.encode(leaves[i].salt)), "leaf": leaves[i].leaf,
                            "path": .array(out.map { JSONValue.string(Base64URLStrict.encode($0)) })])
        }

        /// Z0 disclosure for an action; throws when the action lies outside the map.
        public func disclose(_ verb: String, _ resource: JSONValue?, _ params: JSONValue?) throws -> JSONValue {
            guard let hi = full.firstIndex(where: { IV.same($0[JKey("verb")]?.asString, verb) }) else {
                throw JSError("commitMap.disclose: verb \(verb) is not in the map")
            }
            guard let w = IntentMap.cellOf(full[hi], resource: resource, params: params) else {
                throw JSError("commitMap.disclose: the action lies outside the committed map's dimension")
            }
            guard let first = IV.int(full[hi][JKey("first")]) else { throw JSError("commitMap.disclose: bad header") }
            let at = Int(first) + Int(w.flat)
            if at < 0 || at >= leaves.count { throw JSError("commitMap.disclose: cell leaf out of range") }
            return .object(["size": .int(Int64(size)), "header": entry(hi), "cell": entry(at), "metrics": entry(size - 2)])
        }
    }

    private static func split(_ n: Int) -> Int {
        var k = 1
        while k * 2 < n { k *= 2 }
        return k
    }

    static func auditPath(_ hs: ArraySlice<[UInt8]>, _ idx: Int, _ out: inout [[UInt8]]) {
        if hs.count == 1 { return }
        let k = split(hs.count)
        let mid = hs.startIndex + k
        if idx < k {
            auditPath(hs[hs.startIndex..<mid], idx, &out)
            out.append(IntentMap.treeRoot(hs[mid..<hs.endIndex]))
        } else {
            auditPath(hs[mid..<hs.endIndex], idx - k, &out)
            out.append(IntentMap.treeRoot(hs[hs.startIndex..<mid]))
        }
    }

    /// Per-leaf salt: SHA-256(TAG_SALT || secret || u64be(index)).
    public static func mapLeafSalt(_ secret: [UInt8], _ index: Int64) -> [UInt8] {
        return Canonical.sha256(Canonical.utf8(MAP_TAG_SALT) + secret + IntentMap.u64be(index))
    }

    private static func fail(_ what: String) -> JSError { return JSError("commitMap: \(what)") }

    private static func learnerError(_ l: JSONValue?) -> String? {
        guard case let .object(o)? = l, IntentMap.closed(o, ["learner_digest"], ["learner_digest"]) else { return "the learner leaf must be exactly {learner_digest}" }
        return IV.digest(o[JKey("learner_digest")]) != nil ? nil : "learner.learner_digest must be canonical base64url (32 bytes)"
    }

    /// Build the committed form. `headers`: [{verb, dims}], `cells`: verb -> [{cell, p_ppm, in_grant}] in flat order, `metrics`: the
    /// metrics leaf, `learnerDigest`: the learner settings' content address. Throws on a malformed input.
    public static func commitMap(_ headers: [JSONValue], _ cells: [JKey: [JSONValue]], _ metrics: JSONValue, _ learnerDigest: String, _ secret: [UInt8]?) throws -> CommittedMap {
        guard let secret = secret, secret.count == 32 else { throw fail("the secret is 32 bytes") }
        var heads: [(verb: String, dims: JSONValue)] = []
        for h in headers {
            guard let v = h.get("verb")?.asString else { throw fail("a header needs a verb string") }
            heads.append((v, h.get("dims") ?? .null))
        }
        // stable by verb in UTF-8 byte order
        let order = Array(0..<heads.count).sorted { (a: Int, b: Int) -> Bool in
            if IV.utf8Less(heads[a].verb, heads[b].verb) { return true }
            if IV.utf8Less(heads[b].verb, heads[a].verb) { return false }
            return a < b
        }
        heads = order.map { heads[$0] }
        if heads.count > 1 {
            for i in 1..<heads.count where IV.same(heads[i].verb, heads[i - 1].verb) { throw fail("duplicate verb") }
        }
        var counts: [Int64] = []
        for h in heads {
            guard let dims = h.dims.asArray else { throw fail("a header needs a dims array") }
            var n: Int64 = 1
            for d in dims {
                guard let dm = d.asObject else { throw fail("a dimension is not an object") }
                let r = n.multipliedReportingOverflow(by: IntentMap.dimCells(dm))
                if r.overflow { throw fail("too many cells") }
                n = r.partialValue
            }
            counts.append(n)
        }
        var next = Int64(heads.count)
        var full: [JObject] = []
        for i in 0..<heads.count {
            full.append(["verb": .string(heads[i].verb), "first": .int(next), "cells": .int(counts[i]), "dims": heads[i].dims])
            next += counts[i]
        }
        var kinds: [String] = []
        var leaves: [JSONValue] = []
        for h in full { kinds.append("header"); leaves.append(.object(h)) }
        for h in full {
            let verb = h[JKey("verb")]?.asString ?? ""
            let want = IV.int(h[JKey("cells")]) ?? 0
            guard let cs = cells[JKey(verb)], Int64(cs.count) == want else { throw fail("verb \(verb) needs \(want) cell leaves") }
            for c in cs {
                kinds.append("cell")
                leaves.append(.object(["verb": h[JKey("verb")] ?? .null, "cell": c.get("cell") ?? .null, "p_ppm": c.get("p_ppm") ?? .null,
                                       "in_grant": c.get("in_grant") ?? .null]))
            }
        }
        kinds.append("metrics")
        leaves.append(metrics)
        kinds.append("learner")
        leaves.append(.object(["learner_digest": .string(learnerDigest)]))
        for i in 0..<leaves.count {
            let leaf = leaves[i]
            let e: String?
            switch kinds[i] {
            case "header": e = IntentMap.headerError(leaf)
            case "cell": e = IntentMap.cellError(leaf)
            case "metrics": e = IntentMap.metricsError(leaf)
            default: e = learnerError(leaf)
            }
            if let m = e { throw fail(m) }
        }
        if leaves.count < 4 || Int64(leaves.count) > IntentMap.MAX_LEAVES { throw fail("the map has too few or too many leaves") }
        var outLeaves: [Leaf] = []
        var hashes: [[UInt8]] = []
        for i in 0..<leaves.count {
            let salt = mapLeafSalt(secret, Int64(i))
            let norm = WJ.plain(leaves[i])
            outLeaves.append(Leaf(kind: kinds[i], leaf: norm, salt: salt))
            guard let h = IntentMap.leafHash(kinds[i], salt, norm) else { throw fail("a leaf is not strictly canonical") }
            hashes.append(h)
        }
        let root = IntentMap.treeRoot(hashes[...])
        return CommittedMap(mapCommit: IntentMap.commitOf(Int64(hashes.count), root), size: hashes.count, leaves: outLeaves, hashes: hashes,
                            full: full.map { WJ.plain(.object($0)).asObject ?? $0 })
    }
}

extension PCAIntentMap {
    private static func ls(_ o: JSONValue?) throws -> [JSONValue] {
        guard let a = o?.asArray else { throw JSError("pca-intent: not an array") }
        return a
    }

    private static func mp(_ o: JSONValue?) throws -> JObject {
        guard let m = o?.asObject else { throw JSError("pca-intent: not an object") }
        return m
    }

    private static func dbl(_ o: JSONValue?) throws -> Double {
        guard let d = IV.num(o) else { throw JSError("pca-intent: not a number") }
        return d
    }

    private static func numCellCount(_ lo: Double, _ hi: Double, _ cuts: [JSONValue]) throws -> Int64 {
        var n: Int64 = 0
        var cur = lo
        for co in cuts {
            let c = try dbl(co)
            if c < lo || c > hi { continue }
            if cur <= c - 1 { n += 1 }
            n += 1
            cur = c + 1
        }
        return cur <= hi ? n + 1 : n
    }

    static let MAX_COMMIT_CELLS: Int64 = 1 << 20

    /// The committed form of an Intent Map; `secret` (32 bytes) derives every leaf salt.
    public static func commitIntentMap(_ mapO: JSONValue?, _ secret: [UInt8]?) throws -> PCAIntentMapCommit.CommittedMap {
        let m = try mp(mapO)
        let verbs = try ls(try mp(m[JKey("omega")])[JKey("verbs")])
        var headers: [JSONValue] = []
        for vo in verbs {
            let v = try mp(vo)
            var dims: [JSONValue] = []
            for d in try ls(v[JKey("dims")]) {
                let dm = try mp(d)
                var o: JObject = [:]
                if let k = dm[JKey("kind")]?.asString, IV.same(k, "num") {
                    let lo = try dbl(dm[JKey("lo")])
                    let hi = try dbl(dm[JKey("hi")])
                    var cuts: [JSONValue] = []
                    if let cv = dm[JKey("cuts")], !cv.isNull {
                        for c in try ls(cv) {
                            let x = try dbl(c)
                            if x >= lo && x <= hi { cuts.append(c) }
                        }
                    }
                    o["kind"] = .string("num"); o["path"] = dm[JKey("path")] ?? .null; o["lo"] = dm[JKey("lo")] ?? .null
                    o["hi"] = dm[JKey("hi")] ?? .null; o["cuts"] = .array(cuts)
                } else {
                    var vals: [JSONValue] = []
                    if let vv = dm[JKey("values")], !vv.isNull {
                        for x in try ls(vv) {
                            let xm = try mp(x)
                            vals.append(.object(["kind": xm[JKey("kind")] ?? .null, "value": xm[JKey("value")] ?? .null]))
                        }
                    }
                    o["kind"] = .string("cat"); o["path"] = dm[JKey("path")] ?? .null; o["values"] = .array(vals)
                }
                dims.append(.object(o))
            }
            headers.append(.object(["verb": v[JKey("verb")] ?? .null, "dims": .array(dims)]))
        }
        var cells: [JKey: [JSONValue]] = [:]
        for vo in verbs {
            let v = try mp(vo)
            guard let verb = v[JKey("verb")]?.asString else { throw JSError("pca-intent: a verb needs a name") }
            let dims = try ls(v[JKey("dims")])
            var counts: [Int64] = []
            var total: Int64 = 1
            for d in dims {
                let dm = try mp(d)
                var cnt: Int64 = 0
                if let k = dm[JKey("kind")]?.asString, IV.same(k, "num") {
                    var cutList: [JSONValue] = []
                    if let cv = dm[JKey("cuts")], !cv.isNull { cutList = try ls(cv) }
                    cnt = try numCellCount(try dbl(dm[JKey("lo")]), try dbl(dm[JKey("hi")]), cutList)
                } else if let vv = dm[JKey("values")], !vv.isNull {
                    cnt = Int64(try ls(vv).count)
                }
                counts.append(cnt)
                let r = total.multipliedReportingOverflow(by: cnt)
                if r.overflow { throw JSError("commitIntentMap: too many cells for \(verb)") }
                total = r.partialValue
            }
            if total > MAX_COMMIT_CELLS { throw JSError("commitIntentMap: too many cells for \(verb)") }
            var slots = [JSONValue?](repeating: nil, count: Int(total))
            for co in try ls(m[JKey("cells")]) {
                let c = try mp(co)
                if !IV.same(c[JKey("verb")]?.asString, verb) { continue }
                let cell = try ls(c[JKey("cell")])
                if cell.count != counts.count { throw JSError("commitIntentMap: cell of \(verb) has the wrong arity") }
                var flat: Int64 = 0
                for j in 0..<cell.count {
                    let i = IV.num(cell[j]) ?? Double.nan
                    guard i == i.rounded(.down), abs(i) <= 9007199254740991.0, i >= 0, i < Double(counts[j]) else {
                        throw JSError("commitIntentMap: cell index out of range for \(verb)")
                    }
                    flat = flat * counts[j] + Int64(i)
                }
                slots[Int(flat)] = .object(["cell": .array(cell), "p_ppm": c[JKey("p_ppm")] ?? .null, "in_grant": c[JKey("in_grant")] ?? .null])
            }
            var list: [JSONValue] = []
            for s in slots {
                guard let x = s else { throw JSError("commitIntentMap: the map does not list every cell of \(verb)") }
                list.append(x)
            }
            cells[JKey(verb)] = list
        }
        var metrics: JObject = [:]
        let mm = try mp(m[JKey("metrics")])
        for (k, x) in mm where !IV.same(k.s, "log2_vs_mbits") { metrics[k] = x }
        if let l = mm[JKey("log2_vs_mbits")], !l.isNull { metrics[JKey("log2_vs_mbits")] = l }
        guard let learner = m[JKey("learner")] else { throw JSError("commitIntentMap: the map has no learner") }
        return try PCAIntentMapCommit.commitMap(headers, cells, .object(metrics), try WJ.hash(WJ.plain(learner)), secret)
    }
}
