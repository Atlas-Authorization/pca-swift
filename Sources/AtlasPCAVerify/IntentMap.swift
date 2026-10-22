import Foundation

/// Committed map and Z0 disclosure (Intent Layer v2 V15, conformance rule 19). Mirrors
/// `packages/pca/src/intent-map-commit.ts`: salted kind-tagged leaves, the RFC 6962 / 9162 tree with a tagged node hash,
/// `map_commit = base64url(SHA-256(TAG_COMMIT || u64be(n) || root))`, closed and typed leaves, RFC 9162 audit-path
/// openings, and the exact cell of the action.
enum IntentMap {
    static let TAG_HEADER = "atlas-pca/intent-map/header/v1\u{0}"
    static let TAG_CELL = "atlas-pca/intent-map/cell/v1\u{0}"
    static let TAG_METRICS = "atlas-pca/intent-map/metrics/v1\u{0}"
    static let TAG_LEARNER = "atlas-pca/intent-map/learner/v1\u{0}"
    static let TAG_NODE = "atlas-pca/intent-map/node/v1\u{0}"
    static let TAG_COMMIT = "atlas-pca/intent-map/commit/v1\u{0}"
    static let FORM_COMMIT = "commit"
    static let OTHER = "\u{22A5}"
    static let MAX_LEAVES: Int64 = 1 << 24
    static let MAX_VERB_CELLS: Int64 = 1 << 20
    static let MAX_DIMS = 16
    static let MAX_CUTS = 256
    static let MAX_VALUES = 256
    static let MAX_STRING_BYTES = 256
    static let METRIC_FIELDS = ["residual_risk_ppm", "burden_ppm", "uncertainty_ppm", "disagreement_ppm", "mean_harm_ppm", "fidelity_est_ppm",
                                "entropy_mbits", "questions", "conflicts"]

    static func tag(_ kind: String) -> String? {
        switch kind {
        case "header": return TAG_HEADER
        case "cell": return TAG_CELL
        case "metrics": return TAG_METRICS
        case "learner": return TAG_LEARNER
        default: return nil
        }
    }

    static func u64be(_ n: Int64) -> [UInt8] { (0..<8).reversed().map { UInt8((UInt64(n) >> (UInt64($0) * 8)) & 0xff) } }

    /// `SHA-256(TAG_kind || salt || strictCanonical(leaf))`; nil when the leaf is not strictly canonical.
    static func leafHash(_ kind: String, _ salt: [UInt8], _ leaf: JSONValue) -> [UInt8]? {
        guard salt.count == 32, let t = tag(kind), let c = IV.strictCanon(leaf) else { return nil }
        return Canonical.sha256(Canonical.utf8(t) + salt + Canonical.utf8(c))
    }
    static func nodeHash(_ l: [UInt8], _ r: [UInt8]) -> [UInt8] { Canonical.sha256(Canonical.utf8(TAG_NODE) + l + r) }
    static func commitOf(_ size: Int64, _ root: [UInt8]) -> String { Base64URLStrict.encode(Canonical.sha256(Canonical.utf8(TAG_COMMIT) + u64be(size) + root)) }

    static func split(_ n: Int) -> Int {
        var k = 1
        while k * 2 < n { k *= 2 }
        return k
    }
    static func treeRoot(_ hs: ArraySlice<[UInt8]>) -> [UInt8] {
        if hs.count == 1 { return hs.first! }
        let k = split(hs.count)
        return nodeHash(treeRoot(hs.prefix(k)), treeRoot(hs.dropFirst(k)))
    }

    /// RFC 9162 §2.1.3.2 root from an audit path; nil when the path does not fit (index, size).
    static func rootFromPath(_ index: Int64, _ size: Int64, _ leafHash: [UInt8], _ path: [[UInt8]]) -> [UInt8]? {
        if !(index >= 0 && index < size) { return nil }
        var fn = index, sn = size - 1
        var r = leafHash
        for p in path {
            if sn == 0 { return nil }
            if fn % 2 == 1 || fn == sn {
                r = nodeHash(p, r)
                if fn % 2 == 0 {
                    while fn % 2 == 0 && fn != 0 { fn /= 2; sn /= 2 }
                }
            } else {
                r = nodeHash(r, p)
            }
            fn /= 2
            sn /= 2
        }
        return sn == 0 ? r : nil
    }

    // ---- closed and typed leaves ----

    static func closed(_ o: JObject, _ allowed: [String], _ required: [String]) -> Bool {
        o.keys.allSatisfy { k in allowed.contains { JKey($0) == k } } && required.allSatisfy { o[JKey($0)] != nil }
    }
    static func isStr(_ v: JSONValue?, _ max: Int = MAX_STRING_BYTES) -> String? {
        guard let s = v?.asString, !Canonical.hasLoneSurrogate(s), IV.u8(s) <= max else { return nil }
        return s
    }
    static func isDimPath(_ p: String) -> Bool { IV.same(p, "action.resource") || IV.isTopParamPath(p) }

    /// The numeric cells `[lo, c1-1], {c1}, ..., {ck}, [ck+1, hi]` (empty ranges dropped).
    static func numCells(_ d: JObject) -> [(Int64, Int64)] {
        guard let lo = IV.int(d["lo"]), let hi = IV.int(d["hi"]) else { return [] }
        var out: [(Int64, Int64)] = []
        var cur = lo
        for cv in d["cuts"]?.asArray ?? [] {
            guard let c = IV.int(cv) else { continue }
            if cur <= c - 1 { out.append((cur, c - 1)) }
            out.append((c, c))
            cur = c + 1
        }
        if cur <= hi { out.append((cur, hi)) }
        return out
    }
    static func dimCells(_ d: JObject) -> Int64 {
        IV.same(d["kind"]?.asString, "num") ? Int64(numCells(d).count) : Int64(d["values"]?.asArray?.count ?? 0)
    }

    static func dimError(_ dv: JSONValue, _ j: Int) -> String? {
        guard case let .object(d) = dv else { return "dims[\(j)] must be an object" }
        switch d["kind"]?.asString {
        case "num"?:
            if !closed(d, ["kind", "path", "lo", "hi", "cuts"], ["kind", "path", "lo", "hi", "cuts"]) { return "dims[\(j)] must be exactly {kind, path, lo, hi, cuts}" }
            guard let p = d["path"]?.asString, IV.isTopParamPath(p) else { return "dims[\(j)].path must be action.params.<name>" }
            guard let lo = IV.int(d["lo"]), let hi = IV.int(d["hi"]), lo <= hi else { return "dims[\(j)] lo / hi must be safe integers with lo <= hi" }
            guard case let .array(cuts)? = d["cuts"], cuts.count <= MAX_CUTS else { return "dims[\(j)].cuts must be an array of at most \(MAX_CUTS)" }
            var prev: Int64?
            for cv in cuts {
                guard let c = IV.int(cv), prev.map({ c > $0 }) ?? true, c >= lo, c <= hi else { return "dims[\(j)].cuts must be strictly increasing safe integers in [lo, hi]" }
                prev = c
            }
            return nil
        case "cat"?:
            if !closed(d, ["kind", "path", "values"], ["kind", "path", "values"]) { return "dims[\(j)] must be exactly {kind, path, values}" }
            guard let p = d["path"]?.asString, isDimPath(p) else { return "dims[\(j)].path must be action.resource or action.params.<name>" }
            guard case let .array(values)? = d["values"], !values.isEmpty, values.count <= MAX_VALUES else { return "dims[\(j)].values must be an array of 1..\(MAX_VALUES)" }
            var seen = Set<JKey>()
            for (i, vv) in values.enumerated() {
                guard case let .object(v) = vv, closed(v, ["kind", "value"], ["kind", "value"]) else { return "dims[\(j)].values[\(i)] must be exactly {kind, value}" }
                guard let kind = v["kind"]?.asString, ["exact", "prefix", "other"].contains(kind) else { return "dims[\(j)].values[\(i)].kind must be exact, prefix or other" }
                guard let value = isStr(v["value"]) else { return "dims[\(j)].values[\(i)].value must be a string of at most \(MAX_STRING_BYTES) UTF-8 bytes" }
                let bad = kind == "other" ? (i != values.count - 1 || !IV.same(value, OTHER)) : (kind == "prefix" && value.isEmpty)
                if bad { return "dims[\(j)].values: exactly one other ('\(OTHER)'), last; prefixes non-empty" }
                if !seen.insert(JKey(kind + ":" + value)).inserted { return "dims[\(j)].values must be distinct" }
            }
            if !IV.same(values.last?.get("kind")?.asString, "other") { return "dims[\(j)].values must end with the other value" }
            return nil
        default:
            return "dims[\(j)].kind must be num or cat"
        }
    }

    static func headerError(_ hv: JSONValue?) -> String? {
        guard case let .object(h)? = hv, closed(h, ["verb", "first", "cells", "dims"], ["verb", "first", "cells", "dims"]) else {
            return "the header leaf must be exactly {verb, first, cells, dims}"
        }
        guard let verb = isStr(h["verb"], 128), !verb.isEmpty else { return "header.verb must be a non-empty string of at most 128 UTF-8 bytes" }
        guard IV.nonNeg(h["first"]).map({ $0 < MAX_LEAVES }) == true else { return "header.first must be a leaf index" }
        guard let cells = IV.int(h["cells"]), cells >= 1, cells <= MAX_VERB_CELLS else { return "header.cells must be a safe integer in [1, \(MAX_VERB_CELLS)]" }
        guard case let .array(dims)? = h["dims"], dims.count <= MAX_DIMS else { return "header.dims must be an array of at most \(MAX_DIMS)" }
        var paths = Set<JKey>()
        var n: Int64 = 1
        for (j, d) in dims.enumerated() {
            if let e = dimError(d, j) { return "header.\(e)" }
            let dd = d.asObject!
            if !paths.insert(JKey(dd["path"]!.asString!)).inserted { return "header.dims paths must be distinct" }
            n *= dimCells(dd)
            if n > MAX_VERB_CELLS { return "header: too many cells" }
        }
        if n != cells { return "header.cells is not the product of the dimensions' cell counts" }
        return nil
    }

    static func cellError(_ cv: JSONValue?) -> String? {
        guard case let .object(c)? = cv, closed(c, ["verb", "cell", "p_ppm", "in_grant"], ["verb", "cell", "p_ppm", "in_grant"]) else {
            return "the cell leaf must be exactly {verb, cell, p_ppm, in_grant}"
        }
        guard let verb = isStr(c["verb"], 128), !verb.isEmpty else { return "cell.verb must be a non-empty string of at most 128 UTF-8 bytes" }
        guard case let .array(cell)? = c["cell"], cell.count <= MAX_DIMS, cell.allSatisfy({ IV.isSafeNonNeg($0) }) else { return "cell.cell must be an array of non-negative safe integers" }
        guard let p = IV.nonNeg(c["p_ppm"]), p <= 1_000_000 else { return "cell.p_ppm must be a safe integer in [0, 1000000]" }
        guard case .bool? = c["in_grant"] else { return "cell.in_grant must be a boolean" }
        return nil
    }

    static func metricsError(_ mv: JSONValue?) -> String? {
        guard case let .object(m)? = mv, closed(m, METRIC_FIELDS + ["log2_vs_mbits"], METRIC_FIELDS) else {
            return "the metrics leaf must be exactly {\(METRIC_FIELDS.joined(separator: ", ")), log2_vs_mbits?}"
        }
        for k in METRIC_FIELDS + ["log2_vs_mbits"] {
            guard let v = m[JKey(k)] else { continue } // only log2_vs_mbits can be absent (closed above)
            if !IV.isSafeNonNeg(v) { return "metrics.\(k) must be a non-negative safe integer" }
        }
        return nil
    }

    /// The cell of the action under a well-formed header: per dimension the value at `action.resource` or the OWN param
    /// `<name>`; `num` the numeric cell containing a safe integer; `cat` the exact value, else the LONGEST prefix, else other.
    static func cellOf(_ header: JObject, resource: JSONValue?, params: JSONValue?) -> (cell: [Int64], flat: Int64)? {
        cellOfDetailed(header, resource: resource, params: params).value
    }

    /// `cellOf` with the path of the dimension the action falls outside of (for the reference's reason).
    static func cellOfDetailed(_ header: JObject, resource: JSONValue?, params: JSONValue?) -> (value: (cell: [Int64], flat: Int64)?, path: String) {
        var cell: [Int64] = []
        var flat: Int64 = 0
        for dv in header["dims"]?.asArray ?? [] {
            guard case let .object(d) = dv, let path = d["path"]?.asString else { return (nil, "undefined") }
            let x: JSONValue? = IV.same(path, "action.resource") ? resource : params?.asObject?[JKey(IV.dropPrefix(path, 14))]
            var i: Int64 = -1
            if IV.same(d["kind"]?.asString, "num") {
                if let v = IV.int(x), let k = numCells(d).firstIndex(where: { v >= $0.0 && v <= $0.1 }) { i = Int64(k) }
            } else if case let .string(s)? = x, !Canonical.hasLoneSurrogate(s) {
                let values = d["values"]?.asArray ?? []
                var best = -1, bestLen = -1
                for (k, vv) in values.enumerated() {
                    let kind = vv.get("kind")?.asString ?? "", value = vv.get("value")?.asString ?? ""
                    if kind == "exact" && IV.same(value, s) { best = k; break }
                    if kind == "prefix" && Array(s.utf16).starts(with: Array(value.utf16)) && value.utf16.count > bestLen { best = k; bestLen = value.utf16.count }
                }
                i = Int64(best >= 0 ? best : values.count - 1)
            }
            if i < 0 { return (nil, path) }
            cell.append(i)
            flat = flat * dimCells(d) + i
        }
        return ((cell, flat), "")
    }

    static func entryShape(_ ev: JSONValue?, _ what: String) -> String? {
        guard case let .object(e)? = ev, closed(e, ["index", "salt", "leaf", "path"], ["index", "salt", "leaf", "path"]) else {
            return "disclosure.\(what) must be exactly {index, salt, leaf, path}"
        }
        if !IV.isSafeNonNeg(e["index"]) { return "disclosure.\(what).index must be a non-negative safe integer" }
        if IV.digest(e["salt"]) == nil { return "disclosure.\(what).salt must be canonical base64url (32 bytes)" }
        guard case let .array(path)? = e["path"], path.count <= 64, path.allSatisfy({ IV.digest($0) != nil }) else { return "disclosure.\(what).path must be an array of 32-byte digests" }
        return nil
    }

    static func disclosureError(_ dv: JSONValue?) -> String? {
        guard case let .object(d)? = dv, closed(d, ["size", "header", "cell", "metrics"], ["size", "header", "cell", "metrics"]) else {
            return "the disclosure must be exactly {size, header, cell, metrics}"
        }
        guard let size = IV.int(d["size"]), (4...MAX_LEAVES).contains(size) else { return "disclosure.size must be a safe integer in [4, \(MAX_LEAVES)]" }
        for k in ["header", "cell", "metrics"] { if let e = entryShape(d[JKey(k)], k) { return e } }
        return headerError(d["header"]?.get("leaf")) ?? cellError(d["cell"]?.get("leaf")) ?? metricsError(d["metrics"]?.get("leaf"))
    }

    static func opens(_ kind: String, _ e: JSONValue, _ size: Int64, _ commit: String) -> Bool {
        guard let salt = e.get("salt")?.asString.flatMap({ Base64URLStrict.decode($0, length: 32) }), let leaf = e.get("leaf"),
              let h = leafHash(kind, salt, leaf), let idx = IV.nonNeg(e.get("index")) else { return false }
        let path = (e.get("path")?.asArray ?? []).compactMap { $0.asString.flatMap { Base64URLStrict.decode($0, length: 32) } }
        guard let root = rootFromPath(idx, size, h, path) else { return false }
        return IV.same(commitOf(size, root), commit)
    }

    /// `decideMapDisclosure` (rule 19 steps 1-8). On success the action's cell, its `p_ppm` and the committed residual risk.
    static func decide(mapCommit: JSONValue?, action: JSONValue?, params: JSONValue?, disclosure: JSONValue?, maxResidualRiskPpm: Int64?)
        -> (ok: Bool, cell: [Int64], pPpm: Int64, reason: String) {
        func bad(_ r: String) -> (Bool, [Int64], Int64, String) { (false, [], 0, r) }
        if let de = disclosureError(disclosure) { return bad("map disclosure malformed: \(de)") }
        guard let commit = IV.digest(mapCommit) else { return bad("the PCActn carries no map commitment") }
        let d = disclosure!.asObject!
        if let p = params, !p.isObject { return bad("params must be an object") }
        guard let pd = IV.strictHash(params ?? .object([:])), IV.same(pd, action?.get("params_digest")?.asString) else { return bad("the params do not hash to action.params_digest") }
        let size = IV.int(d["size"])!
        let header = d["header"]!, cellE = d["cell"]!, metricsE = d["metrics"]!
        let h = header.get("leaf")!.asObject!
        if !IV.same(h["verb"]?.asString, action?.get("verb")?.asString) { return bad("the disclosed header is not the action's verb") }
        let hIndex = IV.nonNeg(header.get("index"))!, first = IV.nonNeg(h["first"])!, cells = IV.int(h["cells"])!
        if !(hIndex < first) || !(first + cells <= size - 2) { return bad("the disclosed header does not fit the committed layout") }
        if !opens("header", header, size, commit) { return bad("the header leaf does not open the map commitment") }
        if !opens("cell", cellE, size, commit) { return bad("the cell leaf does not open the map commitment") }
        if !opens("metrics", metricsE, size, commit) { return bad("the metrics leaf does not open the map commitment") }
        let cw = cellOfDetailed(h, resource: action?.get("resource"), params: params ?? .object([:]))
        guard let w = cw.value else {
            return bad("the action's \(cw.path) lies outside the committed map's dimension")
        }
        let c = cellE.get("leaf")!.asObject!
        let leafCell = (c["cell"]?.asArray ?? []).compactMap { IV.nonNeg($0) }
        if IV.nonNeg(cellE.get("index")) != first + w.flat || !IV.same(c["verb"]?.asString, h["verb"]?.asString) || leafCell != w.cell {
            return bad("the disclosed cell is not the action's cell")
        }
        guard case .bool(true)? = c["in_grant"] else { return bad("the action's cell is outside the committed grant") }
        if IV.nonNeg(metricsE.get("index")) != size - 2 { return bad("the disclosed metrics leaf is not at its committed position") }
        let rr = IV.nonNeg(metricsE.get("leaf")?.get("residual_risk_ppm"))!
        if let eps = maxResidualRiskPpm, !(rr <= eps) { return bad("the committed residual risk \(rr) ppm exceeds ε = \(eps)") }
        return (true, leafCell, IV.nonNeg(c["p_ppm"])!, "")
    }

    /// The commitment of a full leaf list `[{kind, salt, leaf}]` in leaf order; nil on a malformed entry.
    static func commit(leaves: JSONValue?) -> String? {
        guard case let .array(ls)? = leaves, !ls.isEmpty else { return nil }
        var hs: [[UInt8]] = []
        for l in ls {
            guard let kind = l.get("kind")?.asString, let salt = l.get("salt")?.asString.flatMap({ Base64URLStrict.decode($0, length: 32) }),
                  let leaf = l.get("leaf"), let h = leafHash(kind, salt, leaf) else { return nil }
            hs.append(h)
        }
        return commitOf(Int64(hs.count), treeRoot(hs[...]))
    }
}

extension PCA {
    /// Rule 19 commitment (`primitives.intent_map_commit`): `{leaves: [{kind, salt, leaf}]}` -> `map_commit` (nil: malformed).
    public static func intentMapCommitPrimitive(_ input: JSONValue) -> String? {
        IntentMap.commit(leaves: IV.normalized(input).get("leaves"))
    }

    /// Rule 19 decision (`primitives.intent_map`): `{map_commit, action: {verb, resource, params_digest}, params?, disclosure,
    /// max_residual_risk_ppm?}` -> ok, and when ok the action's cell and its `p_ppm`.
    public static func intentMapPrimitive(_ input: JSONValue) -> (ok: Bool, cell: [Int64], pPpm: Int64, reason: String) {
        let i = IV.normalized(input)
        var eps: Int64?
        if let e = i.get("max_residual_risk_ppm") {
            guard let v = IV.nonNeg(e) else { return (false, [], 0, "max_residual_risk_ppm must be a non-negative safe integer") }
            eps = v
        }
        let r = IntentMap.decide(mapCommit: i.get("map_commit"), action: i.get("action"), params: i.get("params"), disclosure: i.get("disclosure"),
                                 maxResidualRiskPpm: eps)
        return (r.ok, r.cell, r.pPpm, r.reason)
    }
}
