import Foundation

/// Regions over the typed outcome space (reference: @atlasauth/pca-intent region.ts): the part of the outcome space a cell question
/// was about, written in value terms so an observation keeps its meaning when the space is refined. A "yes" claims the cells wholly
/// inside (inner), a "no" widens to every cell that meets the region (outer).
extension PCAIntentRegion {
    /// One restricted dimension: numeric `lo...hi`, or categorical (reference value list plus the listed cell indices).
    public struct RegionDim {
        public let kind: String
        public let lo: Double
        public let hi: Double
        public let values: [PCAIntentOmega.CatValue]?
        public let cells: [Int]?

        init(_ kind: String, _ lo: Double, _ hi: Double, _ values: [PCAIntentOmega.CatValue]?, _ cells: [Int]?) {
            self.kind = kind; self.lo = lo; self.hi = hi; self.values = values; self.cells = cells
        }

        public static func num(_ lo: Double, _ hi: Double) -> RegionDim { RegionDim("num", lo, hi, nil, nil) }
        public static func cat(_ values: [PCAIntentOmega.CatValue], _ cells: [Int]) -> RegionDim { RegionDim("cat", 0.0, 0.0, values, cells) }

        public func toJson() -> JSONValue {
            var m = JObject()
            m[JKey("kind")] = .string(kind)
            if kind == "num" {
                m[JKey("lo")] = PCAIntentOmega.jn(lo)
                m[JKey("hi")] = PCAIntentOmega.jn(hi)
            } else {
                m[JKey("values")] = .array((values ?? []).map { PCAIntentOmega.catValueJson($0) })
                m[JKey("cells")] = .array((cells ?? []).map { JSONValue.int(Int64($0)) })
            }
            return .object(m)
        }

        public static func fromJson(_ o: JSONValue?) throws -> RegionDim {
            let m = try PCAIntentOmega.obj(o)
            if let k = m[JKey("kind")]?.asString, IV.same(k, "num") {
                return num(try PCAIntentOmega.dbl(m[JKey("lo")]), try PCAIntentOmega.dbl(m[JKey("hi")]))
            }
            var vs: [PCAIntentOmega.CatValue] = []
            for x in try PCAIntentOmega.arr(m[JKey("values")]) {
                let xm = try PCAIntentOmega.obj(x)
                vs.append(PCAIntentOmega.CatValue(try PCAIntentOmega.str(xm[JKey("kind")]), try PCAIntentOmega.str(xm[JKey("value")])))
            }
            var cs: [Int] = []
            for c in try PCAIntentOmega.arr(m[JKey("cells")]) { cs.append(PCAIntentOmega.toInt(try PCAIntentOmega.dbl(c))) }
            return cat(vs, cs)
        }
    }

    public struct Region {
        public let verb: String
        public let dims: [JKey: RegionDim]

        public init(_ verb: String, _ dims: [JKey: RegionDim]) { self.verb = verb; self.dims = dims }

        public func toJson() -> JSONValue {
            var ds = JObject()
            for (k, v) in dims { ds[k] = v.toJson() }
            return .object([JKey("verb"): .string(verb), JKey("dims"): .object(ds)])
        }

        public static func fromJson(_ o: JSONValue?) throws -> Region {
            let m = try PCAIntentOmega.obj(o)
            var ds: [JKey: RegionDim] = [:]
            for (k, v) in try PCAIntentOmega.obj(m[JKey("dims")]) { ds[k] = try RegionDim.fromJson(v) }
            return Region(try PCAIntentOmega.str(m[JKey("verb")]), ds)
        }
    }

    /// The value-space region of one cell.
    public static func regionOfCell(_ vs: PCAIntentOmega.VerbSpace, _ idx: [Int]) throws -> Region {
        var dims: [JKey: RegionDim] = [:]
        for k in 0..<vs.dims.count {
            let d = vs.dims[k]
            guard k < idx.count, idx[k] >= 0 else { throw JSError("regionOfCell: cell index out of range") }
            if let n = d as? PCAIntentOmega.NumDim {
                let cs = PCAIntentOmega.numCells(n)
                guard idx[k] < cs.count else { throw JSError("regionOfCell: cell index out of range") }
                dims[JKey(d.path)] = RegionDim.num(cs[idx[k]].lo, cs[idx[k]].hi)
            } else if let c = d as? PCAIntentOmega.CatDim {
                guard idx[k] < c.values.count else { throw JSError("regionOfCell: cell index out of range") }
                dims[JKey(d.path)] = RegionDim.cat(c.values, [idx[k]])
            }
        }
        return Region(vs.verb, dims)
    }

    /// Restrict one dimension: `part` is {lo, hi} for a numeric dimension, {cells} for a categorical one.
    public static func restrictRegion(_ r: Region, _ d: PCAIntentOmega.Dim, _ part: JSONValue?) throws -> Region {
        let p = try PCAIntentOmega.obj(part)
        var dims = r.dims
        if d is PCAIntentOmega.NumDim, p[JKey("lo")] != nil {
            dims[JKey(d.path)] = RegionDim.num(try PCAIntentOmega.dbl(p[JKey("lo")]), try PCAIntentOmega.dbl(p[JKey("hi")]))
        } else if let c = d as? PCAIntentOmega.CatDim, p[JKey("cells")] != nil {
            var cs: [Int] = []
            for x in try PCAIntentOmega.arr(p[JKey("cells")]) { cs.append(PCAIntentOmega.toInt(try PCAIntentOmega.dbl(x))) }
            dims[JKey(d.path)] = RegionDim.cat(c.values, cs)
        } else {
            throw JSError("restrictRegion: part does not match the kind of \(d.path)")
        }
        return Region(r.verb, dims)
    }

    /// The cells of `d` covered by `rd`; `inner` = wholly inside, else meeting it.
    public static func dimCellsIn(_ d: PCAIntentOmega.Dim, _ rd: RegionDim?, _ inner: Bool) throws -> [Int] {
        let n = PCAIntentOmega.cellCount(d)
        let all: [Int] = Array(0..<n)
        guard let rd = rd else { return all }
        var out: [Int] = []
        if let nd = d as? PCAIntentOmega.NumDim {
            guard rd.kind == "num" else { throw JSError("region: \(d.path) is numeric in the space but categorical in the region") }
            let cs = PCAIntentOmega.numCells(nd)
            for i in all {
                let c = cs[i]
                let hit: Bool = inner ? (c.lo >= rd.lo && c.hi <= rd.hi) : (c.hi >= rd.lo && c.lo <= rd.hi)
                if hit { out.append(i) }
            }
            return out
        }
        guard rd.kind == "cat", let rv = rd.values, let rc = rd.cells, let cd = d as? PCAIntentOmega.CatDim else {
            throw JSError("region: \(d.path) is categorical in the space but numeric in the region")
        }
        let ref = PCAIntentOmega.CatDim(d.path, rv)
        let inSet = Set(rc)
        for i in all where inSet.contains(PCAIntentOmega.catCellOf(ref, PCAIntentOmega.catRep(cd, i))) { out.append(i) }
        return out
    }

    /// Flat cell indices covered by the region (row-major, last dimension fastest); refuses a dimension the verb space lacks.
    public static func regionCells(_ vs: PCAIntentOmega.VerbSpace, _ r: Region, _ inner: Bool) throws -> [Int64] {
        guard IV.same(r.verb, vs.verb) else { throw JSError("region: verb \(r.verb) does not match \(vs.verb)") }
        for k in r.dims.keys where !vs.dims.contains(where: { IV.same($0.path, k.s) }) {
            throw JSError("region: restricts \(k.s), which the space has no dimension for")
        }
        var per: [[Int]] = []
        for d in vs.dims { per.append(try dimCellsIn(d, r.dims[JKey(d.path)], inner)) }
        for x in per where x.isEmpty { return [] }
        var acc: [Int64] = [0]
        for k in 0..<per.count {
            let size = Int64(PCAIntentOmega.cellCount(vs.dims[k]))
            var next: [Int64] = []
            for f in acc { for c in per[k] { next.append(f &* size &+ Int64(c)) } }
            acc = next
        }
        return acc
    }

    /// Is a concrete value (a number or a string) inside a region dimension?
    public static func valueInRegionDim(_ path: String, _ rd: RegionDim, _ x: JSONValue?) -> Bool {
        if rd.kind == "num" {
            guard let v = IV.num(x) else { return false }
            return v >= rd.lo && v <= rd.hi
        }
        guard let s = x?.asString, let rv = rd.values, let rc = rd.cells else { return false }
        return rc.contains(PCAIntentOmega.catCellOf(PCAIntentOmega.CatDim(path, rv), s))
    }
}
