import Foundation

/// Specification by example for a fixed grant: boundary facets (admission changes when exactly one dimension moves to an adjacent
/// cell), one verb witness per verb, and one unconstrained witness per dimension the grant ignores. The question count is linear in
/// the number of facets, not in the size of the space.
public enum PCAIntentWitnesses {
    /// One question: an action inside or outside the grant, isolating one literal.
    public struct Witness {
        public let kind: String
        public let side: String
        public let verb: String
        public let cell: [Int]
        /// The outcome `{verb, values}`.
        public let outcome: JSONValue
        public let grantAllows: Bool
        public let facet: String
        public let question: String

        public init(_ kind: String, _ side: String, _ verb: String, _ cell: [Int], _ outcome: JSONValue, _ grantAllows: Bool, _ facet: String, _ question: String) {
            self.kind = kind
            self.side = side
            self.verb = verb
            self.cell = cell
            self.outcome = outcome
            self.grantAllows = grantAllows
            self.facet = facet
            self.question = question
        }

        public func toJson() -> JSONValue {
            return .object([
                "kind": .string(kind), "side": .string(side), "verb": .string(verb),
                "cell": .array(cell.map { JSONValue.int(Int64($0)) }),
                "outcome": outcome, "grantAllows": .bool(grantAllows), "facet": .string(facet), "question": .string(question),
            ])
        }
    }

    private struct Best {
        let ins: [Int]
        let outs: [Int]
        let score: Double
    }

    private static func fail(_ what: String) -> JSError { return JSError("pca-intent: \(what)") }

    public static func boundaryWitnesses(_ grant: JSONValue?, _ omega: WalletOmega, _ catalog: PCACatalog = PCAIntentRender.defaultCatalog) throws -> [Witness] {
        typealias LM = WalletOmegaMath
        let g = try PCAIntentRender.Admitter(grant)
        var out: [Witness] = []
        var seen = Set<String>()
        for vs in omega.verbs {
            let n = LM.verbCellCount(vs)
            var acc = [Bool](repeating: false, count: n)
            var mass = [Double](repeating: 0, count: n)
            var typical = -1
            var typicalOut = -1
            for c in 0..<n {
                let idx = LM.decodeCell(vs, c)
                acc[c] = try g.admits(vs, idx)
                mass[c] = LM.cellStats(vs, idx).mass
                if acc[c] && (typical < 0 || mass[c] > mass[typical]) { typical = c }
                if typicalOut < 0 || mass[c] > mass[typicalOut] { typicalOut = c }
            }
            if typical < 0 {
                if typicalOut < 0 { throw fail("a verb space with no cells") }
                try push(&out, &seen, vs, "verb", LM.decodeCell(vs, typicalOut), false, vs.verb + "|verb", catalog)
                continue
            }
            let base = LM.decodeCell(vs, typical)
            try push(&out, &seen, vs, "verb", base, true, vs.verb + "|verb", catalog)
            var best: [JKey: Best] = [:]
            for c in 0..<n {
                if !acc[c] { continue }
                let idx = LM.decodeCell(vs, c)
                for k in 0..<vs.dims.count {
                    let d = vs.dims[k]
                    let nk = LM.cellCount(d)
                    var neigh: [Int] = []
                    if d.isNum {
                        for x in [idx[k] - 1, idx[k] + 1] where x >= 0 && x < nk { neigh.append(x) }
                    } else {
                        for x in 0..<nk where x != idx[k] { neigh.append(x) }
                    }
                    for x in neigh {
                        var j = idx
                        j[k] = x
                        let cj = PCAIntentLearner.encode(vs, j)
                        if acc[cj] { continue }
                        let facet: String
                        if d.isNum { facet = "\(vs.verb)|\(d.path)|\(min(x, idx[k]))~\(max(x, idx[k]))" } else { facet = "\(vs.verb)|\(d.path)|\(x)" }
                        var shared = 0
                        for t in 0..<idx.count where t != k && idx[t] == base[t] { shared += 1 }
                        let score = Double(shared) * 10 + mass[c]
                        if let prev = best[JKey(facet)], !(score > prev.score) { continue }
                        best[JKey(facet)] = Best(ins: idx, outs: j, score: score)
                    }
                }
            }
            let facets = best.keys.map { $0.s }.sorted { WJ.u16Less($0, $1) }
            for facet in facets {
                guard let b = best[JKey(facet)] else { continue }
                try push(&out, &seen, vs, "boundary", b.ins, true, facet, catalog)
                try push(&out, &seen, vs, "boundary", b.outs, false, facet, catalog)
            }
            for k in 0..<vs.dims.count {
                let d = vs.dims[k]
                let nk = LM.cellCount(d)
                if nk < 2 { continue }
                var depends = false
                var c = 0
                while c < n && !depends {
                    let idx = LM.decodeCell(vs, c)
                    var x = 0
                    while x < nk && !depends {
                        var j = idx
                        j[k] = x
                        if acc[PCAIntentLearner.encode(vs, j)] != acc[c] { depends = true }
                        x += 1
                    }
                    c += 1
                }
                if depends { continue }
                var j = base
                if d.isNum { j[k] = nk - 1 } else { j[k] = d.values.firstIndex(where: { $0.kind == "other" }) ?? -1 }
                try push(&out, &seen, vs, "unconstrained", j, true, vs.verb + "|" + d.path + "|unconstrained", catalog)
            }
        }
        return out
    }

    private static func push(_ out: inout [Witness], _ seen: inout Set<String>, _ vs: WalletVerb, _ kind: String, _ idx: [Int], _ allows: Bool,
                             _ facet: String, _ catalog: PCACatalog) throws {
        let key = vs.verb + "|" + idx.map { String($0) }.joined(separator: ",")
        if seen.contains(key) { return }
        seen.insert(key)
        for (k, d) in vs.dims.enumerated() {
            if k >= idx.count || idx[k] < 0 || idx[k] >= WalletOmegaMath.cellCount(d) { throw fail("cell index out of range") }
        }
        out.append(Witness(kind, allows ? "inside" : "outside", vs.verb, idx, WalletOmegaMath.cellRep(vs, idx), allows, facet,
                           try PCAIntentRender.renderQuestion(vs, idx, catalog)))
    }

    /// The oracle's disagreements with the grant, with the number of questions asked.
    public struct WitnessCheck {
        public let questions: Int
        public let mismatches: [Witness]
    }

    /// Ask an oracle (the principal) about each witness; a mismatch is a place where grant and intent disagree.
    public static func checkWitnesses(_ witnesses: [Witness], _ oracle: (Witness) -> Bool) -> WitnessCheck {
        return WitnessCheck(questions: witnesses.count, mismatches: witnesses.filter { oracle($0) != $0.grantAllows })
    }
}
