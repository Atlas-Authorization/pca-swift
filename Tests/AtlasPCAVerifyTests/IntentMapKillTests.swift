import XCTest
import Foundation
@testable import AtlasPCAVerify

/// Mutation-kill tests for IntentMap.swift: limits, numeric cell decomposition, dim/header/cell validators, cellOf longest
/// prefix, entry path bound, and the rule-19 decision (layout + opened cell checks) over a real RFC 9162 tree built here.
final class IntentMapKillTests: XCTestCase {
    typealias M = IntentMap

    // ---- builders ----

    func s(_ x: String) -> JSONValue { .string(x) }
    func digest(_ b: UInt8 = 0) -> String { Base64URLStrict.encode([UInt8](repeating: b, count: 32)) }

    func numDim(_ path: String = "action.params.x", lo: Int64, hi: Int64, cuts: [Int64]) -> JSONValue {
        .object(["kind": s("num"), "path": s(path), "lo": .int(lo), "hi": .int(hi), "cuts": .array(cuts.map { .int($0) })])
    }
    func val(_ k: String, _ v: String) -> JSONValue { .object(["kind": s(k), "value": s(v)]) }
    func catRaw(_ path: String, _ values: [JSONValue]) -> JSONValue { .object(["kind": s("cat"), "path": s(path), "values": .array(values)]) }
    /// A cat dim with n values: n-1 exact values then the other value.
    func catDim(_ path: String, _ n: Int) -> JSONValue {
        var vs: [JSONValue] = (0..<(n - 1)).map { val("exact", "v\($0)") }
        vs.append(val("other", M.OTHER))
        return catRaw(path, vs)
    }
    func hdr(verb: String = "v", first: Int64 = 0, cells: Int64 = 1, dims: [JSONValue] = []) -> JSONValue {
        .object(["verb": s(verb), "first": .int(first), "cells": .int(cells), "dims": .array(dims)])
    }
    func cellLeaf(verb: String = "v", cell: [Int64] = [], p: Int64 = 0, inGrant: Bool = true) -> JSONValue {
        .object(["verb": s(verb), "cell": .array(cell.map { .int($0) }), "p_ppm": .int(p), "in_grant": .bool(inGrant)])
    }
    func metricsLeaf() -> JSONValue {
        var m = JObject()
        for k in M.METRIC_FIELDS { m[JKey(k)] = .int(0) }
        return .object(m)
    }
    func ranges(_ d: JSONValue) -> [[Int64]] { M.numCells(d.asObject!).map { [$0.0, $0.1] } }

    // ---- constants ----

    func testLimits() {
        XCTAssertEqual(M.MAX_LEAVES, 16_777_216)
        XCTAssertEqual(M.MAX_VERB_CELLS, 1_048_576)
        XCTAssertEqual(M.MAX_DIMS, 16)
        XCTAssertEqual(M.MAX_CUTS, 256)
        XCTAssertEqual(M.MAX_VALUES, 256)
        XCTAssertEqual(M.MAX_STRING_BYTES, 256)
    }

    func testIsStrBounds() {
        XCTAssertNotNil(M.isStr(s(String(repeating: "a", count: 256))))
        XCTAssertNil(M.isStr(s(String(repeating: "a", count: 257))))
        XCTAssertNotNil(M.isStr(s(String(repeating: "a", count: 128)), 128))
        XCTAssertNil(M.isStr(s(String(repeating: "a", count: 129)), 128))
        XCTAssertNil(M.isStr(s("a" + String(Canonical.LONE_SURROGATE_SENTINEL))))
        XCTAssertNil(M.isStr(.int(1)))
    }

    // ---- numCells / dimCells ----

    func testNumCells() {
        XCTAssertEqual(ranges(numDim(lo: 0, hi: 10, cuts: [0, 5, 10])), [[0, 0], [1, 4], [5, 5], [6, 9], [10, 10]])
        XCTAssertEqual(ranges(numDim(lo: 1, hi: 3, cuts: [2])), [[1, 1], [2, 2], [3, 3]])
        XCTAssertEqual(ranges(numDim(lo: 0, hi: 10, cuts: [])), [[0, 10]])
        XCTAssertEqual(ranges(numDim(lo: 5, hi: 5, cuts: [])), [[5, 5]])
        XCTAssertEqual(ranges(numDim(lo: 0, hi: 9, cuts: [3, 6])), [[0, 2], [3, 3], [4, 5], [6, 6], [7, 9]])
        XCTAssertEqual(M.numCells(["kind": s("num")]).count, 0)
    }

    func testDimCells() {
        let cat: JObject = ["kind": s("cat")]
        XCTAssertEqual(M.dimCells(cat), 0)
        XCTAssertEqual(M.dimCells(catDim("action.resource", 4).asObject!), 4)
        XCTAssertEqual(M.dimCells(numDim(lo: 1, hi: 3, cuts: [2]).asObject!), 3)
    }

    // ---- dimError ----

    func testNumDimLoHi() {
        XCTAssertNil(M.dimError(numDim(lo: 5, hi: 5, cuts: []), 0))
        XCTAssertNil(M.dimError(numDim(lo: 5, hi: 6, cuts: []), 0))
        XCTAssertEqual(M.dimError(numDim(lo: 6, hi: 5, cuts: []), 0), "dims[0] lo / hi must be safe integers with lo <= hi")
    }

    func testNumDimCuts() {
        let msg = "dims[0].cuts must be strictly increasing safe integers in [lo, hi]"
        XCTAssertNil(M.dimError(numDim(lo: 0, hi: 10, cuts: [0, 10]), 0))
        XCTAssertNil(M.dimError(numDim(lo: 0, hi: 10, cuts: [0]), 0))
        XCTAssertNil(M.dimError(numDim(lo: 0, hi: 10, cuts: [10]), 0))
        XCTAssertEqual(M.dimError(numDim(lo: 0, hi: 10, cuts: [3, 3]), 0), msg)
        XCTAssertEqual(M.dimError(numDim(lo: 0, hi: 10, cuts: [4, 3]), 0), msg)
        XCTAssertEqual(M.dimError(numDim(lo: 0, hi: 10, cuts: [11]), 0), msg)
        XCTAssertEqual(M.dimError(numDim(lo: 1, hi: 10, cuts: [0]), 0), msg)
        XCTAssertNil(M.dimError(numDim(lo: 0, hi: 10, cuts: [3, 4]), 0))
    }

    func testNumDimCutCount() {
        XCTAssertNil(M.dimError(numDim(lo: 0, hi: 255, cuts: (0..<256).map { Int64($0) }), 0))
        XCTAssertEqual(M.dimError(numDim(lo: 0, hi: 300, cuts: (0..<257).map { Int64($0) }), 0), "dims[0].cuts must be an array of at most 256")
    }

    func testCatDimValueCount() {
        XCTAssertNil(M.dimError(catDim("action.resource", 256), 0))
        XCTAssertEqual(M.dimError(catDim("action.resource", 257), 0), "dims[0].values must be an array of 1..256")
        XCTAssertNil(M.dimError(catDim("action.resource", 1), 0))
        XCTAssertEqual(M.dimError(catRaw("action.resource", []), 0), "dims[0].values must be an array of 1..256")
    }

    func testCatDimOtherRules() {
        let bad = "dims[0].values: exactly one other ('\(M.OTHER)'), last; prefixes non-empty"
        XCTAssertNil(M.dimError(catRaw("action.resource", [val("exact", "a"), val("other", M.OTHER)]), 0))
        XCTAssertNil(M.dimError(catRaw("action.resource", [val("prefix", "p"), val("other", M.OTHER)]), 0))
        XCTAssertEqual(M.dimError(catRaw("action.resource", [val("other", M.OTHER), val("exact", "a")]), 0), bad)
        XCTAssertEqual(M.dimError(catRaw("action.resource", [val("exact", "a"), val("other", "x")]), 0), bad)
        XCTAssertEqual(M.dimError(catRaw("action.resource", [val("prefix", ""), val("other", M.OTHER)]), 0), bad)
        XCTAssertEqual(M.dimError(catRaw("action.resource", [val("exact", "a"), val("exact", "a"), val("other", M.OTHER)]), 0),
                       "dims[0].values must be distinct")
        XCTAssertEqual(M.dimError(catRaw("action.resource", [val("exact", "a")]), 0), "dims[0].values must end with the other value")
    }

    // ---- headerError ----

    func testHeaderVerbLength() {
        let msg = "header.verb must be a non-empty string of at most 128 UTF-8 bytes"
        XCTAssertNil(M.headerError(hdr(verb: String(repeating: "a", count: 128))))
        XCTAssertEqual(M.headerError(hdr(verb: String(repeating: "a", count: 129))), msg)
        XCTAssertEqual(M.headerError(hdr(verb: "")), msg)
        XCTAssertNil(M.headerError(hdr(verb: "a")))
    }

    func testHeaderFirstBound() {
        let msg = "header.first must be a leaf index"
        XCTAssertNil(M.headerError(hdr(first: 0)))
        XCTAssertNil(M.headerError(hdr(first: M.MAX_LEAVES - 1)))
        XCTAssertEqual(M.headerError(hdr(first: M.MAX_LEAVES)), msg)
        XCTAssertEqual(M.headerError(hdr(first: -1)), msg)
    }

    func testHeaderCellsBounds() {
        let msg = "header.cells must be a safe integer in [1, 1048576]"
        XCTAssertNil(M.headerError(hdr(cells: 1)))
        XCTAssertEqual(M.headerError(hdr(cells: 0)), msg)
        XCTAssertEqual(M.headerError(hdr(cells: M.MAX_VERB_CELLS + 1)), msg)
        XCTAssertEqual(M.headerError(hdr(cells: 2)), "header.cells is not the product of the dimensions' cell counts")
        // exactly MAX_VERB_CELLS cells: 256 * 256 * 16
        let dims = [catDim("action.params.a", 256), catDim("action.params.b", 256), catDim("action.params.c", 16)]
        XCTAssertNil(M.headerError(hdr(cells: M.MAX_VERB_CELLS, dims: dims)))
        // one factor more: 256 * 256 * 32 > MAX_VERB_CELLS
        let over = [catDim("action.params.a", 256), catDim("action.params.b", 256), catDim("action.params.c", 32)]
        XCTAssertEqual(M.headerError(hdr(cells: 1, dims: over)), "header: too many cells")
    }

    func testHeaderDimCount() {
        let sixteen = (0..<16).map { catDim("action.params.p\($0)", 1) }
        XCTAssertNil(M.headerError(hdr(cells: 1, dims: sixteen)))
        let seventeen = (0..<17).map { catDim("action.params.p\($0)", 1) }
        XCTAssertEqual(M.headerError(hdr(cells: 1, dims: seventeen)), "header.dims must be an array of at most 16")
    }

    // ---- cellError ----

    func testCellErrorBounds() {
        let vmsg = "cell.verb must be a non-empty string of at most 128 UTF-8 bytes"
        XCTAssertNil(M.cellError(cellLeaf(verb: String(repeating: "a", count: 128))))
        XCTAssertEqual(M.cellError(cellLeaf(verb: String(repeating: "a", count: 129))), vmsg)
        XCTAssertEqual(M.cellError(cellLeaf(verb: "")), vmsg)
        let cmsg = "cell.cell must be an array of non-negative safe integers"
        XCTAssertNil(M.cellError(cellLeaf(cell: [Int64](repeating: 0, count: 16))))
        XCTAssertEqual(M.cellError(cellLeaf(cell: [Int64](repeating: 0, count: 17))), cmsg)
        let pmsg = "cell.p_ppm must be a safe integer in [0, 1000000]"
        XCTAssertNil(M.cellError(cellLeaf(p: 0)))
        XCTAssertNil(M.cellError(cellLeaf(p: 999_999)))
        XCTAssertNil(M.cellError(cellLeaf(p: 1_000_000)))
        XCTAssertEqual(M.cellError(cellLeaf(p: 1_000_001)), pmsg)
        XCTAssertEqual(M.cellError(cellLeaf(p: -1)), pmsg)
    }

    // ---- cellOf ----

    func catHeader(_ values: [JSONValue]) -> JObject {
        ["dims": .array([catRaw("action.params.k", values)])]
    }
    func cellOfK(_ values: [JSONValue], _ x: String) -> (cell: [Int64], flat: Int64)? {
        M.cellOf(catHeader(values), resource: nil, params: .object(["k": s(x)]))
    }

    func testCellOfEmptyPrefixMatches() {
        let r = cellOfK([val("prefix", ""), val("other", M.OTHER)], "zzz")
        XCTAssertEqual(r?.cell, [0])
        XCTAssertEqual(r?.flat, 0)
    }

    func testCellOfFirstOfEqualPrefixesWins() {
        let r = cellOfK([val("prefix", "ab"), val("prefix", "ab"), val("other", M.OTHER)], "abc")
        XCTAssertEqual(r?.cell, [0])
    }

    func testCellOfLongestPrefixExactOther() {
        let vs = [val("prefix", "a"), val("prefix", "abc"), val("exact", "abcd"), val("other", M.OTHER)]
        XCTAssertEqual(cellOfK(vs, "abcx")?.cell, [1])
        XCTAssertEqual(cellOfK(vs, "abcd")?.cell, [2])
        XCTAssertEqual(cellOfK(vs, "ax")?.cell, [0])
        XCTAssertEqual(cellOfK(vs, "zzz")?.cell, [3])
    }

    func testCellOfNumericAndMissing() {
        let h: JObject = ["dims": .array([numDim(lo: 0, hi: 10, cuts: [5])])]
        XCTAssertEqual(M.cellOf(h, resource: nil, params: .object(["x": .int(4)]))?.cell, [0])
        XCTAssertEqual(M.cellOf(h, resource: nil, params: .object(["x": .int(5)]))?.cell, [1])
        XCTAssertEqual(M.cellOf(h, resource: nil, params: .object(["x": .int(6)]))?.cell, [2])
        XCTAssertNil(M.cellOf(h, resource: nil, params: .object(["x": .int(11)])))
        XCTAssertNil(M.cellOf(h, resource: nil, params: .object([:])))
        XCTAssertNil(M.cellOf(h, resource: nil, params: .object(["x": s("4")])))
        // a string value for a cat dim missing: no cell
        XCTAssertNil(M.cellOf(catHeader([val("other", M.OTHER)]), resource: nil, params: .object([:])))
    }

    // ---- entryShape / opens ----

    func entry(_ index: Int64, path: Int) -> JSONValue {
        .object(["index": .int(index), "salt": s(digest()), "leaf": .object([:]), "path": .array((0..<path).map { _ in s(digest()) })])
    }

    func testEntryPathBound() {
        XCTAssertNil(M.entryShape(entry(0, path: 64), "header"))
        XCTAssertNil(M.entryShape(entry(0, path: 63), "header"))
        XCTAssertNil(M.entryShape(entry(0, path: 0), "header"))
        XCTAssertEqual(M.entryShape(entry(0, path: 65), "header"), "disclosure.header.path must be an array of 32-byte digests")
    }

    func testOpensFalseOnMalformedEntry() {
        let bad: JSONValue = .object(["index": .int(0), "salt": s("bad"), "leaf": .object([:]), "path": .array([])])
        XCTAssertFalse(M.opens("header", bad, 4, digest()))
        let noIndex: JSONValue = .object(["salt": s(digest()), "leaf": .object([:]), "path": .array([])])
        XCTAssertFalse(M.opens("header", noIndex, 4, digest()))
        let badKind: JSONValue = .object(["index": .int(0), "salt": s(digest()), "leaf": .object([:]), "path": .array([])])
        XCTAssertFalse(M.opens("nope", badKind, 4, digest()))
    }

    // ---- primitives: failure shape ----

    func testDecideFailureShape() {
        let r = M.decide(mapCommit: nil, action: nil, params: nil, disclosure: nil, maxResidualRiskPpm: nil)
        XCTAssertFalse(r.ok)
        XCTAssertEqual(r.cell, [])
        XCTAssertEqual(r.pPpm, 0)
        XCTAssertTrue(r.reason.hasPrefix("map disclosure malformed: "), r.reason)
    }

    func testPrimitiveBadEpsilon() {
        for e in [JSONValue.int(-1), .string("1"), .double(1.5), .null] {
            let r = PCA.intentMapPrimitive(.object(["max_residual_risk_ppm": e]))
            XCTAssertFalse(r.ok)
            XCTAssertEqual(r.cell, [])
            XCTAssertEqual(r.pPpm, 0)
            XCTAssertEqual(r.reason, "max_residual_risk_ppm must be a non-negative safe integer")
        }
    }

    // ---- decide: layout (no real tree needed: the layout check precedes opening) ----

    func rawDecide(size: Int64, headerIndex: Int64, first: Int64, cells: Int64) -> (ok: Bool, cell: [Int64], pPpm: Int64, reason: String) {
        let params: JSONValue = .object([:])
        let action: JSONValue = .object(["verb": s("v"), "resource": s("r"), "params_digest": s(IV.strictHash(params)!)])
        let d: JSONValue = .object([
            "size": .int(size),
            "header": .object(["index": .int(headerIndex), "salt": s(digest()), "leaf": hdr(first: first, cells: cells, dims: []), "path": .array([])]),
            "cell": .object(["index": .int(first), "salt": s(digest()), "leaf": cellLeaf(), "path": .array([])]),
            "metrics": .object(["index": .int(size - 2), "salt": s(digest()), "leaf": metricsLeaf(), "path": .array([])]),
        ])
        // headerError requires cells == product of dims == 1
        return M.decide(mapCommit: s(digest()), action: action, params: params, disclosure: d, maxResidualRiskPpm: nil)
    }

    func testLayoutRefusals() {
        let layout = "the disclosed header does not fit the committed layout"
        // header index equals first
        XCTAssertEqual(rawDecide(size: 4, headerIndex: 0, first: 0, cells: 1).reason, layout)
        // header index after first
        XCTAssertEqual(rawDecide(size: 6, headerIndex: 3, first: 1, cells: 1).reason, layout)
        // first + cells = size - 1 (one past the metrics slot)
        XCTAssertEqual(rawDecide(size: 4, headerIndex: 0, first: 2, cells: 1).reason, layout)
        // first + cells far past the end
        XCTAssertEqual(rawDecide(size: 4, headerIndex: 0, first: 5, cells: 1).reason, layout)
        // boundary first + cells = size - 2 passes the layout check (then fails opening against the dummy commitment)
        XCTAssertEqual(rawDecide(size: 4, headerIndex: 0, first: 1, cells: 1).reason, "the header leaf does not open the map commitment")
        // header index 0 with first=1, cells=1, size 3 is refused earlier (size >= 4); size 5 with first 2: 2+1 <= 3
        XCTAssertEqual(rawDecide(size: 5, headerIndex: 0, first: 2, cells: 1).reason, "the header leaf does not open the map commitment")
        XCTAssertEqual(rawDecide(size: 5, headerIndex: 0, first: 3, cells: 1).reason, layout)
    }

    // ---- decide over a real tree ----

    func auditPath(_ m: Int, _ hs: [[UInt8]]) -> [[UInt8]] {
        if hs.count == 1 { return [] }
        let k = M.split(hs.count)
        if m < k { return auditPath(m, Array(hs[0..<k])) + [M.treeRoot(Array(hs[k...])[...])] }
        return auditPath(m - k, Array(hs[k...])) + [M.treeRoot(Array(hs[0..<k])[...])]
    }
    func salt(_ i: Int) -> [UInt8] { [UInt8](repeating: UInt8(i + 1), count: 32) }

    struct Tree {
        var commit: String
        var entries: [JSONValue]
    }
    func buildTree(_ leaves: [(String, JSONValue)]) -> Tree {
        let hs = leaves.enumerated().map { M.leafHash($0.element.0, salt($0.offset), $0.element.1)! }
        let commit = M.commitOf(Int64(hs.count), M.treeRoot(hs[...]))
        var es: [JSONValue] = []
        for (i, l) in leaves.enumerated() {
            es.append(.object(["index": .int(Int64(i)), "salt": s(Base64URLStrict.encode(salt(i))), "leaf": l.1,
                               "path": .array(auditPath(i, hs).map { s(Base64URLStrict.encode($0)) })]))
        }
        return Tree(commit: commit, entries: es)
    }

    /// Leaves: 0 header (verb v, first 1, 2 cells over params.k in {a, other}), 1 and 2 the given cells, 3 metrics, 4 learner.
    func scenario(cell1: JSONValue, cell2: JSONValue, disclose cellIndex: Int)
        -> (ok: Bool, cell: [Int64], pPpm: Int64, reason: String) {
        let dim = catRaw("action.params.k", [val("exact", "a"), val("other", M.OTHER)])
        let t = buildTree([("header", hdr(verb: "v", first: 1, cells: 2, dims: [dim])), ("cell", cell1), ("cell", cell2),
                           ("metrics", metricsLeaf()), ("learner", .object(["x": .int(1)]))])
        let params: JSONValue = .object(["k": s("a")])
        let action: JSONValue = .object(["verb": s("v"), "resource": s("r"), "params_digest": s(IV.strictHash(params)!)])
        let d: JSONValue = .object(["size": .int(5), "header": t.entries[0], "cell": t.entries[cellIndex], "metrics": t.entries[3]])
        return M.decide(mapCommit: s(t.commit), action: action, params: params, disclosure: d, maxResidualRiskPpm: nil)
    }

    let notCell = "the disclosed cell is not the action's cell"

    func testDecideAccepts() {
        let r = scenario(cell1: cellLeaf(cell: [0], p: 123_456), cell2: cellLeaf(cell: [1], p: 7), disclose: 1)
        XCTAssertTrue(r.ok, r.reason)
        XCTAssertEqual(r.cell, [0])
        XCTAssertEqual(r.pPpm, 123_456)
        XCTAssertEqual(r.reason, "")
    }

    func testDecideRefusesWrongIndexOnly() {
        // leaf 2 carries the same content as leaf 1 but sits at the wrong index
        let r = scenario(cell1: cellLeaf(cell: [0]), cell2: cellLeaf(cell: [0]), disclose: 2)
        XCTAssertFalse(r.ok)
        XCTAssertEqual(r.reason, notCell)
        XCTAssertEqual(r.pPpm, 0)
        XCTAssertEqual(r.cell, [])
    }

    func testDecideRefusesWrongVerbOnly() {
        let r = scenario(cell1: cellLeaf(verb: "w", cell: [0]), cell2: cellLeaf(cell: [1]), disclose: 1)
        XCTAssertFalse(r.ok)
        XCTAssertEqual(r.reason, notCell)
    }

    func testDecideRefusesWrongCellOnly() {
        let r = scenario(cell1: cellLeaf(cell: [1]), cell2: cellLeaf(cell: [1]), disclose: 1)
        XCTAssertFalse(r.ok)
        XCTAssertEqual(r.reason, notCell)
    }

    func testDecideRefusesOutOfGrant() {
        let r = scenario(cell1: cellLeaf(cell: [0], inGrant: false), cell2: cellLeaf(cell: [1]), disclose: 1)
        XCTAssertFalse(r.ok)
        XCTAssertEqual(r.reason, "the action's cell is outside the committed grant")
    }
}
