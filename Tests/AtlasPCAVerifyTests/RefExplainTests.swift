import XCTest
import Foundation
@testable import AtlasPCAVerify

/// Differential replay of PCAExplain against the reference (@atlasauth/pca-explain): cleanText, explainVerification, explainDecision,
/// explainChain and their text renderers. The explanation objects are compared as JSON (an undefined member is absent). A reference
/// throw requires a native refusal.
final class RefExplainTests: XCTestCase {
    static let file = "ref-explain.json.gz"

    /// The order each verifier result listed its `checks` members (a parsed JSON object keeps none), by case name.
    static func checkOrders() throws -> [String: [String]] {
        let bytes = [UInt8](try K042.bytes(file))
        var out: [String: [String]] = [:]
        let prefix = Array(#"{"fn":"explainVerification"#.utf8), nameKey = Array(#""name":""#.utf8), checksKey = Array(#""checks":{"#.utf8)
        func find(_ hay: [UInt8], _ needle: [UInt8], from: Int = 0) -> Int? {
            guard hay.count >= needle.count, from <= hay.count - needle.count else { return nil }
            for i in from...(hay.count - needle.count) where hay[i] == needle[0] && Array(hay[i..<(i + needle.count)]) == needle { return i }
            return nil
        }
        for var line in bytes.split(separator: 0x0A, omittingEmptySubsequences: true).map({ Array($0) }) where line.starts(with: prefix) {
            if line.last == UInt8(ascii: ",") { line.removeLast() }
            guard let n = find(line, nameKey), let nEnd = line[(n + nameKey.count)...].firstIndex(of: UInt8(ascii: "\"")),
                  let at = find(line, checksKey) else { continue }
            let name = String(decoding: line[(n + nameKey.count)..<nEnd], as: UTF8.self)
            var keys: [String] = []
            var depth = 0, j = at + checksKey.count - 1, expectKey = false
            scan: while j < line.count {
                switch line[j] {
                case UInt8(ascii: "\""):
                    var k = j + 1
                    while k < line.count, line[k] != UInt8(ascii: "\"") { k += line[k] == UInt8(ascii: "\\") ? 2 : 1 }
                    if depth == 1 && expectKey { keys.append(String(decoding: line[(j + 1)..<k], as: UTF8.self)); expectKey = false }
                    j = k
                case UInt8(ascii: "{"), UInt8(ascii: "["):
                    depth += 1
                    if depth == 1 { expectKey = true }
                case UInt8(ascii: "}"), UInt8(ascii: "]"):
                    depth -= 1
                    if depth == 0 { break scan }
                case UInt8(ascii: ","):
                    if depth == 1 { expectKey = true }
                default: break
                }
                j += 1
            }
            out[name] = keys
        }
        return out
    }

    func testExplain() throws {
        try K042.requireCovers(["Explain", "JSLoose"])
        let orders = try Self.checkOrders()
        let d = Base.Diffs()
        var seen = Set<String>()
        try Base.each(Self.file) { c in
            let a0 = c.arg(0), a1 = c.arg(1), a2 = c.arg(2)
            let got: BaseGot
            seen.insert(c.fn)
            switch c.fn {
            case "cleanText": got = .value(.string(PCAExplain.cleanText(a0)))
            case "explainVerification":
                got = .value(PCAExplain.explainVerification(a0, a1, a2, checkOrder: orders[c.name]))
            case "explainVerificationText":
                got = Ref.s { PCAExplain.verificationToText(PCAExplain.explainVerification(a0, a1, a2, checkOrder: orders[c.name])) }
            case "explainDecision": got = Ref.v { try PCAExplain.explainDecision(a0, a1, a2) }
            case "explainDecisionText": got = Ref.s { try PCAExplain.decisionToText(try PCAExplain.explainDecision(a0, a1, a2)) }
            case "explainChain": got = Ref.v { try PCAExplain.explainChain(a0, a1) }
            case "explainChainText": got = Ref.s { PCAExplain.chainToText(try PCAExplain.explainChain(a0, a1)) }
            case "consts":
                got = .value(.object(["VERIFY_CHECK_ORDER": .array(PCAExplain.VERIFY_CHECK_ORDER.map { .string($0) }), "MAX_TEXT": .int(Int64(PCAExplain.MAX_TEXT))]))
            default:
                d.skip("\(c.fn): not mapped"); return
            }
            d.add(c, Base.diff(c, got))
        }
        XCTAssertEqual(seen.count, 8)
        d.finish(1900)
    }

    func testExplainFailClosed() throws {
        // an allow without per-check statuses, or contradicted by a failing check, is a denial
        XCTAssertEqual(PCAExplain.explainVerification(.object([:]), .object(["allow": .bool(true)])).get("verdict"), .string("deny"))
        let r: JSONValue = .object(["allow": .bool(true), "checks": .object(["wire": .string("fail")])])
        XCTAssertEqual(PCAExplain.explainVerification(.object([:]), r).get("verdict"), .string("deny"))
        // a truthy non-boolean admit is not an admission
        let dec: JSONValue = .object(["admit": .string("yes"), "releaseGuardianShare": .bool(true), "r": .int(0),
                                      "requiredThreshold": .object(["t": .int(1)]), "reasons": .array([])])
        XCTAssertEqual(try PCAExplain.explainDecision(.object([:]), dec).get("verdict"), .string("deny"))
        XCTAssertEqual(try PCAExplain.explainDecision(.object([:]), .null).get("verdict"), .string("deny"))
        XCTAssertEqual(PCAExplain.cleanText("Bearer abcdef123456 and token=xyz"), "Bearer [redacted] and token=[redacted]")
    }
}
