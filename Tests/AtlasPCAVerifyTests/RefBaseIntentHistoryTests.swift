import XCTest
import Foundation
@testable import AtlasPCAVerify

/// Session histories (windows, accumulator keys, pre-states, post values, monitor folds) against the 29179-case shared base corpus: every case, every fn, with
/// the fn set and the total asserted. A reference throw (a malformed declaration or event) is a native refusal (the function returns nothing).
final class RefBaseIntentHistoryTests: XCTestCase {
    typealias A = RefAnalyzer

    private static func orThrow(_ c: BaseCase, _ v: JSONValue?) -> BaseGot { v.map { .value($0) } ?? (c.threw ? .threw(nil) : .value(.null)) }

    static func call(_ c: BaseCase) -> BaseGot? {
        let a0 = A.arg(c, 0), a1 = A.arg(c, 1), a2 = A.arg(c, 2), a3 = A.arg(c, 3)
        switch c.fn {
        case "inWindow":
            do { return .value((try IntentHistory.inWindowJS(a0, a1, a2)).map { .bool($0) } ?? .null) } catch { return .threw(nil) }
        case "accKeyOf":
            // a primitive or null parameter bag has no members (the reference's own-property test is false)
            let bag: JObject?
            switch a1 { case let .object(o)?: bag = o; case .null?, .bool?, .int?, .double?: bag = [:]; default: bag = nil }
            guard let a = a0?.asObject, let p = bag else { return .threw(nil) }
            return orThrow(c, IntentHistory.accKeyOf(a, p).map { .string($0) })
        case "accPreState":
            guard let a = a0?.asObject, let h = a1?.asArray, let cand = a2?.asObject, let p = cand[JKey("params")]?.asObject else { return .threw(nil) }
            return orThrow(c, IntentHistory.accPreState(a, h, p, cand[JKey("t")], JS.present(a3)))
        case "accPost":
            guard let a = a0?.asObject, let h = a1?.asArray, let cand = a2?.asObject, let verb = cand[JKey("verb")]?.asString, let p = cand[JKey("params")]?.asObject else { return .threw(nil) }
            return orThrow(c, IntentHistory.accPost(a, h, verb, p, cand[JKey("t")], JS.present(a3)).map { PD.num($0) })
        case "monitorStep":
            guard let m = a0?.asObject, let q = a1?.asString, let e = a2?.asObject else { return .threw(nil) }
            return .value(IntentHistory.monitorStepJS(m, q, e).map { .string($0) } ?? .null)
        case "monitorState":
            guard let m = a0?.asObject, let h = a1?.asArray else { return .threw(nil) }
            do { return .value(try IntentHistory.monitorStateJS(m, h).map { .string($0) } ?? .null) } catch { return .threw(nil) }
        default: return nil
        }
    }

    func testEveryCaseOfTheBaseCorpus() throws {
        let d = Base.Diffs()
        var seen: [String: Int] = [:]
        let n = try Base.each("base-intenthistory.json.gz") { c in
            seen[c.fn, default: 0] += 1
            guard let got = Self.call(c) else { XCTFail("unhandled fn \(c.fn)"); return }
            d.add(c, Base.diff(c, got))
        }
        XCTAssertEqual(n, 29179)
        XCTAssertEqual(seen, ["accPost": 14784, "accPreState": 11340, "inWindow": 1848, "monitorStep": 1003, "accKeyOf": 104, "monitorState": 100])
        d.finish(29179 - d.skipped.values.reduce(0, +))
    }
}
