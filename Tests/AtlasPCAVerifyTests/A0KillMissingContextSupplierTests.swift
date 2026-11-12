import XCTest
import Foundation
@testable import AtlasPCAVerify

/// MissingContext.swift line 35: the supplier is the LONGEST matching key whatever the dictionary's iteration order. Many tables with the same
/// nested keys in different insertion orders give different iteration orders; a selection that takes the first or the last match fails one.
final class A0KillMissingContextSupplierTests: XCTestCase {
    func testLongestMatchingKeyWinsInEveryIterationOrder() {
        let keys = ["env", "env.a", "env.a.b", "env.a.b.c", "env.a.b.c.d", "env.a.b.c.d.e", "env.a.b.c.d.e.f", "env.a.b.c.d.e.f.g"]
        for rot in 0..<keys.count {
            for rev in [false, true] {
                var order = Array(keys[rot...] + keys[..<rot])
                if rev { order.reverse() }
                var table: JObject = [:]
                for k in order { table[JKey(k)] = .string("s\(keys.firstIndex(of: k)!)") }
                XCTAssertEqual(MissingContext.supplierOf("env.a.b.c.d.e.f.g.h", table: table), "s7", "rot \(rot) rev \(rev)")
                XCTAssertEqual(MissingContext.supplierOf("env.a.b.c", table: table), "s3", "rot \(rot) rev \(rev) shorter path")
                XCTAssertEqual(MissingContext.supplierOf("env.ab", table: table), "s0", "only the root key matches at a segment boundary")
                XCTAssertEqual(MissingContext.supplierOf("subject.x", table: table), "principal")
            }
        }
    }
}
