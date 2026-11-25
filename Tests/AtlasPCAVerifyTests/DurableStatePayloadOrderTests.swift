import XCTest
import Foundation
@testable import AtlasPCAVerify

/// The durable-state record hash is the digest of `JSON.stringify([seq, prev, op, payload, ts, gen])` where the payload carries the value as `JSON.stringify` writes it:
/// members in insertion order, not sorted. The expected hash is the one the reference produced for this record.
final class DurableStatePayloadOrderTests: XCTestCase {
    static let prev = "183727228caa026ceed77cbba0a1af3f2814c792605098ca8a8c0a0ec87cd81c"
    static let want = "0031fd725157616f4394e70b83363f9a1ecfa0d10ec14c2f23c687f213c38c77"

    private func hash(_ value: JSONValue) -> String {
        let payload = "d\n" + PCADurableState.js(value)
        return PCADurableState.sha(PCADurableState.DOMAIN + JS.stringify(.array([.int(7), .string(Self.prev), .string("set"), .string(payload), .int(1006), .int(29)])))
    }

    func testAParsedTwoMemberValueKeepsItsWrittenOrder() throws {
        let v = K042.parse(#"{"z":[1,null,true],"a":"q"}"#)
        XCTAssertEqual(PCADurableState.js(v), #"{"z":[1,null,true],"a":"q"}"#)
        XCTAssertEqual(hash(v), Self.want)
    }

    func testABuiltTwoMemberValueKeepsItsInsertionOrder() {
        var o: JObject = [:]
        o[o: "z"] = .array([.int(1), .null, .bool(true)])
        o[o: "a"] = .string("q")
        XCTAssertEqual(PCADurableState.js(.object(o)), #"{"z":[1,null,true],"a":"q"}"#)
        XCTAssertEqual(hash(.object(o)), Self.want)
    }
}
