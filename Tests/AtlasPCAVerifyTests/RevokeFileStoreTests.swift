import XCTest
import Foundation
@testable import AtlasPCAVerify

final class RevokeFileStoreTests: XCTestCase {
    static func entry(_ kind: String, _ value: String, _ extra: JObject = [:]) -> JSONValue {
        var o: JObject = ["kind": .string(kind), "value": .string(value), "reason": .string("r"), "revokedAt": .int(5)]
        for (k, v) in extra { o[k] = v }
        return .object(o)
    }

    func tmp() -> String { NSTemporaryDirectory() + "revoke-" + UUID().uuidString + ".json" }

    func testEntriesPersistAcrossReopenAndReplaceInPlace() throws {
        let p = tmp()
        defer { try? FileManager.default.removeItem(atPath: p) }
        let s = try PCARevoke.FileRevocationStore(path: p)
        XCTAssertEqual(try s.all(), [])
        try s.add(Self.entry("cap", "a"))
        try s.add(Self.entry("holder", "h"))
        try s.add(Self.entry("cap", "a", ["reason": .string("again")]))
        let again = try PCARevoke.FileRevocationStore(path: p)
        XCTAssertEqual(try again.all().count, 2)
        XCTAssertEqual(try again.get("cap", "a")?.get("reason"), .string("again"))
        XCTAssertEqual(try again.all().first?.get("value"), .string("a"))
        XCTAssertTrue(try again.remove("holder", "h"))
        XCTAssertFalse(try again.remove("holder", "h"))
        XCTAssertEqual(try PCARevoke.FileRevocationStore(path: p).all().count, 1)
        try again.clear()
        XCTAssertEqual(try PCARevoke.FileRevocationStore(path: p).all(), [])
        XCTAssertEqual((try FileManager.default.attributesOfItem(atPath: p)[.posixPermissions] as? NSNumber)?.intValue, 0o600)
    }

    func testADamagedOrInvalidFileRefusesToStartEmpty() throws {
        let p = tmp()
        defer { try? FileManager.default.removeItem(atPath: p) }
        for bad in ["not json", "{\"v\":1}", "{\"entries\":[{\"kind\":\"nope\",\"value\":\"x\",\"reason\":\"r\",\"revokedAt\":1}]}",
                    "{\"entries\":[{\"kind\":\"cap\",\"value\":\"\",\"reason\":\"r\",\"revokedAt\":1}]}",
                    "{\"entries\":[{\"kind\":\"cap\",\"value\":\"x\",\"reason\":\"r\",\"revokedAt\":1,\"notBefore\":\"soon\"}]}",
                    "{\"entries\":[{\"kind\":\"prefix\",\"value\":\"a,b\",\"prefix\":[\"a\",\"c\"],\"reason\":\"r\",\"revokedAt\":1}]}"] {
            try Data(bad.utf8).write(to: URL(fileURLWithPath: p))
            XCTAssertThrowsError(try PCARevoke.FileRevocationStore(path: p), bad)
        }
        let ok = "{\"entries\":[{\"kind\":\"prefix\",\"value\":\"a,b\",\"prefix\":[\"a\",\"b\"],\"reason\":\"r\",\"revokedAt\":1}]}"
        try Data(ok.utf8).write(to: URL(fileURLWithPath: p))
        XCTAssertEqual(try PCARevoke.FileRevocationStore(path: p).all().count, 1)
    }

    func testAFailedFlushLeavesMemoryAsItWas() throws {
        let p = NSTemporaryDirectory() + "no-such-dir-" + UUID().uuidString + "/revoke.json"
        let s = try PCARevoke.FileRevocationStore(path: p)
        XCTAssertThrowsError(try s.add(Self.entry("cap", "a")))
        XCTAssertEqual(try s.all(), [])
    }
}
