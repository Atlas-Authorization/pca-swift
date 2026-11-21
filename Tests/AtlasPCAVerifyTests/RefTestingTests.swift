import XCTest
import Foundation
@testable import AtlasPCAVerify

/// Differential replay of the testing kit (PCATesting: the acceptance constants and route mapping, the fake verifier and the assertions
/// over it, tamper, the in-memory state store) against the reference (@atlasauth/pca-testing). A reference throw requires a native refusal.
final class RefTestingTests: XCTestCase {
    static func options(_ v: JSONValue?) -> PCATesting.FakeVerifyOptions {
        var o = PCATesting.FakeVerifyOptions()
        if let n = v?.get("now").flatMap({ IV.int($0) }) { o.now = n }
        if let g = v?.get("grant") { o.grant = g }
        if let a = v?.asObject?[JKey("audience")] { o.audience = .some(a.asString) }
        return o
    }

    /// Walks `path` through objects (a missing step is the reference's TypeError) and sets or deletes the last member.
    static func apply(_ rec: inout JObject, _ path: ArraySlice<String>, _ set: JSONValue?) throws {
        guard let k = path.first else { return }
        if path.count == 1 {
            if let v = set { rec[JKey(k)] = v } else { rec[JKey(k)] = nil }
            return
        }
        guard case var .object(child)? = rec[JKey(k)] else { throw JSError("Cannot set properties of undefined") }
        try apply(&child, path.dropFirst(), set)
        rec[JKey(k)] = .object(child)
    }

    func testTestingKitAgainstTheReference() throws {
        try K042.requireCovers(["Testing", "PCActn"])
        let d = Base.Diffs()
        try Base.each("ref-testing.json.gz") { c in
            let a = c.args
            let got: BaseGot = Base.run {
                switch c.fn {
                case "consts":
                    var rows = JObject()
                    for (name, o) in PCATesting.ADAPTER_ACCEPTANCE_EXPECTED {
                        rows[JKey(name)] = .object(["status": .int(Int64(o.status)), "handlerRan": .bool(o.handlerRan), "bound": .bool(o.bound)])
                    }
                    return .object(["aud": .string(PCATesting.ADAPTER_ACCEPTANCE_AUDIENCE), "expected": .object(rows)])
                case "acceptanceOperation": return try PCATesting.acceptanceOperation(a[0]) ?? .null
                case "fakeVerifyAllow": return .bool(try PCATesting.fakeVerify(a[0], Self.options(a.count > 1 ? a[1] : nil)).allow)
                case "expectVerifies": return .bool(try PCATesting.expectVerifies(a[0], Self.options(a.count > 1 ? a[1] : nil)).allow)
                case "expectDenied": return .bool(try PCATesting.expectDenied(a[0], Self.options(a.count > 1 ? a[1] : nil)).allow)
                case "tamper":
                    guard let enc = a[0].asString, let op = a[1].get("op")?.asString else { throw JSError("bad case") }
                    let path = (a[1].get("path")?.asArray ?? []).compactMap { $0.asString }
                    return .string(try PCATesting.tamper(enc) { rec in
                        switch op {
                        case "set": try Self.apply(&rec, path[...], a[1].get("value") ?? .null)
                        case "delete": try Self.apply(&rec, path[...], nil)
                        default: break
                        }
                    })
                case "memorySession":
                    let s = PCATesting.memoryStateStore()
                    var out: [JSONValue] = []
                    for step in a[0].asArray ?? [] {
                        guard let st = step.asArray, let op = st.first?.asString, st.count > 1, let key = st[1].asString else { throw JSError("bad step") }
                        if op == "put" { s.put(key, st.count > 2 ? st[2] : .null) } else { out.append(s.get(key) ?? .null) }
                    }
                    return .array(out)
                default: throw JSError("not mapped")
                }
            }
            d.add(c, Base.diff(c, got))
        }
        d.finish(2000)
    }
}
