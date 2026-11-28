import XCTest
import Foundation
@testable import AtlasPCAVerify

/// Differential replay of the pure A2A binding surface (receipts and their carriers, the Agent Card extension, the AUTH_REQUIRED mapping, the push token,
/// the chain rule) against the TypeScript reference (@atlasauth/pca-a2a). A reference throw requires a native refusal.
final class RefA2aTests: XCTestCase {
    static let file = "ref-a2a.json.gz"

    static func key(_ label: JSONValue?) throws -> PCAEdKey {
        guard let l = label?.asString else { throw JSError("label expected") }
        return try Ed25519Deterministic.key(seed: Canonical.sha256(Array(("atlas-pca-conformance/" + l).utf8)))
    }

    static func strs(_ v: JSONValue?) throws -> [String] {
        guard let a = v?.asArray else { throw JSError("array expected") }
        return try a.map { guard let s = $0.asString else { throw JSError("string expected") }; return s }
    }

    func testA2aAgainstTheReference() throws {
        let d = Base.Diffs()
        let fns: Set<String> = ["signTaskReceipt", "attachReceipt", "receiptOfPayload", "pcaExtensionDeclaration", "readPcaExtension", "clientOptsIntoPca", "authRequiredStatus",
                                "answerMessage", "readAuthRequiredNeed", "isAuthRequired", "chainExtends", "uniformTaskNotFound", "pcaPushToken", "receiptDigest",
                                "verifyTaskReceipt", "checkChainExtension"]
        let n = try Base.each(Self.file, fns) { c in
            let got: BaseGot = Base.run {
                switch c.fn {
                case "signTaskReceipt":
                    guard let o = c.arg(1)?.asObject, let taskId = o["taskId"]?.asString, let state = o["state"]?.asString, let issued = IV.safe(o["issuedAt"]) else { throw JSError("malformed") }
                    return try A2a.signTaskReceipt(try Self.key(c.arg(0)), taskId: taskId, state: state, chainIds: try Self.strs(o["chainIds"]), issuedAt: Int64(issued), prev: o["prev"])
                case "attachReceipt": return try A2a.attachReceipt(c.arg(0) ?? .null, c.arg(1) ?? .null)
                case "receiptOfPayload": return A2a.receiptOfPayload(c.arg(0)) ?? .null
                case "pcaExtensionDeclaration":
                    guard let p = c.arg(0)?.asObject else { throw JSError("params") }
                    return A2a.pcaExtensionDeclaration(p, required: c.args.count > 1 ? (c.arg(1) == .bool(true)) : true)
                case "readPcaExtension": return A2a.readPcaExtension(c.arg(0))
                case "clientOptsIntoPca": return .bool(A2a.clientOptsIntoPca(c.arg(0)))
                case "authRequiredStatus":
                    guard let o = c.arg(1)?.asObject, let mid = o["messageId"]?.asString, let now = IV.num(o["now"]) else { throw JSError("Invalid time value") }
                    return try A2a.authRequiredStatus(c.arg(0) ?? .null, messageId: mid, now: now, text: o["text"]?.asString)
                case "answerMessage": return A2a.answerMessage(c.arg(0) ?? .null, c.arg(1) ?? .null, messageId: c.arg(2)?.asString ?? "")
                case "readAuthRequiredNeed":
                    guard let r = A2a.readAuthRequiredNeed(c.arg(0)) else { return .null }
                    if let code = r.code { return .object(["ok": .bool(false), "code": .string(code)]) }
                    return .object(["ok": .bool(true), "need": r.need ?? .null])
                case "isAuthRequired": return .bool(A2a.isAuthRequired(c.arg(0)))
                case "chainExtends": return .bool(try A2a.chainExtends(c.arg(0), c.arg(1)))
                case "uniformTaskNotFound": return A2a.uniformTaskNotFound()
                case "pcaPushToken": return .string(try A2a.pushToken(taskId: c.arg(0), chainIds: c.arg(1), salt: c.arg(2)))
                case "receiptDigest": return .string(try A2a.receiptDigestStrict(c.arg(0) ?? .null))
                case "verifyTaskReceipt": return .bool(A2a.verifyTaskReceipt(c.arg(0), signer: c.arg(1)?.asString ?? ""))
                case "checkChainExtension": return try A2a.checkChainExtension(c.arg(0))
                default: throw JSError("unhandled \(c.fn)")
                }
            }
            d.add(c, Base.diff(c, got))
        }
        XCTAssertGreaterThan(n, 250)
        d.finish(250)
    }
}
