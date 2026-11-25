import XCTest
import Foundation
@testable import AtlasPCAVerify

/// Differential replay of PCARotate against the reference (@atlasauth/pca-rotate): agent / principal key rotation, compromised
/// subtree re-issue and applyRotation over a registry sink. Keys cross the corpus as base64url Ed25519 seeds; the test derives
/// the (deterministically signing) keys from them, so no key material is stored beyond the seeds.
final class RefRotateTests: XCTestCase {
    static let file = "ref-rotate.json.gz"
    /// The frozen clock the corpus generator ran under (its header's clockMs).
    static let clock = Base.clockMs(file)
    /// The oracle's fixed time for the entries it registers itself (`T0`); the header's clock is only the wall clock its `<now>` normalisation froze.
    static let T0: Int64 = 1_800_000_000_000

    /// Revoke's normalisation under this corpus's own clock.
    static func norm(_ v: JSONValue) -> JSONValue { RefRevokeTests.norm(v, clock: clock) }

    static func key(_ v: JSONValue?) throws -> PCAEdKey {
        guard let s = v?.asString, let seed = Base64URLStrict.decode(s) else { throw JSError("seed is not a base64url string") }
        return try Ed25519Deterministic.key(seed: seed)
    }

    /// The reference's scenario sink: a registry whose `revoke` throws on its failAt-th call, `unrevoke` always when failUnrevoke.
    final class ScenarioSink: PCARotate.Sink {
        let reg = PCARevoke.Registry()
        var calls = 0
        let failAt: Int?, failUnrevoke: Bool
        init(failAt: Int?, failUnrevoke: Bool) { self.failAt = failAt; self.failUnrevoke = failUnrevoke }
        func revoke(_ input: JSONValue) throws -> JSONValue {
            calls += 1
            if failAt == calls { throw JSError("sink down") }
            return try reg.revoke(input)
        }
        func unrevoke(_ key: JSONValue) throws -> Bool {
            if failUnrevoke { throw JSError("unrevoke down") }
            return try reg.unrevoke(key)
        }
        func lookup(_ kind: String, _ value: String) throws -> JSONValue? { try reg.lookup(kind, value) }
    }

    static func applyScenario(_ spec: JSONValue?) throws -> JSONValue {
        let sink = ScenarioSink(failAt: spec?.get("failAt")?.safeInt.map { Int($0) }, failUnrevoke: spec?.get("failUnrevoke") == .bool(true))
        for id in spec?.get("pre")?.asArray ?? [] {
            try sink.reg.revoke(.object(["kind": .string("cap"), "value": id, "reason": .string("pre"), "revokedAt": .int(T0)]))
        }
        let result: JSONValue
        do {
            let ids = try PCARotate.applyRotation(sink, spec?.get("records") ?? .null, reissued: spec?.get("reissued"))
            result = .array(ids.map { .string($0) })
        } catch { result = .object(["$err": .bool(true)]) }
        return .object(["result": result, "list": RefRotateTests.norm(.array(try sink.reg.list()))])
    }

    func testRotate() throws {
        try K042.requireCovers(["Rotate", "Revoke", "Issue", "JSInterop"])
        let d = Base.Diffs()
        try Base.each(Self.file, seeds: true) { c in
            let a0 = c.arg(0), a1 = c.arg(1)
            let got: BaseGot
            switch c.fn {
            case "rotateAgentKey":
                got = Ref.v { RefRotateTests.norm(try PCARotate.rotateAgentKey(a0, oldHolder: try Self.key(a1?.get("oldSeed")), newKey: try Self.key(a1?.get("newSeed")), opts: a1)) }
            case "rotatePrincipalKey":
                got = Ref.v {
                    var hs: [PCAEdKey] = []
                    if let a = a0?.get("holderSeeds")?.asArray { hs = try a.map { try Self.key($0) } } // absent or null: `holderSecrets ?? []`
                    return RefRotateTests.norm(try PCARotate.rotatePrincipalKey(a0, oldPrincipal: try Self.key(a0?.get("oldSeed")), newPrincipal: try Self.key(a0?.get("newSeed")), holderSecrets: hs))
                }
            case "revokeAndReissueSubtree":
                let op = c.arg(2)
                got = Ref.v { RefRotateTests.norm(try PCARotate.revokeAndReissueSubtree(a0, a1 ?? .null, newKey: try Self.key(op?.get("newSeed")), ancestor: try Self.key(op?.get("ancestorSeed")), opts: op)) }
            case "compromisedKeyFlow":
                let op = c.arg(2)
                got = Ref.v { RefRotateTests.norm(try PCARotate.compromisedKeyFlow(a0, a1 ?? .null, newKey: try Self.key(op?.get("newSeed")), ancestor: try Self.key(op?.get("ancestorSeed")), opts: op)) }
            case "applyRotationScenario":
                got = Ref.v { try Self.applyScenario(a0) }
            default:
                d.skip("\(c.fn): not mapped"); return
            }
            d.add(c, Base.diff(c, got))
        }
        d.finish(1100)
    }

    func testRotateFailClosed() throws {
        let a = try Ed25519Deterministic.key(seed: [UInt8](repeating: 1, count: 32)), b = try Ed25519Deterministic.key(seed: [UInt8](repeating: 2, count: 32))
        let n = try Ed25519Deterministic.key(seed: [UInt8](repeating: 3, count: 32))
        let root = try PCAIssue.mintRoot(principal: PCASuiteKey.ed25519(a), holder: b.id, caveats: [.object(["type": .string("ttl"), "secs": .int(60)])])
        // a root-only chain has no leaf to re-issue; a wrong signer, the old key as the new key and a non-finite clock are refused
        XCTAssertThrowsError(try PCARotate.rotateAgentKey(.array([root]), oldHolder: b, newKey: n))
        let leaf = try PCAIssue.delegate(parent: root, toHolder: n.id, added: [], signer: PCASuiteKey.ed25519(b))
        let chain = JSONValue.array([root, leaf])
        XCTAssertThrowsError(try PCARotate.rotateAgentKey(chain, oldHolder: a, newKey: n))
        XCTAssertThrowsError(try PCARotate.rotateAgentKey(chain, oldHolder: b, newKey: n))
        XCTAssertThrowsError(try PCARotate.rotateAgentKey(chain, oldHolder: b, newKey: a, opts: .object(["now": .null])))
        let ok = try PCARotate.rotateAgentKey(chain, oldHolder: b, newKey: a, opts: .object(["now": .int(5)]))
        XCTAssertEqual(ok.get("chain")?.asArray?.count, 2)
        // applyRotation refuses a re-issued chain that still holds a revoked cap, before touching the sink
        let sink = ScenarioSink(failAt: nil, failUnrevoke: false)
        let rec = ok.get("revocation") ?? .null
        XCTAssertThrowsError(try PCARotate.applyRotation(sink, rec, reissued: chain))
        XCTAssertEqual(try sink.reg.list().count, 0)
        XCTAssertEqual(try PCARotate.applyRotation(sink, rec, reissued: ok.get("chain")).count, 1)
    }
}
