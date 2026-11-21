import XCTest
import Foundation
#if canImport(CryptoKit)
import CryptoKit
#else
import Crypto // Linux: swift-crypto
#endif
@testable import AtlasPCAVerify

/// The mesh proof verifier (packages/pca/src/mesh.ts verifyMeshProof): the limits on chain, evidence and pin tables, the revocation and
/// consistency proofs, JavaScript truthiness, the cosigned head and the success verdict.
final class S2G7MeshKillTests: XCTestCase {
    typealias J = JSONValue

    // ---- the trust configuration ----

    func trust(_ over: JObject = [:]) -> JSONValue {
        var t: JObject = ["humanPrincipal": J.string("h"), "witnesses": J.array([J.string("w")]), "threshold": J.int(1), "now": J.int(1000),
                          "allowedDomains": J.array([J.string("d")]), "rootDomain": J.string("d")]
        for (k, v) in over { t[k] = v }
        return J.object(t)
    }

    func action() -> JSONValue {
        J.object(["type": J.string("t"), "resource": J.string("r"), "service_domain": J.string("d"), "nonce": J.string("n"), "at": J.int(1)])
    }

    func proof(chain: Int = 0, revLeaves: Int = 0, pin: JSONValue? = nil) -> JSONValue {
        var p: JObject = ["chain": J.array(Array(repeating: J.object([:]), count: chain)), "hops": J.array([]), "heads": J.array([]),
                          "rev_leaves": J.array(Array(repeating: J.null, count: revLeaves)), "action": action(), "action_sig": J.string("x")]
        if let x = pin { p["pin_proofs"] = x }
        return J.object(p)
    }

    func reason(_ p: JSONValue, _ t: JSONValue? = nil) -> String { Mesh.verifyMeshProof(p, trust: t ?? trust()).reason }

    func testDefaultMaxChainLength() {
        XCTAssertEqual(Mesh.DEFAULT_MAX_CHAIN, 64)
        XCTAssertTrue(reason(proof(chain: 64)).hasPrefix("chain:"), reason(proof(chain: 64)))
        XCTAssertEqual(reason(proof(chain: 65)), "chain length out of bounds")
    }

    func testChainLengthLowerBound() {
        XCTAssertEqual(reason(proof(chain: 0)), "chain length out of bounds")
        XCTAssertTrue(reason(proof(chain: 1)).hasPrefix("chain:"), reason(proof(chain: 1)))
    }

    func testEvidenceTablesAreBoundedByTheChain() {
        XCTAssertTrue(reason(proof(chain: 1, revLeaves: 2)).hasPrefix("chain:"), reason(proof(chain: 1, revLeaves: 2)))
        XCTAssertEqual(reason(proof(chain: 1, revLeaves: 3)), "evidence tables exceed chain size")
    }

    func testPinProofTableBound() {
        func pins(_ n: Int) -> JSONValue {
            J.array(Array(repeating: J.object(["domain": J.string("d"), "proof": J.object(["oldSize": J.int(0), "newSize": J.int(0), "path": J.array([])])]), count: n))
        }
        XCTAssertEqual(reason(proof(pin: pins(256))), "chain length out of bounds", "256 entries pass the table check")
        XCTAssertEqual(reason(proof(pin: pins(257))), "malformed pin proofs")
    }

    func testPqPinsAreReadFromTheTrustConfiguration() {
        let (t, bad) = Mesh.validTrust(trust(["pqPins": J.object(["k": J.string("v"), "n": J.int(1)])]))
        XCTAssertEqual(bad, "")
        XCTAssertEqual(t.pqPins, ["k": "v"])
        XCTAssertEqual(Mesh.validTrust(trust()).0.pqPins, [:])
    }

    // ---- truthiness ----

    func testTruthy() {
        XCTAssertFalse(Mesh.truthy(J.null))
        XCTAssertFalse(Mesh.truthy(J.bool(false)))
        XCTAssertTrue(Mesh.truthy(J.bool(true)))
        XCTAssertFalse(Mesh.truthy(J.string("")))
        XCTAssertTrue(Mesh.truthy(J.string("x")))
        XCTAssertFalse(Mesh.truthy(J.int(0)))
        XCTAssertTrue(Mesh.truthy(J.int(1)))
        XCTAssertTrue(Mesh.truthy(J.int(-1)))
        XCTAssertFalse(Mesh.truthy(J.double(0)))
        XCTAssertFalse(Mesh.truthy(J.double(-0.0)))
        XCTAssertFalse(Mesh.truthy(J.double(Double.nan)))
        XCTAssertTrue(Mesh.truthy(J.double(1)))
        XCTAssertTrue(Mesh.truthy(J.double(1.5)))
        XCTAssertTrue(Mesh.truthy(J.double(-2.5)))
        XCTAssertTrue(Mesh.truthy(J.double(Double.infinity)))
        XCTAssertTrue(Mesh.truthy(J.array([])))
        XCTAssertTrue(Mesh.truthy(J.object([:])))
    }

    // ---- revocation leaves ----

    func b64(_ b: [UInt8]) -> String { Base64URLStrict.encode(b) }

    func testALeafIndexMustBeBelowTheSize() throws {
        let la = Merkle.leafHash(J.string("a")), lb = Merkle.leafHash(J.string("b"))
        let root = try XCTUnwrap(IntentRevocation.bindRoot(J.int(2), b64(Merkle.nodeHash(la, lb))))
        func p(_ index: Int64) -> JObject {
            ["size": J.int(2), "index": J.int(index), "path": J.array([J.object(["side": J.string("L"), "hash": J.string(b64(la))])])]
        }
        XCTAssertTrue(Mesh.leafOK(root, 2, "b", p(1)))
        XCTAssertFalse(Mesh.leafOK(root, 2, "b", p(2)), "index == size has the same path shape as index 1 but is out of range")
        XCTAssertFalse(Mesh.leafOK(root, 2, "b", p(-1)))
        XCTAssertFalse(Mesh.leafOK(root, 3, "b", p(1)), "the proof's size must be the set's size")
    }

    // ---- consistency ----

    func path(_ n: Int) -> JSONValue { J.array(Array(repeating: J.string(b64([UInt8](repeating: 1, count: 32))), count: n)) }

    func cons(_ old: Int64, _ new: Int64, _ path: JSONValue, _ a: String = "r", _ b: String = "r") -> Bool {
        Mesh.consistency(a, b, ["oldSize": J.int(old), "newSize": J.int(new), "path": path])
    }

    func testConsistencyOfEqualSizes() {
        XCTAssertTrue(cons(3, 3, J.array([])), "the same size and root, no path")
        XCTAssertFalse(cons(3, 3, J.array([]), "r", "s"), "the same size, different roots")
        XCTAssertFalse(cons(3, 3, path(1)), "the same size with a path")
        XCTAssertFalse(cons(3, 3, path(1), "r", "s"))
    }

    func testConsistencyOrderAndPathBound() {
        XCTAssertFalse(cons(5, 3, J.array([])), "the old tree is larger")
        XCTAssertFalse(cons(3, 5, path(129)), "more than 128 path nodes")
        XCTAssertFalse(cons(-1, 3, J.array([])))
    }

    // ---- a cosigned head ----

    func testCosignatureListBound() throws {
        let dk = try Curve25519.Signing.PrivateKey(rawRepresentation: Data(repeating: 4, count: 32))
        let domain = b64(Array(dk.publicKey.rawRepresentation))
        let head: JObject = ["domain": J.string(domain), "root": J.string(""), "rev_root": J.string(""), "size": J.int(0), "rev_size": J.int(0), "timestamp": J.int(1000)]
        let m = try XCTUnwrap(IV.message(Mesh.HEAD_DOMAIN, J.object(head)))
        let sig = b64(Array(try dk.signature(for: Data(m))))
        var t = Mesh.Trust()
        t.witnesses = [JKey("w")]
        t.threshold = 1
        t.now = 1000
        t.maxHeadAge = 300_000
        t.maxSkew = 60_000
        func ch(_ n: Int) -> JSONValue { J.object(["head": J.object(head), "sig": J.string(sig), "cosigs": J.array(Array(repeating: J.null, count: n))]) }
        XCTAssertEqual(Mesh.checkCosignedHead(ch(256), domain, t, nil), "head has 0/1 trusted witness cosignatures")
        XCTAssertEqual(Mesh.checkCosignedHead(ch(257), domain, t, nil), "malformed head")
    }

    // ---- the success verdict ----

    func testAcceptedVectorsNameNoHop() throws {
        let doc = try ConformanceTests.load("mesh-vectors.json")
        var seen = 0
        for v in doc.get("mesh")?.asArray ?? [] where v.get("expect")?.get("ok") == J.bool(true) {
            let r = Mesh.verifyMeshProof(v.get("proof"), trust: v.get("trust"))
            XCTAssertTrue(r.ok, v.get("name")?.asString ?? "?")
            XCTAssertEqual(r.reason, "")
            XCTAssertEqual(r.hop, -1, v.get("name")?.asString ?? "?")
            seen += 1
        }
        XCTAssertGreaterThan(seen, 5)
    }
}
