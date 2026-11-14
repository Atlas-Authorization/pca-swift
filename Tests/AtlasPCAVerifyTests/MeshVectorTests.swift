import XCTest
import Foundation
@testable import AtlasPCAVerify

/// The shared mesh corpus (packages/pca/conformance/mesh-vectors.json): whole mesh proofs with the TypeScript verdict: the
/// verdict, the reason (a `chain:` refusal by prefix) and the failing hop.
final class MeshVectorTests: XCTestCase {
    func testMeshVectors() throws {
        let doc = try ConformanceTests.load("mesh-vectors.json")
        let vecs = doc.get("mesh")?.asArray ?? []
        XCTAssertGreaterThanOrEqual(vecs.count, 100)
        var bad: [String] = []
        for v in vecs {
            let name = v.get("name")?.asString ?? "?"
            let expect = v.get("expect")
            let wantOK = expect?.get("ok") == .bool(true)
            let got = Mesh.verifyMeshProof(v.get("proof"), trust: v.get("trust"))
            if got.ok != wantOK { bad.append("\(name): ok = \(got.ok) (reason '\(got.reason)'), want \(wantOK) (reason '\(expect?.get("reason")?.asString ?? "")')"); continue }
            if wantOK { continue }
            let wantReason = expect?.get("reason")?.asString ?? ""
            if wantReason.hasPrefix("chain:") {
                if !got.reason.hasPrefix("chain:") { bad.append("\(name): reason '\(got.reason)', want a chain refusal ('\(wantReason)')") }
                continue
            }
            if got.reason != wantReason { bad.append("\(name): reason '\(got.reason)', want '\(wantReason)'") }
            let wantHop = expect?.get("hop")?.safeInt.map { Int($0) } ?? -1
            if got.hop != wantHop { bad.append("\(name): hop \(got.hop), want \(wantHop)") }
        }
        XCTAssertTrue(bad.isEmpty, bad.joined(separator: "\n"))
    }

    func testHostileInputsAreVerdictsNotTraps() throws {
        for t in ["null", "1", "\"x\"", "[]", "{}", "{\"chain\":[],\"hops\":[],\"heads\":[],\"rev_leaves\":[]}", "{\"chain\":null}"] {
            let v = try StrictJSON.parseLenient(t)
            let r = Mesh.verifyMeshProof(v, trust: v)
            XCTAssertFalse(r.ok, t)
            XCTAssertEqual(r.reason, "invalid trust configuration", t) // the trust configuration is checked first
        }
        let trust: JSONValue = .object(["humanPrincipal": .string("h"), "witnesses": .array([.string("w")]), "threshold": .int(1), "now": .int(1_000),
                                         "allowedDomains": .array([.string("d")]), "rootDomain": .string("d")])
        for t in ["null", "1", "[]", "{}", "{\"chain\":null}"] {
            let r = Mesh.verifyMeshProof(try StrictJSON.parseLenient(t), trust: trust)
            XCTAssertFalse(r.ok, t)
            XCTAssertEqual(r.hop, -1, t)
        }
        XCTAssertEqual(Mesh.verifyMeshProof(.object([:]), trust: trust).reason, "malformed proof")
    }

    func testTrustConfigurationGuards() {
        func r(_ edit: (inout JObject) -> Void) -> String {
            var t: JObject = ["humanPrincipal": .string("h"), "witnesses": .array([.string("w")]), "threshold": .int(1), "now": .int(1_000),
                              "allowedDomains": .array([.string("d")]), "rootDomain": .string("d")]
            edit(&t)
            return Mesh.verifyMeshProof(.object([:]), trust: .object(t)).reason
        }
        XCTAssertEqual(r { _ in }, "malformed proof") // a good trust configuration reaches the proof
        XCTAssertEqual(r { $0["threshold"] = .int(2) }, "invalid trust configuration: threshold")
        XCTAssertEqual(r { $0["threshold"] = .int(0) }, "invalid trust configuration: threshold")
        XCTAssertEqual(r { $0["now"] = .string("x") }, "invalid trust configuration: now")
        XCTAssertEqual(r { $0["maxHeadAgeMs"] = .int(-1) }, "invalid trust configuration: maxHeadAgeMs")
        XCTAssertEqual(r { $0["allowedDomains"] = .array([]) }, "invalid trust configuration: allowedDomains is required")
        XCTAssertEqual(r { $0["rootDomain"] = .string("other") }, "invalid trust configuration: rootDomain is required and must be in allowedDomains")
        XCTAssertEqual(r { $0["maxChainLength"] = .int(0) }, "invalid trust configuration: maxChainLength")
    }
}
