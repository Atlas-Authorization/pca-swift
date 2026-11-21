import XCTest
@testable import AtlasPCAVerify

/// v2 parameter `provenance_min` and verb `floors` are checked (action-schema.ts schemaFloorsError / the param declaration).
final class S2G4ActionSchemaKillTests: XCTestCase {
    typealias J = JSONValue

    func testProvenanceMinMustBeKnown() {
        func err(_ pm: String) -> String? {
            ActionSchema.paramDeclError("action.params.x", J.object(["type": J.string("string"), "semantic": J.string("x"), "sensitivity": J.string("free"),
                                                                     "provenance_min": J.string(pm)]), nil, v2: true)
        }
        for ok in ["first_party", "tool", "agent"] { XCTAssertNil(err(ok), ok) }
        XCTAssertEqual(err("bogus"), "action.params.x: unknown provenance_min")
        XCTAssertEqual(err(""), "action.params.x: unknown provenance_min")
    }

    func floors(_ over: JObject = [:]) -> JSONValue {
        var f: JObject = ["risk": J.int(0), "esc": J.int(0), "rev": J.string("reversible"), "blast_ppm": J.int(0), "caveats": J.array([]), "context": J.array([]), "prules": J.array([])]
        for (k, v) in over { f[k] = v }
        return JSONValue.object(f)
    }

    func verbErr(_ fl: JSONValue) -> String? {
        let d32 = Base64URLStrict.encode([UInt8](repeating: 1, count: 32))
        let v: JSONValue = J.object(["verb": J.string("v"), "kind": J.string("read"), "params": J.object([:]), "effects": J.array([J.string("read")]),
                                     "traits": J.array([]), "def": J.string(d32), "floors": fl])
        return ActionSchema.verbDeclError(v, nil, v2: true)
    }

    func testAVerbCarriesWellFormedFloors() {
        XCTAssertNil(verbErr(floors()))
        XCTAssertEqual(verbErr(floors(["risk": J.int(9)])), "verb 'v': floors.risk and floors.esc must be integers in 0..3")
        XCTAssertEqual(verbErr(floors(["rev": J.string("sometimes")])), "verb 'v': floors.rev is not a reversibility class")
        XCTAssertEqual(verbErr(J.string("x")), "verb 'v': floors must be an object")
    }
}
