import XCTest
@testable import AtlasPCAVerify

/// `runtime_pins`: accepted, then denied at the gate (blueprint.ts:86-91, :202-205), since admission is not implemented here. And the registry under concurrent calls.
final class BlueprintPinsTests: XCTestCase {
    private static let op = V2F.key("bp-operator")
    private static let BP = "bp-key", ROOT = "root-key", INST = "inst-key"

    private func rec(_ over: JObject = [:], key: String = BlueprintPinsTests.BP) -> JSONValue {
        var b: JObject = ["v": .int(1), "id": .string("bp1"), "key": .string(key), "ceiling": .array([]), "epoch": .int(1), "status": .string("active"),
                          "issued_at": .int(1), "operator": .string(V2F.pub(Self.op))]
        for (k, v) in over { b[k] = v }
        b["sig"] = .string(V2F.sign(Self.op, IV.message(Blueprint.DOMAIN, .object(b))!))
        return .object(b)
    }
    private static let PINS: JSONValue = .array([.object(["model_id": .string("m")])])
    private static let CHAIN: JSONValue = .array([.object(["issuer": .string(ROOT), "holder": .string(BP)]), .object(["issuer": .string(BP), "holder": .string(INST)])])

    private func gate(_ r: JSONValue, mode: String = "any") -> Blueprint.Decision {
        let reg = Blueprint.Registry(operators: [V2F.pub(Self.op)])
        XCTAssertEqual(reg.accept(r).code, nil)
        return Blueprint.check(chain: Self.CHAIN, registry: reg, now: .int(5), mode: mode)
    }

    func testAPinnedBlueprintDenies() {
        XCTAssertEqual(gate(rec()).governed, ["bp1"])
        XCTAssertEqual(gate(rec()).decision, "allow")
        for mode in ["any", "require"] {
            let d = gate(rec(["runtime_pins": Self.PINS]), mode: mode)
            XCTAssertEqual(d.decision, "deny")
            XCTAssertEqual(d.code, "admission_required")
            XCTAssertEqual(d.blueprint, "bp1")
        }
    }

    func testOrderAroundPins() {
        XCTAssertEqual(gate(rec(["runtime_pins": Self.PINS, "status": .string("disabled")])).code, "blueprint_disabled") // a group kill carrying pins
        XCTAssertEqual(gate(rec(["runtime_pins": Self.PINS, "expires_at": .int(5)])).code, "blueprint_expired")
        XCTAssertEqual(gate(rec(["runtime_pins": Self.PINS, "max_depth": .int(1)])).code, "admission_required") // depth 1 fits
        XCTAssertEqual(gate(rec(["runtime_pins": Self.PINS, "ceiling": .array([.object(["type": .string("x")])])])).code, "admission_required") // before the ceiling
    }

    func testTooDeepPrecedesPinsAndACeilingStillDenies() {
        let reg = Blueprint.Registry(operators: [V2F.pub(Self.op)])
        XCTAssertEqual(reg.accept(rec(["runtime_pins": Self.PINS, "max_depth": .int(1)])).ok, true)
        let deep: JSONValue = .array((Self.CHAIN.asArray ?? []) + [.object(["issuer": .string(Self.INST), "holder": .string("next")])])
        XCTAssertEqual(Blueprint.check(chain: deep, registry: reg, now: .int(5), mode: "any").code, "too_deep")
        XCTAssertEqual(gate(rec(["ceiling": .array([.object(["type": .string("x")])])])).code, "ceiling_unevaluable")
    }

    func testPinsShape() {
        let keys = ["runtime_measurement", "model_id", "weights_digest", "operator", "spiffe_id"]
        for k in keys { XCTAssertTrue(Blueprint.verify(rec(["runtime_pins": .array([.object([JKey(k): .string("x")])])])), k) }
        XCTAssertTrue(Blueprint.verify(rec(["runtime_pins": .array(Array(repeating: .object(["model_id": .string("x")]), count: 16))])))
        XCTAssertTrue(Blueprint.verify(rec(["runtime_pins": .array([.object(["model_id": .string(String(repeating: "a", count: 256))])])])))
        let bad: [JSONValue] = [.array([]), .string("x"), .object([:]), .array(Array(repeating: .object(["model_id": .string("x")]), count: 17)), .array([.object([:])]), .array([.string("x")]),
                                .array([.object(["nope": .string("x")])]), .array([.object(["model_id": .int(1)])]), .array([.object(["model_id": .string("")])]),
                                .array([.object(["model_id": .string(String(repeating: "a", count: 257))])])]
        for p in bad { XCTAssertFalse(Blueprint.verify(rec(["runtime_pins": p])), "\(p)") }
    }

    func testRegistryUnderConcurrentCalls() {
        let reg = Blueprint.Registry(operators: [V2F.pub(Self.op)])
        let recs = (0..<64).map { rec(["id": .string("b\($0)")], key: "k\($0)") }
        DispatchQueue.concurrentPerform(iterations: 64) { i in
            XCTAssertEqual(reg.accept(recs[i]).ok, true)
            _ = reg.epoch
            _ = Blueprint.check(chain: Self.CHAIN, registry: reg, now: .int(5), mode: "any")
        }
        XCTAssertEqual(reg.store.count, 64)
    }
}
