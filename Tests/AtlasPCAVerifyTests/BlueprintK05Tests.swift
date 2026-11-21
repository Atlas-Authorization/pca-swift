import XCTest
import Foundation
@testable import AtlasPCAVerify

/// Limits, exact refusals and the fail-closed defaults of agent blueprints, against packages/pca-grants/src/blueprint.ts.
final class BlueprintK05Tests: XCTestCase {
    private static let op = V2F.key("bp-k05-operator"), op2 = V2F.key("bp-k05-operator2")
    private static let CHAIN: JSONValue = .array([.object(["issuer": .string("root"), "holder": .string("BP")]), .object(["issuer": .string("BP"), "holder": .string("inst")])])

    private func text(_ n: Int) -> JSONValue { .string(String(repeating: "a", count: n)) }

    private func body(_ over: JObject = [:]) -> JObject {
        var b: JObject = ["v": .int(1), "id": .string("bp1"), "key": .string("BP"), "ceiling": .array([]), "epoch": .int(1), "status": .string("active"),
                          "issued_at": .int(1), "operator": .string(V2F.pub(Self.op))]
        for (k, v) in over { b[k] = v }
        return b
    }

    private func signed(_ over: JObject = [:], by k: V2F.K = BlueprintK05Tests.op) -> JSONValue {
        var over = over
        over["operator"] = .string(V2F.pub(k))
        var b = body(over)
        b["sig"] = .string(V2F.sign(k, IV.message(Blueprint.DOMAIN, .object(b))!))
        return .object(b)
    }

    private func refused(_ code: String) -> Blueprint.Accept { Blueprint.Accept(ok: false, replaced: false, code: code) }
    private func taken(replaced: Bool) -> Blueprint.Accept { Blueprint.Accept(ok: true, replaced: replaced, code: nil) }

    func testStringBounds() {
        for k in ["id", "key", "operator"] {
            XCTAssertNotNil(Blueprint.wellFormed(.object(body([JKey(k): text(128)]))), k)
            XCTAssertNil(Blueprint.wellFormed(.object(body([JKey(k): text(129)]))), k)
        }
    }

    func testMaxDepthIsAnIntegerOfAtLeastOne() {
        XCTAssertNotNil(Blueprint.wellFormed(.object(body(["max_depth": .int(1)]))))
        XCTAssertNil(Blueprint.wellFormed(.object(body(["max_depth": .int(0)]))))
        XCTAssertNil(Blueprint.wellFormed(.object(body(["max_depth": .string("x")]))))
    }

    func testCeilingSizeBound() {
        let c: JSONValue = .object(["type": .string("x")])
        XCTAssertNotNil(Blueprint.wellFormed(.object(body(["ceiling": .array(Array(repeating: c, count: 32))]))))
        XCTAssertNil(Blueprint.wellFormed(.object(body(["ceiling": .array(Array(repeating: c, count: 33))]))))
    }

    func testEveryRefusalIsExact() {
        let pub = V2F.pub(Self.op), pub2 = V2F.pub(Self.op2)
        XCTAssertEqual(Blueprint.Registry(operators: [pub], store: Blueprint.MemoryStore()).accept(nil), refused("bad_record"))
        XCTAssertEqual(Blueprint.Registry(operators: [pub], store: Blueprint.MemoryStore()).accept(signed(by: Self.op2)), refused("unknown_operator"))

        let both = Blueprint.Registry(operators: [pub, pub2], store: Blueprint.MemoryStore())
        XCTAssertEqual(both.accept(signed()), taken(replaced: true))
        XCTAssertEqual(both.accept(signed(by: Self.op2)), refused("operator_changed"))

        let reg = Blueprint.Registry(operators: [pub], store: Blueprint.MemoryStore())
        let current = signed(["epoch": .int(2)]) // the same bytes twice: CryptoKit's Ed25519 signatures are randomized
        XCTAssertEqual(reg.accept(current), taken(replaced: true))
        XCTAssertEqual(reg.accept(signed(["epoch": .int(1)])), refused("stale_epoch"))
        XCTAssertEqual(reg.accept(signed(["epoch": .int(2), "id": .string("bp2")])), refused("epoch_fork"))
        XCTAssertEqual(reg.accept(current), taken(replaced: false))
    }

    func testAnEmptyRegistryIsAtEpochZero() {
        let reg = Blueprint.Registry(operators: [], store: Blueprint.MemoryStore())
        XCTAssertEqual(reg.epoch, 0)
    }

    func testAStoredRecordWithoutAReadableEpochIsAtZero() {
        let reg = Blueprint.Registry(operators: [V2F.pub(Self.op)], store: Blueprint.MemoryStore())
        var stored = body()
        stored["epoch"] = nil
        try! reg.store.put(stored)
        XCTAssertEqual(reg.accept(signed(["epoch": .int(0)])), refused("epoch_fork"))
    }

    func testHopBounds() {
        let reg = Blueprint.Registry(operators: [], store: Blueprint.MemoryStore())
        func check(_ i: JSONValue, _ h: JSONValue) -> Blueprint.Decision {
            Blueprint.check(chain: .array([.object(["issuer": i, "holder": h])]), registry: reg, now: .int(1), mode: "any")
        }
        XCTAssertEqual(check(text(128), text(1)).decision, "allow")
        XCTAssertEqual(check(text(1), text(128)).decision, "allow")
        XCTAssertEqual(check(text(129), text(1)).code, "bad_input")
        XCTAssertEqual(check(text(1), text(129)).code, "bad_input")
    }

    func testADenialHasNoEpochs() {
        let d = Blueprint.check(chain: nil, registry: Blueprint.Registry(operators: [], store: Blueprint.MemoryStore()), now: .int(1), mode: "any")
        XCTAssertEqual(d.code, "bad_input")
        XCTAssertEqual(d.have, 0)
        XCTAssertEqual(d.need, 0)
    }

    func testAnUnreadableStoredExpiryOrDepthDenies() {
        let reg = Blueprint.Registry(operators: [], store: Blueprint.MemoryStore())
        try! reg.store.put(body(["expires_at": .string("x")]))
        XCTAssertEqual(Blueprint.check(chain: Self.CHAIN, registry: reg, now: .int(0), mode: "any").code, "blueprint_expired")
        try! reg.store.put(body(["max_depth": .string("x")]))
        XCTAssertEqual(Blueprint.check(chain: Self.CHAIN, registry: reg, now: .int(0), mode: "any").code, "too_deep")
    }
}
