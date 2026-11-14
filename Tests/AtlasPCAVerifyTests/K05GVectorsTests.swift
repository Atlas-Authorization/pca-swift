import XCTest
import Foundation
@testable import AtlasPCAVerify

/// Every row of the shared prohibition and contract vectors (packages/pca/conformance/prohibition-vectors.json, contracts-vectors.json):
/// clauses, check, constitution, monitor, evidence; validate, check, advance, verify, enforcer. Results are compared by canonical form.
final class K05GVectorsTests: XCTestCase {
    static func same(_ a: JSONValue?, _ b: JSONValue?) -> Bool {
        guard let x = a, let y = b else { return a == nil && b == nil }
        return Canonical.canonicalize(x) == Canonical.canonicalize(y)
    }

    func strs(_ v: JSONValue?) -> [String]? { v?.asArray?.compactMap { $0.asString } }

    func testProhibitionClauses() throws {
        let rows = try XCTUnwrap(ConformanceTests.load("prohibition-vectors.json").get("clauses")?.asArray)
        XCTAssertEqual(rows.count, 20)
        for v in rows {
            let n = v.get("name")?.asString ?? "?"
            let o = v.get("options")
            let d = ForbidClauses.decideClauses(v.get("clauses"), v.get("action"), precedence: strs(o?.get("precedence")) ?? [], permitSigners: strs(o?.get("permitSigners")))
            let e = try XCTUnwrap(v.get("expect"))
            let err = ForbidClauses.clausesError(v.get("clauses"))
            XCTAssertEqual(err, e.get("error")?.asString, n)
            XCTAssertEqual(d.decision, e.get("decision")?.asString, n)
            XCTAssertTrue(Self.same(d.json.get("winner"), e.get("winner")), n)
            XCTAssertTrue(Self.same(d.json.get("shadowed"), e.get("shadowed")), n)
            XCTAssertTrue(Self.same(d.json.get("values"), e.get("values")), n)
        }
    }

    func testProhibitionCheck() throws {
        let rows = try XCTUnwrap(ConformanceTests.load("prohibition-vectors.json").get("check")?.asArray)
        XCTAssertEqual(rows.count, 11)
        for v in rows {
            let n = v.get("name")?.asString ?? "?"
            let o = v.get("options")
            let prec = strs(o?.get("precedence")) ?? []
            let signers = strs(o?.get("permitSigners"))
            let r = ForbidClauses.checkForbidCertificate(v.get("certificate"), v.get("clauses"), v.get("action"), precedence: prec, permitSigners: signers)
            XCTAssertTrue(Self.same(r.json, v.get("expect")), "\(n): \(r.json.canonicalText)")
            if v.get("expect")?.get("ok") == .bool(true) {
                let c = try ForbidClauses.certify(v.get("clauses"), v.get("action"), precedence: prec, permitSigners: signers)
                XCTAssertTrue(Self.same(c, v.get("certificate")), n)
            }
        }
    }

    func testProhibitionConstitution() throws {
        let rows = try XCTUnwrap(ConformanceTests.load("prohibition-vectors.json").get("constitution")?.asArray)
        XCTAssertEqual(rows.count, 33)
        for v in rows {
            let n = v.get("name")?.asString ?? "?"
            XCTAssertEqual(Prohibitions.validateConstitution(v.get("constitution")), strs(v.get("expect")?.get("problems")), n)
            let r = Prohibitions.checkProhibitions(v.get("action"), v.get("constitution"), v.get("state"))
            XCTAssertTrue(Self.same(r.json, v.get("expect")?.get("result")), "\(n): \(r.json.canonicalText)")
        }
    }

    func testProhibitionMonitor() throws {
        let rows = try XCTUnwrap(ConformanceTests.load("prohibition-vectors.json").get("monitor")?.asArray)
        XCTAssertEqual(rows.count, 5)
        for v in rows {
            let n = v.get("name")?.asString ?? "?"
            var st = Prohibitions.emptyState(IV.num(v.get("genesis_now")) ?? 0)
            for (i, step) in (v.get("steps")?.asArray ?? []).enumerated() {
                var cur = st
                if let now = IV.num(step.get("now")) {
                    let t = Prohibitions.tickState(st, now: now)
                    if !t.ok {
                        let want: JSONValue = .object(["allow": .bool(false), "decidedBy": .string("clock"), "reason": .string(t.reason ?? "")])
                        XCTAssertTrue(Self.same(want, step.get("expect")), "\(n) step \(i)")
                        continue
                    }
                    cur = t.state ?? cur
                }
                let r = Prohibitions.checkAndAdvance(permitted: true, step.get("action"), v.get("constitution"), cur)
                st = r.allow ? r.next : cur
                let got: JSONValue = .object(["allow": .bool(r.allow), "decidedBy": .string(r.decidedBy), "violated": PD.strs(r.prohibition.violated), "seq": r.next.get("seq") ?? .null])
                XCTAssertTrue(Self.same(got, step.get("expect")), "\(n) step \(i): \(got.canonicalText)")
            }
        }
    }

    func testEvidence() throws {
        let rows = try XCTUnwrap(ConformanceTests.load("prohibition-vectors.json").get("evidence")?.asArray)
        XCTAssertEqual(rows.count, 13)
        for v in rows {
            let n = v.get("name")?.asString ?? "?"
            let r = Prohibitions.verifySignedSafetyEvidence(v.get("signed"), v.get("expected"))
            XCTAssertTrue(Self.same(r.json, v.get("expect")), "\(n): \(r.json.canonicalText)")
        }
    }

    func testContractValidateCheckVerify() throws {
        let doc = try ConformanceTests.load("contracts-vectors.json")
        let validate = try XCTUnwrap(doc.get("validate")?.asArray)
        XCTAssertEqual(validate.count, 21)
        for v in validate { XCTAssertEqual(Contracts.validateContract(v.get("contract")), strs(v.get("expect")?.get("problems")), v.get("name")?.asString ?? "?") }
        let check = try XCTUnwrap(doc.get("check")?.asArray)
        XCTAssertEqual(check.count, 11)
        for v in check {
            let r = Contracts.checkContract(v.get("action"), v.get("contract"), v.get("state"))
            XCTAssertTrue(Self.same(r.json, v.get("expect")), "\(v.get("name")?.asString ?? "?"): \(r.json.canonicalText)")
        }
        let verify = try XCTUnwrap(doc.get("verify")?.asArray)
        XCTAssertEqual(verify.count, 7)
        for v in verify {
            let r = Contracts.verifyContract(v.get("contract"), expectedPrincipal: v.get("principal")?.asString)
            XCTAssertTrue(Self.same(r.json, v.get("expect")), "\(v.get("name")?.asString ?? "?"): \(r.json.canonicalText)")
        }
    }

    func testContractAdvance() throws {
        let rows = try XCTUnwrap(ConformanceTests.load("contracts-vectors.json").get("advance")?.asArray)
        XCTAssertEqual(rows.count, 7)
        for v in rows {
            let n = v.get("name")?.asString ?? "?"
            let genesis = IV.num(v.get("genesis_now")) ?? 0
            var st = Prohibitions.emptyState(genesis)
            for (i, step) in (v.get("steps")?.asArray ?? []).enumerated() {
                let op = step.get("options")
                var expectedDigest: String?
                if op?.get("stale_digest_of_genesis") == .bool(true) { expectedDigest = try Prohibitions.stateDigest(Prohibitions.emptyState(genesis)) }
                let r = Contracts.advanceContract(st, step.get("action"), v.get("contract"), now: IV.num(op?.get("now")),
                                                  expectedSeq: IV.num(op?.get("expectedSeq")), expectedStateDigest: expectedDigest)
                if r.ok { st = r.next }
                let latched = (r.next.get("latched")?.asObject?.keys.map { $0.s } ?? []).sorted()
                let got: JSONValue = .object([
                    "ok": .bool(r.ok), "decidedBy": .string(r.decidedBy), "violated": PD.strs(r.violated), "reasons": PD.strs(r.reasons), "seq": r.next.get("seq") ?? .null,
                    "deadlines": r.next.get("deadlines") ?? .object([:]), "latched": PD.strs(latched), "state_digest": .string(try Prohibitions.stateDigest(r.next)),
                ])
                XCTAssertTrue(Self.same(got, step.get("expect")), "\(n) step \(i): \(got.canonicalText)")
            }
        }
    }

    final class Clock { var t: Double; init(_ t: Double) { self.t = t } }

    func testContractEnforcer() throws {
        let rows = try XCTUnwrap(ConformanceTests.load("contracts-vectors.json").get("enforcer")?.asArray)
        XCTAssertEqual(rows.count, 9)
        let head = rows[0]
        let contract = try XCTUnwrap(head.get("contract"))
        let clock0 = IV.num(head.get("clock")) ?? 0
        for v in rows.dropFirst() {
            let n = v.get("name")?.asString ?? "?"
            let kv = MemoryAtomicKV()
            let wall = Clock(clock0)
            let e = try ContractEnforcer.open(kv: kv, contract: contract, principal: head.get("principal")?.asString ?? "", now: { wall.t },
                                              latchOnViolation: v.get("options")?.get("latchOnViolation") != .bool(false))
            if let doc = v.get("stored_document") { kv.update("contract/" + (contract.get("id")?.asString ?? "")) { _ in doc } }
            for (i, st) in (v.get("steps")?.asArray ?? []).enumerated() {
                let label = "\(n) step \(i)"
                let got: JSONValue
                switch st.get("op")?.asString {
                case "check":
                    wall.t = IV.num(st.get("wall")) ?? clock0
                    got = e.check(st.get("action"), permitted: st.get("permitted") != .bool(false)).json
                case "peek":
                    got = e.peek(st.get("action")).json
                case "state":
                    if let r = try e.state() {
                        got = .object(["seq": r.state.get("seq") ?? .null, "now": r.state.get("now") ?? .null, "latched": .bool(r.latched), "state_digest": .string(try Prohibitions.stateDigest(r.state))])
                    } else { got = .null }
                default:
                    got = .object(["cleared": .bool(e.reset(st.get("sig")?.asString ?? ""))])
                }
                XCTAssertTrue(Self.same(got, st.get("expect")), "\(label): \(got.canonicalText)")
            }
        }
    }
}
