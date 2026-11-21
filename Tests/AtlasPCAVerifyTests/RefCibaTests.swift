import XCTest
import Foundation
@testable import AtlasPCAVerify

/// Differential replay of PCACiba / PCACibaBroker against the reference (@atlasauth/pca-ciba): the canonical action, the ASCII
/// form, the auth request and binding message, the gate, the budget effect, the PING callback check and scripted broker
/// lifecycles (memory and durable over the memory store; the random auth_req_id is masked as "ID").
final class RefCibaTests: XCTestCase {
    static let file = "ref-ciba.json.gz"

    /// Replaces every occurrence of the flow's random id with "ID", as the generator does.
    static func mask(_ v: JSONValue, _ id: String?) -> JSONValue {
        switch v {
        case let .string(s) where id != nil && PCACiba.same(s, id!): return .string("ID")
        case let .array(a): return .array(a.map { mask($0, id) })
        case let .object(o): return .object(o.mapValues { mask($0, id) })
        default: return v
        }
    }

    static func lifecycle(_ kind: String, _ ops: [JSONValue]) throws -> JSONValue {
        var t: Double = 1_000_000
        let b = kind == "memory"
            ? PCACibaBroker.memory(now: { t }, onComplete: { _ in })
            : try PCACibaBroker.durable(store: CibaMemoryApprovalStore(), now: { t }, decisionTtlSec: 100)
        var id: String?
        var out: [JSONValue] = []
        for op in ops {
            let name = op.get("op")?.asString ?? ""
            if name == "now" { t = IV.num(op.get("t")) ?? t; out.append(.null); continue }
            do {
                var v: JSONValue
                switch name {
                case "start":
                    let r = try b.start(op.get("stepUp") ?? RefCibaTests.SU, Ref.obj(op.get("opts")))
                    id = r.get("auth_req_id")?.asString
                    v = r
                case "poll": v = .object(["status": .string(try b.poll(id ?? "").rawValue)])
                case "token": v = try b.token(id ?? "").json
                case "resolve":
                    guard let d = PCACibaBroker.Decision(rawValue: op.get("decision")?.asString ?? "") else { throw JSError("bad decision") }
                    v = try b.resolve(id ?? "", d, by: op.get("by")?.asString ?? "").json
                case "get": v = try b.get(id ?? "")?.json ?? .null
                case "unknown":
                    switch op.get("fn")?.asString {
                    case "poll": v = .string(try b.poll("nope").rawValue)
                    case "token": v = try b.token("nope").json
                    case "resolve": v = try b.resolve("nope", .approve, by: "x").json
                    default: v = try b.get("nope")?.json ?? .null
                    }
                default: throw JSError("unknown op")
                }
                out.append(.object(["ok": .bool(true), "value": mask(v, id)]))
            } catch {
                out.append(.object(["ok": .bool(false)]))
            }
        }
        return .array(out)
    }

    /// The generator's default step-up (used when an op carries none).
    static let SU: JSONValue = .object([
        "id": .string("su1"), "verb": .string("stripe.payout"), "resource": .string("acct:1"),
        "params": .object(["amount": .int(80), "currency": .string("USD"), "payee": .string("bob")]), "tier": .int(3), "reason": .string("r"),
        "goalCommit": .string("abcdefghijklmnopqrstuvwxyzabcdefghijklmnopq"), "goal": .string("pay suppliers"), "lineage": .object([:]),
        "r": .double(0.5), "requestedAt": .int(1),
    ])

    func testCiba() throws {
        AdaOptIn.register()
        try K042.requireCovers(["Ciba", "Approval"])
        let d = Base.Diffs()
        try Base.each(Self.file) { c in
            let a0 = c.arg(0), a1 = c.arg(1)
            let got: BaseGot
            switch c.fn {
            case "cibaActionFromStepUp":
                got = Ref.v { try PCACiba.cibaActionFromStepUp(a0 ?? .null) }
            case "asciiForm":
                got = .value(.string(PCACiba.asciiForm(a0?.asString ?? "")))
            case "toCibaAuthRequest":
                if let id = a1?.get("authReqId"), id != .null, id.asString == nil {
                    d.skip("toCibaAuthRequest: a non-string authReqId is refused natively (the reference lets a number through)"); return
                }
                got = Ref.v { try PCACiba.toCibaAuthRequest(a0 ?? .null, options: a1) }
            case "requiresCiba":
                got = .value(.bool(PCACiba.requiresCiba(a0 ?? .null)))
            case "cibaDecisionToCosign":
                guard let b = Risk.Budget(json: a1) else { d.skip("cibaDecisionToCosign: malformed budget"); return }
                let p = c.arg(2)
                let r = PCACiba.cibaDecisionToCosign(approve: a0 == .string("approve"), budget: b, bMax: IV.num(p?.get("bMax")) ?? .nan,
                                                     rho: IV.num(p?.get("rho")) ?? .nan, now: IV.num(c.arg(3)) ?? .nan,
                                                     full: JS.truthy(c.arg(4)?.get("full")))
                got = .value(.object(["budget": r.cosigned ? r.budget.json : (a1 ?? .null), "cosigned": .bool(r.cosigned)]))
            case "verifyPingCallback":
                got = Ref.s {
                    try PCACiba.verifyPingCallback(authorization: a0?.get("authorization")?.asString, body: a0?.get("body"),
                                                   authReqId: a1?.get("authReqId")?.asString ?? "",
                                                   clientNotificationToken: a1?.get("clientNotificationToken")?.asString,
                                                   clientNotificationTokenIsNull: a1?.get("clientNotificationToken") == .null)
                }
            case "lifecycle":
                got = Ref.v { try Self.lifecycle(a0?.asString ?? "", a1?.asArray ?? []) }
            default:
                d.skip("fn \(c.fn) not replayed"); return
            }
            d.add(c, Base.diff(c, got))
        }
        d.finish(190)
    }

    /// The pure surface against the second (larger, variant-heavy) reference corpus.
    func testCibaVariantCorpus() throws {
        AdaOptIn.register()
        try K042.requireCovers(["Ciba", "Approval"])
        let d = Base.Diffs()
        try Base.each("ref-ciba-java.json.gz", ["cibaActionFromStepUp", "asciiForm", "toCibaAuthRequest", "requiresCiba", "cibaDecisionToCosign", "verifyPingCallback"]) { c in
            let a0 = c.arg(0), a1 = c.arg(1)
            let got: BaseGot
            switch c.fn {
            case "cibaActionFromStepUp":
                got = Ref.v { try PCACiba.cibaActionFromStepUp(a0 ?? .null) }
            case "asciiForm":
                guard let s = a0?.asString else { d.skip("asciiForm: non-string input is a Swift type error"); return }
                got = .value(.string(PCACiba.asciiForm(s)))
            case "toCibaAuthRequest":
                if let id = a1?.get("authReqId"), id != .null, id.asString == nil {
                    d.skip("toCibaAuthRequest: a non-string authReqId is refused natively (the reference lets a number through)"); return
                }
                if let o = a1, o != .null, o.asObject == nil { d.skip("toCibaAuthRequest: non-object options are a Swift type error"); return }
                got = Ref.v { try PCACiba.toCibaAuthRequest(a0 ?? .null, options: a1) }
            case "requiresCiba":
                // the reference throws a TypeError reading a member of null; the typed Swift gate answers false (no CIBA round trip)
                // the engine-crash rule: the native must refuse, and a gate that answers false is the refusal (no CIBA round trip)
                if c.engineCrash { d.add(c, PCACiba.requiresCiba(a0 ?? .null) ? "\(c.name): want a refusal, the gate asked for CIBA" : nil); return }
                if c.threw { d.skip("requiresCiba: a reference throw that is no engine failure"); return }
                got = .value(.bool(PCACiba.requiresCiba(a0 ?? .null)))
            case "cibaDecisionToCosign":
                guard let b = Risk.Budget(json: a1) else { d.skip("cibaDecisionToCosign: malformed budget"); return }
                let p = c.arg(2)
                let r = PCACiba.cibaDecisionToCosign(approve: a0 == .string("approve"), budget: b, bMax: IV.num(p?.get("bMax")) ?? .nan,
                                                     rho: IV.num(p?.get("rho")) ?? .nan, now: IV.num(c.arg(3)) ?? .nan,
                                                     full: JS.truthy(c.arg(4)?.get("full")))
                got = .value(.object(["budget": r.cosigned ? r.budget.json : (a1 ?? .null), "cosigned": .bool(r.cosigned)]))
            default:
                guard a0?.get("authorization").map({ $0.asString != nil || $0 == .null }) ?? true else {
                    d.skip("verifyPingCallback: a non-string Authorization header is a Swift type error"); return
                }
                got = Ref.s {
                    try PCACiba.verifyPingCallback(authorization: a0?.get("authorization")?.asString, body: a0?.get("body"),
                                                   authReqId: a1?.get("authReqId")?.asString ?? "",
                                                   clientNotificationToken: a1?.get("clientNotificationToken")?.asString,
                                                   clientNotificationTokenIsNull: a1?.get("clientNotificationToken") == .null)
                }
            }
            d.add(c, Base.diff(c, got))
        }
        d.finish(700)
    }

    /// The durable broker over the KV store and the file stores keeps the same lifecycle (decision recorded once, single use).
    func testStoresLifecycle() throws {
        let dir = NSTemporaryDirectory() + "ciba-\(UUID().uuidString)"
        defer { try? FileManager.default.removeItem(atPath: dir) }
        let stores: [CibaApprovalStore] = [
            CibaKvApprovalStore(kv: CibaMemoryKv()),
            CibaKvApprovalStore(kv: try CibaDirectoryKv(dir: dir + "/kv")),
            CibaFileApprovalStore(path: dir + "-file.json"),
        ]
        defer { try? FileManager.default.removeItem(atPath: dir + "-file.json") }
        for store in stores {
            var t: Double = 1_000_000
            var pinged = 0
            let b = try PCACibaBroker.durable(store: store, now: { t }, onComplete: { _ in pinged += 1 })
            let req = try b.start(Self.SU)
            let id = try XCTUnwrap(req.get("auth_req_id")?.asString)
            XCTAssertGreaterThanOrEqual(id.count, 22)
            XCTAssertEqual(try b.start(Self.SU).get("auth_req_id")?.asString, id, "a live flow is re-served")
            XCTAssertEqual(try b.poll(id), .pending)
            _ = try b.resolve(id, .approve, by: "owner")
            XCTAssertThrowsError(try b.resolve(id, .deny, by: "owner"))
            XCTAssertEqual(pinged, 1)
            t += 10_000
            guard case .ok = try b.token(id) else { return XCTFail("approval must redeem once") }
            guard case .error("invalid_grant", _) = try b.token(id) else { return XCTFail("a replay must be refused") }
            XCTAssertNotEqual(try b.start(Self.SU).get("auth_req_id")?.asString, id, "a consumed approval is never re-served")
        }
        XCTAssertThrowsError(try PCACibaBroker.durable(store: CibaMemoryApprovalStore(), decisionTtlSec: 0))
        XCTAssertThrowsError(try PCACibaBroker.memory().resolve("x", .approve, by: ""))
    }

    /// A corrupt stored record is refused, never read as "no approval yet".
    func testCorruptRecordRefused() throws {
        let kv = CibaMemoryKv()
        _ = try kv.putIfEquals("a:x", nil, "{\"version\":0,\"value\":1}")
        let store = CibaKvApprovalStore(kv: kv)
        XCTAssertThrowsError(try store.get("a:x"))
        XCTAssertThrowsError(try PCACibaBroker.durable(store: store).token("x"))
    }
}
