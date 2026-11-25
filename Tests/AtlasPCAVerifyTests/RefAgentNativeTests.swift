import XCTest
import Foundation
@testable import AtlasPCAVerify

/// Differential replay of the agent-native primitives (caution claims, rationale binding, the tool-schema firewall, capability introspection, leases)
/// against the TypeScript reference (test-data/ref-agent-native.json.gz, 1632 cases). Keys are seed labels (`{"$bytes": {"$seed": label}}`, resolved to the
/// bytes of sha256("atlas-pca-conformance/" + label)); the claims and heartbeats the corpus feeds to the verifiers carry real signatures, and describeEnvelope
/// chains are checked with the package's own chain verifier. `{"$num": ...}` is a non-finite number. A reference throw requires a refusal; every other result
/// compares as canonical JSON. A case whose fn has no entry here fails.
final class RefAgentNativeTests: XCTestCase {
    private static func revive(_ v: JSONValue) -> JSONValue {
        switch v {
        case let .array(a): return .array(a.map(revive))
        case let .object(o):
            if o.count == 1, let t = o["$num"]?.asString { return .double(t == "Infinity" ? .infinity : t == "-Infinity" ? -.infinity : .nan) }
            return .object(o.mapValues(revive))
        default: return v
        }
    }

    private static func isNum(_ v: JSONValue?) -> Bool { v?.isNumber ?? false }
    private static func numish(_ v: JSONValue?) -> Double {
        switch v {
        case let .int(i)?: return Double(i)
        case let .double(d)?: return d
        default: return .nan
        }
    }
    private static func json(_ d: Double) -> JSONValue { d == d.rounded() && abs(d) < 9e15 ? .int(Int64(d)) : .double(d) }
    private static func firewall(_ r: (ok: Bool, reason: String?)) -> JSONValue {
        r.ok ? .object(["ok": .bool(true)]) : .object(["ok": .bool(false), "reason": r.reason.map { .string($0) } ?? .null])
    }
    private static func judge(_ spec: String) -> (String, JSONValue) throws -> Bool {
        return { rationale, action in
            if spec == "true" { return true }
            if spec == "false" || spec == "truthy" { return false } // "truthy" returns the string "yes", which is not === true
            if spec == "throw" { throw PCAProducerError("judge threw") }
            if spec.hasPrefix("contains:") { return rationale.contains(String(spec.dropFirst("contains:".count))) }
            if spec.hasPrefix("action-verb:") { return action.get("verb")?.asString == String(spec.dropFirst("action-verb:".count)) }
            throw PCAProducerError("unknown judge spec \(spec)")
        }
    }

    private static func constants() -> JSONValue {
        let A = AgentNative.self
        func i(_ n: Int) -> JSONValue { .int(Int64(n)) }
        return .object([
            "CAVEAT_ENVELOPE": .string(A.CAVEAT_ENVELOPE), "CAVEAT_EXPIRES": .string(A.CAVEAT_EXPIRES), "CAVEAT_NOT_BEFORE": .string(A.CAVEAT_NOT_BEFORE),
            "CAVEAT_RATE": .string(A.CAVEAT_RATE), "CAVEAT_MAX_BLAST_RADIUS": .string(A.CAVEAT_MAX_BLAST_RADIUS), "CAVEAT_REVERSIBILITY_MAX": .string(A.CAVEAT_REVERSIBILITY_MAX),
            "CAVEAT_DELEGATION_DEPTH": .string(A.CAVEAT_DELEGATION_DEPTH), "CAVEAT_PREDICATES": .string(A.CAVEAT_PREDICATES), "CAVEAT_TOOL_SCHEMA": .string(A.CAVEAT_TOOL_SCHEMA),
            "CAVEAT_MAX_SPEND": .string(A.CAVEAT_MAX_SPEND), "MAX_CAUTION_REASON_LEN": i(A.MAX_CAUTION_REASON_LEN), "MIN_SALT_BYTES": i(A.MIN_SALT_BYTES),
            "MIN_SALT_DISTINCT_BYTES": i(A.MIN_SALT_DISTINCT_BYTES), "MAX_RATIONALE_LEN": i(A.MAX_RATIONALE_LEN), "MAX_SCHEMA_DEPTH": i(A.MAX_SCHEMA_DEPTH),
            "MAX_SCHEMA_NODES": i(A.MAX_SCHEMA_NODES), "MAX_OBJECT_PROPS": i(A.MAX_OBJECT_PROPS), "MAX_ENUM_VALUES": i(A.MAX_ENUM_VALUES),
            "DEFAULT_MAX_ARRAY_ITEMS": i(A.DEFAULT_MAX_ARRAY_ITEMS), "ABSOLUTE_MAX_ARRAY_ITEMS": i(A.ABSOLUTE_MAX_ARRAY_ITEMS), "DEFAULT_MAX_STRING_LEN": i(A.DEFAULT_MAX_STRING_LEN),
            "ABSOLUTE_MAX_STRING_LEN": i(A.ABSOLUTE_MAX_STRING_LEN), "MAX_VALUE_NODES": i(A.MAX_VALUE_NODES), "HEARTBEAT_SKEW_MS": i(A.HEARTBEAT_SKEW_MS), "MAX_LEASE_TTL_MS": i(A.MAX_LEASE_TTL_MS),
        ])
    }

    func testAgentNativeCorpus() throws {
        try K042.requireCovers(["AgentNative", "ToolSchema"])
        let d = Base.Diffs()
        let n = try Base.each("ref-agent-native.json.gz", seeds: true) { c in
            let a = c.args.map(Self.revive)
            func arg(_ i: Int) -> JSONValue? { i < a.count ? a[i] : nil }
            func opt(_ i: Int) -> JSONValue? { i < a.count && a[i] != .null ? a[i] : nil }
            func key() throws -> PCAEdKey {
                guard let b = Base.bytes(arg(1)) else { throw PCAProducerError("no secret key") }
                return try PCAEdKey(seed: b)
            }
            let got: BaseGot
            switch c.fn {
            case "constants": got = .value(Self.constants())
            case "signCaution": got = Base.run { try PCASigners.signCaution(arg(0) ?? .null, holder: try key()) }
            case "signHeartbeat": got = Base.run { try PCASigners.signHeartbeat(arg(0) ?? .null, holder: try key()) }
            case "verifyCaution":
                // a given expectation that is not a string can never equal the claim's string member
                if let x = opt(1), x.asString == nil { got = .value(.bool(false)); break }
                if let x = opt(2), x.asString == nil { got = .value(.bool(false)); break }
                got = .value(.bool(AgentNative.verifyCaution(arg(0), opt(1)?.asString, opt(2)?.asString)))
            case "combineCaution": got = .value(Self.json(AgentNative.combineCaution(Self.isNum(arg(0)) ? Self.numish(arg(0)) : nil, Self.numish(arg(1)))))
            case "combineSignedCaution": got = .value(AgentNative.combineSignedCaution(opt(0), arg(1)?.asString ?? "", Self.numish(arg(2)), opt(3)?.asString))
            case "checkCautionMonotone": got = .value(AgentNative.checkCautionMonotone((arg(0)?.asArray ?? []).filter { Self.isNum($0) }.map { Self.numish($0) }))
            case "isStrongSalt": got = .value(.bool(AgentNative.isStrongSalt(arg(0))))
            case "bindRationale":
                got = Base.run {
                    guard let text = arg(1)?.asString else { throw PCAProducerError("rationale must be a string") }
                    return try AgentNative.bindRationale(arg(0) ?? .null, text, salt: arg(2)?.asString ?? "") // a salt that is not a string is below the floor
                }
            case "verifyRationale":
                got = .value(.bool(c.args.count > 2 ? AgentNative.verifyRationale(arg(0), arg(1), action: arg(2)) : AgentNative.verifyRationale(arg(0), arg(1))))
            case "auditRationale": got = .value(AgentNative.auditRationale(arg(0), arg(1) ?? .null, reveal: opt(2), judge: Self.judge(arg(3)?.asString ?? "")))
            case "validateArgSchema": got = .value(ToolSchema.validateArgSchema(arg(0)).map { .string($0) } ?? .null)
            case "toolSchemaCaveat": got = Base.run { try AgentNative.toolSchemaCaveat(arg(0) ?? .null, arg(1) ?? .null) }
            case "evaluateToolSchema": got = .value(Self.firewall(AgentNative.evaluateToolSchemaCall(arg(0), arg(1))))
            case "toolSchemaEvaluator": got = .value(.bool(AgentNative.toolSchemaEvaluator(arg(0), arg(1))))
            case "predicatesCaveat": got = Base.run { try AgentNative.predicatesCaveat(arg(0) ?? .null) }
            case "actionSpendUsd": got = .value(AgentNative.actionSpendUsd(arg(0)).map { Self.json($0) } ?? .null)
            case "agentNativeCaveatEvaluator": got = .value(.bool(AgentNative.agentNativeCaveatEvaluator(arg(0), arg(1))))
            case "describeEnvelope":
                got = .value(AgentNative.describeEnvelope(arg(0), now: Self.isNum(arg(1)) ? Self.numish(arg(1)) : nil, expectedRootIssuer: arg(2)?.asString, policy: opt(3)))
            case "envelopePermits":
                got = .value(.bool(AgentNative.envelopePermits(arg(0), verb: arg(1)?.asString ?? "", resource: arg(2)?.asString ?? "", now: opt(3).map { Self.numish($0) }, params: opt(4))))
            case "envelopePermitsToolCall": got = .value(Self.firewall(AgentNative.envelopePermitsToolCall(arg(0), arg(1))))
            case "grantLease": got = Base.run { try AgentNative.grantLease(arg(0)) }
            case "leaseState": got = .value(AgentNative.leaseState(arg(0), Self.numish(arg(1))))
            case "renewLease": got = .value(AgentNative.renewCapabilityLease(arg(0), arg(1), Self.numish(arg(2))))
            default:
                d.add(c, "\(c.name): no Swift entry point for \(c.fn)")
                return
            }
            d.add(c, Base.diff(c, got))
        }
        XCTAssertEqual(n, 1632)
        d.finish(1500)
    }
}
