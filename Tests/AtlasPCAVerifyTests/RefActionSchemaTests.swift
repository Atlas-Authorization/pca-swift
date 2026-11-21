import XCTest
import Foundation
@testable import AtlasPCAVerify
#if canImport(AtlasPCAOpenSSL)
import AtlasPCAOpenSSL
#endif

/// The action schema's vocabulary, signing, key, digest and verification, the value-dependent reversibility, the wallet floor, the verb lookup and the drafting
/// importers (MCP tool lists, OpenAPI documents) against the reference corpora ref-action-schema and ref-action-schema-draft: every case, every fn. A
/// verification reason that carries the reference's exception text (`schema verification error:`, the `malformed schema:` suffix) is compared by prefix.
/// Signing under ML-DSA is compared byte for byte when the opt-in OpenSSL product is linked.
final class RefActionSchemaTests: XCTestCase {
    typealias S = PCAActionSchema
    typealias A = RefAnalyzer

    private static func mlDsa(_ seed: [UInt8]) throws -> PCAPQKey {
        #if canImport(AtlasPCAOpenSSL)
        if PCAOpenSSL.mlDsaAvailable() { return try PCAOpenSSL.mlDsaKey(.mlDsa65, seed: seed) }
        #endif
        return try PCAPQKey.fromSeed(.mlDsa65, seed: seed)
    }
    private static var exactMlDsa: Bool {
        #if canImport(AtlasPCAOpenSSL)
        return PCAOpenSSL.mlDsaAvailable()
        #else
        return false
        #endif
    }

    private static func key(_ secret: JSONValue?, _ suite: JSONValue?) throws -> PCASuiteKey {
        guard let s = Base.bytes(secret) else { throw PCAProducerError("secret") }
        let ed = try Ed25519Deterministic.key(seed: s)
        var key = PCASuiteKey.ed25519(ed)
        if let su = JS.present(suite) {
            guard let alg = IV.sigAlg(su.get("alg")) else { throw PCAProducerError("alg") }
            key = try PCASuiteKey(alg: alg, ed: ed, pq: try Base.bytes(su.get("pqSeed")).map { try mlDsa($0) })
        }
        return key
    }

    private static func strs(_ a: [String]) -> JSONValue { .array(a.map { .string($0) }) }
    private static func re(_ s: String) -> JSONValue { .object(["$regex": .string(s)]) }

    static func call(_ c: BaseCase) -> BaseGot? {
        let a0 = A.arg(c, 0), a1 = A.arg(c, 1), a2 = A.arg(c, 2), a3 = A.arg(c, 3)
        switch c.fn {
        case "constants":
            return .value(.object([
                "ACTION_SCHEMA_DOMAIN": .string(S.ACTION_SCHEMA_DOMAIN), "ACTION_SCHEMA_KIND": .string(S.ACTION_SCHEMA_KIND), "ACTION_SCHEMA_REF_DOMAIN": .string(S.ACTION_SCHEMA_REF_DOMAIN),
                "DEFAULT_MAX_ITEMS": .int(S.DEFAULT_MAX_ITEMS), "DEFAULT_MAX_LEN": .int(S.DEFAULT_MAX_LEN), "MAX_SCHEMA_PARAMS": .int(Int64(S.MAX_SCHEMA_PARAMS)),
                "MAX_SCHEMA_VALUES": .int(Int64(S.MAX_SCHEMA_VALUES)), "MAX_SCHEMA_VERBS": .int(Int64(S.MAX_SCHEMA_VERBS)), "PARAM_PATH_RE": re(S.PARAM_PATH_RE),
                "PARAM_PATH_RE_V2": re(S.PARAM_PATH_RE_V2), "PARAM_TYPES": strs(S.PARAM_TYPES), "PARAM_TYPES_V2": strs(S.PARAM_TYPES_V2), "SCHEMA_REVERSIBILITY": strs(S.SCHEMA_REVERSIBILITY),
                "SCHEMA_V2_CAVEATS": strs(S.SCHEMA_V2_CAVEATS), "SCHEMA_V2_CONTEXT": strs(S.SCHEMA_V2_CONTEXT), "SCHEMA_V2_EFFECTS": strs(S.SCHEMA_V2_EFFECTS),
                "SCHEMA_V2_PROVENANCE": strs(S.SCHEMA_V2_PROVENANCE), "SCHEMA_V2_PRULES": strs(S.SCHEMA_V2_PRULES), "SCHEMA_V2_TAGS": strs(S.SCHEMA_V2_TAGS), "SENSITIVITIES": strs(S.SENSITIVITIES),
                "UNIT_ID_RE": re(S.UNIT_ID_RE), "WALLET_FLOOR_EXACT": strs(S.WALLET_FLOOR_EXACT), "WALLET_FLOOR_PREFIXES": strs(S.WALLET_FLOOR_PREFIXES),
                "WELL_KNOWN_PCA_ACTIONS_PATH": .string(S.WELL_KNOWN_PCA_ACTIONS_PATH)]))
        case "reversibilityOf": return .value(.string(PCA.reversibilityOf(a0 ?? .null, a1)))
        case "floorApplies": return .value(.bool(S.floorApplies(a0?.asString ?? "", JS.present(a1))))
        case "schemaVerb": return .value(S.schemaVerb(a0 ?? .null, a1?.asString ?? "") ?? .null)
        case "signActionSchema": return A.run { try PCASigners.signActionSchema(a0 ?? .null, kid: a1?.asString ?? "", site: try key(a2, a3)) }
        case "actionSchemaKeyOf": return A.run { try PCASigners.actionSchemaKeyOf(kid: a0?.asString ?? "", site: try key(a1, a2)) }
        case "actionSchemaDigest": return A.run { guard let d = ActionSchema.digest(a0 ?? .null) else { throw JSError("canonicalize") }; return .string(d) }
        case "verifyActionSchema":
            let r = ActionSchema.verify(a0 ?? .null, keys: a1)
            return .value(r.ok ? .object(["ok": .bool(true)]) : .object(["ok": .bool(false), "reason": .string(r.reason)]))
        case "reversibilityFromMcpHints":
            let h = S.reversibilityFromMcpHints(JS.present(a0))
            return .value(.object(["kind": .string(h.kind), "atLeast": .string(h.atLeast)]))
        case "draftSchemaFromMcpTools": return A.run { try S.draftSchemaFromMcpTools(a0 ?? .null, a1 ?? .null) }
        case "draftSchemaFromOpenApi": return A.run { try S.draftSchemaFromOpenApi(a0 ?? .null, a1 ?? .null) }
        default: return nil
        }
    }

    private static func cut(_ v: JSONValue) -> JSONValue {
        guard case var .object(o) = v, let r = o["reason"]?.asString else { return v }
        for p in ["schema verification error:", "malformed schema:"] where r.hasPrefix(p) { o["reason"] = .string(p) }
        return .object(o)
    }

    private static func signed(_ c: BaseCase, _ got: BaseGot) -> BaseGot {
        guard c.fn == "signActionSchema", !exactMlDsa, !c.threw, case let .value(v) = got, case var .object(mine) = v, case var .object(want) = c.out,
              case var .object(ms)? = mine["sig"], case var .object(ws)? = want["sig"], let alg = ws["alg"]?.asString, alg != "ed25519" else { return got }
        let field = JKey(alg.hasPrefix("hybrid") ? "pq_value" : "value")
        ms[field] = nil
        ws[field] = nil
        mine["sig"] = .object(ms)
        want["sig"] = .object(ws)
        return Base.canon(.object(mine)) == Base.canon(.object(want)) ? .value(c.out) : got
    }

    private func replay(_ file: String, _ total: Int, _ fns: [String: Int]) throws {
        let d = Base.Diffs()
        var seen: [String: Int] = [:]
        let n = try Base.each(file, seeds: true) { c in
            seen[c.fn, default: 0] += 1
            guard let got = Self.call(c) else { XCTFail("unhandled fn \(c.fn)"); return }
            var g = Self.signed(c, got)
            if c.fn == "verifyActionSchema", case let .value(v) = g, !c.threw {
                let (x, y) = (Self.cut(v), Self.cut(c.out))
                d.add(c, Base.canon(x) == Base.canon(y) ? nil : Base.diff(c, .value(x)))
                return
            }
            if !MLDSA.available, Base.diff(c, g) != nil, Base.canon(.array(c.args)).contains("ml-dsa") { d.skip("ML-DSA is not available on this OS"); return }
            if case .threw = got { g = got }
            d.add(c, Base.diff(c, g))
        }
        XCTAssertEqual(n, total)
        XCTAssertEqual(seen, fns)
        d.finish(total - d.skipped.values.reduce(0, +))
    }

    func testEveryCaseOfTheActionSchemaCorpus() throws {
        try replay("ref-action-schema.json.gz", 173, ["draftSchemaFromOpenApi": 32, "draftSchemaFromMcpTools": 31, "verifyActionSchema": 30, "reversibilityOf": 20, "floorApplies": 19,
                                                       "signActionSchema": 12, "schemaVerb": 9, "reversibilityFromMcpHints": 9, "actionSchemaKeyOf": 6, "actionSchemaDigest": 4, "constants": 1])
    }

    func testEveryCaseOfTheDraftCorpus() throws {
        try replay("ref-action-schema-draft.json.gz", 104, ["reversibilityOf": 72, "draftSchemaFromOpenApi": 16, "reversibilityFromMcpHints": 9, "schemaVerb": 7])
    }
}
