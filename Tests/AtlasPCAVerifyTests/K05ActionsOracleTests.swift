import XCTest
import Foundation
@testable import AtlasPCAVerify

/// Differential test of Actions.swift against the TS reference (pca-actions: validate, idpattern, traits, normalize, digest,
/// effective, confirmation, rule 22, pack): test-data/k05-actions.json.gz (65203 cases). A reference throw requires a native
/// ActionKitError (same code when the case carries one); cmp = "code" compares only the `<code>:` prefix (the reference's own
/// exception text follows it). An argument the typed Swift API cannot take (a non-object verb, a non-array registry, a non-string
/// context key) must be one the reference refuses too. Cases where the reference accepts a -0 the Swift side refuses are skipped:
/// TS Number.isSafeInteger takes -0 in a few checks while the strict JSON profile refuses it everywhere else (Swift stays
/// fail-closed; reported as a reference inconsistency).
final class K05ActionsOracleTests: XCTestCase {
    static let file = "k05-actions.json.gz"
    static let covers = ["Actions", "ActionSchema", "Merkle", "IntentValues", "StrictJSON", "Canonical", "Base64URLStrict", "Ed25519Strict", "JSONValue"]

    static func code(_ e: Error) -> String? { (e as? ActionKitError)?.code }
    static func reg(_ custom: JSONValue?) throws -> TraitRegistry {
        guard let c = custom, c != .null else { return Actions.coreRegistry }
        guard case let .array(a) = c else { throw ActionKitError(code: "bad_registry", message: "not an array") }
        return try Actions.extendRegistry(Actions.coreRegistry, a)
    }
    static func strs(_ xs: [String]) -> JSONValue { .array(xs.map { .string($0) }) }
    static func ids(_ v: JSONValue?) throws -> [String] {
        guard let a = v?.asArray else { throw ActionKitError(code: "", message: "not a list") }
        return try a.map { guard let s = $0.asString else { throw ActionKitError(code: "", message: "not a string") }; return s }
    }

    /// The comparison of one case: `typed` = nil means the typed API cannot take the argument (the reference must refuse it).
    static func compare(_ d: K05.Diffs, _ c: K05Case, _ got: K05Got?) {
        guard let got = got else {
            d.add(c, (c.threw || c.out.asString != nil) ? nil : "\(c.name): the typed API refuses an input the reference accepts: \(K05.canon(c.out).prefix(200))")
            return
        }
        if c.meta("cmp") == "code", case let .value(.string(g)) = got, let w = c.out.asString {
            func pre(_ s: String) -> Substring { s.range(of: ": ").map { s[..<$0.lowerBound] } ?? Substring(s) }
            d.add(c, pre(g) == pre(w) ? nil : "\(c.name): want code of \(w.prefix(160)) got \(g.prefix(160))")
            return
        }
        let r = K05.diff(c, got)
        if r != nil, !c.threw, c.out.asString == nil, c.args.contains(where: K05.negZero) {
            if case .threw = got { d.skip("-0 accepted by the reference (Number.isSafeInteger), refused by the strict Swift profile"); return }
            if case .value(.string) = got { d.skip("-0 accepted by the reference (Number.isSafeInteger), refused by the strict Swift profile"); return }
        }
        d.add(c, r)
    }

    /// A Swift object keeps no member order, so when a def has several faults the first one found can be another than the reference's
    /// (which walks members in insertion order). Such a case agrees iff both refuse at the same stage and the native, asked about the
    /// member the reference named, gives exactly the reference's reason: the strict JSON profile (the reference's fault is one the
    /// native finds in the document) or a parameter (its name check, or its declaration check when every name is valid).
    static func otherFirstFault(_ def: JSONValue, _ want: String, _ got: String) -> Bool {
        let jp = "not strict JSON: "
        if want.hasPrefix(jp) || got.hasPrefix(jp) {
            return want.hasPrefix(jp) && got.hasPrefix(jp) && profileFaults(def, 0).contains(String(want.dropFirst(jp.count)))
        }
        guard case let .object(d) = def, case let .object(params)? = d["params"] else { return false }
        let names = Set(params.keys)
        func nameFault(_ e: String) -> JKey? {
            for pre in ["param name '", "param '"] where e.hasPrefix(pre) {
                let rest = e.dropFirst(pre.count)
                guard let end = rest.range(of: "' is ") else { return nil }
                let n = JKey(String(rest[..<end.lowerBound]))
                return names.contains(n) ? n : nil
            }
            return nil
        }
        func nameFaults(_ n: JKey) -> [String] {
            if let e = Actions.paramNameError(n.s) { return [e] }
            return names.filter { $0 != n && IV.startsWith($0.s, n.s + ".") }.map { "param '\(n.s)' is both a value and the parent of '\($0.s)'" }
        }
        if let wn = nameFault(want) { return nameFault(got) != nil && nameFaults(wn).contains(want) }
        if nameFault(got) != nil || names.contains(where: { !nameFaults($0).isEmpty }) { return false }
        func owner(_ e: String) -> JKey? { names.filter { e.hasPrefix($0.s + ": ") }.max { $0.s.utf8.count < $1.s.utf8.count } }
        guard let wn = owner(want), owner(got) != nil else { return false }
        return Actions.paramError(wn.s, params[wn]!, names) == want
    }

    /// Every strict-JSON-profile fault anywhere in `v` (the reference reports the first in member order).
    static func profileFaults(_ v: JSONValue, _ depth: Int) -> Set<String> {
        if depth > 32 { return ["nesting deeper than 32"] }
        switch v {
        case let .array(a): return a.reduce(into: Set<String>()) { $0.formUnion(profileFaults($1, depth + 1)) }
        case let .object(o):
            var out = Set<String>()
            for (k, x) in o {
                if Actions.jsonProfileError(.string(k.s)) != nil { out.insert("member name is not NFC / has a lone surrogate") }
                out.formUnion(profileFaults(x, depth + 1))
            }
            return out
        default: return Actions.jsonProfileError(v).map { [$0] } ?? []
        }
    }

    func testValidateDefAndGrammars() throws {
        try K042.requireCovers(Self.covers)
        let d = K05.Diffs()
        try K05.each(Self.file, ["validateDef", "isRole", "isFormat", "isContextKey", "paramNameError", "jsonProfileError", "idPatternError", "profileError",
                                 "reviewerPinsError"]) { c in
            let a = c.arg(0) ?? .null
            let got: K05Got?
            switch c.fn {
            case "validateDef":
                let r = Actions.validateDef(a)
                if let w = c.out.asString, let g = r, w != g, Self.otherFirstFault(a, w, g) {
                    d.add(c, nil); return
                }
                got = .value(K05.opt(r))
            case "isRole": got = .value(.bool(Actions.isRole(a)))
            case "isFormat": got = .value(.bool(Actions.isFormat(a)))
            case "isContextKey": got = .value(.bool(a.asString.map(Actions.isContextKey) ?? false))
            case "paramNameError": got = a.asString.map { .value(K05.opt(Actions.paramNameError($0))) }
            case "jsonProfileError": got = .value(K05.opt(Actions.jsonProfileError(a)))
            case "idPatternError": got = .value(K05.opt(Actions.idPatternError(a)))
            case "profileError": got = .value(K05.opt(Actions.profileError(a)))
            default: got = .value(K05.opt(Actions.reviewerPinsError(a)))
            }
            Self.compare(d, c, got)
        }
        d.finish(30_500) // 32414 cases, 1401 carry a lone surrogate (skipped)
    }

    func testTraitAlgebra() throws {
        try K042.requireCovers(Self.covers)
        let d = K05.Diffs()
        try K05.each(Self.file, ["registryError", "closure", "floorOf", "topTraits", "traitsDigest", "tablesDigest", "floorDecision", "worstReversibility",
                                 "sensitivityFloor", "impliedFromFacts"]) { c in
            let got: K05Got?
            switch c.fn {
            case "registryError":
                got = c.arg(0)?.asArray.map { .value(K05.opt(Actions.registryError($0, core: c.arg(1) == .bool(true)))) }
            case "closure": got = K05.run(Self.code) { Self.strs(try Actions.closure(try Self.reg(c.arg(0)), try Self.ids(c.arg(1)))) }
            case "floorOf": got = K05.run(Self.code) { try Actions.floorOf(try Self.reg(c.arg(0)), try Self.ids(c.arg(1))).json }
            case "topTraits": got = K05.run(Self.code) { Self.strs(Actions.topTraits(try Self.reg(c.arg(0)))) }
            case "traitsDigest": got = K05.run(Self.code) { .string(Actions.traitsDigest(try Self.reg(c.arg(0)))) }
            case "tablesDigest": got = .value(.string(Actions.tablesDigest()))
            case "floorDecision":
                let g = c.arg(0), call = c.arg(1)
                guard let caveats = Actions.strings(g?.get("caveats")), let me = IV.int(g?.get("max_esc")), let pe = IV.int(g?.get("preauth_esc")),
                      let ctx = Actions.strings(call?.get("context")), let rho = Profile(json: c.arg(2)) else { d.skip("floorDecision: untyped args"); return }
                got = .value(.string(Actions.floorDecision(grantCaveats: caveats, maxEsc: Int(me), preauthEsc: Int(pe), callContext: ctx, rho: rho)))
            case "worstReversibility":
                got = .value(.string(Actions.worstReversibility(c.arg(0) ?? .null, c.arg(1)?.asObject ?? [:])))
            case "sensitivityFloor":
                // the reference's sensitivityFloor({role, tags}) is the floor half of effectiveParamSensitivity (no declared sensitivity)
                guard let p = c.arg(0)?.asObject, p["sensitivity"] == nil else { d.skip("sensitivityFloor: input carries a declared sensitivity"); return }
                got = .value(.string(Actions.effectiveParamSensitivity(p)))
            default:
                guard let f = c.arg(0)?.asObject, let eff = Actions.strings(f["effects"]), let ps = f["params"]?.asArray, let wr = f["worstRev"]?.asString else {
                    d.skip("impliedFromFacts: untyped facts"); return
                }
                got = K05.run(Self.code) {
                    Self.strs(try Actions.impliedFromFacts(effects: eff, params: ps.map { $0.asObject ?? [:] }, scope: f["scope"]?.asString, worstRev: wr))
                }
            }
            Self.compare(d, c, got)
        }
        d.finish(4100)
    }

    func testDownstreamOfAcceptedDefs() throws {
        try K042.requireCovers(Self.covers)
        let d = K05.Diffs()
        try K05.each(Self.file, ["normalize", "defDigest", "declProfile", "hintTraits", "effective", "isConfirmed"]) { c in
            guard let def = c.arg(0)?.asObject else { Self.compare(d, c, nil); return }
            let pins: JSONValue? = c.arg(1) == .null ? nil : c.arg(1)
            let got: K05Got
            switch c.fn {
            case "normalize": got = .value(.object(Actions.normalize(def)))
            case "defDigest": got = .value(.string(Actions.defDigest(def)))
            case "declProfile": got = .value(Actions.declProfile(def).json)
            case "hintTraits": got = .value(Self.strs(Actions.hintTraits(def)))
            case "isConfirmed":
                got = .value(.bool(Actions.isConfirmed(def, Actions.coreRegistry, pins)))
            default:
                got = K05.run(Self.code) {
                    let e = try Actions.effective(def, Actions.coreRegistry, pins)
                    return .object(["confirmed": .bool(e.confirmed), "traits": Self.strs(e.traits), "closure": Self.strs(e.closure), "floor": e.floor.json,
                                    "decl": e.decl.json, "eff": e.eff.json])
                }
            }
            Self.compare(d, c, got)
        }
        d.finish(13_000)
    }

    func testSchemaFloorsReviewAndPack() throws {
        try K042.requireCovers(Self.covers)
        let d = K05.Diffs()
        try K05.each(Self.file, ["factsDigest", "schemaVerbFloorError", "schemaFloorError", "reviewMessage", "packRoot", "packProof"]) { c in
            let pins: JSONValue? = c.arg(1) == .null ? nil : c.arg(1)
            let got: K05Got?
            switch c.fn {
            case "factsDigest": got = c.arg(0)?.asObject.map { .value(.string(Actions.factsDigest($0))) }
            case "schemaVerbFloorError":
                guard let v = c.arg(0)?.asObject else { got = nil; break }
                let r = Actions.schemaVerbFloorError(v, Actions.coreRegistry, pins)
                // the reference reads non-object params / parameter entries (Object.entries) as facts-free; Swift refuses them
                if c.out == .null, r == "schema_floor_forged: params" || r == "schema_floor_forged: malformed parameter" {
                    d.skip("schemaVerbFloorError: the reference accepts unreadable params as no facts (suspected reference bug); Swift refuses"); return
                }
                got = .value(K05.opt(r))
            case "schemaFloorError": got = c.arg(0)?.asObject.map { .value(K05.opt(Actions.schemaFloorError($0, pins))) }
            case "reviewMessage": got = c.arg(0)?.asObject.map { o in Actions.reviewMessage(o).map { .value(K05.bytesValue($0)) } ?? .threw(nil) }
            case "packRoot": got = K05.run(Self.code) { .string(try Actions.packRoot(try Self.ids(c.arg(0)))) }
            default:
                guard let dg = c.arg(1)?.asString else { d.skip("packProof: non-string digest"); return }
                got = K05.run(Self.code) { try Actions.packProof(try Self.ids(c.arg(0)), dg) }
            }
            Self.compare(d, c, got)
        }
        d.finish(11_300) // 12322 cases, 427 carry a lone surrogate, ~372 unreadable-params skips
    }

    // ---- the reference fixes of d36d91ac7, one each ----

    /// The typed API cannot take a missing / string / fractional / -0 tier (the k05 rule22Decide replay maps each to deny); a negative one denies.
    func testFloorDecisionDeniesANegativeTier() {
        XCTAssertEqual(Actions.floorDecision(grantCaveats: [], maxEsc: 3, preauthEsc: 3, callContext: [], rho: Profile()), "allow")
        XCTAssertEqual(Actions.floorDecision(grantCaveats: [], maxEsc: 3, preauthEsc: -1, callContext: [], rho: Profile()), "deny")
        XCTAssertEqual(Actions.floorDecision(grantCaveats: [], maxEsc: -1, preauthEsc: 0, callContext: [], rho: Profile()), "deny")
    }

    func testAReadAttestationWithoutAnArrayFinalTraitsIsNotConfirmed() throws {
        var found: JObject?, pins: JSONValue?
        _ = try K05.each(Self.file, ["isConfirmed"]) { c in if c.name == "isConfirmed/read good" { found = c.arg(0)?.asObject; pins = c.arg(1) } }
        guard let def = found else { return XCTFail("isConfirmed/read good is missing") }
        XCTAssertTrue(Actions.isConfirmed(def, Actions.coreRegistry, pins), "control")
        let finals: [JSONValue?] = [nil, JSONValue.null, JSONValue.string("")]
        for f in finals {
            guard case var .object(rv)? = def["review"], case var .object(att)? = rv["attestation"] else { return XCTFail("no attestation") }
            att["final_traits"] = f
            rv["attestation"] = .object(att)
            var d = def
            d["review"] = .object(rv)
            XCTAssertFalse(Actions.isConfirmed(d, Actions.coreRegistry, pins), "final_traits \(String(describing: f))")
        }
    }

    func testANullMaxItemsImpliesBulk() throws {
        let cases: [(JSONValue?, Bool)] = [(nil, true), (JSONValue.null, true), (JSONValue.int(10), false)]
        for (mi, bulk) in cases {
            var p: JObject = ["type": .string("array")]
            p["max_items"] = mi
            XCTAssertEqual(try Actions.impliedFromFacts(effects: ["create"], params: [p], scope: nil, worstRev: "reversible").contains("pca.bulk"), bulk)
        }
    }
}
