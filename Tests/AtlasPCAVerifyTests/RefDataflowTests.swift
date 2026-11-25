import XCTest
import Foundation
@testable import AtlasPCAVerify

/// Differential replay of the data-flow model, the trace rules (parse / compile / lethal-trifecta lint) and the detector adapters
/// against the reference (@atlasauth/pca-dataflow). A tagged value crosses as {"$t": value, "cap": {...}}; {"$raw": v} is an
/// UNtagged value; a null item of the checkAction argument list is an omitted optional argument and {"$hole": true} an argument
/// nobody tagged. The detector gateway key is rebuilt from its seed label (the corpus carries no key material).
final class RefDataflowTests: XCTestCase {
    static let file = "ref-dataflow.json.gz"
    typealias DF = PCADataflow
    typealias TR = PCATraceRules

    static func bad(_ m: String = "malformed spec") -> JSError { JSError(m) }

    static func strList(_ v: JSONValue?) throws -> [String]? {
        guard let v = v else { return nil }
        guard case let .array(a) = v else { throw bad() }
        return try a.map { (x: JSONValue) throws -> String in guard let s = x.asString else { throw bad() }; return s }
    }

    static func arr(_ v: JSONValue?) throws -> [JSONValue] {
        guard let a = v?.asArray else { throw bad() }
        return a
    }

    static func cap(_ spec: JSONValue?) throws -> DF.Capability {
        guard case let .object(m)? = spec, case let .array(src)? = m["sources"], case let .bool(trusted)? = m["isTrusted"] else {
            throw JSError("tag: a capability needs a set of sources and a boolean isTrusted")
        }
        var readers: [String]?
        if let r = m["readers"] {
            guard case .array = r else { throw JSError("tag: readers must be a Set when given") }
            readers = try strList(r)
        }
        return DF.Capability(sources: try strList(.array(src))!, isTrusted: trusted, readers: readers)
    }

    /// {$raw} -> an untagged value, {$t, cap} -> tag; anything else is a malformed spec.
    static func val(_ spec: JSONValue?) throws -> DF.Tagged {
        guard case let .object(m)? = spec else { throw bad() }
        if let raw = m["$raw"] { return .untagged(raw) }
        if let t = m["$t"] { return try DF.tag(t, try cap(m["cap"])) }
        throw bad()
    }

    static func sink(_ spec: JSONValue?) -> DF.Sink? {
        guard case let .object(m)? = spec, let id = m["id"]?.asString else { return nil }
        guard case let .object(a)? = m["accepts"] else { return DF.Sink(id: id, accepts: nil) }
        func list(_ k: String) -> [String]? { a[JKey(k)]?.asArray?.compactMap { $0.asString } }
        return DF.Sink(id: id, accepts: DF.FlowPolicy(external: a["external"] == .bool(true), requireTrusted: a["requireTrusted"] == .bool(true),
                                                       allowedSources: list("allowedSources"), deniedSources: list("deniedSources")))
    }

    static func selector(_ v: JSONValue?) throws -> TR.Selector {
        guard case let .object(m)? = v else { throw bad() }
        return TR.Selector(tools: try strList(m["tools"]) ?? [], traits: try strList(m["traits"]) ?? [], resources: try strList(m["resources"]) ?? [], any: m["any"] == .bool(true))
    }

    /// The reference's rule list: shapes it refuses with a runtime TypeError are plain errors, an absent / non-integer within_ms is the
    /// coded window refusal, an absent id reads as the string "undefined".
    static func rules(_ v: JSONValue?) throws -> [TR.Rule] {
        let window = JSError("within_ms must be 1..30 days", code: "window")
        if case let .string(s)? = v, !s.isEmpty { throw window }
        guard case let .array(l)? = v else { throw JSError("rules is not iterable") }
        return try l.map { (x: JSONValue) throws -> TR.Rule in
            switch x {
            case .null: throw JSError("null rule")
            case let .object(m):
                var id = "undefined"
                if let s = m["id"] { guard let str = s.asString else { throw bad() }; id = str }
                guard let w = IV.int(m["within_ms"]) else { throw window }
                return TR.Rule(id: id, never: try selector(m["never"]), after: try selector(m["after"]), withinMs: w, reason: m["reason"])
            default: throw window
            }
        }
    }

    static func table(_ v: JSONValue?) -> TR.VerbTable {
        var t: TR.VerbTable = [:]
        for (k, d) in v?.asObject ?? [:] {
            let o = d.asObject ?? [:]
            t[k] = TR.VerbDef(traits: o["traits"]?.asArray?.compactMap { $0.asString } ?? [], effects: o["effects"]?.asArray?.compactMap { $0.asString })
        }
        return t
    }

    static func edges(_ v: JSONValue?) throws -> [TR.Edge] {
        guard case let .array(l)? = v else { throw bad() }
        return try l.map { (e: JSONValue) throws -> TR.Edge in
            guard case let .object(m) = e, let rule = m["rule"]?.asString, let to = m["to"]?.asString, let w = IV.int(m["within_ms"]), case let .object(f)? = m["from"] else { throw bad() }
            if let t = f["tool"]?.asString { return TR.Edge(rule: rule, from: .tool(t), to: to, withinMs: w) }
            if let r = f["resource"]?.asString { return TR.Edge(rule: rule, from: .resource(r), to: to, withinMs: w) }
            throw bad()
        }
    }

    static func ctx(_ v: JSONValue?, _ keys: [String: PCASuiteKey]) throws -> PCADetectors.Context {
        guard case let .object(m)? = v, let det = m["detector"]?.asString, let ver = m["version"]?.asString,
              case let .object(sk)? = m["secretKey"], let label = (sk["$seed"] ?? sk["$bytes"]?.get("$seed"))?.asString, let key = keys[label], let now = IV.num(m["now"]) else { throw bad() }
        return PCADetectors.Context(detector: det, version: ver, content: m["content"] ?? .null, signer: key, now: now, session: m["session"], calibrationRef: m["calibration_ref"])
    }

    func testDataflow() throws {
        try K042.requireCovers(["Dataflow", "TraceRules", "DetectorAdapters", "JSInterop"])
        let keys = ["dataflow/gateway": PCASuiteKey.ed25519(try Ed25519Deterministic.key(seed: Canonical.sha256(Array("atlas-pca-conformance/dataflow/gateway".utf8))))]
        let d = Base.Diffs()
        var seen = Set<String>()
        try Base.each(Self.file) { c in
            let a0 = c.arg(0), a1 = c.arg(1), a2 = c.arg(2), a3 = c.arg(3)
            seen.insert(c.fn)
            let got: BaseGot
            switch c.fn {
            case "classifyFlow": got = Ref.v { DF.classifyFlow(try Self.val(a0), Self.sink(a1)).json }
            case "canFlow":
                got = Ref.v {
                    let r = DF.canFlow(try Self.val(a0), Self.sink(a1))
                    var o: JObject = ["ok": .bool(r.ok)]
                    if let m = r.reason { o["reason"] = .string(m) }
                    return .object(o)
                }
            case "tag": got = Ref.v { try DF.tag(a0 ?? .null, try Self.cap(a1)).json }
            case "fromTrustedQuery": got = Ref.v { DF.fromTrustedQuery(a0 ?? .null, readers: try Self.strList(Ref.obj(a1)["readers"])).json }
            case "fromToolOutput": got = Ref.v { DF.fromToolOutput(a0?.asString ?? "", a1 ?? .null, readers: try Self.strList(Ref.obj(a2)["readers"])).json }
            case "fromSource":
                got = Ref.v { try DF.fromSource(a0?.asString ?? "", a1 ?? .null, isTrusted: Ref.obj(a2)["isTrusted"] == .bool(true), readers: try Self.strList(Ref.obj(a2)["readers"])).json }
            case "unionSources":
                got = Ref.v { PCADataflow.strs(DF.unionSources(try (try Self.arr(a0)).map { try Self.cap($0) })) }
            case "combineCaps":
                got = Ref.v { DF.combineCaps(try (try Self.arr(a0)).map { try Self.cap($0) }).json }
            case "derive":
                let name = a1?.asString ?? ""
                if name == "first", a0?.asArray?.isEmpty ?? false { d.skip("first of no inputs is undefined"); return }
                got = Ref.v {
                    try DF.derive(try (a0?.asArray ?? []).map { try Self.val($0) }) { vals in
                        switch name {
                        case "count": return .int(Int64(vals.count))
                        case "pair": return .array(vals)
                        case "first": return vals[0]
                        default: throw JSError("combiner failed")
                        }
                    }.json
                }
            case "checkAction":
                got = Ref.v {
                    let am = Ref.obj(a0)
                    let action = DF.PcaStyleAction(verb: am["verb"]?.asString ?? "", resource: am["resource"]?.asString ?? "")
                    let slots: [DF.ArgSlot] = try (a1?.asArray ?? []).map { (it: JSONValue) throws -> DF.ArgSlot in
                        if it == .null { return .undefined }
                        if Ref.obj(it)["$hole"] == .bool(true) { return .hole }
                        return .tagged(try Self.val(it))
                    }
                    let g = Ref.obj(a2)
                    let throwsGov = g["throws"] == .bool(true)
                    let expected = Ref.obj(a3)["expectedArgs"].flatMap { IV.num($0) }
                    return DF.checkAction(action, slots, sinkFor: { _ in if throwsGov { throw JSError("governor failed") }; return Self.sink(g["sink"]) }, expectedArgs: expected).json
                }
            case "dualContext":
                got = Ref.v {
                    let spec = Ref.obj(a0)
                    let r = try DF.dualContext(query: try Self.val(spec["query"]), plan: { p in
                        switch spec["plan"]?.asString {
                        case "identity": return p
                        case "wrap": return .object(["planned": p])
                        default: throw JSError("planner failed")
                        }
                    }, quarantine: { p in
                        switch spec["quarantine"]?.asString {
                        case "tagged_untrusted": return DF.fromToolOutput("quarantine", p)
                        case "trusted": return DF.fromTrustedQuery(p)
                        case "raw": return .untagged(p)
                        default: throw JSError("q failed")
                        }
                    })
                    return .object(["plan": r.plan, "result": r.result.json])
                }
            case "externalSendSink": got = .value(DF.externalSendSink(a0?.asString ?? "").json)
            case "sensitiveSink": got = .value(DF.sensitiveSink(a0?.asString ?? "").json)
            case "levelOf": got = Ref.v { .string(DF.levelOf(try Self.val(a0))) }
            case "consts":
                got = .value(.object(["TRUSTED_QUERY": .string(DF.TRUSTED_QUERY), "tool": .string(DF.toolProvenance("x")), "tool2": .string(DF.toolProvenance(""))]))
            case "parseTraceRule":
                guard let id = a0?.asString, let text = a1?.asString else { d.skip("non-string id / rule text"); return }
                got = Ref.v { try TR.parseTraceRule(id, text, reason: c.args.count > 2 ? c.args[2] : nil).json }
            case "parseInvariantRule":
                guard let id = a0?.asString, let text = a1?.asString else { d.skip("non-string id / rule text"); return }
                let o = Ref.obj(a2)
                got = Ref.v { try TR.parseInvariantRule(id, text, horizon: o["horizon"]?.asString, dropUnsupported: o["dropUnsupported"] == .bool(true)).json }
            case "compileTraceRules": got = Ref.v { try TR.compileTraceRules(try Self.rules(a0), Self.table(a1)).json }
            case "lethalTrifecta":
                got = Ref.v {
                    let t = Self.table(a0)
                    // `o.untrusted` of a null options object is a TypeError once there is a verb to filter
                    if a2 == .null && !t.isEmpty { throw JSError("cannot read properties of null") }
                    let o = Ref.obj(a2)
                    return TR.lethalTrifecta(t, try Self.edges(a1), untrusted: try Self.strList(o["untrusted"]) ?? [], untrustedTraits: try Self.strList(o["untrusted_traits"]) ?? []).json
                }
            case "traceConsts":
                got = .value(.object(["MAX_TRACE_CAVEATS": .int(Int64(TR.MAX_TRACE_CAVEATS)), "PRIVATE_READ_TRAITS": DF.strs(TR.PRIVATE_READ_TRAITS),
                                      "EXTERNAL_SEND_TRAITS": DF.strs(TR.EXTERNAL_SEND_TRAITS)]))
            case "categoryId": got = .value(.string(PCADetectors.categoryId(a0)))
            case "lakeraReceipt": got = Ref.v { try PCADetectors.lakeraReceipt(a0, try Self.ctx(a1, keys)) }
            case "promptSecurityReceipt": got = Ref.v { try PCADetectors.promptSecurityReceipt(a0, try Self.ctx(a1, keys)) }
            case "genericReceipt": got = Ref.v { try PCADetectors.genericReceipt(a0, try Self.ctx(a1, keys)) }
            default: d.skip("\(c.fn): not mapped"); return
            }
            d.add(c, Base.diff(c, got))
        }
        XCTAssertEqual(seen.count, 24)
        d.finish(2100)
    }
}
