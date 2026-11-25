import XCTest
import Foundation
@testable import AtlasPCAVerify

/// Differential replay of the authoring-file text loader (YAML 1.2 core and JSON, with source positions) and of the YAML writer (byte for byte).
/// A syntax error is compared by class (the parser's wording is its own). Where the loader is deliberately STRICTER than the reference the result must
/// be a single "not YAML" refusal on a text that uses one of the documented constructs, never a different successful value.
final class RefActionsYamlTests: XCTestCase {
    private static let stricter = try! NSRegularExpression(pattern: "(^|\\s)!(?!!(str|map|seq)\\b)\\S|\\? \\[|\r(?!\n)|!!binary")

    /// Whether a JSON text has an object with two equal keys (decided by the lenient last-wins parse against the strict one).
    private static func hasDuplicateKey(_ text: String) -> Bool {
        (try? StrictJSON.parseLenientLastWins(text)) != nil && (try? StrictJSON.parseLenient(text)) == nil
    }

    private static func norm(_ r: JSONValue?) -> String {
        var o: JObject = [:]
        for k in ["defs", "notes", "errors", "locs", "rules", "ns"] { if let v = r?.get(k) { o[JKey(k)] = v } }
        return Canonical.canonicalize(IV.normalized(.object(o)))
    }

    func testLoadActionsText() throws {
        try K042.requireCovers(["ActionsText", "ActionAuthor"])
        var bad: [String] = []
        var n = 0
        _ = try Base.each("ref-actions-yaml-load-py.json.gz") { c in
            guard c.fn == "loadActionsText", let text = c.arg(0)?.asString, let fmt = c.arg(1)?.asString else { return }
            n += 1
            let got = JSONValue.object(ActionsText.loadActionsText(text, fmt))
            let exp = c.out
            let gotErrors = AK.arr(got.get("errors"))
            let e0 = AK.arr(exp.get("errors")).first?.get("message")?.asString ?? ""
            let gm = gotErrors.count == 1 ? (gotErrors[0].get("message")?.asString ?? "") : ""
            let ok: Bool
            if e0.hasPrefix("not YAML") || e0.hasPrefix("YAML warning") || e0.hasPrefix("not JSON") {
                let prefixOk = fmt == "yaml" ? (gm.hasPrefix("not YAML") || gm.hasPrefix("YAML warning")) : gm.hasPrefix("not JSON")
                ok = gotErrors.count == 1 && AK.arr(got.get("defs")).isEmpty && prefixOk
            } else if Self.norm(exp) == Self.norm(got) { ok = true }
            else if fmt == "json", Self.hasDuplicateKey(text) {
                // STRICTER than the reference (which keeps the last of two equal keys): two equal keys in an authorization definition are ambiguous, so the
                // loader refuses the whole file as `not JSON ... duplicate key` and yields no definition. Pinned, never skipped.
                ok = gotErrors.count == 1 && gm.hasPrefix("not JSON") && gm.contains("duplicate key") && AK.arr(got.get("defs")).isEmpty
            }
            else {
                ok = Self.stricter.firstMatch(in: text, range: NSRange(location: 0, length: text.utf16.count)) != nil && gotErrors.count == 1 && gm.hasPrefix("not YAML") && AK.arr(got.get("defs")).isEmpty
            }
            if !ok { bad.append(c.name) }
        }
        XCTAssertGreaterThanOrEqual(n, 100)
        XCTAssertTrue(bad.isEmpty, "\(bad.count) divergent case(s):\n" + bad.prefix(40).joined(separator: "\n"))
    }

    func testDefsToYamlPlain() throws {
        try K042.requireCovers(["YamlEmit", "ImportRegistry"])
        let d = Base.Diffs()
        d.acceptsLoneSurrogates = true // the emitter writes the library's lone-surrogate scalar as `\ud800`, the only half the corpus holds
        try Base.each("ref-core-yaml-java.json.gz") { c in
            guard c.fn == "defsToYaml" else { return }
            let got = RefActions.v { .string(try ImportRegistry.defsToYaml(c.arg(0)?.asString ?? "", RefActions.list(c.arg(1)).map { RefActions.obj($0) }, c.arg(2)?.asObject)) }
            d.add(c, Base.diff(c, got))
        }
        d.finish(800)
    }

    /// `{"$ref": id}` marks a container the graph holds once: every reference is the ONE instance built for that id.
    private static func graph(_ v: JSONValue, _ built: [String: YamlEmit.Node]) throws -> YamlEmit.Node {
        if case let .object(o) = v, o.count == 1, let id = o[JKey("$ref")]?.asString, let b = built[id] { return b }
        switch v {
        case let .array(a): return .seq(YamlEmit.Seq(try a.map { try graph($0, built) }))
        case let .object(o): return .map(YamlEmit.Map(try JS.keyOrder(o).map { ($0.s, try graph(o[$0]!, built)) }))
        default: return try YamlEmit.node(v)
        }
    }

    func testDefsToYamlAnchors() throws {
        try K042.requireCovers(["YamlEmit", "ImportRegistry"])
        let d = Base.Diffs()
        try Base.each("ref-core-yaml-anchors-java.json.gz") { c in
            guard c.fn == "defsToYaml" else { return }
            let got = RefActions.v { () throws -> JSONValue in
                // build one empty container per shared id, then fill them (a shared container may hold another)
                let shared = RefActions.obj(c.arg(3))
                var built: [String: YamlEmit.Node] = [:]
                for (k, v) in shared { built[k.s] = v.asArray != nil ? .seq(YamlEmit.Seq()) : .map(YamlEmit.Map()) }
                for (k, v) in shared {
                    switch (built[k.s]!, v) {
                    case let (.seq(s), .array(a)): s.items = try a.map { try Self.graph($0, built) }
                    case let (.map(m), .object(o)): m.members = try JS.keyOrder(o).map { ($0.s, try Self.graph(o[$0]!, built)) }
                    default: break
                    }
                }
                let defs: [YamlEmit.Map] = try RefActions.list(c.arg(1)).map { x in
                    guard case let .map(m) = try Self.graph(x, built) else { throw JSError("a def is an object") }
                    return m
                }
                var rules: [String: YamlEmit.Node] = [:]
                for (k, v) in RefActions.obj(c.arg(2)) { rules[k.s] = try Self.graph(v, built) }
                return .string(try ImportRegistry.defsToYaml(c.arg(0)?.asString ?? "", defs, rules))
            }
            d.add(c, Base.diff(c, got))
        }
        d.finish(30)
    }
}
