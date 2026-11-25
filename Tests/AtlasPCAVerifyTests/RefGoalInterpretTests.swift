import XCTest
import Foundation
@testable import AtlasPCAVerify

/// Replay of the goal interpreters against the reference: candidate extraction, slot fill, prompt, grounding, the rule / form /
/// model interpreters, recorded completions, the vendor completions over a scripted fetch, the typed refund form and the lexical
/// comparator. A reference throw requires a native refusal.
final class RefGoalInterpretTests: XCTestCase {
    typealias I = PCAGoalInterpret
    static let file = "ref-goal-interpret.json.gz"

    private static func need(_ v: JSONValue?, _ what: String) throws -> JSONValue {
        guard let x = v else { throw JSError("missing argument: \(what)") }
        return x
    }

    private static func text(_ v: JSONValue?) throws -> String {
        guard let s = v?.asString else { throw JSError("string expected") }
        return s
    }

    /// An ontology argument: a shipped ontology by name, or the object itself.
    private static func ont(_ v: JSONValue?) throws -> JSONValue {
        if let n = v?.asString {
            guard let o = try PCAGoalOntologies.ontology(n) else { throw JSError("unknown ontology \(n)") }
            return o
        }
        return try need(v, "ontology")
    }

    private static func byKey(_ list: JSONValue?, _ key: String, _ want: JSONValue?) throws -> JSONValue {
        for x in list?.asArray ?? [] where x.get(key) == want { return x }
        throw JSError("not found")
    }

    private static func req(_ ont: JSONValue, _ text: JSONValue?, _ sources: JSONValue?, _ form: JSONValue?) -> JSONValue {
        var o = JObject()
        o[JKey("principal")] = .string("p1")
        o[JKey("text")] = text ?? .null
        o[JKey("ontology")] = ont
        if let s = sources, !s.isNull { o[JKey("sources")] = s }
        if let f = form, !f.isNull { o[JKey("form")] = f }
        return .object(o)
    }

    private static func prompt(_ p: I.Prompt) -> JSONValue {
        return .object([JKey("system"): .string(p.system), JKey("user"): .string(p.user)])
    }

    private final class Seen {
        var url = ""
        var method = ""
        var headers: [String: String] = [:]
        var body = ""
    }

    private static func vendor(_ a: [JSONValue]) throws -> JSONValue {
        let kind = try text(a[1])
        let cfg = try need(a[2], "config")
        let fk = try need(a[3], "fake")
        let seen = Seen()
        let fixed = fk.asObject?.isEmpty ?? false
        let fetch: I.Fetch = { (url: String, method: String, headers: [String: String], body: String) throws -> I.Fetched in
            seen.url = url
            seen.method = method
            seen.headers = headers
            seen.body = body
            if fixed {
                let b = kind == "openai" ? #"{"choices":[{"message":{"content":"x"}}]}"# : #"{"content":[{"type":"text","text":"x"}]}"#
                return I.Fetched(ok: true, status: 200, body: b)
            }
            if let m = fk.get("throwMsg")?.asString, !m.isEmpty { throw JSError(m) }
            let st = Int(IV.int(fk.get("status")) ?? 0)
            var body = "null"
            if let bv = fk.get("body"), !bv.isNull { body = Base.canon(bv) }
            return I.Fetched(ok: fk.get("ok") == JSONValue.bool(true), status: st, body: body)
        }
        let c: I.Completion
        if kind == "anthropic" {
            var mt: Int? = nil
            if let n = IV.int(cfg.get("maxTokens")) { mt = Int(n) }
            c = I.anthropicCompletion(try text(cfg.get("apiKey")), cfg.get("model")?.asString, fetch, mt)
        } else {
            c = I.openaiCompletion(try text(cfg.get("apiKey")), cfg.get("model")?.asString, cfg.get("baseUrl")?.asString, fetch)
        }
        var out = JObject()
        do {
            out[JKey("text")] = .string(try c(I.Prompt(try text(a[4]), try text(a[5]))))
        } catch {
            out[JKey("error")] = .string(I.messageOf(error))
        }
        var hs = JObject()
        for (k, v) in seen.headers { hs[JKey(k)] = .string(v) }
        out[JKey("req")] = .object([JKey("url"): .string(seen.url), JKey("method"): .string(seen.method), JKey("headers"): .object(hs), JKey("body"): .string(seen.body)])
        return .object(out)
    }

    private static func call(_ c: BaseCase) throws -> JSONValue? {
        var a: [JSONValue] = c.args
        while a.count < 8 { a.append(.null) }
        switch c.fn {
        case "sourceDigest":
            return .string(try I.sourceDigest(try text(a[0])))
        case "slotStemsOf":
            return .array(try I.slotStems(try need(a[0], "slot")).map { JSONValue.string($0) })
        case "extractCandidates":
            return try I.extractCandidates(try text(a[1]), try ont(a[0]), a[2].asString).toJson()
        case "fillTemplateById":
            let o = try ont(a[0])
            return try I.fillTemplate(try byKey(o.get("templates"), "id", a[1]), o, try text(a[2]), a[3].asString)
        case "buildPromptOf":
            return prompt(try I.buildPrompt(req(try ont(a[0]), a[1], a[2], nil), a[3] == .bool(true)))
        case "promptKeyOf":
            return .string(I.promptKey(try text(a[1]), I.Prompt(try text(a[2]), try text(a[3]))))
        case "replayLookup":
            var rec: [String: String] = [:]
            for (k, v) in a[2].asObject ?? [:] {
                guard let s = v.asString else { throw JSError("recording must be a string") }
                rec[k.s] = s
            }
            return .string(try I.replayCompletion(try text(a[1]), rec)(I.Prompt(try text(a[3]), try text(a[4]))))
        case "parseTemplateJSON":
            return I.parseTemplateJSON(try text(a[0]))
        case "groundedOf":
            let o = try ont(a[0])
            let t = try byKey(o.get("templates"), "id", a[1])
            let s = try byKey(t.get("slots"), "name", a[2])
            return .bool(try I.grounded(s, a[3], try I.extractCandidates(try text(a[4]), o, nil)))
        case "interpretRule":
            return try I.ruleInterpreter("rule", a[3].asString).interpret(req(try ont(a[0]), a[1], a[2], nil))
        case "interpretForm":
            // the reference run of the typed-form cases cites one source "s" when its text is "form text"
            let src: JSONValue? = a[2].asString == "form text" ? .array([.string("s")]) : nil
            return try I.formInterpreter("form").interpret(req(try ont(a[0]), a[2], src, a[1]))
        case "interpretLlm":
            let mode = try need(a[3], "mode")
            let completion: I.Completion = { (_: I.Prompt) throws -> String in
                if mode.get("throw") != nil { throw JSError("boom") }
                return try text(mode.get("raw"))
            }
            return try I.llmInterpreter("m", "f", completion, a[4] == .bool(true), a[5].asString).interpret(req(try ont(a[0]), a[1], a[2], nil))
        case "vendor":
            return try vendor(a)
        case "interpretRefundForm":
            return try I.interpretForm(a[0], a[1], a[2].asString)
        case "lexicalCompare":
            return try I.lexicalComparator(try ont(a[0]))(try text(a[1]), try text(a[2]))
        default:
            return nil
        }
    }

    func testReplayAgainstReference() throws {
        let d = Base.Diffs()
        var unknown = 0
        try Base.each(Self.file) { c in
            var known = true
            let got: BaseGot = Base.run { () throws -> JSONValue in
                guard let v = try Self.call(c) else { known = false; return .null }
                return v
            }
            if !known { unknown += 1; d.skip("function not replayed: \(c.fn)"); return }
            d.add(c, Base.diff(c, got))
        }
        XCTAssertEqual(unknown, 0, "every function of the corpus is replayed")
        d.finish(4500)
    }
}
