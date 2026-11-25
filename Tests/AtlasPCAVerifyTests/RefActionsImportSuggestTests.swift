import XCTest
import Foundation
@testable import AtlasPCAVerify

/// Differential replay of the suggestion rules (digest, signature, facts, apply), the model assist and the provider adapters.
final class RefActionsImportSuggestTests: XCTestCase {
    private struct Adapter: ModelAdapter {
        let spec: JObject
        func id() -> String { spec[JKey("id")]?.asString ?? "" }
        func version() -> String? { spec[JKey("version")]?.asString }
        func complete(_ req: JObject) throws -> String? {
            if let t = spec[JKey("throws")]?.asString { throw JSError(t) }
            return spec[JKey("answer")]?.asString
        }
    }

    private final class Fake: ImportProviders.FetchResponse {
        let okV: Bool, code: Int, body: JSONValue?, bad: Bool
        init(_ spec: JObject) {
            okV = spec[JKey("ok")] == nil || spec[JKey("ok")] == .bool(true)
            code = Int(IV.int(spec[JKey("status")]) ?? 200)
            body = spec[JKey("json")]
            bad = spec[JKey("badjson")] == .bool(true)
        }
        func ok() -> Bool { okV }
        func status() -> Int { code }
        func json() throws -> JSONValue? { if bad { throw JSError("bad json") }; return body }
    }

    func testImportSuggest() throws {
        try K042.requireCovers(["ImportSuggest", "ImportModelProviders", "ImportRules"])
        let d = Base.Diffs()
        let core = Actions.coreRegistry
        try Base.each("ref-actions-import-suggest.json.gz") { c in
            let a0 = c.arg(0), a1 = c.arg(1)
            func rules(_ x: JSONValue?) -> JObject { x == .string("default") ? ImportRules.DEFAULT_RULES : RefActions.obj(x) }
            let got: BaseGot
            switch c.fn {
            case "stem": got = .value(.string(ImportSuggest.stem(a0?.asString ?? "")))
            case "factsOf": got = .value(ImportSuggest.factsOf(RefActions.obj(a0)).toJson())
            case "DEFAULT_RULES": got = .value(.object(ImportRules.DEFAULT_RULES))
            case "DEFAULT_RULES_SEALED_DIGEST":
                XCTAssertEqual(ImportRules.publishedDigest(), ImportRules.DEFAULT_RULES_SEALED[JKey("digest")]?.asString)
                got = .value(ImportRules.DEFAULT_RULES_SEALED[JKey("digest")] ?? .null)
            case "suggestRulesError":
                var known: Set<String>? = nil
                if c.args.count > 1, let l = a1?.asArray { known = Set(l.compactMap { $0.asString }) }
                got = .value(Base.opt(ImportSuggest.suggestRulesError(a0 == .string("default") ? .object(ImportRules.DEFAULT_RULES) : a0, known)))
            case "rulesDigest": got = RefActions.v { .string(try ImportSuggest.rulesDigest(rules(a0))) }
            case "sealRules": got = RefActions.v { .object(try ImportSuggest.sealRules(RefActions.obj(a0))) }
            case "signRules": got = RefActions.v { .object(try ImportSuggest.signRules(RefActions.obj(a0), a1?.asString ?? "", try RefActionsImportReviewTests.seedKey(c.arg(2)?.asString ?? ""))) }
            case "verifyRules": got = .value(.object(ImportSuggest.verifyRules(a0, RefActions.list(a1).map { RefActions.obj($0) })))
            case "suggestWithRules": got = RefActions.v { .object(try ImportSuggest.suggestWithRules(RefActions.obj(a0), rules(a1), c.args.count > 2 && c.arg(2) == .string("core") ? core : nil)) }
            case "unionSuggestions": got = .value(.object(ImportSuggest.unionSuggestions(RefActions.obj(a0), RefActions.obj(a1))))
            case "applySuggestion": got = .value(.object(ImportSuggest.applySuggestion(RefActions.obj(a0), RefActions.obj(a1), RefActions.obj(c.arg(2)))))
            case "vocabulary": got = .value(RefActions.strs(ImportModel.vocabulary(core)))
            case "promptDigest": got = .value(.string(ImportModel.promptDigest(core)))
            case "buildRequest": got = .value(.object(ImportModel.buildRequest(RefActions.obj(a0), core)))
            case "parseTraitList": got = .value(RefActions.strs(ImportModel.parseTraitList(a0?.asString ?? "", core)))
            case "suggestWithModels": got = .value(.object(ImportModel.suggestWithModels(RefActions.obj(a0), RefActions.list(a1).map { Adapter(spec: RefActions.obj($0)) }, core)))
            case "modelConfigFromEnv": got = RefActions.v { .object(try ImportProviders.modelConfigFromEnv(RefActions.obj(a0), RefActions.obj(a1)).toMap()) }
            case "providerAdapterComplete":
                got = RefActions.v {
                    let cfg = RefActions.obj(a0), spec = RefActions.obj(a1), req = RefActions.obj(c.arg(2))
                    var env: JObject = [:]
                    env[JKey(cfg[JKey("provider")] == .string("anthropic") ? "ANTHROPIC_API_KEY" : "OPENAI_API_KEY")] = cfg[JKey("apiKey")]
                    let conf = try ImportProviders.modelConfigFromEnv(env, Jx.obj(["provider": cfg[JKey("provider")] ?? .null, "model": cfg[JKey("model")] ?? .null]))
                    var call: JSONValue = .null
                    let fetch: ImportProviders.FetchLike = { url, headers, body, _ in
                        call = .object(Jx.obj(["url": .string(url), "headers": .object(headers.reduce(into: JObject()) { $0[JKey($1.key)] = .string($1.value) }), "body": .string(body)]))
                        if let t = spec[JKey("throws")]?.asString { throw JSError(t) }
                        return Fake(spec)
                    }
                    var out: JObject = [:]
                    do { out[JKey("text")] = .string(try ImportProviders.providerAdapter(conf, fetch).complete(req) ?? ""); out[JKey("call")] = .null }
                    catch { out[JKey("error")] = .string((error as? JSError)?.message ?? "\(error)"); out[JKey("call")] = call }
                    return .object(out)
                }
            default: d.skip("\(c.fn): not mapped"); return
            }
            d.add(c, Base.diff(c, got))
        }
        d.finish(1000)
    }
}
