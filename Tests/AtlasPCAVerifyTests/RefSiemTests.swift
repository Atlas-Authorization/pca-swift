import XCTest
import Foundation
@testable import AtlasPCAVerify

/// Differential replay of PCASiem (OCSF / CEF / ECS event mapping, formatDecision, scrubError, the HTTP and console sinks, exportBatch)
/// against the reference. The corpus carries no key material (records hold public placeholders only).
final class RefSiemTests: XCTestCase {
    static let file = "ref-siem.json.gz"

    static func opts(_ v: JSONValue?) -> PCASiem.Options? {
        guard let o = v, o.isObject else { return nil }
        return PCASiem.Options(signature: o.get("signature")?.asString)
    }

    static func event(_ r: JSONValue, _ format: String) -> PCASiem.Event {
        // the reference formats the scenario's records the same way, without options
        return (try? PCASiem.formatDecision(r, format, nil)) ?? PCASiem.Event(format: format, object: nil, line: "")
    }

    static func httpScenario(_ spec: JSONValue) -> JSONValue {
        let mode = spec.get("mode")?.asString ?? "ok"
        let format = spec.get("format")?.asString ?? "ocsf"
        var first: PCASiem.HttpRequest?
        let fetch: (PCASiem.HttpRequest) throws -> PCASiem.FetchResponse = { req in
            if first == nil { first = req }
            if mode == "ok" { return PCASiem.FetchResponse(ok: true, status: 200) }
            if mode == "okStatus" { return PCASiem.FetchResponse(ok: true, status: 204) }
            if mode.hasPrefix("st:") {
                let parts = mode.split(separator: ":", maxSplits: 2, omittingEmptySubsequences: false).map(String.init)
                return PCASiem.FetchResponse(ok: false, status: Int(parts[1]) ?? 0, statusText: parts.count > 2 ? parts[2] : nil)
            }
            if mode.hasPrefix("throws:") { throw JSError(String(mode.dropFirst(7))) }
            throw PCASiem.FetchTimeout()
        }
        var headers: [String: String]?
        if let h = spec.get("headers")?.asObject { headers = Dictionary(uniqueKeysWithValues: h.map { ($0.key.s, $0.value.asString ?? "") }) }
        let sink = PCASiem.httpSink(spec.get("url")?.asString ?? "", PCASiem.HttpSinkOptions(
            format: format, headers: headers, fetch: fetch, contentType: spec.get("contentType")?.asString,
            name: spec.get("name")?.asString, timeoutMs: spec.get("timeoutMs").flatMap { IV.num($0) }))
        let events = (spec.get("events")?.asArray ?? []).map { event($0, format) }
        let result = (try? sink.deliver(events)) ?? PCASiem.SinkResult(ok: false, error: "threw")
        var out: JObject = ["name": .string(sink.name), "format": .string(sink.format), "result": result.json]
        if let r = first {
            var h = JObject()
            for (k, v) in r.headers { h[JKey(k)] = .string(v) }
            out["request"] = .object(["url": .string(r.url), "method": .string(r.method), "headers": .object(h), "body": .string(r.body)])
        }
        return .object(out)
    }

    static func consoleScenario(_ spec: JSONValue) -> JSONValue {
        final class Lines { var v: [JSONValue] = [] }
        let lines = Lines()
        let boom = spec.get("throws")?.asString
        let sink = PCASiem.consoleSink(format: spec.get("format")?.asString, logger: { l in
            if let b = boom { throw JSError(b) }
            lines.v.append(.string(l))
        }, name: spec.get("name")?.asString)
        let events = (spec.get("records")?.asArray ?? []).map { event($0, sink.format) }
        let result = (try? sink.deliver(events)) ?? PCASiem.SinkResult(ok: false, error: "threw")
        return .object(["name": .string(sink.name), "format": .string(sink.format), "result": result.json, "lines": .array(lines.v)])
    }

    static func exportScenario(_ spec: JSONValue) -> JSONValue {
        final class Log { var errors: [JSONValue] = []; var delivered: [JSONValue] = [] }
        let log = Log()
        let mode = spec.get("sinkMode")?.asString ?? "ok"
        let sink = PCASiem.Sink(name: "s1", format: spec.get("format")?.asString ?? "ocsf") { events in
            for e in events { log.delivered.append(.string(e.line)) }
            if mode == "ok" { return PCASiem.SinkResult(ok: true) }
            if mode == "fail" { return PCASiem.SinkResult(ok: false, error: "collector said no token=abcdef123") }
            if mode == "failNoError" { return PCASiem.SinkResult(ok: false) }
            throw JSError("deliver exploded Bearer abcdefghij")
        }
        let throwsOnError = mode == "throwsOnError" || spec.get("onErrorThrows") == .bool(true)
        let options = PCASiem.ExportOptions(onError: { m, s, c in
            log.errors.append(.object(["message": .string(m), "sink": .string(s), "count": .int(Int64(c))]))
            if throwsOnError { throw JSError("cb") }
        }, serialize: opts(spec.get("serialize")))
        let result = PCASiem.exportBatch(spec.get("records")?.asArray ?? [], sink, options)
        return .object(["result": result.json, "errors": .array(log.errors), "delivered": .array(log.delivered)])
    }

    func testSiem() throws {
        try K042.requireCovers(["Siem"])
        let d = Base.Diffs()
        try Base.each(Self.file) { c in
            let got: BaseGot
            switch c.fn {
            case "toOcsfEvent": got = Base.run { try PCASiem.toOcsfEvent(c.arg(0) ?? .null, Self.opts(c.arg(1))) }
            case "toEcs": got = Base.run { try PCASiem.toEcs(c.arg(0) ?? .null, Self.opts(c.arg(1))) }
            case "toCef": got = Base.run { .string(try PCASiem.toCef(c.arg(0) ?? .null, Self.opts(c.arg(1)))) }
            case "formatDecision":
                guard let f = c.arg(1)?.asString else { d.skip("formatDecision: non-string format"); return }
                got = Base.run { try PCASiem.formatDecision(c.arg(0) ?? .null, f, Self.opts(c.arg(2))).toMap() }
            case "scrubError":
                guard let s = c.arg(0)?.asString else { d.skip("scrubError: non-string"); return }
                got = .value(.string(PCASiem.scrubError(s)))
            case "httpSinkScenario": got = .value(Self.httpScenario(c.arg(0) ?? .null))
            case "consoleSinkScenario": got = .value(Self.consoleScenario(c.arg(0) ?? .null))
            case "exportScenario": got = .value(Self.exportScenario(c.arg(0) ?? .null))
            default: d.skip("\(c.fn): not mapped"); return
            }
            d.add(c, Base.diff(c, got))
        }
        d.finish(1000)
    }
}
