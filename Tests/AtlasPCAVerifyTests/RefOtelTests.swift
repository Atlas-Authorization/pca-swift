import XCTest
import Foundation
@testable import AtlasPCAVerify

/// Differential replay of PCAOtel (credential redaction, span attributes, the instrumented guard over scripted tracers and meters)
/// against the reference. The recorded exception's error NAME is not compared (it is not in the corpus's events).
final class RefOtelTests: XCTestCase {
    static let file = "ref-otel.json.gz"

    static func mode(_ m: JSONValue?) -> ((String) -> String)? {
        switch m?.asString {
        case "identity": return { $0 }
        case "upper": return { $0.uppercased() }
        case "brackets": return { "<\($0)>" }
        default: return nil
        }
    }

    final class Log { var events: [JSONValue] = [] }

    static func scenario(_ spec: JSONValue) -> JSONValue {
        let log = Log()
        let tm = spec.get("tracerMode")?.asString ?? "ok", mm = spec.get("meterMode")?.asString ?? "ok"
        func boom(_ cond: Bool) throws { if cond { throw JSError("exporter boom") } }
        func ev(_ name: String, _ more: [String: JSONValue] = [:]) {
            var o: JObject = ["ev": .string(name)]
            for (k, v) in more { o[JKey(k)] = v }
            log.events.append(.object(o))
        }
        let tracer: PCAOtel.Tracer? = spec.get("tracer") == .bool(true) ? PCAOtel.Tracer(startSpan: { name in
            ev("startSpan", ["name": .string(name)])
            try boom(tm == "startThrows")
            return PCAOtel.Span(
                setAttribute: { k, v in ev("setAttribute", ["k": .string(k), "v": v]); try boom(tm == "attrThrows") },
                setStatus: { code, msg in
                    var m: [String: JSONValue] = ["code": .int(Int64(code))]
                    if let msg = msg { m["message"] = .string(msg) }
                    ev("setStatus", m)
                    try boom(tm == "statusThrows")
                },
                recordException: { _, msg in ev("recordException", ["message": .string(msg), "noStack": .bool(true)]); try boom(tm == "recordThrows") },
                end: { ev("end"); try boom(tm == "endThrows") })
        }) : nil
        let meter: PCAOtel.Meter? = spec.get("meter") == .bool(true) ? PCAOtel.Meter(
            createCounter: { name in
                ev("createCounter", ["name": .string(name)])
                try boom(mm == "createThrows")
                return PCAOtel.Instrument { v, a in ev("add", ["v": v, "a": a]); try boom(mm == "addThrows") }
            },
            createHistogram: { name in
                ev("createHistogram", ["name": .string(name)])
                return PCAOtel.Instrument { v, a in ev("record", ["v": v, "a": a]); try boom(mm == "recordThrows") }
            }) : nil
        let g = spec.get("guard")
        let guardFn: (JSONValue) throws -> JSONValue = { _ in
            if let t = g?.get("throws")?.asString { throw JSError(t) }
            return g?.get("result") ?? .null
        }
        let wrapped: (JSONValue) throws -> JSONValue
        do {
            wrapped = try PCAOtel.instrumentGuard(guardFn, tracer: tracer, meter: meter, spanName: spec.get("spanName")?.asString, redact: mode(spec.get("redact")))
        } catch {
            return .object(["wrap": .string((error as? JSError)?.message ?? "\(error)"), "events": .array(log.events)])
        }
        let outcome: JSONValue
        do { outcome = .object(["result": try wrapped(.string("req"))]) } catch { outcome = .object(["threw": .string((error as? JSError)?.message ?? "\(error)")]) }
        return .object(["outcome": outcome, "events": .array(log.events)])
    }

    func testOtel() throws {
        try K042.requireCovers(["Otel"])
        let d = Base.Diffs()
        try Base.each(Self.file) { c in
            let got: BaseGot
            switch c.fn {
            case "redactSecrets":
                guard let s = c.arg(0)?.asString else { d.skip("redactSecrets: non-string"); return }
                got = .value(.string(PCAOtel.redactSecrets(s)))
            case "pcaSpanAttributes": got = .value(PCAOtel.pcaSpanAttributes(c.arg(0), redact: Self.mode(c.arg(1))))
            case "instrumentScenario": got = .value(Self.scenario(c.arg(0) ?? .null))
            default: d.skip("\(c.fn): not mapped"); return
            }
            d.add(c, Base.diff(c, got))
        }
        d.finish(500)
    }
}
