import XCTest
import Foundation
@testable import AtlasPCAVerify

/// The scripted scenarios of the second CIBA reference corpus (151 cases): the client configuration check, the in-memory and durable approval brokers
/// (over the memory store and over a key-value-backed store), the key-value approval store and the network client over a scripted transport with a
/// scripted clock. The random `auth_req_id` of a broker flow is replaced by `<ID1>`, `<ID2>`... in the trace (as the generator does), a generated
/// notification token by `<NTOKEN>`, and the random `auth_req_id` of a client flow's request by `<RAND>`.
///
/// Inputs the typed API cannot express (a `resolve` decision that is neither approve nor deny, a decider that is not a string, a login hint that is
/// not a string, a durable broker without a store) are refused before the call by the type system: the step is not run, the reference's entry must be
/// a refusal, and it is counted.
final class RefCibaScenarioTests: XCTestCase {
    private static let T0 = 1_800_000_000_000.0

    private static func message(_ e: Error) -> (msg: String, code: String?) {
        if let j = e as? JSError { return (j.message, j.code) }
        return ("\(e)", nil)
    }

    private static func redact(_ v: JSONValue, _ ids: [String]) -> JSONValue {
        switch v {
        case let .string(s):
            var t = s
            for (i, id) in ids.enumerated() { t = t.replacingOccurrences(of: id, with: "<ID\(i + 1)>") }
            return .string(t)
        case let .array(a): return .array(a.map { redact($0, ids) })
        case let .object(o): return .object(o.mapValues { redact($0, ids) })
        default: return v
        }
    }

    /// Scrubs what is random in a client trace (the auth_req_id a flow's request carries).
    private static func scrub(_ v: JSONValue) -> JSONValue {
        switch v {
        case let .array(a): return .array(a.map(scrub))
        case let .object(o):
            var m = o.mapValues(scrub)
            if case var .object(r)? = m["request"], r["auth_req_id"] != nil { r["auth_req_id"] = .string("<RAND>"); m["request"] = .object(r) }
            return .object(m)
        default: return v
        }
    }

    private static func num(_ d: Double) -> JSONValue { d == d.rounded() && abs(d) <= 9007199254740991 ? .int(Int64(d)) : .double(d) }

    // MARK: brokers

    /// Returns the trace, and how many steps the type system refused.
    static func broker(_ s: JSONValue, expected: [JSONValue], refused: inout Int) -> JSONValue {
        var clock = T0
        var completes: [JSONValue] = []
        let kind = s.get("kind")?.asString ?? ""
        let mode = s.get("opts")?.get("onComplete")?.asString
        let onComplete: ((CibaSession) -> Void)? = (mode == "record" || mode == "throws") ? { completes.append($0.json) } : nil
        let store: CibaApprovalStore
        var kv: CibaMemoryKv?
        let b: PCACibaBroker
        do {
            if kind == "memory" {
                store = CibaMemoryApprovalStore()
                b = PCACibaBroker.memory(now: { clock }, onComplete: onComplete)
            } else {
                if kind == "durable-kv" {
                    let k = CibaMemoryKv()
                    kv = k
                    store = CibaKvApprovalStore(kv: k)
                } else {
                    store = CibaMemoryApprovalStore()
                }
                b = try PCACibaBroker.durable(store: store, now: { clock }, decisionTtlSec: IV.num(s.get("opts")?.get("decisionTtlSec")) ?? 300, onComplete: onComplete)
            }
        } catch {
            return .null
        }
        var ids: [String] = []
        func sub(_ x: JSONValue?) -> String {
            guard let t = x?.asString, t.hasPrefix("$id") else { return x?.asString ?? "" }
            if t == "$id" { return ids.last ?? t }
            if let n = Int(t.dropFirst(3)), n >= 1, n <= ids.count { return ids[n - 1] }
            return t
        }
        func keyOf(_ x: JSONValue?) -> String {
            let k = x?.asString ?? ""
            guard let r = k.range(of: "$id") else { return k }
            return k.replacingCharacters(in: r, with: ids.last ?? "")
        }
        var trace: [JSONValue] = []
        for (i, st) in (s.get("steps")?.asArray ?? []).enumerated() {
            let op = st.get("op")?.asString ?? ""
            var entry: JObject = ["op": .string(op)]
            do {
                var value: JSONValue = .null
                switch op {
                case "start":
                    value = try b.start(st.get("stepUp") ?? .null, st.get("opts")?.asObject ?? [:])
                    if let id = value.get("auth_req_id")?.asString, !ids.contains(id) { ids.append(id) }
                case "poll": value = .object(["status": .string(try b.poll(sub(st.get("id"))).rawValue)])
                case "token": value = try b.token(sub(st.get("id"))).json
                case "resolve":
                    guard let ds = st.get("decision")?.asString, let d = PCACibaBroker.Decision(rawValue: ds), let by = st.get("by")?.asString else {
                        refused += 1
                        trace.append(i < expected.count ? expected[i] : .null)
                        XCTAssertEqual(i < expected.count ? expected[i].get("ok") : nil, .bool(false), "the reference must refuse a decision / decider the type cannot express")
                        continue
                    }
                    value = try b.resolve(sub(st.get("id")), d, by: by).json
                case "get": value = try b.get(sub(st.get("id")))?.json ?? .null
                case "advance":
                    clock += IV.num(st.get("ms")) ?? 0
                    value = num(clock)
                case "storeSet":
                    let key = keyOf(st.get("key"))
                    value = .bool(try store.cas(key, try store.get(key)?.version ?? 0, st.get("value") ?? .null))
                case "kvRaw":
                    let key = keyOf(st.get("key"))
                    guard let k = kv else { throw JSError("no kv") }
                    value = .bool(try k.putIfEquals(key, try k.get(key), st.get("raw")?.asString ?? ""))
                default: break
                }
                entry["ok"] = .bool(true)
                entry["value"] = value
            } catch {
                let m = message(error)
                entry["ok"] = .bool(false)
                entry["msg"] = .string(m.msg)
                if let c = m.code { entry["code"] = .string(c) }
            }
            if !completes.isEmpty {
                entry["complete"] = .array(completes)
                completes = []
            }
            trace.append(.object(entry))
        }
        return redact(.array(trace), ids)
    }

    // MARK: the key-value approval store

    static func kvStore(_ s: JSONValue) -> JSONValue {
        let kv = CibaMemoryKv()
        let store = CibaKvApprovalStore(kv: kv)
        var trace: [JSONValue] = []
        for st in s.get("steps")?.asArray ?? [] {
            let op = st.get("op")?.asString ?? ""
            let key = st.get("key")?.asString ?? ""
            do {
                var value: JSONValue = .null
                switch op {
                case "get": value = try store.get(key).map { (v: CibaVersioned) -> JSONValue in .object(["version": .int(Int64(v.version)), "value": v.value]) } ?? .null
                case "cas": value = .bool(try store.cas(key, Int(IV.int(st.get("expected")) ?? 0), st.get("value") ?? .null))
                case "kvSet": value = .bool(try kv.putIfEquals(key, try kv.get(key), st.get("raw")?.asString ?? ""))
                case "kvGet": value = try kv.get(key).map { (v: String) -> JSONValue in .string(v) } ?? .null
                default: break
                }
                trace.append(.object(["op": .string(op), "ok": .bool(true), "value": value]))
            } catch {
                trace.append(.object(["op": .string(op), "ok": .bool(false), "code": .string(message(error).code ?? "other")]))
            }
        }
        return .array(trace)
    }

    // MARK: the client

    static func pollJSON(_ r: PCACiba.PollResult) -> JSONValue {
        switch r {
        case let .pending(i): return .object(["status": .string("pending"), "intervalSec": num(i)])
        case let .approved(t): return .object(["status": .string("approved"), "tokens": t])
        case let .denied(e): return .object(["status": .string("denied"), "error": .string(e)])
        case .expired: return .object(["status": .string("expired")])
        }
    }

    private static let hintKeys = ["loginHint", "loginHintToken", "idTokenHint", "delivery", "clientNotificationToken", "acrValues", "userCode"]

    static func client(_ s: JSONValue, expected: [JSONValue], refused: inout Int) -> JSONValue {
        var clock = T0
        var reqs: [JSONValue] = []
        var sleeps: [JSONValue] = []
        var queue = s.get("responses")?.asArray ?? []
        let c = s.get("cfg")
        let fetch: PCACiba.ClientFetch = { url, headers, body, _ in
            var h: JObject = [:]
            for (k, v) in headers { h[JKey(k)] = .string(v) }
            reqs.append(.object(["url": .string(url), "method": .string("POST"), "headers": .object(h), "body": .string(body)]))
            guard !queue.isEmpty else { throw JSError("no scripted response") }
            let r = queue.removeFirst()
            if r.get("fail") == .bool(true) { throw JSError("connection reset") }
            let b = r.get("body") ?? .null
            return (Int(IV.int(r.get("status")) ?? 0), b.asString ?? Canonical.canonicalize(b))
        }
        let cfg = PCACiba.ClientConfig(backchannelAuthenticationEndpoint: c?.get("backchannelAuthenticationEndpoint")?.asString ?? "", tokenEndpoint: c?.get("tokenEndpoint")?.asString ?? "",
                                       clientId: c?.get("clientId")?.asString ?? "", clientSecret: c?.get("clientSecret")?.asString ?? "", fetch: fetch,
                                       sleep: { ms in sleeps.append(num(ms)); clock += ms }, now: { clock }, timeoutMs: IV.num(c?.get("timeoutMs")),
                                       allowInsecureHttp: c?.get("allowInsecureHttp") == .bool(true))
        guard let client = try? PCACiba.createCibaClient(cfg) else { return .null }
        var poller: PCACiba.Poller?
        var nt = ""
        var trace: [JSONValue] = []
        for (i, st) in (s.get("steps")?.asArray ?? []).enumerated() {
            let op = st.get("op")?.asString ?? ""
            var entry: JObject = ["op": .string(op)]
            do {
                var value: JSONValue = .null
                switch op {
                case "initiate":
                    let o = st.get("opts")
                    var opts = PCACiba.InitiateOptions()
                    if let od = o?.asObject {
                        // a hint, delivery or token that is not a string is refused by the type
                        if Self.hintKeys.contains(where: { od[JKey($0)] != nil && od[JKey($0)]?.asString == nil }) {
                            refused += 1
                            var e: JSONValue = i < expected.count ? expected[i] : .null
                            if case var .object(x) = e { x["requests"] = .array(reqs); x["sleeps"] = .array(sleeps); e = .object(x) }
                            XCTAssertEqual(i < expected.count ? expected[i].get("ok") : nil, .bool(false), "the reference must refuse an option the type cannot express")
                            trace.append(e)
                            reqs = []
                            sleeps = []
                            continue
                        }
                        opts.loginHint = od["loginHint"]?.asString
                        opts.loginHintToken = od["loginHintToken"]?.asString
                        opts.idTokenHint = od["idTokenHint"]?.asString
                        opts.delivery = od["delivery"]?.asString
                        opts.clientNotificationToken = od["clientNotificationToken"]?.asString
                        opts.acrValues = od["acrValues"]?.asString
                        opts.userCode = od["userCode"]?.asString
                        for (k, v) in od where !Self.hintKeys.contains(k.s) { opts.request[k] = v }
                    }
                    let flow = try client.initiate(st.get("stepUp") ?? .null, opts)
                    poller = client.poller(flow)
                    var f: JObject = ["authReqId": .string(flow.authReqId), "expiresInSec": .int(flow.expiresInSec), "intervalSec": .int(flow.intervalSec),
                                      "startedAt": num(flow.startedAt), "delivery": .string(flow.delivery), "request": flow.request]
                    if let t = flow.clientNotificationToken {
                        f["clientNotificationToken"] = .string(t)
                        if opts.clientNotificationToken == nil { nt = t }
                    }
                    value = .object(f)
                case "poll": value = pollJSON(try poller?.poll() ?? .expired)
                case "wait": value = pollJSON(try poller?.wait() ?? .expired)
                case "notify": poller?.notify()
                case "advance":
                    clock += IV.num(st.get("ms")) ?? 0
                    value = num(clock)
                case "interval": value = num(poller?.intervalSec() ?? 0)
                default: break
                }
                entry["ok"] = .bool(true)
                entry["value"] = value
            } catch let e as PCACiba.ProviderError {
                entry["ok"] = .bool(false)
                entry["error"] = .string(e.error)
                entry["status"] = .int(Int64(e.status))
                entry["retryable"] = .bool(e.retryable)
                entry["errorDescription"] = e.errorDescription.map { .string($0) } ?? .null
            } catch {
                entry["ok"] = .bool(false)
                entry["other"] = .bool(true)
            }
            entry["requests"] = .array(reqs)
            entry["sleeps"] = .array(sleeps)
            reqs = []
            sleeps = []
            var out = JSONValue.object(entry)
            if !nt.isEmpty { out = markToken(out, nt) }
            trace.append(out)
        }
        return .array(trace)
    }

    private static func markToken(_ v: JSONValue, _ nt: String) -> JSONValue {
        switch v {
        case let .string(s): return .string(s.replacingOccurrences(of: nt, with: "<NTOKEN>"))
        case let .array(a): return .array(a.map { markToken($0, nt) })
        case let .object(o): return .object(o.mapValues { markToken($0, nt) })
        default: return v
        }
    }

    // MARK: the replay

    func testEveryCaseOfTheScenarioCorpus() throws {
        AdaOptIn.register()
        let d = Base.Diffs()
        var refused = 0
        let n = try Base.each("ref-ciba-java.json.gz", ["createCibaClientConfig", "brokerScenario", "durableBrokerConfig", "kvScenario", "clientScenario"]) { c in
            let a0 = c.arg(0) ?? .null
            switch c.fn {
            case "createCibaClientConfig":
                let fetch: PCACiba.ClientFetch = { _, _, _, _ in (200, "{}") }
                let cfg = PCACiba.ClientConfig(backchannelAuthenticationEndpoint: a0.get("backchannelAuthenticationEndpoint")?.asString ?? "", tokenEndpoint: a0.get("tokenEndpoint")?.asString ?? "",
                                               clientId: a0.get("clientId")?.asString ?? "", clientSecret: a0.get("clientSecret")?.asString ?? "", fetch: fetch,
                                               timeoutMs: IV.num(a0.get("timeoutMs")), allowInsecureHttp: a0.get("allowInsecureHttp") == .bool(true))
                d.add(c, Base.diff(c, Base.run { _ = try PCACiba.createCibaClient(cfg); return .bool(true) }))
            case "durableBrokerConfig":
                if a0.get("noStore") == .bool(true) {
                    // a store is a required argument of the typed constructor
                    refused += 1
                    d.add(c, c.out == .string("throws") ? nil : "\(c.name): the reference must refuse a broker without a store")
                } else {
                    let ttl = IV.num(a0.get("decisionTtlSec")) ?? 300
                    let r: JSONValue = (try? PCACibaBroker.durable(store: CibaMemoryApprovalStore(), decisionTtlSec: ttl)) != nil ? .string("ok") : .string("throws")
                    d.add(c, Base.diff(c, .value(r)))
                }
            case "kvScenario":
                d.add(c, Base.diff(c, .value(Self.kvStore(a0))))
            case "brokerScenario":
                let want = c.out.asArray ?? []
                d.add(c, Base.diff(c, .value(Self.broker(a0, expected: want, refused: &refused))))
            case "clientScenario":
                let want = c.out.asArray ?? []
                let got = Self.client(a0, expected: want, refused: &refused)
                let scrubbed = BaseCase(fn: c.fn, name: c.name, args: c.args, out: Self.scrub(c.out), suspect: c.suspect, raw: c.raw)
                d.add(c, Base.diff(scrubbed, .value(Self.scrub(got))))
            default: XCTFail("unhandled fn \(c.fn)")
            }
        }
        XCTAssertEqual(n, 151, "29 client configurations, 71 broker scenarios, 6 broker configurations, 6 store scenarios, 39 client scenarios")
        print("ciba scenarios: \(refused) refused by the type system")
        d.finish(151)
    }
}
