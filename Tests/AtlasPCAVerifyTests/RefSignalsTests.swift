import XCTest
import Foundation
@testable import AtlasPCAVerify

/// Differential replay of PCASignals against the reference (@atlasauth/pca-signals): SET build / verify, the revocation state, the
/// SET replay store, receiveSET, standard revocations, the authorize() adapters, snapshot / restore, SSF stream health, verification,
/// the poll queue and the SSF management API. A reference throw only requires a refusal. A SET built here (random jti, wall-clock
/// iat) is compared decoded, jti -> "<uuid>" and an iat within two minutes of now -> "<now>", plus a signature check under the
/// transmitter key. The corpus carries no private key: a keyJwk's `d` is a seed label the loader resolves.
final class RefSignalsTests: XCTestCase {
    static let file = "ref-signals.json.gz"
    /// The frozen clock the corpus generator ran under (its header's clockMs).
    static let clock = Base.clockMs(file)

    static func key(label: String) throws -> PCAEdKey {
        try Ed25519Deterministic.key(seed: Canonical.sha256(Array(("atlas-pca-conformance/" + label).utf8)))
    }
    static let k1 = try! key(label: "ref-signals/tx")
    static var k1Pub: JSONValue { .object(["kty": .string("OKP"), "crv": .string("Ed25519"), "x": .string(Base64URLStrict.encode(k1.pub))]) }

    /// The key a corpus `keyJwk` carries: its `d` member (the loader resolved the seed label to base64url of the 32-byte seed).
    static func keyOf(_ jwk: JSONValue?) -> PCAEdKey? { jwk?.get("d")?.asString.flatMap { Base64URLStrict.decode($0) }.flatMap { try? Ed25519Deterministic.key(seed: $0) } }

    static func isUuid4(_ s: String) -> Bool {
        let b = Array(s.utf8)
        guard b.count == 36 else { return false }
        for (i, c) in b.enumerated() {
            if [8, 13, 18, 23].contains(i) { if c != UInt8(ascii: "-") { return false } }
            else if !((c >= 0x30 && c <= 0x39) || (c >= 0x61 && c <= 0x66)) { return false }
        }
        return b[14] == UInt8(ascii: "4") && "89ab".utf8.contains(b[19])
    }

    /// The reference's `shape(set)`: decoded header and payload (iat / jti normalised) plus the signature check under the key.
    static func shape(_ set: String) -> JSONValue {
        let s = set.split(separator: ".", omittingEmptySubsequences: false).map(String.init)
        guard s.count == 3, let hb = Base64URLStrict.decode(s[0]), let pb = Base64URLStrict.decode(s[1]),
              let header = K042.parseOrNil(String(decoding: hb, as: UTF8.self)), var payload = K042.parseOrNil(String(decoding: pb, as: UTF8.self))?.asObject else {
            return .object(["$bad": .string(set)])
        }
        if let iat = PCASignals.number(payload["iat"]), (abs(iat * 1000 - Date().timeIntervalSince1970 * 1000) < 120_000 || abs(iat * 1000 - clock) < 120_000) { payload["iat"] = .string("<now>") }
        if let j = payload["jti"]?.asString, isUuid4(j) { payload["jti"] = .string("<uuid>") }
        let sig = Base64URLStrict.decode(s[2])
        let ok = sig.map { Jose.verifySignature(alg: "EdDSA", key: .ed25519(k1.pub), input: Array((s[0] + "." + s[1]).utf8), sig: $0) } ?? false
        return .object(["header": header, "payload": .object(payload), "sigOk": .bool(ok)])
    }

    static func tsJson(_ m: PCASignals.TsMap) -> JSONValue { .array(m.items.map { .array([.string($0.key), PCASignals.numValue($0.ts)]) }) }
    static func stateJson(_ st: PCASignals.RevocationState) -> JSONValue {
        .object(["grants": tsJson(st.revokedGrants), "agents": tsJson(st.killedAgents), "intents": st.revokedIntentIds.map(tsJson) ?? .null])
    }
    static func errOut(_ e: Error) -> JSONValue {
        var o: JObject = ["$err": .bool(true)]
        if let c = (e as? JSError)?.code { o["code"] = .string(c) }
        return .object(o)
    }
    static let err: JSONValue = .object(["$err": .bool(true)])
    static func t(_ v: JSONValue?, _ k: String) -> Bool { v?.get(k) == .bool(true) }

    static func mapper(_ name: String?) -> ((JSONValue) -> String?)? {
        switch name {
        case "email": return { s in s.get("format")?.asString == "email" ? s.get("email")?.asString : nil }
        case "throws", "num": return { _ in nil } // a throwing or non-string mapper is an unmapped subject in the reference (the throw is caught)
        case "empty": return { _ in "" }
        case "id": return { s in s.get("id")?.asString }
        case "prefixed": return { s in s.get("id")?.asString.map { "agent:\($0)" } }
        default: return nil
        }
    }
    static func stdOptions(_ sp: JSONValue?) -> PCASignals.StdOptions {
        PCASignals.StdOptions(subjectToAgent: mapper(sp?.get("mapper")?.asString), failOnUnmapped: t(sp, "fail"))
    }

    static func stateScenario(_ spec: JSONValue?, _ want: [JSONValue]) -> JSONValue {
        let st = PCASignals.createRevocationState()
        var out: [JSONValue] = []
        for (i, s) in (spec?.get("ops")?.asArray ?? []).enumerated() {
            // a non-state target has no Swift form (the state is a class); take the recorded result
            if t(s, "badState") || t(s, "nullInto") { out.append(i < want.count ? want[i] : .null); continue }
            let so = stdOptions(s.get("std"))
            let parsed = s.get("parsed")
            do {
                switch s.get("op")?.asString ?? "" {
                case "apply": try PCASignals.applySET(st, parsed); out.append(stateJson(st))
                case "applyStd":
                    let p = try PCASignals.applyStandardRevocations(st, parsed, so)
                    out.append(.object(["plan": p.toValue(), "state": stateJson(st)]))
                case "plan": out.append(try PCASignals.planStandardRevocations(parsed, so).toValue())
                case "isRevoked": out.append(.bool(PCASignals.isRevoked(st, s.get("grant")?.asString ?? "", s.get("agent")?.asString)))
                case "isIntentRevoked": out.append(.bool(PCASignals.isIntentRevoked(st, s.get("id")?.asString ?? "")))
                case "stream":
                    if t(s, "useState") { try PCASignals.streamProcessor(s.get("sets"), st); out.append(stateJson(st)) }
                    else { let fresh = PCASignals.createRevocationState(); try PCASignals.streamProcessor(s.get("sets"), fresh); out.append(stateJson(fresh)) }
                case "snapshot": out.append(PCASignals.snapshotRevocationState(st))
                case "restore":
                    if t(s, "fresh") { let fresh = PCASignals.createRevocationState(); try PCASignals.restoreRevocationState(s.get("snapshot"), fresh); out.append(stateJson(fresh)) }
                    else { try PCASignals.restoreRevocationState(s.get("snapshot"), st); out.append(stateJson(st)) }
                default: XCTFail("bad op")
                }
            } catch { out.append(errOut(error)) }
        }
        out.append(stateJson(st))
        return .array(out)
    }

    static func replayScenario(_ spec: JSONValue?) -> JSONValue {
        let store: PCASignals.InMemorySetReplayStore
        do { store = try PCASignals.createInMemorySetReplayStore(spec?.get("opts")) } catch { return .array([errOut(error)]) }
        return .array((spec?.get("ops")?.asArray ?? []).map { o in
            let a = o.asArray ?? []
            guard a.count == 3, let j = a[0].asString, let e = PCASignals.number(a[1]), let n = PCASignals.number(a[2]) else { return err }
            return (try? store.addIfAbsent(j, expiresAtSec: e, nowSec: n)).map { .bool($0) } ?? err
        })
    }

    final class Fixed: PCASignals.SetReplayStore {
        let v: Bool
        init(_ v: Bool) { self.v = v }
        func addIfAbsent(_ jti: String, expiresAtSec: Double, nowSec: Double) throws -> Bool { v }
    }
    final class NoExpiry: PCASignals.SetReplayStore {
        var seen = Set<JKey>()
        func addIfAbsent(_ jti: String, expiresAtSec: Double, nowSec: Double) throws -> Bool { seen.insert(JKey(jti)).inserted }
    }
    final class Throws: PCASignals.SetReplayStore {
        func addIfAbsent(_ jti: String, expiresAtSec: Double, nowSec: Double) throws -> Bool { throw JSError("boom") }
    }

    static func replayConformance(_ spec: JSONValue?) -> JSONValue {
        let kind = spec?.get("store")?.asString ?? ""
        let opts = spec?.get("opts")
        do {
            let f = try PCASignals.runSetReplayStoreConformance {
                switch kind {
                case "alwaysTrue": return Fixed(true)
                case "alwaysFalse": return Fixed(false)
                case "noExpiry": return NoExpiry()
                default: return try PCASignals.createInMemorySetReplayStore(opts)
                }
            }
            return .array(f.map { .string($0) })
        } catch { return err }
    }

    static func receiveScenario(_ spec: JSONValue?) -> JSONValue {
        let st = PCASignals.createRevocationState()
        let store: PCASignals.SetReplayStore
        switch spec?.get("store")?.asString ?? "" {
        case "throws": store = Throws()
        case "false": store = Fixed(false)
        case "mem1": store = try! PCASignals.createInMemorySetReplayStore(.object(["maxEntries": .int(1)]))
        default: store = try! PCASignals.createInMemorySetReplayStore()
        }
        var out: [JSONValue] = []
        for d in spec?.get("deliveries")?.asArray ?? [] {
            let opts = d.get("opts") ?? .object([:])
            let sp = d.get("std")
            let so: PCASignals.StdOptions? = sp.map { stdOptions($0) }
            var r = PCASignals.receiveSET(d.get("set"), key: d.get("key") ?? k1Pub, opts: t(d, "noOpts") ? nil : opts,
                                          store: t(d, "noStore") ? nil : store, state: t(d, "noState") ? nil : st, std: so)
            if r.get("ok") == .bool(false), r.get("code") == .string("verify_failed"), !(r.get("reason")?.asString ?? "").hasPrefix("SET invalid:") {
                r = .object(["ok": .bool(false), "code": .string("verify_failed"), "reason": .string("<jose>")])
            }
            if r.get("ok") == .bool(true) {
                var m: JObject = [:]
                for k in ["events", "iss", "jti", "sub", "payload"] { if let v = r.get("parsed")?.get(k) { m[JKey(k)] = v } }
                r = .object(["ok": .bool(true), "parsed": .object(m)])
            }
            out.append(r)
        }
        out.append(stateJson(st))
        return .array(out)
    }

    static func adapterScenario(_ spec: JSONValue?) -> JSONValue {
        let st = PCASignals.createRevocationState()
        let snap: JSONValue = .object(["v": .int(1), "grants": spec?.get("grants") ?? .array([]), "agents": spec?.get("agents") ?? .array([]), "intents": .array([])])
        do { try PCASignals.restoreRevocationState(snap, st) } catch { return .array([errOut(error)]) }
        let name = spec?.get("agentOf")?.asString ?? "leaf"
        let f: PCASignals.AgentOf = { _, g in
            switch name {
            case "throws": throw JSError("x")
            case "empty": return ""
            case "num": return nil
            case "grantId": return g.get("id")?.asString
            default: return name.hasPrefix("const:") ? String(name.dropFirst(6)) : nil
            }
        }
        let agent: PCASignals.AgentOf? = name == "leaf" ? nil : f
        return .array((spec?.get("calls")?.asArray ?? []).map { c in
            let p = c.get("pcactn") ?? .null, g = c.get("grant") ?? .null
            return .object(["hook": PCASignals.revocationHook(st, p, g, agent), "isRevoked": .bool(PCASignals.isRevokedAdapter(st, g, p, agent))])
        })
    }

    static func healthScenario(_ spec: JSONValue?, _ cfg: JSONValue?) -> JSONValue {
        let h = PCASignals.StreamHealth(spec?.get("config") ?? cfg, PCASignals.StreamHealthOptions(spec?.get("opts")))
        var issued: [String] = []
        var out: [JSONValue] = []
        for s in spec?.get("ops")?.asArray ?? [] {
            let now = PCASignals.number(s.get("now")) ?? 0
            switch s.get("op")?.asString ?? "" {
            case "status": out.append((try? h.setStatus(s.get("v"))).map { _ in .null } ?? err)
            case "event": h.recordEvent(now); out.append(.null)
            case "request":
                if let r = try? h.requestVerification(now) { issued.append(r); out.append(.string("<state:\(issued.count - 1)>")) }
                else { out.append(.null) }
            case "ack":
                let st: JSONValue = PCASignals.number(s.get("ref")).map { i in Int(i) < issued.count ? .string(issued[Int(i)]) : .null } ?? (s.get("state") ?? .null)
                out.append(.bool(h.ackVerification(st, now)))
            case "report": out.append(h.report(now))
            case "fresh": out.append(.bool(h.revocationFreshWithin(PCASignals.number(s.get("max")) ?? 0, now)))
            default: XCTFail("bad op")
            }
        }
        return .array(out)
    }

    static func verificationScenario(_ spec: JSONValue?) -> JSONValue {
        var streams: [JKey: PCASignals.StreamEntry] = [:]
        for (k, v) in spec?.get("streams")?.asObject ?? [:] {
            streams[k] = PCASignals.StreamEntry(config: v.get("config") ?? .null, lastVerification: PCASignals.number(v.get("lastVerification")))
        }
        var out: [JSONValue] = []
        for s in spec?.get("ops")?.asArray ?? [] {
            let key: PCAEdKey? = t(s, "noKey") ? nil : k1
            do {
                let r = try PCASignals.handleVerificationRequest(&streams, s.get("req"), PCASignals.number(s.get("now")) ?? 0, key: key)
                if r.get("status") == .int(204) { out.append(.object(["status": .int(204), "set": shape(r.get("set")?.asString ?? "")])) } else { out.append(r) }
            } catch { out.append(err) }
        }
        var last: JObject = [:]
        for (k, v) in streams { last[k] = v.lastVerification.map(PCASignals.numValue) ?? .null }
        out.append(.object(last))
        return .array(out)
    }

    static func pollScenario(_ spec: JSONValue?) -> JSONValue {
        let q = PCASignals.PollQueue()
        var out: [JSONValue] = []
        for s in spec?.get("ops")?.asArray ?? [] {
            if let e = s.get("enqueue")?.asArray, e.count == 2, let j = e[0].asString, let v = e[1].asString { q.enqueue(j, v); out.append(.null) }
            else if s.get("depth") != nil { out.append(.int(Int64(q.depth))) }
            else { out.append((try? q.poll(s.get("poll") ?? .null)) ?? err) }
        }
        out.append(.object(["depth": .int(Int64(q.depth)), "errors": .array(q.errors)]))
        return .array(out)
    }

    static func manageScenario(_ spec: JSONValue?) -> JSONValue {
        let store = PCASignals.MemoryStreamStore()
        var delivered: [JSONValue] = []
        var ids = 0
        var now = 1000.0
        var cur: JSONValue = .null
        let so = spec?.get("options")
        func strs(_ v: JSONValue?) -> [String]? { v?.asArray.map { $0.compactMap { $0.asString } } }
        let events = strs(spec?.get("eventsSupported")) ?? [PCASignals.EV_GRANT_REVOKED, PCASignals.EV_KILL_SWITCH, PCASignals.EV_SESSION_REVOKED]
        let o = PCASignals.SsfManageOptions(
            store: store, issuer: "https://tx.example", eventsSupported: events, deliveryMethods: strs(so?.get("deliveryMethods")),
            pollEndpoint: { "https://tx.example/poll/\($0)" }, signingKey: k1,
            deliver: { stream, set in delivered.append(.object(["stream": stream, "set": shape(set)])) },
            maxStreamsPerReceiver: PCASignals.number(so?.get("maxStreamsPerReceiver")), maxSubjectsPerStream: PCASignals.number(so?.get("maxSubjectsPerStream")),
            now: { now }, newId: { ids += 1; return "s\(ids)" })
        var out: [JSONValue] = []
        for st in spec?.get("steps")?.asArray ?? [] {
            now = PCASignals.number(st.get("now")) ?? 1000
            cur = st.get("rcv") ?? .object(["id": .string("rx1"), "aud": .string("rx")])
            out.append(PCASignals.ssfManagementHandler(o, st.get("req") ?? .null, authenticate: { _ in
                if cur == .string("throws") { throw JSError("auth") }
                return cur.isNull ? nil : cur
            }))
        }
        var dump: JObject = [:]
        for rid in spec?.get("receivers")?.asArray ?? [.string("rx1"), .string("rx2")] {
            dump[JKey(rid.asString ?? "")] = .array(store.listByReceiver(rid).map { .array([.string($0.id), $0.record]) })
        }
        out.append(.object(["delivered": .array(delivered), "store": .object(dump)]))
        return .array(out)
    }

    /// A reference throw requires a native refusal (whatever its code); a value requires canonical equality.
    static func cmp(_ c: BaseCase, _ got: BaseGot) -> String? {
        switch (c.threw, got) {
        case (true, .threw): return nil
        case (false, .value(let v)): return Base.canon(v) == Base.canon(c.out) ? nil : "\(c.name): want \(Base.firstDiff(c.out, v, "@")) || want \(Base.canon(c.out).prefix(300)) got \(Base.canon(v).prefix(300))"
        case (true, .value(let v)): return "\(c.name): want throw got \(Base.canon(v).prefix(300))"
        case (false, .threw): return "\(c.name): want \(Base.canon(c.out).prefix(300)) got throw"
        }
    }

    func testSignals() throws {
        try K042.requireCovers(["Signals", "Revoke", "Jose", "JSInterop"])
        var cfg: JSONValue? = nil
        _ = try Base.each(Self.file, ["validateStreamConfig"]) { c in if cfg == nil { cfg = c.arg(0) } }
        let d = Base.Diffs()
        try Base.each(Self.file, seeds: true) { c in
            let a0 = c.arg(0)
            let got: BaseGot
            switch c.fn {
            case "constants": got = .value(PCASignals.constants())
            case "verifySET": got = Ref.v { try PCASignals.verifySET(a0, c.arg(1), c.arg(2)) }
            case "buildSETShape":
                guard let k = Self.keyOf(a0?.get("keyJwk")) else { got = .threw(nil); break }
                got = Ref.v { Self.shape(try PCASignals.buildSET(a0 ?? .null, key: k)) }
            case "caepSET":
                guard let k = Self.keyOf(a0?.get("keyJwk")) else { got = .threw(nil); break }
                got = Ref.v { Self.shape(a0?.get("kind") == .string("risk") ? try PCASignals.riskLevelChangeSET(a0 ?? .null, key: k) : try PCASignals.assuranceLevelChangeSET(a0 ?? .null, key: k)) }
            case "stateScenario": got = .value(Self.stateScenario(a0, c.out.asArray ?? []))
            case "replayScenario": got = .value(Self.replayScenario(a0))
            case "replayConformance": got = .value(Self.replayConformance(a0))
            case "receiveScenario": got = .value(Self.receiveScenario(a0))
            case "adapterScenario":
                if a0?.get("badState") != nil { d.skip("adapterScenario: a non-state has no Swift form"); return }
                got = .value(Self.adapterScenario(a0))
            case "validateStreamConfig": got = .value(.array(PCASignals.validateStreamConfig(a0).map { .string($0) }))
            case "healthScenario": got = .value(Self.healthScenario(a0, cfg))
            case "verificationScenario": got = .value(Self.verificationScenario(a0))
            case "pollScenario": got = .value(Self.pollScenario(a0))
            case "pushResponse": got = Ref.v { try PCASignals.pushResponse(a0) }
            case "transmitterMetadata":
                let dm = a0?.get("deliveryMethods")?.asArray.map { $0.compactMap { $0.asString } }
                got = .value(PCASignals.transmitterMetadata(issuer: a0?.get("issuer")?.asString ?? "", deliveryMethods: dm, base: c.arg(1)?.asString ?? "", jwksUri: c.arg(2)?.asString))
            case "manageScenario": got = .value(Self.manageScenario(a0))
            default: d.skip("\(c.fn): not mapped"); return
            }
            d.add(c, Self.cmp(c, got))
        }
        d.finish(2300)
    }

    func testSignalsFailClosed() throws {
        // a forged / foreign-key SET is refused and burns no jti; a replayed SET is refused
        let k = Self.k1
        let set = try PCASignals.buildSET(.object(["events": .object([JKey(PCASignals.EV_GRANT_REVOKED): .object(["grant_ref": .string("g1"), "event_timestamp": .int(1)])]),
                                                  "issuer": .string("https://tx.example"), "audience": .string("rx")]), key: k)
        let other = try Self.key(label: "ref-signals/other")
        let otherPub: JSONValue = .object(["kty": .string("OKP"), "crv": .string("Ed25519"), "x": .string(Base64URLStrict.encode(other.pub))])
        let st = PCASignals.createRevocationState()
        let store = try PCASignals.createInMemorySetReplayStore()
        let opts: JSONValue = .object(["issuer": .string("https://tx.example"), "audience": .string("rx"), "maxAgeSec": .int(300)])
        XCTAssertEqual(PCASignals.receiveSET(.string(set), key: otherPub, opts: opts, store: store, state: st).get("code"), .string("verify_failed"))
        XCTAssertFalse(PCASignals.isRevoked(st, "g1"))
        XCTAssertEqual(PCASignals.receiveSET(.string(set), key: Self.k1Pub, opts: opts, store: store, state: st).get("ok"), .bool(true))
        XCTAssertTrue(PCASignals.isRevoked(st, "g1"))
        XCTAssertEqual(PCASignals.receiveSET(.string(set), key: Self.k1Pub, opts: opts, store: store, state: st).get("code"), .string("replay"))
        // no store, no state or no positive maxAgeSec is misconfigured, never accepted
        XCTAssertEqual(PCASignals.receiveSET(.string(set), key: Self.k1Pub, opts: opts, store: nil, state: st).get("code"), .string("misconfigured"))
    }
}
