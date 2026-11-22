import XCTest
import Foundation
@testable import AtlasPCAVerify

/// Differential oracle: the durable state store (`openDurableState` / `recoverDurableState`) against the traces generated from the TypeScript reference
/// (ref-durable-state): commit and compaction bytes, tamper / rollback / generation-fence loading, the lock protocol and operator recovery. A scenario is an
/// initial directory plus steps (open + ops, recover, write, dir); the whole trace (results, error codes and messages, the final directory) must match.
final class RefDurableStateTests: XCTestCase {
    static let file = "ref-durable-state.json.gz"
    static let DEAD = "999999999"
    /// The reference spells the options in object-literal form inside messages.
    static let NAMES: [(String, String)] = [
        ("recoverDurableState(dir:, force: true, legacyLock: true, expectedHolder:)", "recoverDurableState({ dir, force: true, legacyLock: true, expectedHolder })"),
        ("recoverDurableState(dir:, force: true, expectedHolder:)", "recoverDurableState({ dir, force: true, expectedHolder })"),
        ("expectedHolder must be {'host','pid','nonce'} as", "expectedHolder must be { host, pid, nonce } as"),
    ]

    func scenario(_ sc: JSONValue) throws -> JSONValue {
        let d = NSTemporaryDirectory() + "pca-ds-replay-\(UUID().uuidString)"
        try FileManager.default.createDirectory(atPath: d, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(atPath: d) }
        let host = PCADurableState.hostname()
        let pid = String(getpid())
        func subst(_ s: String) -> String { s.replacingOccurrences(of: "$HOST", with: host).replacingOccurrences(of: "$PID", with: pid).replacingOccurrences(of: "$DEAD", with: Self.DEAD) }
        func norm(_ s0: String) -> String {
            var s = s0.replacingOccurrences(of: d, with: "$DIR").replacingOccurrences(of: host, with: "$HOST").replacingOccurrences(of: "pid=\(pid)", with: "pid=$PID").replacingOccurrences(of: "pid \(pid)", with: "pid $PID")
            for (a, b) in Self.NAMES { s = s.replacingOccurrences(of: a, with: b) }
            return s
        }
        func normName(_ f0: String) -> String {
            var f = f0
            f = f.replacingOccurrences(of: #"^(state\.fence\.\d+)-[0-9a-f]+"#, with: "$1-*", options: .regularExpression)
            f = f.replacingOccurrences(of: #"\.quarantine-.*$"#, with: ".quarantine-*", options: .regularExpression)
            f = f.replacingOccurrences(of: #"^state\.lock\.legacy-recovered-.*$"#, with: "state.lock.legacy-recovered-*", options: .regularExpression)
            return f.replacingOccurrences(of: #"^state\.lock\.tmp-.*$"#, with: "state.lock.tmp-*", options: .regularExpression)
        }
        func err(_ e: DurableStateError) -> JSONValue { .object(["err": .object(["code": .string(e.code), "msg": .string(norm(e.description))])]) }
        func read(_ f: String) -> JSONValue {
            guard let t = PCADurableState.readText(d + "/" + f) else { return .null }
            return .string(t)
        }
        func put(_ f: String, _ text: JSONValue?) {
            let p = d + "/" + f
            if let t = text?.asString { FileManager.default.createFile(atPath: p, contents: Data(subst(t).utf8)) } else { try? FileManager.default.removeItem(atPath: p) }
        }
        func snapshot() -> JSONValue {
            let names = PCADurableState.children(d).sorted { $0.utf16.lexicographicallyPrecedes($1.utf16) }
            var fences: [JSONValue] = []
            func tryFence(_ f: String, _ pick: (JSONValue) -> [JSONValue]) {
                guard let t = PCADurableState.readText(d + "/" + f), let o = PCADurableState.parseJSON(t) else { fences.append(.object(["unreadable": .string(normName(f))])); return }
                for x in pick(o) {
                    guard var m = x.asObject else { fences.append(.object(["unreadable": .string(normName(f))])); return }
                    m.removeValue(forKey: JKey("t"))
                    fences.append(.object(m))
                }
            }
            if names.contains("state.fence") { tryFence("state.fence") { $0.get("fences")?.asArray ?? [] } }
            let entries = names.compactMap { n in PCADurableState.fenceEntry(n).map { (n, $0) } }.sorted { $0.1 != $1.1 ? $0.1 < $1.1 : $0.0.utf16.lexicographicallyPrecedes($1.0.utf16) }
            for (n, _) in entries { tryFence(n) { [$0.get("fence") ?? .null] } }
            let gens = names.compactMap(PCADurableState.lockGen)
            var top: JSONValue = .null
            if let g = gens.max() {
                if let t = PCADurableState.readText(d + "/state.lock.\(g)"), let b = PCADurableState.parseJSON(t), b.isObject {
                    var m: JObject = ["g": .int(g), "st": b.get("st") ?? .null]
                    for k in ["recovering", "recoveredFrom"] { if let v = b.asObject?[JKey(k)] { m[JKey(k)] = v } }
                    top = .object(m)
                } else { top = .object(["g": .int(g), "st": .string("unreadable")]) }
            }
            let keep = names.filter { !$0.hasPrefix("state.lock.tmp-") && !$0.hasPrefix("state.probe-") && !$0.contains(".tmp-") }
            return .object(["t": .string("dir"), "files": .array(keep.map { .string(normName($0)) }), "journal": read("state.journal"), "head": read("state.head"), "fences": .array(fences), "top": top])
        }
        func so(_ v: JSONValue) -> JSONValue {
            switch v {
            case .string("$HOST"): return .string(host)
            case .string("$PID"): return .int(Int64(getpid()))
            case let .array(a): return .array(a.map(so))
            case let .object(o): return .object(o.mapValues(so))
            default: return v
            }
        }

        var out: [JSONValue] = []
        for (f, t) in sc.get("files")?.asObject ?? [:] { put(f.s, t) }
        for st in sc.get("steps")?.asArray ?? [] {
            switch st.get("t")?.asString ?? "" {
            case "write": put(st.get("file")?.asString ?? "", st.get("text")); out.append(.null)
            case "dir": out.append(snapshot())
            case "recover":
                let o = so(st.get("opts") ?? .object([:]))
                var holder: DurableExpectedHolder?
                if o.get("expectedHolder")?.asString == "unreadable" { holder = .unreadable }
                else if let h = o.get("expectedHolder"), h.isObject, let host = h.get("host")?.asString, h.get("pid")?.isNumber == true, let n = h.get("nonce")?.asString {
                    holder = .holder(host: host, pid: JS.toNumber(h.get("pid")), nonce: n)
                }
                do {
                    let r = try recoverDurableState(dir: d, force: (o.get("force") ?? .bool(true)) == .bool(true), expectedHolder: holder, legacyLock: o.get("legacyLock") == .bool(true))
                    var ok: JObject = ["released": .bool(r.released), "reason": .string(r.reason)]
                    if let lf = r.lockFile { ok["lockFile"] = .string(norm(lf)) }
                    out.append(.object(["ok": .object(ok)]))
                } catch let e as DurableStateError { out.append(err(e)) }
            case "open":
                let op = st.get("opts") ?? .object([:])
                var clock: Int64 = 1000
                var o = DurableStateOptions(dir: op.asObject?[JKey("dir")] != nil ? (op.get("dir")?.asString ?? "") : d, now: { clock += 1; return clock - 1 })
                if let label = op.get("hmacKey")?.asString { o.hmacKey = Canonical.sha256(Array(label.utf8)) }
                // `new Uint8Array(n)`: n zero bytes
                if let n = op.get("hmacKeyBytes")?.safeInt, n >= 0 { o.hmacKey = [UInt8](repeating: 0, count: Int(n)) }
                if let v = op.get("recoverFromCorruption") { o.recoverFromCorruption = v == .bool(true) }
                if let v = op.get("lockTimeoutMs").flatMap({ IV.num($0) }) { o.lockTimeoutMs = v }
                if let v = op.get("compactEvery")?.safeInt { o.compactEvery = Int(v) }
                if let v = op.get("maxValueBytes")?.safeInt { o.maxValueBytes = Int(v) }
                let h: DurableState
                do { h = try openDurableState(o) } catch let e as DurableStateError { out.append(err(e)); continue }
                var res: [JSONValue] = []
                var saved: [String: (JSONValue, JSONValue)] = [:]
                let undef: JSONValue = .object(["$undef": .bool(true)])
                for x in st.get("ops")?.asArray ?? [] {
                    do {
                        var v: JSONValue = .null
                        let key = x.get("key")?.asString ?? ""
                        switch x.get("op")?.asString ?? "" {
                        case "set": try h.set(key, x.get("value") ?? .null)
                        case "get": let r = try h.getPresent(key); v = (r.value == nil && !r.present) ? undef : (r.value ?? .null)
                        case "keys": v = .array(try h.keys().map { .string($0) })
                        case "verify": let p = try h.verify(); v = .object(["seq": .int(p.seq), "hash": .string(p.hash)])
                        case "position": let p = h.position(); v = .object(["seq": .int(p.seq), "hash": .string(p.hash)])
                        case "update":
                            let arg = x.get("arg") ?? .null
                            let r = try h.updateValuePresent(key) { p in
                                switch x.get("kind")?.asString ?? "" {
                                case "append": return .array((p?.asArray ?? []) + [arg])
                                case "max": return (p == nil || (IV.num(arg) ?? .nan) > (IV.num(p) ?? .nan)) ? arg : nil
                                case "noop": return nil
                                case "same": return p
                                default: return arg
                                }
                            }
                            v = (r.value == nil && !r.present) ? undef : (r.value ?? .null)
                        case "fs": put(x.get("file")?.asString ?? "", x.get("text"))
                        case "save": saved[x.get("name")?.asString ?? ""] = (read("state.journal"), read("state.head"))
                        case "restore":
                            if let (j, hd) = saved[x.get("name")?.asString ?? ""] { put("state.journal", j); put("state.head", hd) }
                        default: throw XCTSkip("unknown op")
                        }
                        res.append(.object(["ok": v]))
                    } catch let e as DurableStateError { res.append(err(e)) }
                }
                out.append(.object(["ok": .object(["recovered": .bool(h.recovered), "ops": .array(res)])]))
            default: throw XCTSkip("unknown step")
            }
        }
        out.append(snapshot())
        return .array(out)
    }

    /// The lock-timeout advice names the recovery call in the native's own call syntax (labelled arguments, no pointer to the TypeScript docs); this is a deliberate native
    /// difference. The native text is pinned exactly and renamed to the reference's, so the rest of the message is compared as usual.
    static func referenceRecoveryText(_ v: JSONValue) -> JSONValue {
        switch v {
        case let .string(s):
            return .string(s
                .replacingOccurrences(of: "recoverDurableState(dir:, force: true, legacyLock: true, expectedHolder:) after confirming the holder is dead",
                                      with: "recoverDurableState({ dir, force: true, legacyLock: true, expectedHolder }) after confirming the holder is dead; see the durable-state docs")
                .replacingOccurrences(of: "recoverDurableState(dir:, force: true, expectedHolder:) after confirming the holder is dead",
                                      with: "recoverDurableState({ dir, force: true, expectedHolder }) after confirming the holder is dead; see the durable-state docs"))
        case let .array(a): return .array(a.map(referenceRecoveryText))
        case let .object(o): return .object(o.mapValues(referenceRecoveryText))
        default: return v
        }
    }

    func testScenariosMatchTheReference() throws {
        var n = 0
        var bad: [String] = []
        try Base.each(Self.file, ["scenario"]) { c in
            n += 1
            let got = Self.referenceRecoveryText(try scenario(c.arg(0) ?? .null))
            if Base.canon(got) != Base.canon(c.out) { bad.append("\(c.name): \(Base.firstDiff(c.out, got, "@"))") }
        }
        XCTAssertGreaterThan(n, 200)
        XCTAssertTrue(bad.isEmpty, "\(bad.count) of \(n) scenarios differ from the TS reference:\n" + bad.prefix(20).joined(separator: "\n"))
    }

    // ---- the store as a store (no reference needed) ----

    func tmp() throws -> String {
        let d = NSTemporaryDirectory() + "pca-ds-\(UUID().uuidString)"
        try FileManager.default.createDirectory(atPath: d, withIntermediateDirectories: true)
        addTeardownBlock { try? FileManager.default.removeItem(atPath: d) }
        return d
    }

    func testReopenKeepsTheStateAndTheChainVerifies() throws {
        let d = try tmp()
        let a = try openDurableState(DurableStateOptions(dir: d))
        try a.set("k", .int(1))
        _ = try a.updateValue("n") { _ in .int(5) }
        let b = try openDurableState(DurableStateOptions(dir: d))
        XCTAssertEqual(try b.get("k"), .int(1))
        XCTAssertEqual(try b.keys(), ["k", "n"])
        XCTAssertEqual(try b.verify().seq, 2)
        XCTAssertEqual(PCADurableState.children(d).filter { $0.hasPrefix("state.lock.") && !$0.contains("tmp") }.isEmpty, false)
    }

    func testAnEditedJournalIsRefusedAndRecoveryQuarantinesIt() throws {
        let d = try tmp()
        let key = Canonical.sha256(Array("k".utf8))
        let a = try openDurableState(DurableStateOptions(dir: d, hmacKey: key))
        try a.set("k", .int(1))
        let jp = d + "/state.journal"
        let text = try String(contentsOfFile: jp, encoding: .utf8)
        try text.replacingOccurrences(of: "\\n1", with: "\\n2").write(toFile: jp, atomically: false, encoding: .utf8)
        XCTAssertThrowsError(try openDurableState(DurableStateOptions(dir: d, hmacKey: key))) { XCTAssertEqual(($0 as? DurableStateError)?.code, "corrupt") }
        let r = try openDurableState(DurableStateOptions(dir: d, hmacKey: key, recoverFromCorruption: true))
        XCTAssertTrue(r.recovered)
        XCTAssertNil(try r.get("k"))
        XCTAssertTrue(PCADurableState.children(d).contains { $0.contains(".quarantine-") })
    }

    func testAShortKeyAndABadKeyAreRefused() throws {
        let d = try tmp()
        XCTAssertThrowsError(try openDurableState(DurableStateOptions(dir: d, hmacKey: [1, 2, 3]))) { XCTAssertEqual(($0 as? DurableStateError)?.code, "invalid") }
        let a = try openDurableState(DurableStateOptions(dir: d))
        XCTAssertThrowsError(try a.set("a\nb", .int(1))) { XCTAssertEqual(($0 as? DurableStateError)?.code, "invalid") }
    }

    func testTheReplayStoreRunsOverTheDurableState() throws {
        let d = try tmp()
        let s = PCA.durablePcaStateStore(try openDurableState(DurableStateOptions(dir: d)))
        XCTAssertTrue(try s.claim(key: "g:h", counter: 1).ok)
        let again = PCA.durablePcaStateStore(try openDurableState(DurableStateOptions(dir: d)))
        XCTAssertFalse(try again.claim(key: "g:h", counter: 1).ok)
        XCTAssertTrue(try again.claim(key: "g:h", counter: 2).ok)
    }
}
