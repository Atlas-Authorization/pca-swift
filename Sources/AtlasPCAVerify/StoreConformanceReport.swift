import Foundation

/// The report side of pca-store-conformance (runner.ts, recorder.ts, harness.ts prng): folding a conformance run (`overall`), the text report with each violating
/// key's minimal counterexample (`formatReport`), its JSON form (`reportJson`), the recorder (in memory or an append-only file a killed client leaves torn),
/// the history parser and the deterministic workload PRNG. A report is the JSON object the runner produces:
/// `{adapter, status, tests: [{test, kind, status, ops, keys, errors, violations, unresolved, note?}]}`; a non-finite number travels as `{"$num": ...}`.
extension PCAStoreConformance {
    public static let ALL_TESTS = ["burst", "concurrent", "retention", "durability", "crash"]

    /// The folded status of a run: any fail is a fail, else any unresolved is unresolved, else pass (a test is a map with a `status`).
    public static func overall(_ tests: [JSONValue]) -> String {
        var unresolved = false
        for t in tests {
            let s = t.get("status")?.asString
            if s == "fail" { return "fail" }
            if s == "unresolved" { unresolved = true }
        }
        return unresolved ? "unresolved" : "pass"
    }

    private static func str(_ v: JSONValue?) -> String { JS.toString(v) }

    private static func padEnd(_ s: String, _ n: Int) -> String { s + String(repeating: " ", count: Swift.max(0, n - IV.u16(s))) }

    /// Human-readable report: one line per test, then each violating key's minimal counterexample (at most `maxKeys` per test).
    public static func formatReport(_ report: JSONValue, maxKeys: Int = 3) throws -> String {
        guard let r = report.asObject else { throw JSError("TypeError: cannot read properties of undefined (reading 'adapter')") }
        var out = ["pca-store-conformance: \(str(r["adapter"])) -> \(str(r["status"]).uppercased())"]
        for t in r["tests"]?.asArray ?? [] {
            let kind = t.get("kind")?.asString
            let opName = kind == "consume" ? "consumeOnce" : kind == "advance" ? "advance" : "undefined"
            let name = padEnd("\(str(t.get("test")))/\(opName)", 24)
            let status = str(t.get("status"))
            let stats = status == "skip" ? "" : "\(str(t.get("ops"))) ops, \(str(t.get("keys"))) keys, \(str(t.get("errors"))) errors/timeouts"
            let violations = t.get("violations")?.asArray ?? []
            var extra: [String] = []
            if !violations.isEmpty { extra.append("\(violations.count) NON-LINEARIZABLE key(s)") }
            if JS.truthy(t.get("unresolved")) { extra.append("\(str(t.get("unresolved"))) unresolved key(s) (over the search budget)") }
            if JS.truthy(t.get("note")) { extra.append(str(t.get("note"))) }
            let tail = [stats, extra.joined(separator: "; ")].filter { !$0.isEmpty }
            out.append("  [\(status.uppercased())] \(name) \(tail.joined(separator: "; "))")
            for v in violations.prefix(Swift.max(0, maxKeys)) {
                out.append("      key \(str(v.get("key"))) (\(str(v.get("ops"))) ops, decided by \(str(v.get("method")))): "
                           + (JS.truthy(v.get("minimized")) ? "minimal counterexample" : "violating history (not shrunk)") + ":")
                let ce = try (v.get("counterexample")?.asArray ?? []).map { try op(from: $0) }
                for line in formatOps(ce) { out.append("        \(line)") }
            }
        }
        return out.joined(separator: "\n")
    }

    /// `{"$num": ...}` becomes null (JSON.stringify writes a non-finite number as null).
    private static func decodeNums(_ v: JSONValue) -> JSONValue {
        switch v {
        case let .array(a): return .array(a.map(decodeNums))
        case let .object(o):
            if o.count == 1, o["$num"]?.asString != nil { return .null }
            var out: JObject = [:]
            for (k, x) in o { out[k] = decodeNums(x) }
            return .object(out)
        default: return v
        }
    }

    /// `JSON.stringify(v, null, 2)` (members in their written order).
    private static func pretty(_ v: JSONValue, _ indent: String) -> String {
        let inner = indent + "  "
        switch v {
        case let .array(a):
            if a.isEmpty { return "[]" }
            return "[\n" + a.map { inner + pretty($0, inner) }.joined(separator: ",\n") + "\n" + indent + "]"
        case let .object(o):
            if o.isEmpty { return "{}" }
            return "{\n" + JS.keyOrder(o).map { inner + JS.stringify(.string($0.s)) + ": " + pretty(o[$0] ?? .null, inner) }.joined(separator: ",\n") + "\n" + indent + "}"
        default: return JS.stringify(v)
        }
    }

    /// JSON-safe form of a report (Infinity becomes null), indented by two spaces.
    public static func reportJson(_ report: JSONValue) -> String { pretty(decodeNums(report), "") }

    // ---- recorder ----

    /// Wall-clock milliseconds with sub-millisecond resolution; comparable across threads (and processes on one host).
    public static func clock() -> Double { Date().timeIntervalSince1970 * 1000 }

    /// History recording. The invocation is recorded BEFORE the request leaves the client and the response after it completes. An operation that errors, times
    /// out or whose client dies keeps an open-ended interval (ret infinite, outcome unknown): it may or may not have taken effect, at any time after its invocation.
    public protocol Recorder: AnyObject {
        /// Record an invocation; the returned token identifies it in `complete`.
        func invoke(client: String, kind: String, key: String, lo: Double, w: Double) -> Int
        /// `true` / `false`: the definite answer; nil: the call failed or timed out (stays open-ended).
        func complete(_ token: Int, _ result: Bool?)
    }

    /// In memory (one process).
    public final class MemoryRecorder: Recorder, @unchecked Sendable {
        private var list: [Op] = []
        private let lock = PCALock()
        public init() {}

        public func ops() -> [Op] { lock.lock(); defer { lock.unlock() }; return list }

        public func invoke(client: String, kind: String, key: String, lo: Double, w: Double) -> Int {
            lock.lock(); defer { lock.unlock() }
            list.append(Op(client: client, kind: kind, key: key, lo: lo, w: w, call: PCAStoreConformance.clock(), ret: Double.infinity, res: "unknown"))
            return list.count - 1
        }

        public func complete(_ token: Int, _ result: Bool?) {
            guard let r = result else { return }
            let at = PCAStoreConformance.clock()
            lock.lock(); defer { lock.unlock() }
            list[token].ret = at
            list[token].res = r ? "true" : "false"
        }
    }

    /// Appends `i` / `r` lines to a file, one write per event, so a client that is killed (`kill()`) leaves its in-flight operations PENDING, exactly like a crash
    /// in production; torn lines are skipped by `parseHistory`.
    public final class FileRecorder: Recorder, @unchecked Sendable {
        private let handle: FileHandle
        private let proc: String
        private var ids: [Int64] = []
        private var seq: Int64 = 0
        private var killed = false
        private let lock = PCALock()

        public init(path: String, proc: String) throws {
            if !FileManager.default.fileExists(atPath: path) { FileManager.default.createFile(atPath: path, contents: nil) }
            guard let h = FileHandle(forWritingAtPath: path) else { throw JSError("FileRecorder: cannot open \(path)") }
            h.seekToEndOfFile()
            self.handle = h
            self.proc = proc
        }

        /// After a kill nothing more is written: whatever is in flight stays pending.
        public func kill() { lock.lock(); killed = true; lock.unlock() }

        public func close() { try? handle.close() }

        private func line(_ v: JSONValue) {
            if killed { return }
            handle.write(Data((JS.stringify(v) + "\n").utf8))
        }

        public func invoke(client: String, kind: String, key: String, lo: Double, w: Double) -> Int {
            lock.lock(); defer { lock.unlock() }
            seq += 1
            ids.append(seq)
            line(.array([.string("i"), .string(proc), .int(seq), PCAStoreConformance.numValue(PCAStoreConformance.clock()), .string(client), .string(kind), .string(key), PCAStoreConformance.numValue(lo), PCAStoreConformance.numValue(w)]))
            return ids.count - 1
        }

        public func complete(_ token: Int, _ result: Bool?) {
            lock.lock(); defer { lock.unlock() }
            let res: String = result.map { $0 ? "true" : "false" } ?? "unknown"
            line(.array([.string("r"), .string(proc), .int(ids[token]), PCAStoreConformance.numValue(PCAStoreConformance.clock()), .string(res)]))
        }
    }

    public struct ParsedHistory: Equatable {
        public var ops: [Op]
        public var torn: Int
        public var pending: Int
    }

    private static func jsNumber(_ v: JSONValue?) -> Double {
        switch v {
        case let .int(i)?: return Double(i)
        case let .double(d)?: return d
        case nil: return Double.nan
        case .null?: return 0
        case let .bool(b)?: return b ? 1 : 0
        case let .string(s)?: return IV.jsNumber(s)
        case .array?: return IV.jsNumber(JS.toString(v))
        case .object?: return Double.nan
        }
    }

    /// Rebuild the operations from recorder lines (any number of files concatenated). An invocation without a response is pending (unknown, open-ended); an
    /// `unknown` response stays open-ended too. Lines that do not parse are counted as torn.
    public static func parseHistory(_ text: String) -> ParsedHistory {
        var open: [String: Int] = [:]
        var ops: [Op] = []
        var torn = 0
        for line in IV.split(text, "\n") {
            if line.isEmpty { continue }
            guard let parsed = try? StrictJSON.parseLenient(line), let e = parsed.asArray else { torn += 1; continue }
            func at(_ i: Int) -> JSONValue? { i < e.count ? e[i] : nil }
            let id = JS.toString(at(1)) + "/" + JS.toString(at(2))
            if at(0) == .string("i") && e.count == 9 {
                open[id] = ops.count
                ops.append(Op(client: JS.toString(at(4)), kind: JS.toString(at(5)), key: JS.toString(at(6)), lo: jsNumber(at(7)), w: jsNumber(at(8)), call: jsNumber(at(3)),
                              ret: Double.infinity, res: "unknown"))
            } else if at(0) == .string("r") && e.count == 5, let i = open[id] {
                open[id] = nil
                if at(4) != .string("unknown") {
                    ops[i].ret = jsNumber(at(3))
                    ops[i].res = at(4) == .string("true") ? "true" : "false"
                }
            } else {
                torn += 1
            }
        }
        return ParsedHistory(ops: ops, torn: torn, pending: open.count)
    }

    public static func json(_ h: ParsedHistory) -> JSONValue {
        .object(["ops": .array(h.ops.map { json($0) }), "torn": .int(Int64(h.torn)), "pending": .int(Int64(h.pending))])
    }

    // ---- workload PRNG ----

    /// Deterministic PRNG (mulberry32): `rand(n)` is an integer in [0, n).
    public final class Prng {
        private var a: UInt32
        public init(seed: Double) {
            // `seed >>> 0`: ToUint32 (truncate toward zero, modulo 2^32; a non-finite value is 0)
            var t = seed < 0 ? seed.rounded(.up) : seed.rounded(.down)
            if t.isNaN || t.isInfinite { t = 0 }
            var m = t.truncatingRemainder(dividingBy: 4294967296)
            if m < 0 { m += 4294967296 }
            a = UInt32(m)
        }
        public func rand(_ n: Double) -> Double {
            a = a &+ 0x6d2b79f5
            var t = a
            t = (t ^ (t >> 15)) &* (t | 1)
            t ^= t &+ ((t ^ (t >> 7)) &* (t | 61))
            return (((Double(t ^ (t >> 14))) / 4294967296) * n).rounded(.down)
        }
    }
}
