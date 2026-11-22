import Foundation

/// The goal compiler: typecheck, compileGoal, decideGoal, decidePolicy and renderTape over token tapes, hand-ported from the proved
/// model (GoalKernelIr / GoalKernelTape / GoalKernelTypes / GoalKernelCompile / GoalKernelDecide hold the IR, the tape decoders and
/// encoders, the typing judgement, the lowering and the decision functions). A token tape is an array of `["k", n]`, `["i", n]` and
/// `["s", text]`; the first output token is `i0` ok, `i1` rejected with reasons, `i9` malformed input. All integers are exact (no
/// floating point); anything that does not parse is refused, never repaired.
public enum PCAGoalKernel {
    /// The kernel is part of the library; there is nothing to load.
    public static func available() -> Bool { return true }

    private static func safe(_ v: JSONValue?) throws -> Int64 {
        guard let i = GV.safeInt(v) else { throw IrError("goal tape: " + GV.jsStr(v) + " is not a safe integer") }
        return i
    }

    private static func toToks(_ tape: JSONValue?) throws -> [KTok] {
        guard let tape = tape, !tape.isNull else { return [] }
        guard let items = tape.asArray else { throw IrError("goal tape: array expected") }
        var out: [KTok] = []
        out.reserveCapacity(items.count)
        for o in items {
            guard let t = o.asArray, t.count == 2 else { throw IrError("goal tape: token expected") }
            let v: JSONValue = t[1]
            switch t[0].asString {
            case "k"?: out.append(.kw(try safe(v)))
            case "i"?: out.append(.i(try safe(v)))
            case "s"?:
                guard let s = v.asString else { throw IrError("goal tape: string token expected") }
                out.append(.s(s))
            default: throw IrError("goal tape: unknown token tag")
            }
        }
        return out
    }

    private static func tok(_ tag: String, _ v: JSONValue) -> JSONValue { return .array([.string(tag), v]) }

    private static func fromToks(_ ts: [KTok]) -> JSONValue {
        var out: [JSONValue] = []
        out.reserveCapacity(ts.count)
        for t in ts {
            switch t {
            case let .kw(k): out.append(tok("k", .int(k)))
            case let .i(i): out.append(tok("i", .int(i)))
            case let .s(s): out.append(tok("s", .string(s)))
            }
        }
        return .array(out)
    }

    private static func bad() -> [KTok] { return [.i(9)] }

    private static func reasonsTape(_ rs: [String]) -> [KTok] {
        var o: [KTok] = [.i(1)]
        KEnc.strings(&o, rs)
        return o
    }

    private static func exec(_ op: String, _ goal: JSONValue?, _ ont: JSONValue?, _ act: JSONValue?, _ hist: JSONValue?) throws -> [KTok] {
        switch op {
        case "typecheck", "compile", "render", "decideg", "decidep": break
        default: throw IrError("goal kernel: unknown op " + op)
        }
        let gt = try toToks(goal)
        let gOpt: KGoal? = try KDec.goal(gt)
        if op == "render" {
            guard let g = gOpt else { return bad() }
            return [.i(0)] + KEnc.goal(g)
        }
        let oOpt: KOntology? = try KDec.ontology(try toToks(ont))
        if op == "typecheck" || op == "compile" {
            guard let g = gOpt, let o = oOpt else { return bad() }
            if op == "typecheck" {
                let rs = KTypes.reasons(o, g)
                return rs.isEmpty ? [.i(0)] : reasonsTape(rs)
            }
            let c = KCompile.compile(o, g)
            guard let p = c.policy else { return reasonsTape(c.reasons) }
            return [.i(0)] + KCompile.encPol(p)
        }
        let aOpt: KAct? = try KDec.act(try toToks(act))
        let hOpt: KHist? = try KDec.hist(try toToks(hist))
        guard let g = gOpt, let o = oOpt, let a = aOpt, let h = hOpt else { return bad() }
        if op == "decideg" { return [.i(0), .i(Int64(KDecide.dg(o, g, a, h)))] }
        let c = KCompile.compile(o, g)
        guard let p = c.policy else { return reasonsTape(c.reasons) }
        let w = KDecide.decideW(p, a, h)
        var out: [KTok] = [.i(0), .i(Int64(w.decision)), .s(w.gid.text)]
        KEnc.strs(&out, w.bids)
        out.append(.i((w.decision == 2 && KDecide.verifyWitness(p, a, h, w)) ? 1 : 0))
        return out
    }

    /// One entry point over token tapes: op in typecheck, compile, decideg, decidep, render (act and hist are read by the decide ops).
    /// First output token: i0 ok, i1 rejected with reasons, i9 malformed input. A nil tape is the empty tape.
    public static func call(_ op: String, _ goal: JSONValue?, _ ont: JSONValue?, _ act: JSONValue?, _ hist: JSONValue?) throws -> JSONValue {
        return try onBigStack { return fromToks(try exec(op, goal, ont, act, hist)) }
    }

    private final class Box: @unchecked Sendable {
        var result: JSONValue? = nil
        var error: Error? = nil
    }

    /// Runs `body` on a thread with a large stack, so a deep tape does not overflow the caller's.
    private static func onBigStack(_ body: @escaping () throws -> JSONValue) throws -> JSONValue {
        let box = Box()
        let sem = DispatchSemaphore(value: 0)
        let t = Thread {
            KStack.mark()
            do { box.result = try body() } catch { box.error = error }
            sem.signal()
        }
        t.stackSize = KStack.size
        t.start()
        sem.wait()
        if let e = box.error { throw e }
        guard let r = box.result else { throw IrError("goal tape: no result") }
        return r
    }

    // ---- the typed front door (compiler.ts) ----

    private static func tokAt(_ t: [JSONValue], _ i: Int) throws -> [JSONValue] {
        guard i >= 0, i < t.count, let x = t[i].asArray, x.count == 2 else { throw IrError("malformed compiler output") }
        return x
    }

    private static func first(_ t: [JSONValue]) throws -> Int64 {
        let x = try tokAt(t, 0)
        if x[0].asString != "i" { throw IrError("malformed compiler output") }
        return try safe(x[1])
    }

    private static func at(_ t: [JSONValue], _ i: Int) throws -> Int64 { return try safe(try tokAt(t, i)[1]) }

    private static func str(_ t: [JSONValue], _ i: Int) throws -> String {
        let x = try tokAt(t, i)
        if x[0].asString == "s" { return x[1].asString ?? "" }
        return ""
    }

    private static func count(_ n: Int64, _ t: [JSONValue], _ from: Int) throws -> Int {
        if n < 0 || n > Int64(t.count) || from + Int(n) > t.count { throw IrError("malformed compiler output") }
        return Int(n)
    }

    private static func reasons(_ t: [JSONValue]) throws -> [String] {
        var n = 0
        if t.count > 1 { n = try count(try at(t, 1), t, 2) }
        var out: [String] = []
        for i in 0..<n { out.append(try str(t, 2 + i)) }
        return out
    }

    private static func decision(_ n: Int64) -> String { return n == 2 ? "allow" : (n == 1 ? "escalate" : "deny") }

    private static func tape(_ v: JSONValue) throws -> [JSONValue] {
        guard let a = v.asArray else { throw IrError("malformed compiler output") }
        return a
    }

    /// Type reasons of a goal against an ontology; empty = well typed.
    public static func typecheck(_ goal: JSONValue, _ ont: JSONValue) throws -> [String] {
        let out = try tape(try call("typecheck", try PCAGoalCodec.encodeGoal(goal), try PCAGoalCodec.encodeOntology(ont), nil, nil))
        let s = try first(out)
        if s == 0 { return [] }
        if s == 1 { return try reasons(out) }
        throw IrError("compiler rejected the input tape")
    }

    /// C: Goal -> {ok: true, policy} | {ok: false, reasons}. Ill-typed goals are rejected, never coerced.
    public static func compileGoal(_ goal: JSONValue, _ ont: JSONValue) throws -> JSONValue {
        let out = try tape(try call("compile", try PCAGoalCodec.encodeGoal(goal), try PCAGoalCodec.encodeOntology(ont), nil, nil))
        let s = try first(out)
        if s == 0 { return GV.obj([("ok", .bool(true)), ("policy", try PCAGoalCodec.decodePolicy(.array(Array(out[1...]))))]) }
        if s == 1 { return GV.obj([("ok", .bool(false)), ("reasons", .array(try reasons(out).map { JSONValue.string($0) }))]) }
        throw IrError("compiler rejected the input tape")
    }

    /// The reference semantics D_G(a, H): "allow" | "escalate" | "deny".
    public static func decideGoal(_ goal: JSONValue, _ ont: JSONValue, _ act: JSONValue, _ hist: JSONValue) throws -> String {
        let out = try tape(try call("decideg", try PCAGoalCodec.encodeGoal(goal), try PCAGoalCodec.encodeOntology(ont),
                                    try PCAGoalCodec.encodeAct(act), try PCAGoalCodec.encodeHist(hist)))
        if try first(out) != 0 { throw IrError("compiler rejected the input tape") }
        return decision(try at(out, 1))
    }

    /// The compiled policy's decision: {ok: false, reasons} | {ok: true, decision, witness (null unless allow), witnessChecked}.
    public static func decidePolicy(_ goal: JSONValue, _ ont: JSONValue, _ act: JSONValue, _ hist: JSONValue) throws -> JSONValue {
        let out = try tape(try call("decidep", try PCAGoalCodec.encodeGoal(goal), try PCAGoalCodec.encodeOntology(ont),
                                    try PCAGoalCodec.encodeAct(act), try PCAGoalCodec.encodeHist(hist)))
        let s = try first(out)
        if s == 1 { return GV.obj([("ok", .bool(false)), ("reasons", .array(try reasons(out).map { JSONValue.string($0) }))]) }
        if s != 0 { throw IrError("compiler rejected the input tape") }
        let d = decision(try at(out, 1))
        let n = try count(try at(out, 3), out, 4)
        var bids: [JSONValue] = []
        for i in 0..<n { bids.append(.string(try str(out, 4 + i))) }
        var w: JSONValue = .null
        if d == "allow" { w = GV.obj([("gid", .string(try str(out, 2))), ("bids", .array(bids))]) }
        return GV.obj([("ok", .bool(true)), ("decision", .string(d)), ("witness", w), ("witnessChecked", .bool(try at(out, 4 + n) == 1))])
    }

    /// The card as a token tape: `PCAGoalCodec.decodeGoal(renderTape(g))` equals g.
    public static func renderTape(_ goal: JSONValue) throws -> JSONValue {
        let out = try tape(try call("render", try PCAGoalCodec.encodeGoal(goal), nil, nil, nil))
        if try first(out) != 0 { throw IrError("goal tape rejected") }
        return .array(Array(out[1...]))
    }

    /// The review kernel of the reference (`provedKernel`): compile, policy digest and the reference decision.
    public struct ProvedKernel: PCAGoalReviewKernel {
        public init() {}
        public func compile(_ goal: JSONValue, _ ont: JSONValue) throws -> JSONValue { try PCAGoalKernel.compileGoal(goal, ont) }
        public func policyDigest(_ policy: JSONValue) throws -> String { try PCAGoalCompiler.policyDigest(policy) }
        public func canDecide() -> Bool { true }
        public func decide(_ goal: JSONValue, _ ont: JSONValue, _ act: JSONValue, _ hist: JSONValue) throws -> String {
            try PCAGoalKernel.decideGoal(goal, ont, act, hist)
        }
    }

    public static func provedKernel() -> PCAGoalReviewKernel { ProvedKernel() }

    // ---- harness text syntax (kN, iN, s<hex>.<hex>...) ----

    /// A tape in the differential-harness syntax.
    public static func tapeToText(_ tape: JSONValue) throws -> String {
        guard let items = tape.asArray else { throw IrError("goal tape: array expected") }
        var parts: [String] = []
        for o in items {
            guard let t = o.asArray, t.count == 2, let tag = t[0].asString else { throw IrError("goal tape: token expected") }
            if tag == "s" {
                guard let s = t[1].asString else { throw IrError("goal tape: string token expected") }
                var hex: [String] = []
                for c in s.unicodeScalars { hex.append(String(c.value, radix: 16)) }
                parts.append("s" + hex.joined(separator: "."))
            } else {
                parts.append(tag + String(try safe(t[1])))
            }
        }
        return parts.joined(separator: " ")
    }

    private static func splitScalars(_ s: String, _ sep: Unicode.Scalar) -> [String] {
        var out: [String] = []
        var cur = String.UnicodeScalarView()
        for c in s.unicodeScalars {
            if c == sep { out.append(String(cur)); cur = String.UnicodeScalarView() } else { cur.append(c) }
        }
        out.append(String(cur))
        return out
    }

    /// Parse the differential-harness syntax. A hex value that is not a Unicode scalar (a lone surrogate) is refused: a Swift String cannot hold one.
    public static func tapeFromText(_ s: String) throws -> JSONValue {
        var out: [JSONValue] = []
        for x in splitScalars(s, " ") {
            if x.isEmpty { continue }
            let sc = Array(x.unicodeScalars)
            let b = String(String.UnicodeScalarView(sc[1...]))
            let c = sc[0]
            if c == "k" || c == "i" {
                guard let n = Int64(b) else { throw IrError("goal tape text: bad token " + x) }
                out.append(tok(String(c), .int(n)))
            } else if c == "s" {
                var sv = String.UnicodeScalarView()
                if !b.isEmpty {
                    for h in splitScalars(b, ".") {
                        guard let v = UInt32(h, radix: 16), let u = Unicode.Scalar(v) else { throw IrError("goal tape text: bad code point in " + x) }
                        sv.append(u)
                    }
                }
                out.append(tok("s", .string(String(sv))))
            } else {
                throw IrError("goal tape text: bad token " + x)
            }
        }
        return .array(out)
    }
}
