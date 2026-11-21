import Foundation

/// The typed front door of the proved goal compiler. Every function is a thin wrapper over a kernel entry point
/// (`PCAGoalKernel.call` over token tapes); there is no decision logic here. The policy canonical form and digest are pure.
public enum PCAGoalCompiler {
    private static func malformed() -> IrError { return IrError("malformed compiler output") }

    /// A tape token's value member.
    private static func tokVal(_ t: [JSONValue], _ i: Int) throws -> JSONValue {
        guard i >= 0, i < t.count, let x = t[i].asArray, x.count == 2 else { throw malformed() }
        return x[1]
    }

    private static func tokInt(_ t: [JSONValue], _ i: Int) throws -> Int64 {
        guard let n = GV.safeInt(try tokVal(t, i)) else { throw IrError("goal tape: not a safe integer") }
        return n
    }

    private static func tokStr(_ t: [JSONValue], _ i: Int) throws -> String {
        guard i >= 0, i < t.count, let x = t[i].asArray, x.count == 2 else { throw malformed() }
        if let tag = x[0].asString, IV.same(tag, "s") { return x[1].asString ?? "" }
        return ""
    }

    private static func first(_ t: [JSONValue]) throws -> Int64 {
        guard let x = t.first?.asArray, x.count == 2, let tag = x[0].asString, IV.same(tag, "i") else { throw malformed() }
        guard let n = GV.safeInt(x[1]) else { throw IrError("goal tape: not a safe integer") }
        return n
    }

    private static func reasonsOf(_ t: [JSONValue]) throws -> [String] {
        let n: Int = t.count > 1 ? Int(try tokInt(t, 1)) : 0
        if n < 0 || 2 + n > t.count { throw malformed() }
        var out: [String] = []
        for i in 2..<(2 + n) { out.append(try tokStr(t, i)) }
        return out
    }

    private static func decision(_ n: Int64) -> String { return n == 2 ? "allow" : (n == 1 ? "escalate" : "deny") }

    private static func run(_ op: String, _ goal: JSONValue, _ ont: JSONValue?, _ act: JSONValue?, _ hist: JSONValue?) throws -> [JSONValue] {
        let r = try PCAGoalKernel.call(op, goal, ont, act, hist)
        guard let a = r.asArray else { throw malformed() }
        return a
    }

    /// Type reasons of a goal against an ontology; empty = well typed. A malformed tape throws.
    public static func typecheck(_ goal: JSONValue, _ ont: JSONValue) throws -> [String] {
        let out = try run("typecheck", try PCAGoalCodec.encodeGoal(goal), try PCAGoalCodec.encodeOntology(ont), nil, nil)
        let s = try first(out)
        if s == 0 { return [] }
        if s == 1 { return try reasonsOf(out) }
        throw IrError("compiler rejected the input tape")
    }

    /// C: Goal -> {ok: true, policy} | {ok: false, reasons}. Ill-typed goals are rejected, never coerced.
    public static func compileGoal(_ goal: JSONValue, _ ont: JSONValue) throws -> JSONValue {
        let out = try run("compile", try PCAGoalCodec.encodeGoal(goal), try PCAGoalCodec.encodeOntology(ont), nil, nil)
        let s = try first(out)
        if s == 0 {
            let policy = try PCAGoalCodec.decodePolicy(JSONValue.array(Array(out.dropFirst())))
            return GV.obj([("ok", JSONValue.bool(true)), ("policy", policy)])
        }
        if s == 1 {
            return GV.obj([("ok", JSONValue.bool(false)), ("reasons", JSONValue.array(try reasonsOf(out).map { JSONValue.string($0) }))])
        }
        throw IrError("compiler rejected the input tape")
    }

    /// The reference semantics D_G(a, H): "allow" | "escalate" | "deny".
    public static func decideGoal(_ goal: JSONValue, _ ont: JSONValue, _ act: JSONValue, _ hist: JSONValue) throws -> String {
        let out = try run("decideg", try PCAGoalCodec.encodeGoal(goal), try PCAGoalCodec.encodeOntology(ont),
                          try PCAGoalCodec.encodeAct(act), try PCAGoalCodec.encodeHist(hist))
        if try first(out) != 0 { throw IrError("compiler rejected the input tape") }
        return decision(try tokInt(out, 1))
    }

    /// The compiled policy's decision: {ok: false, reasons} | {ok: true, decision, witness (null unless allow), witnessChecked}.
    public static func decidePolicy(_ goal: JSONValue, _ ont: JSONValue, _ act: JSONValue, _ hist: JSONValue) throws -> JSONValue {
        let out = try run("decidep", try PCAGoalCodec.encodeGoal(goal), try PCAGoalCodec.encodeOntology(ont),
                          try PCAGoalCodec.encodeAct(act), try PCAGoalCodec.encodeHist(hist))
        let s = try first(out)
        if s == 1 {
            return GV.obj([("ok", JSONValue.bool(false)), ("reasons", JSONValue.array(try reasonsOf(out).map { JSONValue.string($0) }))])
        }
        if s != 0 { throw IrError("compiler rejected the input tape") }
        let d = decision(try tokInt(out, 1))
        let n = Int(try tokInt(out, 3))
        if n < 0 || 4 + n >= out.count { throw malformed() }
        var bids: [JSONValue] = []
        for i in 4..<(4 + n) { bids.append(JSONValue.string(try tokStr(out, i))) }
        var w: JSONValue = JSONValue.null
        if d == "allow" { w = GV.obj([("gid", JSONValue.string(try tokStr(out, 2))), ("bids", JSONValue.array(bids))]) }
        let checked = try tokInt(out, 4 + n) == 1
        return GV.obj([("ok", JSONValue.bool(true)), ("decision", JSONValue.string(d)), ("witness", w), ("witnessChecked", JSONValue.bool(checked))])
    }

    /// The goal as a token tape: `decodeGoal(renderTape(g))` equals g.
    public static func renderTape(_ goal: JSONValue) throws -> JSONValue {
        let out = try run("render", try PCAGoalCodec.encodeGoal(goal), nil, nil, nil)
        if try first(out) != 0 { throw IrError("goal tape rejected") }
        return JSONValue.array(Array(out.dropFirst()))
    }

    /// Canonical bytes of a policy (sorted-key JSON, no floats): the input of the policy digest.
    public static func canonicalPolicy(_ p: JSONValue) -> String { return PCAGoalNormalize.stable(p) }

    public static func policyDigest(_ p: JSONValue) -> String {
        return Base64URLStrict.encode(Canonical.sha256(Canonical.utf8(canonicalPolicy(p))))
    }
}
