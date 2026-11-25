import Foundation

/// The structural half of the undo-window engine over action definitions: the class of a reversibility declaration for concrete params,
/// whether any value of it is reversible, and whether a compensating action can undo another without the agent's help (derived, never
/// authored by the agent). The confirmation-gated engine (`ActionUndoEngine`) sits on top of these.
public enum ActionUndo {
    /// The class of a reversibility declaration for concrete params (an unmapped or absent value takes `default`, else irreversible).
    public static func reversibilityFor(_ d: JObject, _ params: JObject) throws -> String {
        let r = try Actions.normalize(d)["reversibility"]
        if let s = r?.asString { return s }
        guard let by = r?.get("by")?.asString else { throw AK.fail("bad_def", "reversibility.by") }
        var k: String?
        switch params[JKey(by)] {
        case let .string(s)?: k = s
        case let .bool(b)?: k = b ? "true" : "false"
        case let v? where IV.int(v) != nil: k = JS.toString(v)
        default: k = nil
        }
        if let k = k, let m = AK.o(r?.get("map"))[JKey(k)] {
            guard let s = m.asString else { throw AK.fail("bad_def", "reversibility.map") }
            return s
        }
        if let df = AK.pres(AK.o(r), "default") {
            guard let s = df.asString else { throw AK.fail("bad_def", "reversibility.default") }
            return s
        }
        return "irreversible"
    }

    /// True when some value of the declaration is `reversible` (a fixed class, a map value or the default).
    public static func mayBeReversible(_ d: JObject) -> Bool {
        guard let r = AK.pres(d, "reversibility") else { return false }
        if let s = r.asString { return s == "reversible" }
        return AK.o(r.get("map")).values.contains(.string("reversible")) || r.get("default") == .string("reversible")
    }

    private static func sameType(_ a: JSONValue?, _ b: JObject) -> Bool {
        guard let a = JS.present(a) else { return false }
        return a.get("type") == b["type"] && AK.pres(AK.o(a), "items") == AK.pres(b, "items")
    }

    private static func isReadOnly(_ effects: JSONValue?) -> Bool {
        guard let e = effects?.asArray, !e.isEmpty else { return false }
        return e.allSatisfy { $0 == .string("read") }
    }

    /// Can `comp` undo `orig`? `{ok: true, shape: {copied, target?}}` or `{ok: false, reason}`.
    public static func compensationShape(_ orig: JObject, _ comp: JObject) throws -> JSONValue {
        let cv = JS.toString(comp["verb"])
        if isReadOnly(comp["effects"]) { return AK.obj(["ok": .bool(false), "reason": .string("the compensating action \(cv) only reads")]) }
        guard let ct = AK.o(comp["resource"])["type"]?.asString, let ot = AK.o(orig["resource"])["type"]?.asString else { throw AK.fail("bad_def", "resource.type") }
        if ct != ot { return AK.obj(["ok": .bool(false), "reason": .string("the compensating action \(cv) acts on \(ct), not \(ot)")]) }
        let nc = try Actions.normalize(comp)
        var copied: [JSONValue] = []
        var target: String?
        let idemO = AK.o(nc["idempotency"])
        let idem: String? = idemO["mode"]?.asString == "key_param" ? idemO["param"]?.asString : nil
        let origParams = AK.o(orig["params"])
        let ncp = AK.o(nc["params"])
        for name in AK.sortedKeys(ncp) {
            let p = AK.o(ncp[JKey(name)])
            if name == idem { continue }
            if sameType(origParams[JKey(name)], p) { copied.append(.string(name)); continue }
            if p["required"] != .bool(true) { continue }
            if p["role"] == .string("id.\(ct)") && target == nil { target = name; continue }
            return AK.obj(["ok": .bool(false), "reason": .string("the compensating action \(cv) needs '\(name)', which neither the original call nor its result supplies")])
        }
        var shape: JObject = ["copied": .array(copied)]
        if let t = target { shape["target"] = .string(t) }
        return AK.obj(["ok": .bool(true), "shape": .object(shape)])
    }
}

/// The undo-window engine over action definitions. Reversibility counts only when it is CONFIRMED: the definition carries a valid signed review by a
/// pinned reviewer key, its effective class (declared joined with every trait floor, and for value-dependent reversibility the class of THESE params) is
/// `reversible`, and it names a compensating action that is itself confirmed and can be derived before the effect runs. The compensating call is
/// derived, never authored by the agent. Anything it cannot decide is "not undoable" (a nil plan).
public final class ActionUndoEngine {
    private var byVerb: [JKey: JObject] = [:]
    private let reg: TraitRegistry
    private let verified: ((JObject) -> Bool)?

    public init(defs: [JSONValue], verified: ((JObject) -> Bool)?, registry: TraitRegistry = Actions.coreRegistry) {
        for d in defs { if let v = d.get("verb")?.asString, byVerb[JKey(v)] == nil { byVerb[JKey(v)] = AK.o(d) } }
        self.verified = verified
        self.reg = registry
    }

    /// The engine over pinned reviewer keys (`pins` nil: nothing is confirmed).
    public static func undoEngine(defs: [JSONValue], pins: JSONValue?, registry: TraitRegistry = Actions.coreRegistry) -> ActionUndoEngine {
        ActionUndoEngine(defs: defs, verified: pins == nil || pins == .null ? nil : attestationVerifier(pins, registry), registry: registry)
    }

    /// The attestation check a pinned-reviewer engine uses. Never throws.
    public static func attestationVerifier(_ pins: JSONValue?, _ reg: TraitRegistry) -> (JObject) -> Bool { { d in Actions.isConfirmed(d, reg, pins) } }

    private func confirmed(_ d: JObject) -> Bool { ActionEffective.isConfirmed(d, verified) }

    /// The plan `{def_digest, compensation: {verb, params, def_digest, target_param?}, render, render_digest}` for an operation `{verb, params?}`, or nil.
    public func plan(_ op: JObject) -> JSONValue? {
        do {
            guard let verb = op["verb"]?.asString else { return nil }
            let params = AK.o(op["params"])
            guard let d = byVerb[JKey(verb)], confirmed(d), !(Actions.isReadOnly(Actions.strings(d["effects"]) ?? [])), let cv = AK.pres(d, "compensates") else { return nil }
            let eff = AK.o(try ActionEffective.effective(d, reg, verified)["eff"])
            guard eff["rev"] == .string("reversible"), try ActionUndo.reversibilityFor(d, params) == "reversible" else { return nil }
            guard let cname = cv.asString, let c = byVerb[JKey(cname)], confirmed(c) else { return nil }
            let s = try ActionUndo.compensationShape(d, c)
            guard s.get("ok") == .bool(true) else { return nil }
            let shape = AK.o(s.get("shape"))
            var cparams: JObject = [:]
            let nc = AK.o(try Actions.normalize(c)["params"])
            for k0 in AK.arr(shape["copied"]) {
                guard let k = k0.asString else { return nil }
                if let pv = params[JKey(k)] { cparams[JKey(k)] = pv }
                else if AK.o(nc[JKey(k)])["required"] == .bool(true) { return nil }
            }
            let render = try Approval.render(def: d, params: .object(params), confirmed: confirmed(d))
            var comp: JObject = ["verb": c["verb"] ?? .null, "params": .object(cparams), "def_digest": .string(try Actions.defDigest(c))]
            if let t = shape["target"] { comp["target_param"] = t }
            guard let rd = Approval.renderDigest(render) else { return nil }
            return AK.obj(["def_digest": .string(try Actions.defDigest(d)), "compensation": .object(comp), "render": render, "render_digest": .string(rd)])
        } catch {
            return nil
        }
    }
}
