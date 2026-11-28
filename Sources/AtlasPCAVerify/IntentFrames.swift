import Foundation

/// Small JSON-tree accessors shared by the compiler, frame, refinement and semantic-judge modules: a value that is not the expected
/// shape is a thrown refusal (the reference's casts), numbers are binary64.
enum IntentTree {
    static func obj(_ v: JSONValue?) throws -> JObject {
        guard let o = v?.asObject else { throw JSError("not an object") }
        return o
    }

    static func arr(_ v: JSONValue?) throws -> [JSONValue] {
        guard let a = v?.asArray else { throw JSError("not an array") }
        return a
    }

    static func dbl(_ v: JSONValue?) throws -> Double {
        guard let d = IV.num(v) else { throw JSError("not a number") }
        return d
    }

    static func str(_ v: JSONValue?) throws -> String {
        guard let s = v?.asString else { throw JSError("not a string") }
        return s
    }

    /// A member that is absent or JSON null is "no value".
    static func present(_ v: JSONValue?) -> JSONValue? {
        if let x = v, !x.isNull { return x }
        return nil
    }

    /// Equality of two members where absent and JSON null are the same and primitives compare by type and value.
    static func eq(_ a: JSONValue?, _ b: JSONValue?) -> Bool {
        let x = present(a), y = present(b)
        if x == nil && y == nil { return true }
        guard let p = x, let q = y else { return false }
        return IV.strictEq(p, q)
    }

    static func jsonNumber(_ d: Double) -> JSONValue { WJ.plain(.double(d)) }
}

/// Frame and side-effect constraints: the monitored state of a site, a per-verb write set, and postconditions over the pre- and
/// post-state and the site's effect record. By default intent is frame-closed: a monitored variable outside the write set must not
/// change unless the site's log attributes the change to another actor. A violation is a negative runtime observation (it vetoes the
/// cell). Specs, snapshots and reports are JSON trees. A parsed object has no member order, so the pre- and post-state paths are
/// nested in code-point order of their names (it matters only when one name is a dotted prefix of another).
public enum PCAIntentFrames {
    public static let FRAME_STATE_DOMAIN = "atlas-pca/intent-frame-state/v1"

    /// Digest of a state value (site-local: the lenient canonical form; an absent value is null).
    public static func stateDigest(_ value: JSONValue?) -> String {
        let m: JSONValue = .object(["d": .string(FRAME_STATE_DOMAIN), "v": value ?? .null])
        let text = Canonical.canonicalize(IV.normalized(m))
        return Base64URLStrict.encode(Canonical.sha256(Canonical.utf8(text)))
    }

    /// Snapshot already-read values: variable to {digest, value?}.
    public static func snapshotState(_ values: JSONValue, _ keepValues: Bool) throws -> JSONValue {
        let src = try IntentTree.obj(values)
        var out = JObject()
        for (k, v) in src {
            var s: JObject = ["digest": .string(stateDigest(v))]
            if keepValues { s["value"] = v }
            out[k] = .object(s)
        }
        return .object(out)
    }

    /// Read every monitored variable through its reader (sorted by name) and snapshot it: the middleware hook, called before and after
    /// the action.
    public static func captureState(_ readers: [String: () -> JSONValue?], _ keepValues: Bool) throws -> JSONValue {
        let names = readers.keys.sorted { Canonical.compareUtf8($0, $1) < 0 }
        var values = JObject()
        for k in names {
            guard let reader = readers[k] else { continue }
            values[JKey(k)] = reader() ?? .null
        }
        return try snapshotState(.object(values), keepValues)
    }

    /// `^(0|[1-9][0-9]{0,8})$`
    private static func isIndex(_ s: String) -> Bool {
        let b = Array(s.utf8)
        if b.isEmpty || b.count > 9 { return false }
        for c in b where c < 48 || c > 57 { return false }
        return b.count == 1 || b[0] != 48
    }

    private static func step(_ cur: JSONValue?, _ s: String) -> (found: Bool, value: JSONValue?) {
        if let o = cur?.asObject {
            if let v = o[JKey(s)] { return (true, v) }
            return (false, nil)
        }
        if let a = cur?.asArray, isIndex(s), let n = Int(s), n < a.count { return (true, a[n]) }
        return (false, nil)
    }

    private static func get(_ root: JSONValue?, _ path: String) -> JSONValue? {
        var cur = root
        for s in IV.split(path, ".") {
            let r = step(cur, s)
            if !r.found { return nil }
            cur = r.value
        }
        return cur
    }

    private static func present(_ root: JSONValue?, _ path: String) -> Bool {
        var cur = root
        for s in IV.split(path, ".") {
            let r = step(cur, s)
            if !r.found { return false }
            cur = r.value
        }
        return true
    }

    /// W(action): the declared write list, or the parameter-selected list (an unknown parameter value: the default, else empty).
    public static func writeSetOf(_ spec: JSONValue, _ action: JSONValue) throws -> [String] {
        let writes = try IntentTree.obj(spec.get("writes"))
        let verb = action.get("verb")
        var d: JSONValue?
        if let v = verb?.asString, let w = writes[JKey(v)] { d = w }
        var out: [String] = []
        guard let dv = d, !dv.isNull else { return out }
        if let list = dv.asArray {
            for x in list { out.append(try IntentTree.str(x)) }
            return out
        }
        let dm = try IntentTree.obj(dv)
        let param = try IntentTree.str(dm["param"])
        let params: JSONValue = IntentTree.present(action.get("params")) ?? .object([:])
        let prefix = "action.params."
        let v = get(params, IV.startsWith(param, prefix) ? IV.dropPrefix(param, prefix.unicodeScalars.count) : param)
        var key: String?
        switch v {
        case let .string(s)?: key = s
        case let .bool(b)?: key = b ? "true" : "false"
        case .int?, .double?: key = JS.toString(v)
        default: key = nil
        }
        let map = try IntentTree.obj(dm["map"])
        var chosen: JSONValue?
        if let k = key, let m = map[JKey(k)] { chosen = m } else { chosen = dm["default"] }
        if let c = chosen, !c.isNull { for x in try IntentTree.arr(c) { out.append(try IntentTree.str(x)) } }
        return out
    }

    private static func envReads(_ c: JSONValue?, _ out: inout [String]) {
        guard let o = c?.asObject else { return }
        if o[JKey("all_of")] != nil || o[JKey("any_of")] != nil || o[JKey("not")] != nil {
            if let a = o[JKey("all_of")]?.asArray { for x in a { envReads(x, &out) } }
            else if let a = o[JKey("any_of")]?.asArray { for x in a { envReads(x, &out) } }
            else if let n = o[JKey("not")] { envReads(n, &out) }
            return
        }
        if let f = o[JKey("field")]?.asString {
            if IV.startsWith(f, "env.") { out.append(f) }
            if let ref = o[JKey("ref")]?.asString, IV.startsWith(ref, "env.") { out.append(ref) }
        }
    }

    private static func setNested(_ node: JSONValue, _ segs: ArraySlice<String>, _ value: JSONValue) -> JSONValue {
        guard let first = segs.first else { return value }
        var o = node.asObject ?? JObject()
        if segs.count == 1 { o[JKey(first)] = value; return .object(o) }
        o[JKey(first)] = setNested(o[JKey(first)] ?? .null, segs.dropFirst(), value)
        return .object(o)
    }

    private static func nest(_ s: JObject) throws -> JSONValue {
        var root: JSONValue = .object([:])
        for k in JS.keyOrder(s) {
            let v = try IntentTree.obj(s[k])
            guard let value = v[JKey("value")] else { continue }
            root = setNested(root, IV.split(k.s, ".")[...], value)
        }
        return root
    }

    private static func uniqSorted(_ xs: [String]) -> [String] {
        var seen = Set<JKey>()
        var out: [String] = []
        for x in xs where seen.insert(JKey(x)).inserted { out.append(x) }
        return out.sorted { Canonical.compareUtf8($0, $1) < 0 }
    }

    private static func jsonStrings(_ xs: [String]) -> JSONValue { .array(xs.map { .string($0) }) }

    /// Check one executed action: the frame condition over the monitored state outside its write set and the verb's postconditions.
    /// `opts`: effect?, attributions? ([{var, actor}]), self?. Returns {status, outOfFrame, attributed, postViolated, missing, unmonitored};
    /// never throws.
    public static func checkFrame(_ specO: JSONValue?, _ actionO: JSONValue?, _ preO: JSONValue?, _ postO: JSONValue?, _ opts: JSONValue?) -> JSONValue {
        var outOfFrame: [String] = []
        var attributed: [String] = []
        var postViolated: [String] = []
        var missing: [String] = []
        var unmonitored = false
        do {
            guard let spec = specO, spec.isObject, spec.get("state")?.isArray == true, let action = actionO, action.isObject,
                  let preV = preO, let pre = preV.asObject, let postV = postO, let post = postV.asObject else {
                throw JSError("spec, action, pre and post must be objects (spec.state an array)")
            }
            let state = try IntentTree.arr(spec.get("state"))
            unmonitored = state.isEmpty
            let w = Set(try writeSetOf(spec, action).map { JKey($0) })
            let sortedState = try state.map { try IntentTree.str($0) }.sorted { Canonical.compareUtf8($0, $1) < 0 }
            var attrs: [JSONValue] = []
            if let a = IntentTree.present(opts?.get("attributions")) { attrs = try IntentTree.arr(a) }
            let selfActor = opts?.get("self")
            for v in sortedState {
                if w.contains(JKey(v)) { continue }
                guard let a = IntentTree.present(pre[JKey(v)]), let b = IntentTree.present(post[JKey(v)]) else { missing.append(v); continue }
                if IntentTree.eq(try IntentTree.obj(a)["digest"], try IntentTree.obj(b)["digest"]) { continue }
                var other = false
                for xo in attrs {
                    let x = try IntentTree.obj(xo)
                    if IntentTree.eq(x["var"], .string(v)) && !IntentTree.eq(x["actor"], selfActor) { other = true }
                }
                if other { attributed.append(v) } else { outOfFrame.append(v) }
            }
            let envPre = try nest(pre)
            let envPost = try nest(post)
            let effect: JSONValue = IntentTree.present(opts?.get("effect")) ?? .object([:])
            let env: JSONValue = .object(["pre": envPre, "post": envPost, "effect": effect])
            let params: JSONValue = IntentTree.present(action.get("params")) ?? .object([:])
            var act = JObject()
            if let v = action.get("verb") { act["verb"] = v }
            if let r = action.get("resource") { act["resource"] = r }
            act["params"] = params
            let ctx: JSONValue = .object(["action": .object(act), "env": env])
            let envRoot: JSONValue = .object(["env": env])
            let posts: [JSONValue] = try IntentTree.present(spec.get("post")) == nil ? [] : IntentTree.arr(spec.get("post"))
            for pco in posts {
                let pc = try IntentTree.obj(pco)
                if !IntentTree.eq(pc["verb"], action.get("verb")) { continue }
                var pending = false
                let deltas: [JSONValue] = try IntentTree.present(pc["deltas"]) == nil ? [] : IntentTree.arr(pc["deltas"])
                for dO in deltas {
                    let d = try IntentTree.obj(dO)
                    let path = try IntentTree.str(d["path"])
                    let x = get(envPre, path)
                    let y = get(envPost, path)
                    if !(x?.isNumber ?? false) || !(y?.isNumber ?? false) {
                        missing.append(JS.toString(pc["id"]) + ":" + path)
                        pending = true
                    } else if try IntentTree.dbl(y) != (try IntentTree.dbl(x)) + (try IntentTree.dbl(d["by"])) {
                        postViolated.append(try IntentTree.str(pc["id"]))
                        pending = true
                        break
                    }
                }
                if pending { continue }
                var reads: [String] = []
                let whereList: [JSONValue] = try IntentTree.present(pc["where"]) == nil ? [] : IntentTree.arr(pc["where"])
                for c in whereList { envReads(c, &reads) }
                var absent: [String] = []
                for r in reads where !present(envRoot, r) { absent.append(r) }
                if !absent.isEmpty {
                    for r in absent { missing.append(JS.toString(pc["id"]) + ":" + r) }
                    continue
                }
                if !whereList.isEmpty {
                    var pred = JObject()
                    if let v = action.get("verb") { pred["verb"] = v }
                    pred["where"] = .array(whereList)
                    if !Predicates.evaluate(.array([.object(pred)]), ctx) { postViolated.append(try IntentTree.str(pc["id"])) }
                }
            }
        } catch {
            let msg = (error as? JSError)?.message ?? ""
            missing.append("error: " + (IV.startsWith(msg, "spec, action") ? msg : "error"))
        }
        let miss = uniqSorted(missing)
        let pv = uniqSorted(postViolated)
        let status = !outOfFrame.isEmpty || !pv.isEmpty ? "violated" : (!miss.isEmpty ? "pending" : "ok")
        return .object(["status": .string(status), "outOfFrame": jsonStrings(outOfFrame), "attributed": jsonStrings(attributed),
                        "postViolated": jsonStrings(pv), "missing": jsonStrings(miss), "unmonitored": .bool(unmonitored)])
    }

    /// A runtime divergence is one more labelled observation; a negative one also vetoes the cell. Returns {before, after, grant}.
    private static func divergence(_ l: PCAIntentLearner, _ outcome: JSONValue, _ y: Int) throws -> JSONValue {
        let before = l.cells().filter { $0.inGrant }.count
        try l.observe(outcome, y: y, source: "runtime", region: nil)
        let after = l.cells().filter { $0.inGrant }.count
        return .object(["before": .int(Int64(before)), "after": .int(Int64(after)), "grant": l.synthesize()])
    }

    /// Feed a frame report back: a violation is a negative runtime observation that vetoes the outcome's cell; ok and pending change
    /// nothing. `outcome` is {verb, values}.
    public static func applyFrameReport(_ l: PCAIntentLearner, _ outcome: JSONValue, _ report: JSONValue?) throws -> JSONValue {
        guard let status = report?.get("status")?.asString, IV.same(status, "violated") else { return .object([:]) }
        return .object(["signal": .string("postcondition-violation"), "divergence": try divergence(l, outcome, 0)])
    }
}
