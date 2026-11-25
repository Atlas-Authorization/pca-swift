import Foundation

/// A tape that does not parse (the kernel answers i9).
struct KTapeFail: Error {}

/// The kernel thread's stack (512 MiB, as the other lanes' kernel threads) and the share the tape decoder may use. The reference
/// (and the Kotlin kernel, which maps its StackOverflowError to the same refusal) runs out of stack on a deeply nested tape; Swift cannot
/// catch an overflow, so the decoder measures the stack it has used and refuses the same way at a quarter of it, which leaves the
/// later recursive walks (compile, decide) four times the headroom per level.
enum KStack {
    static let size = 1 << 29
    static let decodeBudget = size / 4
    /// The deepest condition the decoder takes whatever the platform's frame size (the stack budget alone is a measure in bytes, so the depth it admits differs per platform).
    static let maxNesting = 100_000
    private static let key = "pca.goal.kernel.stack"

    @inline(never) private static func address() -> UInt {
        var x = 0
        return withUnsafeMutablePointer(to: &x) { UInt(bitPattern: $0) }
    }

    /// Records the base of the kernel thread's stack (call first thing on that thread).
    static func mark() { Thread.current.threadDictionary[key] = NSNumber(value: address()) }

    static func used() -> Int {
        guard let n = Thread.current.threadDictionary[key] as? NSNumber else { return 0 }
        let base = n.uintValue, cur = address()
        return base > cur ? Int(base - cur) : 0
    }
}

final class KRd {
    private let ts: [KTok]
    private var p: Int = 0
    init(_ ts: [KTok]) { self.ts = ts }
    func left() -> Int { return ts.count - p }
    func done() -> Bool { return p >= ts.count }
    func next() throws -> KTok {
        if p >= ts.count { throw KTapeFail() }
        let t = ts[p]
        p += 1
        return t
    }
}

/// Decoders of the token tapes (the Dec* functions of the proved renderer and the entry module); any deviation fails the whole parse.
enum KDec {
    static func str(_ r: KRd) throws -> KS {
        if case let .s(s) = try r.next() { return KS(s) }
        throw KTapeFail()
    }
    static func int(_ r: KRd) throws -> Int64 {
        if case let .i(i) = try r.next() { return i }
        throw KTapeFail()
    }
    static func kw(_ r: KRd) throws -> Int64 {
        if case let .kw(k) = try r.next() { return k }
        throw KTapeFail()
    }
    private static func expect(_ r: KRd, _ k: Int64) throws { if try kw(r) != k { throw KTapeFail() } }
    private static func bool(_ r: KRd) throws -> Bool {
        let i = try int(r)
        if i != 0 && i != 1 { throw KTapeFail() }
        return i == 1
    }

    private static func count(_ r: KRd) throws -> Int64 {
        let n = try int(r)
        if n < 0 { throw KTapeFail() }
        return n
    }

    static func strs(_ r: KRd) throws -> [KS] {
        let n = try count(r)
        var out: [KS] = []
        var i: Int64 = 0
        while i < n { out.append(try str(r)); i += 1 }
        return out
    }

    static func unit(_ r: KRd) throws -> KUnit {
        switch try kw(r) {
        case 300: return .money(try str(r))
        case 301: return .count
        case 302: return .duration
        case 303: return .instant
        case 304: return .bytes
        case 305: return .ratio
        default: throw KTapeFail()
        }
    }

    static func q(_ r: KRd) throws -> KQ {
        let u = try unit(r)
        let n = try int(r)
        return KQ(u: u, n: n)
    }

    static func ty(_ r: KRd) throws -> KTy {
        switch try kw(r) {
        case 310: return .tyQ(try unit(r))
        case 311: return .tyS
        default: throw KTapeFail()
        }
    }

    private static func atom(_ r: KRd) throws -> KAtom {
        switch try kw(r) {
        case 320: return .aq(try q(r))
        case 321: return .aS(try str(r))
        default: throw KTapeFail()
        }
    }

    static func v(_ r: KRd) throws -> KVal {
        switch try kw(r) {
        case 330: return .vq(try q(r))
        case 331: return .vs(try str(r))
        case 332:
            let n = try count(r)
            var items: [KAtom] = []
            var i: Int64 = 0
            while i < n { items.append(try atom(r)); i += 1 }
            return .vset(items)
        default: throw KTapeFail()
        }
    }

    static func term(_ r: KRd) throws -> KTerm {
        switch try kw(r) {
        case 340:
            let p = try str(r)
            return .param(p, try ty(r))
        case 341: return .lit(try v(r))
        case 342:
            let b = try str(r)
            return .histAgg(b, try unit(r))
        default: throw KTapeFail()
        }
    }

    private static func op(_ r: KRd) throws -> KOp {
        let k = try kw(r)
        if k < 350 || k > 357 { throw KTapeFail() }
        guard let o = KOp(rawValue: Int(k - 350)) else { throw KTapeFail() }
        return o
    }

    /// fuel = the remaining token count: it bounds the depth, exactly as the proved decoder.
    private static func cond(_ r: KRd, _ fuel: Int64, _ depth: Int) throws -> KCond {
        if fuel == 0 { throw KTapeFail() }
        if depth > KStack.maxNesting || (depth & 63 == 0 && KStack.used() > KStack.decodeBudget) { throw IrError("goal tape: nesting too deep") }
        switch try kw(r) {
        case 360: return .ctrue
        case 361:
            let o = try op(r)
            let l = try term(r)
            return .cmp(o, l, try term(r))
        case 362:
            let x = try cond(r, fuel - 1, depth + 1)
            return .and(x, try cond(r, fuel - 1, depth + 1))
        case 363:
            let x = try cond(r, fuel - 1, depth + 1)
            return .or(x, try cond(r, fuel - 1, depth + 1))
        case 364: return .not(try cond(r, fuel - 1, depth + 1))
        default: throw KTapeFail()
        }
    }

    // fuel counts the keyword about to be read, so the cursor must not have advanced
    private static func condTop(_ r: KRd) throws -> KCond { return try cond(r, Int64(r.left()), 0) }

    private static func part(_ r: KRd) throws -> KResPart {
        switch try kw(r) {
        case 375: return .exact(try str(r))
        case 376: return .oneOf(try strs(r))
        case 377:
            let rel = try str(r)
            return .related(rel, try str(r))
        default: throw KTapeFail()
        }
    }

    private static func resSel(_ r: KRd) throws -> KResSel {
        switch try kw(r) {
        case 370: return .exact(try str(r))
        case 371: return .oneOf(try strs(r))
        case 372:
            let rel = try str(r)
            return .related(rel, try str(r))
        case 373: return .anyRes(try str(r))
        case 374:
            let n = try count(r)
            var ps: [KResPart] = []
            var i: Int64 = 0
            while i < n { ps.append(try part(r)); i += 1 }
            return .allOf(ps)
        default: throw KTapeFail()
        }
    }

    private static func grant(_ r: KRd) throws -> KGrant {
        try expect(r, 380)
        let gid = try str(r)
        let verb = try str(r)
        let res = try resSel(r)
        return KGrant(gid: gid, verb: verb, res: res, cond: try condTop(r))
    }

    private static func prohTarget(_ r: KRd) throws -> KProhTarget {
        switch try kw(r) {
        case 390: return .verb(try str(r))
        case 391: return .effect(try str(r))
        default: throw KTapeFail()
        }
    }

    private static func prohibit(_ r: KRd) throws -> KProhibit {
        try expect(r, 392)
        let pid = try str(r)
        let tg = try prohTarget(r)
        let res = try resSel(r)
        return KProhibit(pid: pid, target: tg, res: res, cond: try condTop(r))
    }

    private static func agg(_ r: KRd) throws -> KAgg {
        let k = try kw(r)
        if k < 400 || k > 403 { throw KTapeFail() }
        guard let a = KAgg(rawValue: Int(k - 400)) else { throw KTapeFail() }
        return a
    }

    private static func sel(_ r: KRd) throws -> KSel {
        switch try kw(r) {
        case 410: return .gids(try strs(r))
        case 411: return .effect(try str(r))
        default: throw KTapeFail()
        }
    }

    private static func window(_ r: KRd) throws -> KWindow {
        switch try kw(r) {
        case 420: return .task
        case 421: return .sliding(try int(r))
        case 422:
            let ms = try int(r)
            return .period(ms, try int(r))
        case 423: return .lifetime
        default: throw KTapeFail()
        }
    }

    private static func scope(_ r: KRd) throws -> KScope {
        switch try kw(r) {
        case 430: return .session
        case 431: return .principal
        case 432: return .org
        case 433: return .fleet(try strs(r))
        default: throw KTapeFail()
        }
    }

    private static func onExceed(_ r: KRd) throws -> KOnExceed {
        switch try kw(r) {
        case 440: return .deny
        case 441: return .escalate
        default: throw KTapeFail()
        }
    }

    private static func bcore(_ r: KRd) throws -> KBCore {
        try expect(r, 450)
        let a = try agg(r)
        let value = try term(r)
        let key = try str(r)
        let w = try window(r)
        let sc = try scope(r)
        let cap = try q(r)
        return KBCore(agg: a, value: value, key: key, window: w, scope: sc, cap: cap, onExceed: try onExceed(r))
    }

    private static func bound(_ r: KRd) throws -> KBound {
        try expect(r, 451)
        let bid = try str(r)
        let s = try sel(r)
        return KBound(bid: bid, sel: s, core: try bcore(r))
    }

    private static func validity(_ r: KRd) throws -> KValidity {
        try expect(r, 460)
        let nb = try int(r)
        let na = try int(r)
        return KValidity(notBefore: nb, notAfter: na, maxIdle: try int(r))
    }

    private static func deleg(_ r: KRd) throws -> KDeleg {
        try expect(r, 461)
        let md = try int(r)
        let no = try bool(r)
        return KDeleg(maxDepth: md, narrowOnly: no, mayTouch: try strs(r))
    }

    private static func hole(_ r: KRd) throws -> KHole {
        try expect(r, 470)
        let hid = try str(r)
        let q = try str(r)
        let dom = try strs(r)
        let aff = try strs(r)
        return KHole(hid: hid, q: q, domain: dom, affects: aff, global: try bool(r))
    }

    private static func list<T>(_ r: KRd, _ f: (KRd) throws -> T) throws -> [T] {
        let n = try count(r)
        var out: [T] = []
        var i: Int64 = 0
        while i < n { out.append(try f(r)); i += 1 }
        return out
    }

    /// The whole-tape parse of a goal; nil unless the tape is exactly one goal.
    static func goal(_ ts: [KTok]) throws -> KGoal? {
        return try whole(ts) { r in
            try expect(r, 480)
            let v = try int(r)
            let principal = try str(r)
            let od = try str(r)
            let nd = try str(r)
            let sources = try strs(r)
            let grants = try list(r) { try grant($0) }
            let prohibits = try list(r) { try prohibit($0) }
            let bounds = try list(r) { try bound($0) }
            let vd = try validity(r)
            let dl = try deleg(r)
            let esc = try list(r) { try condTop($0) }
            let ack = try strs(r)
            let holes = try list(r) { try hole($0) }
            return KGoal(v: v, principal: principal, ontDigest: od, nlDigest: nd, sources: sources, grants: grants, prohibits: prohibits,
                         bounds: bounds, validity: vd, deleg: dl, escalateOn: esc, wildcardAck: ack, holes: holes)
        }
    }

    private static func whole<T>(_ ts: [KTok], _ f: (KRd) throws -> T) throws -> T? {
        let r = KRd(ts)
        do {
            let x = try f(r)
            return r.done() ? x : nil
        } catch is KTapeFail {
            return nil
        }
    }

    private static func paramDecl(_ r: KRd) throws -> KParamDecl {
        try expect(r, 500)
        let p = try str(r)
        return KParamDecl(path: p, ty: try ty(r))
    }

    private static func verbDecl(_ r: KRd) throws -> KVerbDecl {
        try expect(r, 501)
        let v = try str(r)
        let c = try str(r)
        return KVerbDecl(verb: v, cls: c, params: try list(r) { try paramDecl($0) })
    }

    private static func relDecl(_ r: KRd) throws -> KRelDecl {
        try expect(r, 502)
        let rel = try str(r)
        let an = try str(r)
        return KRelDecl(rel: rel, anchor: an, members: try strs(r))
    }

    static func ontology(_ ts: [KTok]) throws -> KOntology? {
        return try whole(ts) { r in
            try expect(r, 510)
            let vs = try list(r) { try verbDecl($0) }
            return KOntology(verbs: vs, rels: try list(r) { try relDecl($0) })
        }
    }

    // a later entry for the same key replaces an earlier one
    private static func params(_ r: KRd) throws -> [KS: KVal] {
        var m: [KS: KVal] = [:]
        let n = try count(r)
        var i: Int64 = 0
        while i < n {
            try expect(r, 520)
            let k = try str(r)
            m[k] = try v(r)
            i += 1
        }
        return m
    }

    private static func act(_ r: KRd) throws -> KAct {
        try expect(r, 530)
        let verb = try str(r)
        let res = try str(r)
        let ps = try params(r)
        let t = try int(r)
        let sess = try str(r)
        let prin = try str(r)
        let org = try str(r)
        let agent = try str(r)
        return KAct(verb: verb, res: res, params: ps, t: t, sess: sess, prin: prin, org: org, agent: agent, depth: try int(r))
    }

    static func act(_ ts: [KTok]) throws -> KAct? { return try whole(ts) { try act($0) } }

    private static func adm(_ r: KRd) throws -> KAdm {
        try expect(r, 531)
        let gid = try str(r)
        return KAdm(gid: gid, act: try act(r))
    }

    static func hist(_ ts: [KTok]) throws -> KHist? {
        return try whole(ts) { r in
            try expect(r, 541)
            let adms = try list(r) { try adm($0) }
            let last = try int(r)
            var aggs: [KS: KQ] = [:]
            let n = try count(r)
            var i: Int64 = 0
            while i < n {
                try expect(r, 540)
                let k = try str(r)
                aggs[k] = try q(r)
                i += 1
            }
            return KHist(adms: adms, last: last, aggs: aggs)
        }
    }
}

/// Encoders (the Enc* functions): tokens appended to `o`.
enum KEnc {
    static func str(_ o: inout [KTok], _ s: KS) { o.append(.s(s.text)) }
    static func int(_ o: inout [KTok], _ i: Int64) { o.append(.i(i)) }
    static func kw(_ o: inout [KTok], _ k: Int64) { o.append(.kw(k)) }
    private static func bool(_ o: inout [KTok], _ b: Bool) { o.append(.i(b ? 1 : 0)) }

    static func strs(_ o: inout [KTok], _ xs: [KS]) {
        int(&o, Int64(xs.count))
        for x in xs { str(&o, x) }
    }

    /// Reasons are plain Swift strings.
    static func strings(_ o: inout [KTok], _ xs: [String]) {
        int(&o, Int64(xs.count))
        for x in xs { o.append(.s(x)) }
    }

    static func unit(_ o: inout [KTok], _ u: KUnit) {
        switch u {
        case let .money(c): kw(&o, 300); str(&o, c)
        case .count: kw(&o, 301)
        case .duration: kw(&o, 302)
        case .instant: kw(&o, 303)
        case .bytes: kw(&o, 304)
        case .ratio: kw(&o, 305)
        }
    }

    static func q(_ o: inout [KTok], _ q: KQ) { unit(&o, q.u); int(&o, q.n) }

    static func ty(_ o: inout [KTok], _ t: KTy) {
        switch t {
        case let .tyQ(u): kw(&o, 310); unit(&o, u)
        case .tyS: kw(&o, 311)
        }
    }

    private static func atom(_ o: inout [KTok], _ a: KAtom) {
        switch a {
        case let .aq(x): kw(&o, 320); q(&o, x)
        case let .aS(s): kw(&o, 321); str(&o, s)
        }
    }

    static func v(_ o: inout [KTok], _ v: KVal) {
        switch v {
        case let .vq(x): kw(&o, 330); q(&o, x)
        case let .vs(s): kw(&o, 331); str(&o, s)
        case let .vset(items):
            kw(&o, 332)
            int(&o, Int64(items.count))
            for a in items { atom(&o, a) }
        }
    }

    static func term(_ o: inout [KTok], _ t: KTerm) {
        switch t {
        case let .param(p, ty): kw(&o, 340); str(&o, p); self.ty(&o, ty)
        case let .lit(x): kw(&o, 341); v(&o, x)
        case let .histAgg(b, u): kw(&o, 342); str(&o, b); unit(&o, u)
        }
    }

    static func op(_ o: inout [KTok], _ op: KOp) { kw(&o, 350 + Int64(op.rawValue)) }

    static func cond(_ o: inout [KTok], _ c: KCond) {
        switch c {
        case .ctrue: kw(&o, 360)
        case let .cmp(p, l, r): kw(&o, 361); op(&o, p); term(&o, l); term(&o, r)
        case let .and(a, b): kw(&o, 362); cond(&o, a); cond(&o, b)
        case let .or(a, b): kw(&o, 363); cond(&o, a); cond(&o, b)
        case let .not(x): kw(&o, 364); cond(&o, x)
        }
    }

    private static func part(_ o: inout [KTok], _ p: KResPart) {
        switch p {
        case let .exact(s): kw(&o, 375); str(&o, s)
        case let .oneOf(ids): kw(&o, 376); strs(&o, ids)
        case let .related(rel, an): kw(&o, 377); str(&o, rel); str(&o, an)
        }
    }

    private static func resSel(_ o: inout [KTok], _ s: KResSel) {
        switch s {
        case let .exact(id): kw(&o, 370); str(&o, id)
        case let .oneOf(ids): kw(&o, 371); strs(&o, ids)
        case let .related(rel, an): kw(&o, 372); str(&o, rel); str(&o, an)
        case let .anyRes(reason): kw(&o, 373); str(&o, reason)
        case let .allOf(parts):
            kw(&o, 374)
            int(&o, Int64(parts.count))
            for p in parts { part(&o, p) }
        }
    }

    private static func grant(_ o: inout [KTok], _ g: KGrant) {
        kw(&o, 380); str(&o, g.gid); str(&o, g.verb); resSel(&o, g.res); cond(&o, g.cond)
    }

    private static func prohibit(_ o: inout [KTok], _ p: KProhibit) {
        kw(&o, 392); str(&o, p.pid)
        switch p.target {
        case let .verb(v): kw(&o, 390); str(&o, v)
        case let .effect(c): kw(&o, 391); str(&o, c)
        }
        resSel(&o, p.res); cond(&o, p.cond)
    }

    static func window(_ o: inout [KTok], _ w: KWindow) {
        switch w {
        case .task: kw(&o, 420)
        case let .sliding(ms): kw(&o, 421); int(&o, ms)
        case let .period(ms, t0): kw(&o, 422); int(&o, ms); int(&o, t0)
        case .lifetime: kw(&o, 423)
        }
    }

    static func scope(_ o: inout [KTok], _ s: KScope) {
        switch s {
        case .session: kw(&o, 430)
        case .principal: kw(&o, 431)
        case .org: kw(&o, 432)
        case let .fleet(a): kw(&o, 433); strs(&o, a)
        }
    }

    static func bcore(_ o: inout [KTok], _ b: KBCore) {
        kw(&o, 450); kw(&o, 400 + Int64(b.agg.rawValue)); term(&o, b.value); str(&o, b.key); window(&o, b.window); scope(&o, b.scope); q(&o, b.cap)
        kw(&o, b.onExceed == .deny ? 440 : 441)
    }

    private static func bound(_ o: inout [KTok], _ b: KBound) {
        kw(&o, 451); str(&o, b.bid)
        switch b.sel {
        case let .gids(g): kw(&o, 410); strs(&o, g)
        case let .effect(c): kw(&o, 411); str(&o, c)
        }
        bcore(&o, b.core)
    }

    static func validity(_ o: inout [KTok], _ v: KValidity) { kw(&o, 460); int(&o, v.notBefore); int(&o, v.notAfter); int(&o, v.maxIdle) }

    static func deleg(_ o: inout [KTok], _ d: KDeleg) { kw(&o, 461); int(&o, d.maxDepth); bool(&o, d.narrowOnly); strs(&o, d.mayTouch) }

    private static func hole(_ o: inout [KTok], _ h: KHole) {
        kw(&o, 470); str(&o, h.hid); str(&o, h.q); strs(&o, h.domain); strs(&o, h.affects); bool(&o, h.global)
    }

    /// The card: the goal as its canonical token stream.
    static func goal(_ g: KGoal) -> [KTok] {
        var o: [KTok] = []
        kw(&o, 480); int(&o, g.v); str(&o, g.principal); str(&o, g.ontDigest); str(&o, g.nlDigest)
        strs(&o, g.sources)
        int(&o, Int64(g.grants.count)); for x in g.grants { grant(&o, x) }
        int(&o, Int64(g.prohibits.count)); for x in g.prohibits { prohibit(&o, x) }
        int(&o, Int64(g.bounds.count)); for x in g.bounds { bound(&o, x) }
        validity(&o, g.validity)
        deleg(&o, g.deleg)
        int(&o, Int64(g.escalateOn.count)); for x in g.escalateOn { cond(&o, x) }
        strs(&o, g.wildcardAck)
        int(&o, Int64(g.holes.count)); for x in g.holes { hole(&o, x) }
        return o
    }
}
