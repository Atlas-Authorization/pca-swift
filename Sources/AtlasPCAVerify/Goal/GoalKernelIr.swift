import Foundation

// The goal IR of the proved compiler (types, ontology, action and history) as immutable values with structural equality.

/// A string compared by Unicode scalar values, never by canonical equivalence (Swift's String == is canonical).
struct KS: Hashable {
    let u: [UInt32]
    init(_ s: String) { var a: [UInt32] = []; for c in s.unicodeScalars { a.append(c.value) }; self.u = a }
    var isEmpty: Bool { return u.isEmpty }
    /// Code-point order, as the proved string comparison (a strict total order).
    func lt(_ o: KS) -> Bool {
        var i = 0
        while true {
            if i >= o.u.count { return false }
            if i >= u.count { return true }
            if u[i] != o.u[i] { return u[i] < o.u[i] }
            i += 1
        }
    }
    var text: String {
        var s = String.UnicodeScalarView()
        for x in u { if let c = Unicode.Scalar(x) { s.append(c) } }
        return String(s)
    }
}

enum KUnit: Hashable {
    case money(KS)
    case count
    case duration
    case instant
    case bytes
    case ratio
}

struct KQ: Hashable { let u: KUnit; let n: Int64 }

enum KAtom: Hashable {
    case aq(KQ)
    case aS(KS)
}

enum KVal: Hashable {
    case vq(KQ)
    case vs(KS)
    case vset([KAtom])
}

enum KTy: Hashable {
    case tyQ(KUnit)
    case tyS
}

enum KTerm: Hashable {
    case param(KS, KTy)
    case lit(KVal)
    case histAgg(KS, KUnit)
}

/// Declaration order is the tape index (350 + raw value).
enum KOp: Int { case eq = 0, ne, lt, lte, gt, gte, inn, nin }

indirect enum KCond {
    case ctrue
    case cmp(KOp, KTerm, KTerm)
    case and(KCond, KCond)
    case or(KCond, KCond)
    case not(KCond)
}

enum KResPart {
    case exact(KS)
    case oneOf([KS])
    case related(KS, KS)
}

enum KResSel {
    case exact(KS)
    case oneOf([KS])
    case related(KS, KS)
    case anyRes(KS)
    case allOf([KResPart])
}

struct KGrant { let gid: KS; let verb: KS; let res: KResSel; let cond: KCond }

enum KProhTarget {
    case verb(KS)
    case effect(KS)
}

struct KProhibit { let pid: KS; let target: KProhTarget; let res: KResSel; let cond: KCond }

/// Declaration order is the tape index (400 + raw value).
enum KAgg: Int { case count = 0, sum, max, distinct }

enum KSel {
    case gids([KS])
    case effect(KS)
}

enum KWindow {
    case task
    case sliding(Int64)
    case period(Int64, Int64)
    case lifetime
}

enum KScope {
    case session
    case principal
    case org
    case fleet([KS])
}

enum KOnExceed { case deny, escalate }

struct KBCore { let agg: KAgg; let value: KTerm; let key: KS; let window: KWindow; let scope: KScope; let cap: KQ; let onExceed: KOnExceed }

struct KBound { let bid: KS; let sel: KSel; let core: KBCore }

struct KValidity { let notBefore: Int64; let notAfter: Int64; let maxIdle: Int64 }

struct KDeleg { let maxDepth: Int64; let narrowOnly: Bool; let mayTouch: [KS] }

struct KHole { let hid: KS; let q: KS; let domain: [KS]; let affects: [KS]; let global: Bool }

struct KGoal {
    let v: Int64
    let principal: KS
    let ontDigest: KS
    let nlDigest: KS
    let sources: [KS]
    let grants: [KGrant]
    let prohibits: [KProhibit]
    let bounds: [KBound]
    let validity: KValidity
    let deleg: KDeleg
    let escalateOn: [KCond]
    let wildcardAck: [KS]
    let holes: [KHole]
}

struct KParamDecl: Equatable { let path: KS; let ty: KTy }
struct KVerbDecl { let verb: KS; let cls: KS; let params: [KParamDecl] }
struct KRelDecl { let rel: KS; let anchor: KS; let members: [KS] }
struct KOntology { let verbs: [KVerbDecl]; let rels: [KRelDecl] }

struct KAct {
    let verb: KS
    let res: KS
    let params: [KS: KVal]
    let t: Int64
    let sess: KS
    let prin: KS
    let org: KS
    let agent: KS
    let depth: Int64
}

struct KAdm { let gid: KS; let act: KAct }
struct KHist { let adms: [KAdm]; let last: Int64; let aggs: [KS: KQ] }

/// A tape token: keyword, exact integer, exact string.
enum KTok {
    case kw(Int64)
    case i(Int64)
    case s(String)
}
