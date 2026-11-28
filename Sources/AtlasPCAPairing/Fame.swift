import Foundation
import CBlst
import AtlasPCAVerify

/// FAME (Agrawal and Chase, CCS 2017, ePrint 2017/807): ciphertext-policy ABE in the asymmetric (type-3) pairing, adaptively secure
/// in the random-oracle model, for monotone span programs with an injective row labelling. Group work is blst; GT work (parse,
/// multiply, exponentiate, multi-pairing) is the shim over blst's public API. This file is only the scheme's arithmetic; the wire
/// format and AEAD are in Abe.swift.
enum Fame {
    static let attrDST = Array("ATLAS-PCA-ABE:FAME:H-G1:SHA256-SSWU-RO:v1".utf8)

    struct Mpk {
        var h1 = G2(), h2 = G2()          // h^a1, h^a2
        var t1: [UInt8] = [], t2: [UInt8] = [] // GT: e(g,h)^(d1*a1+d3), e(g,h)^(d2*a2+d3)
    }

    struct Msk {
        var a: [Fr] = [], b: [Fr] = []    // two scalars each
        var g: [G1] = []                  // g^d1, g^d2, g^d3
    }

    struct Key {
        var k0: [G2] = []                 // 3
        var kp: [G1] = []                 // 3
        var attrs: [JKey: [G1]] = [:]
    }

    struct Ct {
        var ct0: [G2] = []                // 3
        var rows: [[G1]] = []
    }

    static let g1 = G1.generator
    static let h2 = G2.generator

    /// A uniformly random non-zero scalar (48 bytes of entropy reduced mod r).
    static func randomScalar() -> Fr {
        var rng = SystemRandomNumberGenerator()
        while true {
            let v = Fr(reducing: (0..<48).map { _ in UInt8.random(in: 0...255, using: &rng) })
            if !v.isZero { return v }
        }
    }

    static func hashToG1(_ msg: [UInt8]) -> G1 { G1.hash(msg, dst: attrDST) }

    static func u32(_ n: Int) -> [UInt8] { [UInt8(truncatingIfNeeded: n >> 24), UInt8(truncatingIfNeeded: n >> 16), UInt8(truncatingIfNeeded: n >> 8), UInt8(truncatingIfNeeded: n)] }

    /// H(y, l, t): kind byte 1, length-prefixed UTF-8 attribute, l, t.
    static func hAttr(_ attr: JKey, _ l: Int, _ t: Int) -> G1 {
        let a = Array(attr.s.utf8)
        return hashToG1([1] + u32(a.count) + a + [UInt8(l), UInt8(t)])
    }

    /// H0(j, l, t): the column-indexed oracle (kind byte 2).
    static func hCol(_ j: Int, _ l: Int, _ t: Int) -> G1 { hashToG1([2] + u32(j) + [UInt8(l), UInt8(t)]) }

    static func setup(a: [Fr], b: [Fr], d: [Fr]) throws -> (Mpk, Msk) {
        guard let egh = Gt.pairing([g1.compressed], [h2.compressed]) else { throw PairingError("abe: pairing failed") }
        let e1: Fr = d[0] * a[0], e2: Fr = d[1] * a[1]
        guard let t1 = Gt.pow(egh, (e1 + d[2]).bytes), let t2 = Gt.pow(egh, (e2 + d[2]).bytes) else { throw PairingError("abe: GT exponentiation failed") }
        var mpk = Mpk()
        mpk.h1 = a[0] * h2; mpk.h2 = a[1] * h2; mpk.t1 = t1; mpk.t2 = t2
        var msk = Msk()
        msk.a = a; msk.b = b
        msk.g = [d[0] * g1, d[1] * g1, d[2] * g1]
        return (mpk, msk)
    }

    /// (sum_l oracle(l)^pow[l] + g^sigma)^aInv.
    static func keyTerm(_ oracle: (Int) -> G1, _ pow: [Fr], _ sigma: Fr, _ aInv: Fr) -> G1 {
        var sum: G1 = sigma * g1
        for l in 0..<3 { let t: G1 = pow[l] * oracle(l); sum = sum + t }
        return aInv * sum
    }

    static func keygen(_ msk: Msk, attrs: [JKey], r: [Fr], sigmas: [Fr], sigmaPrime: Fr) throws -> Key {
        let br0: Fr = msk.b[0] * r[0], br1: Fr = msk.b[1] * r[1]
        let pow: [Fr] = [br0, br1, r[0] + r[1]]
        let aInv = [try msk.a[0].inverse(), try msk.a[1].inverse()]
        var key = Key()
        key.k0 = (0..<3).map { pow[$0] * h2 }
        for (i, y) in attrs.enumerated() {
            guard i < sigmas.count else { throw PairingError("fameKeygen: one sigma per attribute is required") }
            var comp: [G1] = []
            for t in 0..<2 { comp.append(keyTerm({ hAttr(y, $0, t) }, pow, sigmas[i], aInv[t])) }
            comp.append((Fr() - sigmas[i]) * g1)
            key.attrs[y] = comp
        }
        var kp: [G1] = []
        for t in 0..<2 { kp.append(keyTerm({ hCol(0, $0, t) }, pow, sigmaPrime, aInv[t]) + msk.g[t]) }
        kp.append((Fr() - sigmaPrime) * g1 + msk.g[2])
        key.kp = kp
        return key
    }

    // ---- span program from the threshold tree

    struct Row {
        let attr: JKey
        let vec: [Int: Fr] // column -> coefficient; column 0 is the secret column and is always 1
    }

    /// The leaves in depth-first order with their span-program rows (Shamir down the tree).
    static func buildRows(_ tree: AbeTree) -> [Row] {
        var rows: [Row] = []
        var ncols = 1
        func walk(_ n: AbeTree, _ vec: [Int: Fr]) {
            if n.isLeaf { rows.append(Row(attr: n.attr, vec: vec)); return }
            let base = ncols
            ncols += n.t - 1
            for (idx, child) in n.of.enumerated() {
                var cv = vec
                let x = Fr(UInt64(idx + 1))
                var pw = Fr(1)
                if n.t > 1 { for k in 1..<n.t { pw = pw * x; cv[base + k - 1] = pw } }
                walk(child, cv)
            }
        }
        walk(tree, [0: Fr(1)])
        return rows
    }

    static func encrypt(_ mpk: Mpk, _ tree: AbeTree, s: [Fr]) throws -> (Ct, [UInt8]) {
        let rows = buildRows(tree)
        var colMemo: [[Int]: G1] = [:]
        func colTerm(_ j: Int, _ l: Int) -> G1 {
            if let v = colMemo[[j, l]] { return v }
            let a: G1 = s[0] * hCol(j, l, 0), b: G1 = s[1] * hCol(j, l, 1)
            let v = a + b
            colMemo[[j, l]] = v
            return v
        }
        var ct = Ct()
        for row in rows {
            var out: [G1] = []
            for l in 0..<3 {
                let a: G1 = s[0] * hAttr(row.attr, l, 0), b: G1 = s[1] * hAttr(row.attr, l, 1)
                var acc = a + b
                for (j, m) in row.vec { let t: G1 = m * colTerm(j, l); acc = acc + t }
                out.append(acc)
            }
            ct.rows.append(out)
        }
        let s01 = s[0] + s[1]
        ct.ct0 = [s[0] * mpk.h1, s[1] * mpk.h2, s01 * h2]
        guard let p1 = Gt.pow(mpk.t1, s[0].bytes), let p2 = Gt.pow(mpk.t2, s[1].bytes) else { throw PairingError("abe: GT exponentiation failed") }
        guard let k = Gt.mul(p1, p2) else { throw PairingError("abe: GT multiplication failed") }
        return (ct, k)
    }

    // ---- decrypt

    final class Plan {
        var row = 0
        var of: [(x: Fr, sub: Plan)] = []
        var isGate = false
    }

    /// L_i(0) = prod_{j!=i} x_j / (x_j - x_i); nil on an empty set, a zero point or points that coincide mod r.
    static func lagrangeAtZero(_ xs: [Fr]) -> [Fr]? {
        if xs.isEmpty { return nil }
        var seen = Set<[UInt8]>()
        for x in xs { if x.isZero || !seen.insert(x.bytes).inserted { return nil } }
        var out: [Fr] = []
        for i in xs.indices {
            var num = Fr(1), den = Fr(1)
            for j in xs.indices where j != i { num = num * xs[j]; den = den * (xs[j] - xs[i]) }
            guard let inv = try? den.inverse() else { return nil }
            out.append(num * inv)
        }
        return out
    }

    /// Chooses, bottom-up, the first t satisfiable children of every gate; nil when `has` does not satisfy the subtree.
    static func planFor(_ n: AbeTree, _ has: (JKey) -> Bool, _ offset: Int) -> Plan? {
        if n.isLeaf {
            if has(n.attr) { let p = Plan(); p.row = offset; return p }
            return nil
        }
        let p = Plan()
        p.isGate = true
        var off = offset
        for (i, child) in n.of.enumerated() {
            if let sub = planFor(child, has, off) { p.of.append((Fr(UInt64(i + 1)), sub)) }
            if p.of.count >= n.t { break }
            off += child.leafCount
        }
        return p.of.count < n.t ? nil : p
    }

    static func planWeights(_ p: Plan, _ w: Fr, _ out: inout [Int: Fr]) -> Bool {
        if !p.isGate { out[p.row] = w; return true }
        guard let lam = lagrangeAtZero(p.of.map { $0.x }) else { return false }
        for (i, c) in p.of.enumerated() {
            let wl: Fr = w * lam[i]
            if !planWeights(c.sub, wl, &out) { return false }
        }
        return true
    }

    /// Recovers the KEM key (GT bytes), or nil when the key does not satisfy the tree or a point is degenerate.
    static func decrypt(_ key: Key, _ tree: AbeTree, _ ct: Ct) -> [UInt8]? {
        var rows: [JKey] = []
        tree.leafAttrs(&rows)
        guard rows.count == ct.rows.count, key.k0.count == 3, key.kp.count == 3, ct.ct0.count == 3 else { return nil }
        guard let p = planFor(tree, { key.attrs[$0] != nil }, 0) else { return nil }
        var w: [Int: Fr] = [:]
        guard planWeights(p, Fr(1), &w) else { return nil }
        var g1s: [[UInt8]] = [], g2s: [[UInt8]] = []
        for l in 0..<3 {
            var ctProd = G1(), keyProd = key.kp[l]
            for (i, wi) in w {
                guard let comp = key.attrs[rows[i]] else { return nil }
                let a: G1 = wi * ct.rows[i][l], b: G1 = wi * comp[l]
                ctProd = ctProd + a
                keyProd = keyProd + b
            }
            g1s += [keyProd.compressed, (-ctProd).compressed]
            g2s += [ct.ct0[l].compressed, key.k0[l].compressed]
        }
        return Gt.pairing(g1s, g2s)
    }
}
