import XCTest
import Foundation
@testable import AtlasPCAVerify

/// Differential replay of PCAFrost (RFC 9591 FROST(Ed25519, SHA-512)) against the reference: scalar reduction, the five hashes,
/// strict point decoding, dealer key generation, commit, sign, aggregate, the per-share check and the one-shot coordinator.
/// Hostile shapes (a missing member, a non-integer identifier) are refused while decoding, as the reference refuses them.
///
/// The corpus carries no key material. A secret in an argument is a descriptor the test resolves: {"$seed": label} = sha256("atlas-pca-conformance/" +
/// label); {"$share": {t, n, secret, coefficients, identifiers, id}} = that participant's dealer share (recomputed with this SDK's keygen);
/// {"$nonce": {r, share}} = the commit nonce H3(r || share). In an expected result every secret is {"$sha256": b64u(sha256(bytes))} and the native
/// result is hashed the same way before the comparison. What stays literal is public: the RFC 9591 appendix E.1 test vector and constant
/// all-zero / group-order / counting-pattern scalars of the degenerate-input cases.
final class RefFrostTests: XCTestCase {
    static let file = "ref-frost.json.gz"

    /// Resolves the descriptors of a value tree to {"$bytes"} members.
    final class Restorer {
        private var keygens: [String: PCAFrost.KeygenResult] = [:]

        func bytes(_ v: JSONValue?) throws -> [UInt8] {
            if let b = Base.bytes(v) { return b }
            guard let o = v?.asObject, o.count == 1, let (k, x) = o.first else { throw JSError("not a descriptor") }
            switch k.s {
            case "$seed":
                guard let l = x.asString else { throw JSError("bad seed") }
                return Canonical.sha256(Array("atlas-pca-conformance/\(l)".utf8))
            case "$share":
                guard let t = x.get("t")?.safeInt, let n = x.get("n")?.safeInt, let id = x.get("id")?.safeInt else { throw JSError("bad share descriptor") }
                var body = x.asObject ?? [:]
                body["id"] = nil
                let key = Canonical.canonicalize(.object(body))
                if keygens[key] == nil {
                    let secret: [UInt8]? = (x.get("secret").map { $0 == .null } ?? true) ? nil : try bytes(x.get("secret"))
                    let coeffs = try (x.get("coefficients")?.asArray ?? []).map { try bytes($0) }
                    let ids = try x.get("identifiers")?.asArray?.map { v -> Int64 in guard let i = v.safeInt else { throw JSError("bad id") }; return i }
                    keygens[key] = try PCAFrost.trustedDealerKeygen(t: t, n: n, secret: secret, coefficients: coeffs, identifiers: ids)
                }
                guard let s = keygens[key]?.participantShares.first(where: { $0.identifier == id }) else { throw JSError("no such participant") }
                return s.share
            case "$nonce":
                return try PCAFrost.nonceGenerate(try bytes(x.get("r")), try bytes(x.get("share")))
            default: throw JSError("unknown descriptor \(k.s)")
            }
        }

        func restore(_ v: JSONValue) throws -> JSONValue {
            switch v {
            case let .array(a): return .array(try a.map(restore))
            case let .object(o):
                if o.count == 1, let (k, _) = o.first, ["$seed", "$share", "$nonce"].contains(k.s) { return Base.bytesValue(try bytes(v)) }
                return .object(try o.mapValues(restore))
            default: return v
            }
        }
    }

    /// The native result with every value the reference result hides behind {"$sha256"} hashed the same way.
    static func masked(_ got: BaseGot, _ want: JSONValue) -> BaseGot {
        guard case let .value(v) = got else { return got }
        func go(_ w: JSONValue?, _ n: JSONValue) -> JSONValue {
            if let o = w?.asObject, o.count == 1, let h = o["$sha256"], h.asString != nil, let b = Base.bytes(n) {
                return .object(["$sha256": .string(Base64URLStrict.encode(Canonical.sha256(b)))])
            }
            switch n {
            case let .array(a):
                let ws = w?.asArray ?? []
                var out: [JSONValue] = []
                for (i, x) in a.enumerated() { out.append(go(i < ws.count ? ws[i] : nil, x)) }
                return .array(out)
            case let .object(o):
                var out = JObject()
                for (k, x) in o { out[k] = go(w?.asObject?[k], x) }
                return .object(out)
            default: return n
            }
        }
        return .value(go(want, v))
    }

    static func bytes(_ v: JSONValue?) throws -> [UInt8] {
        guard let b = Base.bytes(v) else { throw JSError("not bytes") }
        return b
    }
    static func id(_ v: JSONValue?) throws -> Int64 {
        guard let i = v?.safeInt else { throw JSError("not a safe integer") }
        return i
    }
    static func commitment(_ v: JSONValue?) throws -> PCAFrost.Commitment {
        guard v?.asObject != nil else { throw JSError("malformed commitment") }
        return PCAFrost.Commitment(identifier: try id(v?.get("identifier")), hiding: try bytes(v?.get("hiding")), binding: try bytes(v?.get("binding")))
    }
    static func commitments(_ v: JSONValue?) throws -> [PCAFrost.Commitment] {
        guard let a = v?.asArray else { throw JSError("not a list") }
        return try a.map(commitment)
    }
    static func sigShares(_ v: JSONValue?) throws -> [PCAFrost.SigShare] {
        guard let a = v?.asArray else { throw JSError("not a list") }
        return try a.map { PCAFrost.SigShare(identifier: try id($0.get("identifier")), sigShare: try bytes($0.get("sigShare"))) }
    }
    static func vss(_ v: JSONValue?) throws -> [PCAFrost.VerificationShare]? {
        guard let v = v, v != .null else { return nil }
        guard let a = v.asArray else { throw JSError("not a list") }
        return try a.map { PCAFrost.VerificationShare(identifier: try id($0.get("identifier")), publicKey: try bytes($0.get("publicKey"))) }
    }
    static func participant(_ v: JSONValue?) throws -> PCAFrost.ParticipantShare {
        guard v?.asObject != nil else { throw JSError("malformed participant") }
        return PCAFrost.ParticipantShare(identifier: try id(v?.get("identifier")), share: try bytes(v?.get("share")), publicKey: (try? bytes(v?.get("publicKey"))) ?? [])
    }
    static func b(_ x: [UInt8]) -> JSONValue { Base.bytesValue(x) }
    static func commitJSON(_ c: PCAFrost.Commitment) -> JSONValue { .object(["identifier": .int(c.identifier), "hiding": b(c.hiding), "binding": b(c.binding)]) }
    static func keygenJSON(_ k: PCAFrost.KeygenResult) -> JObject {
        ["groupPublicKey": b(k.groupPublicKey),
         "participantShares": .array(k.participantShares.map { .object(["identifier": .int($0.identifier), "share": b($0.share), "publicKey": b($0.publicKey)]) }),
         "groupCommitment": .array(k.groupCommitment.map(b))]
    }
    static func keygen(_ o: JSONValue?) throws -> PCAFrost.KeygenResult {
        guard o?.asObject != nil else { throw JSError("malformed options") }
        guard let t = o?.get("t")?.safeInt, let n = o?.get("n")?.safeInt else { throw JSError("t and n must be integers") }
        var secret: [UInt8]? = nil, coeffs: [[UInt8]]? = nil, ids: [Int64]? = nil
        if let s = o?.get("secret"), s != .null { secret = try bytes(s) }
        if let c = o?.get("coefficients"), c != .null { guard let a = c.asArray else { throw JSError("coefficients") }; coeffs = try a.map { try bytes($0) } }
        if let i = o?.get("identifiers"), i != .null { guard let a = i.asArray else { throw JSError("identifiers") }; ids = try a.map { try id($0) } }
        return try PCAFrost.trustedDealerKeygen(t: t, n: n, secret: secret, coefficients: coeffs, identifiers: ids)
    }
    static func opts(_ o: JSONValue?) throws -> PCAFrost.SignOpts {
        guard let o = o, o != .null else { return PCAFrost.SignOpts() }
        guard o.asObject != nil else { throw JSError("malformed options") }
        var s = PCAFrost.SignOpts()
        s.threshold = o.get("threshold")
        if let v = o.get("verificationShare") { s.verificationShare = try bytes(v) }
        s.verificationShares = try vss(o.get("verificationShares"))
        return s
    }

    func testFrost() throws {
        try K042.requireCovers(["Frost", "RatchetGroup"])
        let d = Base.Diffs()
        let restorer = Restorer()
        let body: (BaseCase) throws -> Void = { c0 in
            // a flow case carries one options object as its args (the other cases a positional list)
            let args = c0.fn == "flow" ? [c0.raw.get("args") ?? .null] : c0.args
            let c = BaseCase(fn: c0.fn, name: c0.name, args: try args.map(restorer.restore), out: c0.out, suspect: c0.suspect, raw: c0.raw)
            let a0 = c.arg(0), a1 = c.arg(1), a2 = c.arg(2)
            let got: BaseGot
            switch c.fn {
            case "scalar": got = Ref.v { Self.b(try PCAFrost.bytesToScalar(try Self.bytes(a0))) }
            case "isCanonicalScalar": got = .value(.bool(PCAFrost.isCanonicalScalar(Base.bytes(a0))))
            case "hash":
                got = Ref.v {
                    let m = try Self.bytes(a1)
                    switch a0?.asString {
                    case "H1": return Self.b(try PCAFrost.H1(m))
                    case "H2": return Self.b(try PCAFrost.H2(m))
                    case "H3": return Self.b(try PCAFrost.H3(m))
                    case "H4": return Self.b(PCAFrost.H4(m))
                    case "H5": return Self.b(PCAFrost.H5(m))
                    default: throw JSError("unknown hash")
                    }
                }
            case "decodeSafePoint": got = Ref.v { Self.b(try PCAFrost.decodeSafePoint(Base.bytes(a0))) }
            case "keygen": got = Ref.v { .object(Self.keygenJSON(try Self.keygen(a0))) }
            case "verifyingShare": got = Ref.v { Self.b(try PCAFrost.verifyingShare(try Self.bytes(a0))) }
            case "commit":
                got = Ref.v {
                    let p = PCAFrost.ParticipantShare(identifier: try Self.id(a0), share: try Self.bytes(a1), publicKey: [])
                    let r = try PCAFrost.commit(p, hidingRandomness: try Self.bytes(c.arg(2)), bindingRandomness: try Self.bytes(c.arg(3)))
                    return .object(["hidingNonce": Self.b(r.hidingNonce), "bindingNonce": Self.b(r.bindingNonce), "commitment": Self.commitJSON(r.commitment)])
                }
            case "flow":
                got = Ref.v {
                    let kg = try Self.keygen(a0)
                    let message = try Self.bytes(a0?.get("message"))
                    guard let signers = a0?.get("signers")?.asArray, let rnd = a0?.get("randomness")?.asArray else { throw JSError("malformed flow") }
                    let quorum = try signers.map { s -> PCAFrost.ParticipantShare in
                        let i = try Self.id(s)
                        guard let p = kg.participantShares.first(where: { $0.identifier == i }) else { throw JSError("unknown signer") }
                        return p
                    }
                    guard rnd.count >= quorum.count else { throw JSError("randomness") }
                    let commits = try quorum.enumerated().map { (i, p) in
                        try PCAFrost.commit(p, hidingRandomness: try Self.bytes(rnd[i].get("hr")), bindingRandomness: try Self.bytes(rnd[i].get("br")))
                    }
                    let cs = commits.map { $0.commitment }
                    let vs = quorum.map { PCAFrost.VerificationShare(identifier: $0.identifier, publicKey: $0.publicKey) }
                    var thr: JSONValue? = a0?.get("threshold")
                    if thr == .null { thr = nil }
                    let shares = try quorum.enumerated().map { (i, p) in
                        try PCAFrost.sign(p.identifier, p.share, kg.groupPublicKey, PCAFrost.Nonces(hiding: commits[i].hidingNonce, binding: commits[i].bindingNonce),
                                          message, cs, PCAFrost.SignOpts(threshold: thr, verificationShare: p.publicKey, verificationShares: vs))
                    }
                    let agg = try PCAFrost.aggregate(message, cs, shares, kg.groupPublicKey, threshold: thr, verificationShares: vs)
                    var out = Self.keygenJSON(kg)
                    out["commitments"] = .array(cs.map(Self.commitJSON))
                    out["sigShares"] = .array(shares.map { .object(["identifier": .int($0.identifier), "sigShare": Self.b($0.sigShare)]) })
                    out["aggregate"] = Self.b(agg)
                    return .object(out)
                }
            case "sign":
                got = Ref.v {
                    var nonces: PCAFrost.Nonces? = nil
                    if let n = c.arg(3), n != .null {
                        guard n.asObject != nil else { throw JSError("malformed nonces") }
                        nonces = PCAFrost.Nonces(hiding: try Self.bytes(n.get("hiding")), binding: try Self.bytes(n.get("binding")))
                    }
                    let r = try PCAFrost.sign(try Self.id(a0), try Self.bytes(a1), try Self.bytes(a2), nonces, try Self.bytes(c.arg(4)),
                                              try Self.commitments(c.arg(5)), try Self.opts(c.arg(6)))
                    return .object(["identifier": .int(r.identifier), "sigShare": Self.b(r.sigShare)])
                }
            case "aggregate":
                got = Ref.v {
                    let o = c.arg(4)
                    let thr = o?.get("threshold")
                    return Self.b(try PCAFrost.aggregate(try Self.bytes(a0), try Self.commitments(a1), try Self.sigShares(a2), try Self.bytes(c.arg(3)),
                                                         threshold: thr, verificationShares: try Self.vss(o?.get("verificationShares"))))
                }
            case "verifySigShare":
                let ok: Bool = {
                    do {
                        guard let p = a0, p.asObject != nil else { return false }
                        let share = p.get("sigShare")
                        return PCAFrost.verifySigShare(identifier: try Self.id(p.get("identifier")), publicKey: try Self.bytes(p.get("publicKey")),
                                                       commitment: try Self.commitment(p.get("commitment")),
                                                       sigShare: PCAFrost.SigShare(identifier: try Self.id(share?.get("identifier")), sigShare: try Self.bytes(share?.get("sigShare"))),
                                                       signingCommitments: try Self.commitments(p.get("signingCommitments")),
                                                       groupPublicKey: try Self.bytes(p.get("groupPublicKey")), message: try Self.bytes(p.get("message")))
                    } catch { return false }
                }()
                got = .value(.bool(ok))
            case "cosign":
                got = Ref.v {
                    guard let q = a1?.asArray else { throw JSError("quorum is not a list") }
                    _ = try PCAFrost.cosign(try Self.bytes(a0), try q.map(Self.participant), try Self.bytes(a2), threshold: c.arg(3)?.get("threshold"))
                    return .bool(true)
                }
            default: d.skip("unknown fn \(c.fn)"); return
            }
            d.add(c, Base.diff(c, Self.masked(got, c.out)))
        }
        try Base.each(Self.file, nil, body)
        // the 21 cases that carry private keys live in ref-frost-gen.json.gz (CI-generated): 281 in all
        if let g = K042.secretCorpusPath(Self.file) { try Base.each(g, nil, body); d.finish(270) } else { d.finish(249) }
    }

    /// 1*B is the Ed25519 base point; 0*B is the identity encoding; the dealer's group key is a0*B.
    func testBaseAndIdentity() throws {
        XCTAssertEqual(PCAFrost.mulBase([1] + [UInt8](repeating: 0, count: 31)), [0x58] + [UInt8](repeating: 0x66, count: 31))
        XCTAssertEqual(PCAFrost.mulBase([UInt8](repeating: 0, count: 32)), [1] + [UInt8](repeating: 0, count: 31))
        let k = try PCAFrost.trustedDealerKeygen(t: 1, n: 1, secret: [1])
        XCTAssertEqual(k.groupPublicKey, [0x58] + [UInt8](repeating: 0x66, count: 31))
    }

    /// decodeSafePoint refuses what libsodium's own validity query may let through, on every platform.
    func testDecodeSafePointIsFailClosed() throws {
        let base: [UInt8] = [0x58] + [UInt8](repeating: 0x66, count: 31)
        XCTAssertEqual(try PCAFrost.decodeSafePoint(base), base)
        // (0, -1): the order-2 point; B + T is a mixed-order point (prime-order part plus order-2 torsion)
        let t: [UInt8] = [0xec] + [UInt8](repeating: 0xff, count: 30) + [0x7f]
        let mixed = try PCAFrost.add(base, t)
        XCTAssertThrowsError(try PCAFrost.decodeSafePoint(mixed), "a mixed-order point")
        XCTAssertThrowsError(try PCAFrost.decodeSafePoint(t), "the order-2 point")
        XCTAssertThrowsError(try PCAFrost.decodeSafePoint(PCAFrost.identity), "the identity")
        XCTAssertThrowsError(try PCAFrost.decodeSafePoint([UInt8](repeating: 0, count: 32)), "the order-4 point (y = 0)")
        // y = p + 1: the identity under a non-canonical encoding
        XCTAssertThrowsError(try PCAFrost.decodeSafePoint([0xee] + [UInt8](repeating: 0xff, count: 30) + [0x7f]), "a non-canonical encoding")
        // the base point with its sign bit flipped is -B: valid, still prime order
        var neg = base; neg[31] |= 0x80
        XCTAssertNoThrow(try PCAFrost.decodeSafePoint(neg))
    }
}
