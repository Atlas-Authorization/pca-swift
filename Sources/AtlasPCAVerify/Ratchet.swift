import Foundation
import CryptoKit

/// The state of a capability ratchet: the leaf commitments and the seeds of the subtrees that can still sign. A spent leaf's seed is
/// gone from `covering` (puncturing), so the holder cannot sign there again even with the whole state.
public struct PCARatchetState {
    public struct Node {
        public let level: Int
        public let nodeIndex: Int
        public let seed: [UInt8]
    }
    public let depth: Int
    public let leafCount: Int
    public let rootCommitment: String
    public let leafPubKeys: [String]
    public let covering: [String: Node]
}

/// First claim of a nullifier wins; `record` is what the first claimant stored.
public protocol PCASpentLeafStore {
    func claim(_ nullifier: String, _ record: String) throws -> (first: Bool, record: String?)
}

/// In-process spent-leaf store; use a shared store for a verifier fleet.
public final class PCAMemorySpentLeafStore: PCASpentLeafStore {
    private var seen: [String: String] = [:]
    private let lock = NSLock()
    public init() {}
    public func claim(_ nullifier: String, _ record: String) throws -> (first: Bool, record: String?) {
        lock.lock(); defer { lock.unlock() }
        if let prev = seen[nullifier] { return (false, prev) }
        seen[nullifier] = record
        return (true, nil)
    }
}

/// What a risk authority hands out for one action: the commitment, its opening, the range proof and the signed attestation.
public struct PCARiskCommitment {
    public let commitment: String
    public let blinding: PCABigInt
    public let rangeProof: JSONValue
    public let attestation: JSONValue
}

/// Carry-forward quantizer: the running total of emitted units is always ceil(sum(true risk) * RISK_SCALE).
public struct PCARiskQuantizer {
    private var nano = BigUInt()
    private var emitted = BigUInt()
    public init() {}

    public mutating func next(_ r: JSONValue?) throws -> PCABigInt {
        guard let x = r, x.isNumber, case let d = JS.toNumber(x), d.isFinite, d >= 0 else {
            throw PCARatchetError("invalid_value", "risk must be a finite number >= 0")
        }
        let c = (d * Double(PCARatchet.RISK_SCALE) * 1e6 - 1e-3).rounded(.up)
        guard c.isFinite else { throw PCARatchetError(nil, "the number cannot be converted to a BigInt") }
        let sum = nano + BigUInt.ratchetFrom(double: c)
        let total = (sum + BigUInt(999_999)).ratchetDivMod(1_000_000).0
        let out = total - emitted
        nano = sum
        emitted = total
        return PCABigInt(neg: false, mag: out)
    }

    public var totalUnits: PCABigInt { PCABigInt(neg: false, mag: emitted) }
}

/// The PCA Capability Ratchet: puncturable forward-secure one-time capability keys (a GGM tree of Ed25519 leaf keys under a Merkle
/// root commitment), the verifier-side spent-leaf and attested-risk bindings, and the adapters to the PCActn counter and the risk
/// budget. The accumulator lives in `PCARatchetAccumulator`. Wire shapes are the reference's JSON shapes (camelCase members).
/// Dynamic inputs (leaf indices, depths, counters) are `JSONValue`s with JavaScript number semantics, so a hostile wire value is
/// refused or false, never a trap.
public enum PCARatchet {
    public static let MAX_RATCHET_DEPTH = 20
    public static let RISK_SCALE = 1000

    /// Signs `message` with the Ed25519 key of `seed` (the platform signer when none is given).
    public typealias LeafSigner = (_ seed: [UInt8], _ message: [UInt8]) throws -> [UInt8]

    // MARK: JS number helpers

    private static func integer(_ v: JSONValue?) -> Double? {
        switch v {
        case let .int(i)?: return Double(i)
        case let .double(d)?: return d.isFinite && d.rounded(.towardZero) == d ? d : nil
        default: return nil
        }
    }

    private static func safeInteger(_ v: JSONValue?) -> Double? { integer(v).flatMap { abs($0) <= 9_007_199_254_740_991 ? $0 : nil } }

    private static func isNegZero(_ v: JSONValue?) -> Bool {
        if case let .double(d)? = v { return d == 0 && d.sign == .minus }
        return false
    }

    private static func be32(_ n: Int) -> [UInt8] { (0..<4).map { UInt8(truncatingIfNeeded: n >> (24 - 8 * $0)) } }

    private static func u64(_ v: JSONValue?) throws -> [UInt8] {
        guard let b = PCABigInt.js(v) else { throw PCARatchetError(nil, "BigInt: cannot convert the leaf index") }
        let low = b.mag.ratchetLow64
        let w = b.neg ? 0 &- low : low
        return (0..<8).map { UInt8(truncatingIfNeeded: w >> UInt64(56 - 8 * $0)) }
    }

    // MARK: GGM puncturable PRF tree

    private static let prgDomain = Array("atlas-pca-ratchet/ggm-prg/v1".utf8)
    private static let leafKeyDomain = Array("atlas-pca-ratchet/ggm-leafkey/v1".utf8)
    private static let rootDomain = Array("atlas-pca-ratchet/ggm-root/v1".utf8)

    private static func hmac(_ key: [UInt8], _ msg: [UInt8]) -> [UInt8] {
        Array(HMAC<SHA256>.authenticationCode(for: Data(msg), using: SymmetricKey(data: Data(key))))
    }

    private static func prgLeft(_ seed: [UInt8]) -> [UInt8] { hmac(seed, prgDomain + [0]) }
    private static func prgRight(_ seed: [UInt8]) -> [UInt8] { hmac(seed, prgDomain + [1]) }
    static func rootSeed(_ seed: [UInt8]) -> [UInt8] { hmac(seed, rootDomain) }
    static func leafSigningSeed(_ leafSeed: [UInt8]) -> [UInt8] { hmac(leafSeed, leafKeyDomain) }

    private static func edPublic(_ seed: [UInt8]) throws -> [UInt8] {
        Array(try Curve25519.Signing.PrivateKey(rawRepresentation: Data(seed)).publicKey.rawRepresentation)
    }

    static func leafPublicKey(_ leafSeed: [UInt8]) throws -> String { Base64URLStrict.encode(try edPublic(leafSigningSeed(leafSeed))) }

    /// Whether the subtree (level, nodeIndex) contains the leaf; the leaf is coerced to a number like the reference (a fraction or a
    /// numeric string still lands in a subtree).
    static func covers(_ level: Int, _ nodeIndex: Int, _ leafIndex: JSONValue?, _ depth: Int) -> Bool {
        let q = JS.toNumber(leafIndex) / Double(UInt64(1) << UInt64(depth - level))
        return q.isFinite && q.rounded(.down) == Double(nodeIndex)
    }

    private static func descendBit(_ level: Int, _ leaf: Int, _ depth: Int) -> Int { (leaf >> (depth - level - 1)) & 1 }

    static func deriveLeafSeed(_ node: PCARatchetState.Node, _ leaf: Int, _ depth: Int) -> [UInt8] {
        var seed = node.seed
        for level in node.level..<depth { seed = descendBit(level, leaf, depth) == 0 ? prgLeft(seed) : prgRight(seed) }
        return seed
    }

    /// The off-path siblings covering every leaf under `node` except `leaf`; on-path seeds are dropped.
    static func punctureSiblings(_ node: PCARatchetState.Node, _ leaf: Int, _ depth: Int) -> [PCARatchetState.Node] {
        var out: [PCARatchetState.Node] = []
        var seed = node.seed
        var nodeIndex = node.nodeIndex
        for level in node.level..<depth {
            let bit = descendBit(level, leaf, depth)
            let left = prgLeft(seed), right = prgRight(seed)
            out.append(.init(level: level + 1, nodeIndex: nodeIndex * 2 + (1 - bit), seed: bit == 0 ? right : left))
            seed = bit == 0 ? left : right
            nodeIndex = nodeIndex * 2 + bit
        }
        return out
    }

    private static func allLeafPublicKeys(_ root: [UInt8], _ depth: Int) throws -> [String] {
        var out = [String](repeating: "", count: 1 << depth)
        func recurse(_ seed: [UInt8], _ level: Int, _ base: Int) throws {
            if level == depth { out[base] = try leafPublicKey(seed); return }
            try recurse(prgLeft(seed), level + 1, base)
            try recurse(prgRight(seed), level + 1, base + (1 << (depth - level - 1)))
        }
        try recurse(root, 0, 0)
        return out
    }

    private static func coverKey(_ level: Int, _ node: Int) -> String { "\(level):\(node)" }

    // MARK: ratchet

    private static let nullifierDomain = Array("atlas-pca-ratchet/nullifier/v1\0".utf8)
    private static let sigDomain = Array("atlas-pca-ratchet/leaf-sig/v1\0".utf8)

    /// b64u(sha256(domain || len32(root) || root || index64)): what a verifier records to detect leaf reuse.
    public static func leafNullifier(rootCommitment: String, leafIndex: JSONValue?) throws -> String {
        let root = Array(rootCommitment.utf8)
        return Base64URLStrict.encode(Canonical.sha256(nullifierDomain + be32(root.count) + root + (try u64(leafIndex))))
    }

    private static func leafSigMessage(_ leaf: JSONValue?, _ message: [UInt8]) throws -> [UInt8] { sigDomain + (try u64(leaf)) + message }

    /// Build a ratchet from at least 32 bytes of entropy and a tree depth in [1, MAX_RATCHET_DEPTH].
    public static func deriveRatchetRoot(seed: [UInt8], depth: JSONValue?) throws -> (rootCommitment: String, state: PCARatchetState) {
        guard let d = integer(depth), d >= 1, d <= Double(MAX_RATCHET_DEPTH) else {
            throw PCARatchetError("invalid_depth", "depth must be an integer in [1, \(MAX_RATCHET_DEPTH)]")
        }
        guard seed.count >= 32 else { throw PCARatchetError("invalid_seed", "seed must be bytes of at least 32 bytes") }
        let depth = Int(d)
        let root = rootSeed(seed)
        let pubs = try allLeafPublicKeys(root, depth)
        guard let rc = Merkle.merkleRoot(pubs.map { .string($0) }) else { throw PCARatchetError(nil, "empty tree") }
        let covering = [coverKey(0, 0): PCARatchetState.Node(level: 0, nodeIndex: 0, seed: root)]
        return (rc, PCARatchetState(depth: depth, leafCount: 1 << depth, rootCommitment: rc, leafPubKeys: pubs, covering: covering))
    }

    private static func findCovering(_ state: PCARatchetState, _ leaf: JSONValue?) -> PCARatchetState.Node? {
        state.covering.values.first { covers($0.level, $0.nodeIndex, leaf, state.depth) }
    }

    private static func merkleProof(_ leaves: [String], _ index: Int) -> JSONValue {
        var path: [JSONValue] = []
        func prove(_ hs: [[UInt8]], _ idx: Int) {
            if hs.count == 1 { return }
            let k = Int(Merkle.split(UInt64(hs.count)))
            if idx < k {
                prove(Array(hs[..<k]), idx)
                path.append(.object(["side": .string("R"), "hash": .string(Base64URLStrict.encode(Merkle.build(Array(hs[k...]))))]))
            } else {
                prove(Array(hs[k...]), idx - k)
                path.append(.object(["side": .string("L"), "hash": .string(Base64URLStrict.encode(Merkle.build(Array(hs[..<k]))))]))
            }
        }
        prove(leaves.map { Merkle.leafHash(.string($0)) }, index)
        return .object(["index": .int(Int64(index)), "size": .int(Int64(leaves.count)), "path": .array(path)])
    }

    /// Sign at a leaf, then puncture it. Throws `leaf_out_of_range` for a leaf outside the tree and `leaf_punctured` for a spent one.
    public static func signAtLeaf(_ state: PCARatchetState, leafIndex: JSONValue?, message: [UInt8],
                                  signer: LeafSigner? = nil) throws -> (signature: JSONValue, newState: PCARatchetState) {
        guard let d = integer(leafIndex), d >= 0, d < Double(state.leafCount) else {
            throw PCARatchetError("leaf_out_of_range", "leaf is out of range [0, \(state.leafCount))")
        }
        let leaf = Int(d)
        let idx = JSONValue.int(Int64(leaf))
        guard let node = findCovering(state, idx) else {
            throw PCARatchetError("leaf_punctured", "leaf \(leaf) is already punctured (spent) and cannot sign")
        }
        let leafSeed = deriveLeafSeed(node, leaf, state.depth)
        let signingSeed = leafSigningSeed(leafSeed)
        let sign: LeafSigner = signer ?? { seed, msg in try PCAEd25519.sign(seed: seed, msg) }
        let edSig = Base64URLStrict.encode(try sign(signingSeed, try leafSigMessage(idx, message)))
        var covering = state.covering
        covering[coverKey(node.level, node.nodeIndex)] = nil
        for s in punctureSiblings(node, leaf, state.depth) { covering[coverKey(s.level, s.nodeIndex)] = s }
        let sig: JSONValue = try .object([
            "edSig": .string(edSig), "leafPubKey": .string(try leafPublicKey(leafSeed)),
            "merklePath": merkleProof(state.leafPubKeys, leaf),
            "nullifier": .string(try leafNullifier(rootCommitment: state.rootCommitment, leafIndex: idx)),
        ])
        return (sig, PCARatchetState(depth: state.depth, leafCount: state.leafCount, rootCommitment: state.rootCommitment,
                                     leafPubKeys: state.leafPubKeys, covering: covering))
    }

    /// Offline check against the root commitment; never throws, malformed input is false.
    public static func verifyLeafSignature(rootCommitment: JSONValue?, leafIndex: JSONValue?, message: [UInt8], signature: JSONValue?) -> Bool {
        guard let root = rootCommitment?.asString, let sig = signature, sig.isObject,
              let nullifier = sig.get("nullifier")?.asString, (try? leafNullifier(rootCommitment: root, leafIndex: leafIndex)) == nullifier,
              let edSig = sig.get("edSig")?.asString, let leafPub = sig.get("leafPubKey")?.asString,
              let mp = sig.get("merklePath"), let proof = mp.asObject,
              let mpIndex = proof["index"], mpIndex.isNumber, let leaf = leafIndex, leaf.isNumber,
              JS.toNumber(mpIndex) == JS.toNumber(leaf) else { return false }
        // the root commits under sha256: a proof naming any other hash suite cannot belong to it
        if let hs = proof["hash_suite"], hs != .string("sha256") { return false }
        guard let msg = try? leafSigMessage(leaf, message), Ed25519Strict.verifyB64u(leafPub, msg, edSig) else { return false }
        return Merkle.verifyInclusion(root, proof, .string(leafPub))
    }

    public static func availableLeaves(_ state: PCARatchetState) -> [Int] {
        var out: [Int] = []
        for n in state.covering.values {
            let span = 1 << (state.depth - n.level)
            out.append(contentsOf: (n.nodeIndex * span)..<(n.nodeIndex * span + span))
        }
        return out.sorted()
    }

    public static func isLeafAvailable(_ state: PCARatchetState, leafIndex: JSONValue?) -> Bool { findCovering(state, leafIndex) != nil }

    // MARK: adapters: ratchet leaf <-> PCActn counter, accumulator units <-> RiskPolicy budget

    private static func validDepth(_ depth: JSONValue?) throws -> Int {
        guard let d = integer(depth), d >= 1, d <= Double(MAX_RATCHET_DEPTH) else {
            throw PCARatchetError("invalid_depth", "depth must be an integer in [1, \(MAX_RATCHET_DEPTH)]")
        }
        return Int(d)
    }

    public static func counterToLeafIndex(_ counter: JSONValue?, depth: JSONValue?) throws -> Int {
        let depth = try validDepth(depth)
        guard let c = safeInteger(counter), !isNegZero(counter), c >= 0 else {
            throw PCARatchetError("leaf_out_of_range", "counter must be a non-negative safe integer")
        }
        guard c < Double(1 << depth) else { throw PCARatchetError("leaf_out_of_range", "counter exceeds the ratchet capacity 2^\(depth)") }
        return Int(c)
    }

    public static func leafIndexToCounter(_ leafIndex: JSONValue?) throws -> Int {
        guard let c = safeInteger(leafIndex), !isNegZero(leafIndex), c >= 0 else {
            throw PCARatchetError("leaf_out_of_range", "leafIndex must be a non-negative safe integer")
        }
        return Int(c)
    }

    public static func leafIndexForAction(_ actn: JSONValue?, depth: JSONValue?) throws -> Int {
        guard let a = actn, a.isObject else { throw PCARatchetError(nil, "action must be an object") }
        return try counterToLeafIndex(a.get("counter"), depth: depth)
    }

    /// Quantize a risk score to integer accumulator units, rounding UP so the sum never under-counts (float noise tolerated).
    public static func riskToUnits(_ r: JSONValue?) throws -> PCABigInt {
        guard let x = r, x.isNumber, case let d = JS.toNumber(x), d.isFinite, d >= 0 else {
            throw PCARatchetError("invalid_value", "risk must be a finite number >= 0")
        }
        let v = d * Double(RISK_SCALE)
        guard v.isFinite else { throw PCARatchetError(nil, "the number cannot be converted to a BigInt") }
        let f = v.rounded(.down)
        let nearest = (v - f) >= 0.5 ? f + 1 : f
        let out = abs(v - nearest) <= 1e-9 * max(1, v) ? nearest : v.rounded(.up)
        return PCABigInt(neg: false, mag: BigUInt.ratchetFrom(double: out))
    }

    /// The accumulator ceiling in units: floor(safetyBound(policy) * RISK_SCALE).
    public static func budgetCeilingUnits(_ policy: JSONValue?) throws -> PCABigInt {
        guard let o = policy?.asObject else { throw PCARatchetError(nil, "policy must be an object") }
        // JS arithmetic on the members: a missing or non-numeric bMax is NaN (refused below), a missing kappa is not > 0 (bound 0)
        let bMax = o["bMax"].map { JS.toNumber($0) } ?? .nan
        let kappa = o["kappa"].map { JS.toNumber($0) } ?? .nan
        let bound = kappa > 0 ? (bMax.isNaN ? Double.nan : max(0.0, bMax)) / kappa : 0.0
        guard bound.isFinite, bound >= 0 else { throw PCARatchetError("invalid_value", "safety bound (bMax/kappa) must be finite and >= 0") }
        guard (bound * Double(RISK_SCALE)).isFinite else { throw PCARatchetError(nil, "the number cannot be converted to a BigInt") }
        return PCABigInt(neg: false, mag: BigUInt.ratchetFrom(double: (bound * Double(RISK_SCALE)).rounded(.down)))
    }

    // MARK: verifier-side bindings

    private static func messageDigest(_ leaf: JSONValue?, _ message: [UInt8]) -> String {
        let idx = integer(leaf).map { String(Int64($0)) } ?? JS.toString(leaf)
        return Base64URLStrict.encode(Canonical.sha256(message)) + "@" + idx
    }

    /// Verify a leaf signature and enforce one-time use: a second signature at a leaf is `replay` (same message) or `equivocation`
    /// (different message). Fail closed: a store that throws denies with `store-error`.
    public static func verifyLeafSignatureOnce(rootCommitment: JSONValue?, leafIndex: JSONValue?, message: [UInt8], signature: JSONValue?,
                                               store: PCASpentLeafStore) -> JSONValue {
        guard verifyLeafSignature(rootCommitment: rootCommitment, leafIndex: leafIndex, message: message, signature: signature),
              let root = rootCommitment?.asString, let nullifier = try? leafNullifier(rootCommitment: root, leafIndex: leafIndex) else {
            return .object(["ok": .bool(false), "reason": .string("invalid")])
        }
        let mine = messageDigest(leafIndex, message)
        do {
            let r = try store.claim(nullifier, mine)
            if r.first { return .object(["ok": .bool(true)]) }
            if r.record == mine { return .object(["ok": .bool(false), "reason": .string("replay"), "nullifier": .string(nullifier)]) }
            return .object(["ok": .bool(false), "reason": .string("equivocation"), "nullifier": .string(nullifier),
                            "firstMessageDigest": .string(r.record ?? ""), "secondMessageDigest": .string(mine)])
        } catch { return .object(["ok": .bool(false), "reason": .string("store-error")]) }
    }

    private static let attestDomain = Array("atlas-pca-ratchet/risk-attestation/v1\0".utf8)

    private static func attestMessage(_ digest: String, _ commitment: String) -> [UInt8] {
        let a = Array(digest.utf8), c = Array(commitment.utf8)
        return attestDomain + be32(a.count) + a + be32(c.count) + c
    }

    /// Risk authority side: commit to the risk, prove its range, and sign (actionDigest, commitment) with the authority's 32-byte key.
    public static func issueRiskCommitment(risk: PCABigInt, actionDigest: String, authoritySecretKey: [UInt8],
                                           signer: LeafSigner? = nil) throws -> PCARiskCommitment {
        let c = try PCARatchetAccumulator.commitRisk(risk)
        let rangeProof = try PCARatchetAccumulator.proveRiskRange(risk, blinding: c.blinding)
        guard authoritySecretKey.count == 32 else { throw PCARatchetError(nil, "private key of length 32 expected, got \(authoritySecretKey.count)") }
        let sign: LeafSigner = signer ?? { seed, msg in try PCAEd25519.sign(seed: seed, msg) }
        let sig = Base64URLStrict.encode(try sign(authoritySecretKey, attestMessage(actionDigest, c.commitment)))
        return PCARiskCommitment(commitment: c.commitment, blinding: c.blinding, rangeProof: rangeProof,
                                 attestation: .object(["actionDigest": .string(actionDigest), "sig": .string(sig)]))
    }

    public static func verifyRiskAttestation(commitment: JSONValue?, attestation: JSONValue?, authorityPublicKey: JSONValue?) -> Bool {
        guard let att = attestation, att.isObject, let digest = att.get("actionDigest")?.asString, let sig = att.get("sig")?.asString,
              let c = commitment?.asString, let pk = authorityPublicKey?.asString else { return false }
        return Ed25519Strict.verifyB64u(pk, attestMessage(digest, c), sig)
    }

    /// Every item must carry a valid authority attestation for exactly the expected digest and commitment, then the bounded-budget
    /// proof must hold. Never throws.
    public static func verifyAttestedBudget(items: JSONValue?, expectedActionDigests: JSONValue?, authorityPublicKey: JSONValue?,
                                            bMax: PCABigInt, budgetProof: JSONValue?) -> Bool {
        guard let its = items?.asArray, let expected = expectedActionDigests?.asArray, its.count == expected.count else { return false }
        for (i, it) in its.enumerated() {
            guard it.isObject, let att = it.get("attestation"), att.isObject, att.get("actionDigest") == expected[i],
                  verifyRiskAttestation(commitment: it.get("commitment"), attestation: att, authorityPublicKey: authorityPublicKey) else { return false }
        }
        return PCARatchetAccumulator.verifyBoundedBudget(.array(its.map { $0.get("commitment") ?? .null }),
                                                         rangeProofs: .array(its.map { $0.get("rangeProof") ?? .null }),
                                                         bMax: bMax, budgetProof: budgetProof)
    }
}
