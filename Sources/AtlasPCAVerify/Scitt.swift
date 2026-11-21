import Foundation
import CryptoKit

/// SCITT transparency receipts for Proof-Carrying Authority (RFC 9943 architecture, RFC 9942 COSE Receipts): a deterministic CBOR
/// codec (RFC 8949 core deterministic encoding, the minimal profile COSE_Sign1 needs), COSE Signed Statements, the RFC 9162 inclusion
/// proof codec and signed COSE Receipts. Signature suites: EdDSA (Ed25519) and ES256 (ECDSA P-256, raw r||s, LOW-S only: a high-S
/// variant of a signature would be a second, distinct Merkle leaf for the same statement). Everything fails closed.
public enum PCAScitt {
    public static let COSE_SIGN1_TAG: Int64 = 18
    public static let HDR_ALG: Int64 = 1
    public static let HDR_CONTENT_TYPE: Int64 = 3
    public static let HDR_CWT_CLAIMS: Int64 = 15
    public static let CWT_ISS: Int64 = 1
    public static let CWT_SUB: Int64 = 2
    public static let HDR_VDS: Int64 = 395
    public static let HDR_VDS_PROOFS: Int64 = 396
    public static let VDS_RFC9162_SHA256: Int64 = 1
    public static let PROOF_TYPE_INCLUSION: Int64 = -1
    public static let DEFAULT_CONTENT_TYPE = "application/pca+json"

    // MARK: CBOR model

    public enum CborKey: Equatable, Hashable {
        case int(Int64)
        case text(String)
    }

    public struct CborEntry: Equatable {
        public let key: CborKey
        public let value: CborValue
        public init(_ key: CborKey, _ value: CborValue) { self.key = key; self.value = value }
    }

    /// A CBOR value in the supported profile: integers (safe range only), text, bytes, booleans, null, arrays, maps (entries in wire order
    /// when decoded) and tags. Floats, simple values and indefinite lengths are refused.
    public indirect enum CborValue: Equatable {
        case int(Int64)
        case text(String)
        case bytes([UInt8])
        case bool(Bool)
        case null
        case array([CborValue])
        case map([CborEntry])
        case tag(Int64, CborValue)

        /// The first map entry under `key` (a map has no duplicate keys when decoded).
        public func mapGet(_ key: CborKey) -> CborValue? {
            guard case let .map(es) = self else { return nil }
            return es.first { $0.key == key }?.value
        }
    }

    static let maxSafe: Int64 = Canonical.MAX_SAFE
    static let maxDepth = 512

    private static func isInt(_ n: Int64) -> Bool { n >= -maxSafe && n <= maxSafe }

    private static func head(_ major: UInt8, _ arg: UInt64) -> [UInt8] {
        let mt = major << 5
        if arg < 24 { return [mt | UInt8(arg)] }
        if arg < 0x100 { return [mt | 24, UInt8(arg)] }
        if arg < 0x10000 { return [mt | 25, UInt8(arg >> 8), UInt8(arg & 0xff)] }
        if arg < 0x1_0000_0000 { return [mt | 26] + (0..<4).reversed().map { UInt8((arg >> UInt64(8 * $0)) & 0xff) } }
        return [mt | 27] + (0..<8).reversed().map { UInt8((arg >> UInt64(8 * $0)) & 0xff) }
    }

    private static func cmpBytes(_ a: [UInt8], _ b: [UInt8]) -> Int {
        let n = min(a.count, b.count)
        for i in 0..<n where a[i] != b[i] { return Int(a[i]) - Int(b[i]) }
        return a.count - b.count
    }

    private static func encodeText(_ s: String) throws -> [UInt8] {
        // a Swift String is always well-formed; the lone-surrogate stand-in the parsers use is refused like a lone surrogate
        if Canonical.hasLoneSurrogate(s) { throw JSError("cbor: text string contains a lone surrogate") }
        let b = Array(s.utf8)
        return head(3, UInt64(b.count)) + b
    }

    private static func encodeKey(_ k: CborKey) throws -> [UInt8] {
        switch k {
        case let .int(n):
            guard isInt(n) else { throw JSError("cbor: bad integer map key") }
            return n >= 0 ? head(0, UInt64(n)) : head(1, UInt64(-1 - n))
        case let .text(s): return try encodeText(s)
        }
    }

    /// Deterministically encode a CBOR value. Throws on anything outside the supported profile.
    public static func encode(_ v: CborValue) throws -> [UInt8] {
        switch v {
        case .null: return [0xf6]
        case let .bool(b): return [b ? 0xf5 : 0xf4]
        case let .int(n):
            guard isInt(n) else { throw JSError("cbor: only safe-integer numbers are supported") }
            return n >= 0 ? head(0, UInt64(n)) : head(1, UInt64(-1 - n))
        case let .text(s): return try encodeText(s)
        case let .bytes(b): return head(2, UInt64(b.count)) + b
        case let .array(a):
            var out = head(4, UInt64(a.count))
            for x in a { out += try encode(x) }
            return out
        case let .map(es):
            var entries: [(k: [UInt8], v: [UInt8])] = []
            for e in es { entries.append((try encodeKey(e.key), try encode(e.value))) }
            entries.sort { cmpBytes($0.k, $1.k) < 0 }
            for i in entries.indices.dropFirst() where cmpBytes(entries[i - 1].k, entries[i].k) == 0 { throw JSError("cbor: duplicate map key") }
            var out = head(5, UInt64(es.count))
            for e in entries { out += e.k + e.v }
            return out
        case let .tag(t, inner):
            guard isInt(t), t >= 0 else { throw JSError("cbor: bad tag") }
            return head(6, UInt64(t)) + (try encode(inner))
        }
    }

    /// Strict UTF-8 (no overlongs, surrogates, > U+10FFFF); a leading BOM is data.
    private static func validUTF8(_ b: [UInt8]) -> Bool {
        var i = 0
        let n = b.count
        while i < n {
            let c = b[i]
            if c < 0x80 { i += 1; continue }
            let need: Int, minCp: UInt32
            var cp: UInt32
            if c >= 0xC2 && c <= 0xDF { need = 1; cp = UInt32(c & 0x1F); minCp = 0x80 }
            else if c >= 0xE0 && c <= 0xEF { need = 2; cp = UInt32(c & 0x0F); minCp = 0x800 }
            else if c >= 0xF0 && c <= 0xF4 { need = 3; cp = UInt32(c & 0x07); minCp = 0x10000 }
            else { return false }
            if i + need >= n { return false }
            for j in 1...need {
                let x = b[i + j]
                if x & 0xC0 != 0x80 { return false }
                cp = (cp << 6) | UInt32(x & 0x3F)
            }
            if cp < minCp || cp > 0x10FFFF || (cp >= 0xD800 && cp <= 0xDFFF) { return false }
            i += need + 1
        }
        return true
    }

    private struct Reader {
        let buf: [UInt8]
        var pos = 0
        init(_ b: [UInt8]) { buf = b }

        mutating func byte() throws -> UInt8 {
            guard pos < buf.count else { throw JSError("cbor: unexpected end of input") }
            defer { pos += 1 }
            return buf[pos]
        }

        mutating func bytes(_ n: Int) throws -> [UInt8] {
            guard n >= 0, n <= buf.count - pos else { throw JSError("cbor: unexpected end of input") }
            defer { pos += n }
            return Array(buf[pos..<pos + n])
        }

        mutating func readUint(_ n: Int) throws -> UInt64 {
            var v: UInt64 = 0
            for _ in 0..<n {
                let (m, over) = v.multipliedReportingOverflow(by: 256)
                v = m &+ UInt64(try byte())
                if over || v > UInt64(PCAScitt.maxSafe) { throw JSError("cbor: integer out of safe range") }
            }
            return v
        }

        /// (major, argument); the argument must be in its minimal (canonical) length.
        mutating func readHead() throws -> (major: UInt8, arg: UInt64) {
            let ib = try byte()
            let major = ib >> 5, info = ib & 0x1f
            if major == 7 && info >= 24 { throw JSError("cbor: unsupported simple/float value") }
            if info < 24 { return (major, UInt64(info)) }
            let len: Int
            let minimal: UInt64
            switch info {
            case 24: len = 1; minimal = 24
            case 25: len = 2; minimal = 0x100
            case 26: len = 4; minimal = 0x10000
            case 27: len = 8; minimal = 0x1_0000_0000
            default: throw JSError("cbor: unsupported additional information (indefinite/reserved)")
            }
            let arg = try readUint(len)
            if arg < minimal { throw JSError("cbor: non-minimal integer") }
            return (major, arg)
        }

        mutating func value(_ depth: Int) throws -> CborValue {
            if depth > PCAScitt.maxDepth { throw JSError("cbor: nesting too deep") }
            let (major, arg) = try readHead()
            switch major {
            case 0: return .int(Int64(arg))
            case 1:
                guard arg < UInt64(PCAScitt.maxSafe) else { throw JSError("cbor: integer out of safe range") }
                return .int(-1 - Int64(arg))
            case 2: return .bytes(try bytes(Int(arg)))
            case 3:
                let b = try bytes(Int(arg))
                guard PCAScitt.validUTF8(b) else { throw JSError("The encoded data was not valid for encoding utf-8") }
                return .text(String(decoding: b, as: UTF8.self))
            case 4:
                var out: [CborValue] = []
                var i: UInt64 = 0
                while i < arg { out.append(try value(depth + 1)); i += 1 }
                return .array(out)
            case 5:
                var entries: [CborEntry] = []
                var prev: [UInt8]?
                var i: UInt64 = 0
                while i < arg {
                    let keyStart = pos
                    let key = try value(depth + 1)
                    let k: CborKey
                    switch key {
                    case let .int(n): k = .int(n)
                    case let .text(s): k = .text(s)
                    default: throw JSError("cbor: map key must be int or text")
                    }
                    let keyBytes = Array(buf[keyStart..<pos])
                    if let p = prev, PCAScitt.cmpBytes(p, keyBytes) >= 0 { throw JSError("cbor: map keys not canonically ordered / duplicate") }
                    prev = keyBytes
                    entries.append(CborEntry(k, try value(depth + 1)))
                    i += 1
                }
                return .map(entries)
            case 6: return .tag(Int64(arg), try value(depth + 1))
            case 7:
                if arg == 20 { return .bool(false) }
                if arg == 21 { return .bool(true) }
                if arg == 22 { return .null }
                throw JSError("cbor: unsupported simple/float value")
            default: throw JSError("cbor: unsupported major type")
            }
        }
    }

    /// Strictly decode ONE canonical CBOR value; the whole buffer must be consumed.
    public static func decode(_ bytes: [UInt8]) throws -> CborValue {
        var r = Reader(bytes)
        let v = try r.value(0)
        if r.pos != bytes.count { throw JSError("cbor: trailing bytes") }
        return v
    }

    // MARK: keys and signatures

    public enum CoseAlg {
        case eddsa, es256
        var label: Int64 { self == .eddsa ? -8 : -7 }
        static func of(_ label: Int64) -> CoseAlg? { label == -8 ? .eddsa : label == -7 ? .es256 : nil }
    }

    /// A private signing key: Ed25519 (deterministic signatures need `Ed25519Deterministic.key`) or ECDSA P-256.
    public enum CoseSigner {
        case eddsa(PCAEdKey)
        case es256(P256.Signing.PrivateKey)
        var alg: CoseAlg { if case .eddsa = self { return .eddsa } else { return .es256 } }
    }

    /// A public verification key: the 32-byte Ed25519 key, or the P-256 point coordinates (32 bytes each).
    public enum CoseVerifier {
        case eddsa([UInt8])
        case es256(x: [UInt8], y: [UInt8])
    }

    private static func hex(_ s: String) -> [UInt8] {
        let c = Array(s.utf8)
        func v(_ x: UInt8) -> UInt8 { x <= 57 ? x - 48 : x - 87 }
        return stride(from: 0, to: c.count, by: 2).map { v(c[$0]) << 4 | v(c[$0 + 1]) }
    }

    /// NIST P-256 group order n, and n / 2 (big endian): ES256 is canonical only for s <= n / 2.
    private static let p256N = hex("ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551")
    private static let p256HalfN: [UInt8] = {
        var out = p256N, carry: UInt8 = 0
        for i in out.indices { let b = out[i]; out[i] = (b >> 1) | carry; carry = (b & 1) << 7 }
        return out
    }()

    private static func cmpBE(_ a: [UInt8], _ b: [UInt8]) -> Int { cmpBytes(a, b) }
    private static func isZero(_ a: [UInt8]) -> Bool { a.allSatisfy { $0 == 0 } }

    /// n - s (big endian, s < n).
    private static func subFromN(_ s: [UInt8]) -> [UInt8] {
        var out = [UInt8](repeating: 0, count: 32)
        var borrow = 0
        for i in stride(from: 31, through: 0, by: -1) {
            var d = Int(p256N[i]) - Int(s[i]) - borrow
            if d < 0 { d += 256; borrow = 1 } else { borrow = 0 }
            out[i] = UInt8(d)
        }
        return out
    }

    /// A 64-byte raw P-256 signature with 0 < r < n and 0 < s <= n/2.
    static func isCanonicalEs256(_ sig: [UInt8]) -> Bool {
        guard sig.count == 64 else { return false }
        let r = Array(sig[0..<32]), s = Array(sig[32...])
        return !isZero(r) && cmpBE(r, p256N) < 0 && !isZero(s) && cmpBE(s, p256HalfN) <= 0
    }

    private static func signBytes(_ signer: CoseSigner, _ msg: [UInt8]) throws -> [UInt8] {
        switch signer {
        case let .eddsa(k): return try k.sign(msg)
        case let .es256(k):
            var sig = Array(try k.signature(for: Data(msg)).rawRepresentation)
            // normalise to low-S so a statement has exactly ONE valid signature form
            let s = Array(sig[32...])
            if cmpBE(s, p256HalfN) > 0 { sig.replaceSubrange(32..<64, with: subFromN(s)) }
            return sig
        }
    }

    private static func verifyBytes(_ alg: CoseAlg, _ key: CoseVerifier, _ msg: [UInt8], _ sig: [UInt8], allowHighS: Bool) -> Bool {
        switch (alg, key) {
        case let (.eddsa, .eddsa(pk)):
            return Ed25519Strict.verify(publicKey: pk, message: msg, signature: sig)
        case let (.es256, .es256(x, y)):
            // ECDSA is malleable ((r, s) and (r, n-s) both verify): refuse a high-S form unless the caller opts in
            if !allowHighS && !isCanonicalEs256(sig) { return false }
            if allowHighS && sig.count != 64 { return false }
            guard x.count == 32, y.count == 32,
                  let pub = try? P256.Signing.PublicKey(x963Representation: Data([0x04] + x + y)),
                  let s = try? P256.Signing.ECDSASignature(rawRepresentation: Data(sig)) else { return false }
            return pub.isValidSignature(s, for: Data(msg))
        default:
            return false // a key of the other algorithm never verifies
        }
    }

    /// The COSE_Sign1 `Sig_structure` bytes (RFC 9052 section 4.4), external_aad empty.
    private static func sigStructure(_ protectedBytes: [UInt8], _ payload: [UInt8]) throws -> [UInt8] {
        try encode(.array([.text("Signature1"), .bytes(protectedBytes), .bytes([]), .bytes(payload)]))
    }

    // MARK: Signed Statements

    /// Sign a PCActn / verdict as a COSE Signed Statement (COSE_Sign1). The protected header carries the algorithm, the payload content
    /// type and the CWT Claims (issuer, optional subject); the payload is the strict canonical serialization of `payload`.
    public static func signStatement(_ payload: JSONValue, signer: CoseSigner, issuer: String, subject: String? = nil, contentType: String? = nil) throws -> [UInt8] {
        var claims: [CborEntry] = [CborEntry(.int(CWT_ISS), .text(issuer))]
        if let s = subject { claims.append(CborEntry(.int(CWT_SUB), .text(s))) }
        let prot: CborValue = .map([CborEntry(.int(HDR_ALG), .int(signer.alg.label)),
                                    CborEntry(.int(HDR_CONTENT_TYPE), .text(contentType ?? DEFAULT_CONTENT_TYPE)),
                                    CborEntry(.int(HDR_CWT_CLAIMS), .map(claims))])
        let protectedBytes = try encode(prot)
        guard let canon = IV.strictCanon(payload) else { throw JSError("canonicalize: \(IV.strictCanonError(payload) ?? "out of profile")") }
        let payloadBytes = Canonical.utf8(canon)
        let sig = try signBytes(signer, try sigStructure(protectedBytes, payloadBytes))
        return try encode(.tag(COSE_SIGN1_TAG, .array([.bytes(protectedBytes), .map([]), .bytes(payloadBytes), .bytes(sig)])))
    }

    public struct CoseSign1 {
        public let protectedBytes: [UInt8]
        public let protectedMap: CborValue
        public let unprotected: CborValue
        /// The embedded payload, or nil when detached.
        public let payload: [UInt8]?
        public let signature: [UInt8]
    }

    /// Decode and structurally validate a COSE_Sign1 (tag 18). Throws on any deviation.
    public static func decodeCoseSign1(_ bytes: [UInt8]) throws -> CoseSign1 {
        guard case let .tag(t, inner) = try decode(bytes), t == COSE_SIGN1_TAG else { throw JSError("cose: not a COSE_Sign1 (tag 18)") }
        guard case let .array(arr) = inner, arr.count == 4 else { throw JSError("cose: malformed COSE_Sign1 array") }
        guard case let .bytes(protectedBytes) = arr[0] else { throw JSError("cose: protected must be a bstr") }
        guard case .map = arr[1] else { throw JSError("cose: unprotected must be a map") }
        let payload: [UInt8]?
        switch arr[2] {
        case let .bytes(p): payload = p
        case .null: payload = nil
        default: throw JSError("cose: payload must be a bstr or nil")
        }
        guard case let .bytes(signature) = arr[3] else { throw JSError("cose: signature must be a bstr") }
        let pm: CborValue
        if protectedBytes.isEmpty { pm = .map([]) } else {
            let d = try decode(protectedBytes)
            guard case .map = d else { throw JSError("cbor: expected a map") }
            pm = d
        }
        return CoseSign1(protectedBytes: protectedBytes, protectedMap: pm, unprotected: arr[1], payload: payload, signature: signature)
    }

    private static func algOf(_ protectedMap: CborValue) throws -> CoseAlg {
        guard let label = protectedMap.mapGet(.int(HDR_ALG)) else { throw JSError("cose: missing alg header") }
        guard case let .int(n) = label, let alg = CoseAlg.of(n) else { throw JSError("cose: unsupported alg") }
        return alg
    }

    /// Verify a Signed Statement and say WHY it failed: `malformed: <detail>`, `detached payload`, `missing alg header`, `unsupported alg`,
    /// `non-canonical signature (high-S)` or `bad signature`. Never throws. The COSE external_aad is always empty.
    public static func checkStatement(_ statement: [UInt8], _ key: CoseVerifier, allowHighS: Bool = false) -> (ok: Bool, reason: String?) {
        let s: CoseSign1
        do { s = try decodeCoseSign1(statement) } catch { return (false, "malformed: \((error as? JSError)?.message ?? "\(error)")") }
        guard let payload = s.payload else { return (false, "detached payload") }
        let alg: CoseAlg
        do { alg = try algOf(s.protectedMap) } catch { return (false, ((error as? JSError)?.message.contains("missing") ?? false) ? "missing alg header" : "unsupported alg") }
        guard let msg = try? sigStructure(s.protectedBytes, payload) else { return (false, "bad signature") }
        if verifyBytes(alg, key, msg, s.signature, allowHighS: allowHighS) { return (true, nil) }
        // tell a valid-but-high-S malleation from a plain forgery
        if alg == .es256 && !isCanonicalEs256(s.signature) && verifyBytes(alg, key, msg, s.signature, allowHighS: true) {
            return (false, "non-canonical signature (high-S)")
        }
        return (false, "bad signature")
    }

    public static func verifyStatement(_ statement: [UInt8], _ key: CoseVerifier, allowHighS: Bool = false) -> Bool {
        checkStatement(statement, key, allowHighS: allowHighS).ok
    }

    /// The raw canonical payload bytes a Signed Statement carries. Throws on a malformed or detached statement.
    public static func statementPayload(_ statement: [UInt8]) throws -> [UInt8] {
        guard let p = try decodeCoseSign1(statement).payload else { throw JSError("cose: statement payload is detached") }
        return p
    }

    /// The b64u leaf a statement occupies in the log.
    public static func statementLeaf(_ statement: [UInt8]) -> String { Base64URLStrict.encode(statement) }

    // MARK: RFC 9162 inclusion proof codec

    /// Sibling sides (leaf -> root) for `index` in a tree of `size` leaves (RFC 6962 split).
    public static func siblingSides(_ index: Int64, _ size: Int64) -> [String] {
        var out: [String] = []
        var idx = index, n = size
        while n > 1 {
            var k: Int64 = 1
            while k * 2 < n { k *= 2 }
            if idx < k { out.append("R"); n = k } else { out.append("L"); idx -= k; n -= k }
        }
        return out.reversed()
    }

    /// A core-Merkle inclusion proof `{index, size, path: [{side, hash}]}` as RFC 9162 `[tree_size, leaf_index, [sibling hashes]]`.
    public static func encodeInclusionProof(_ proof: JSONValue) throws -> [UInt8] {
        guard let size = proof.get("size")?.safeInt, let index = proof.get("index")?.safeInt, let path = proof.get("path")?.asArray else {
            throw JSError("cbor: unsupported value")
        }
        var sibs: [CborValue] = []
        for step in path {
            guard let h = step.get("hash")?.asString, let b = Base64URLStrict.decode(h, length: 32) else { throw JSError("scitt: proof step hash is not a 32-byte b64u hash") }
            sibs.append(.bytes(b))
        }
        return try encode(.array([.int(size), .int(index), .array(sibs)]))
    }

    /// Decode an RFC 9162 inclusion proof back into `{index, size, path}` (the sides are re-derived from (index, size)).
    public static func decodeInclusionProof(_ bytes: [UInt8]) throws -> JSONValue {
        guard case let .array(v) = try decode(bytes), v.count == 3 else { throw JSError("scitt: malformed inclusion proof") }
        guard case let .int(size) = v[0], case let .int(index) = v[1] else { throw JSError("scitt: proof size/index must be integers") }
        guard size >= 1, index >= 0, index < size else { throw JSError("scitt: proof size/index out of range") }
        guard case let .array(sibs) = v[2] else { throw JSError("scitt: inclusion path must be an array") }
        let sides = siblingSides(index, size)
        guard sibs.count == sides.count else { throw JSError("scitt: inclusion path length does not match (index,size)") }
        var path: [JSONValue] = []
        for (i, h) in sibs.enumerated() {
            guard case let .bytes(b) = h, b.count == 32 else { throw JSError("scitt: inclusion path entry must be a 32-byte bstr") }
            path.append(.object(["side": .string(sides[i]), "hash": .string(Base64URLStrict.encode(b))]))
        }
        return .object(["index": .int(index), "size": .int(size), "path": .array(path)])
    }

    // MARK: COSE Receipts (RFC 9942)

    /// A signed COSE Receipt for `proof` against ledger root `root` (b64u, 32 bytes). The payload is detached: the signature covers the
    /// root a verifier recomputes from the inclusion proof.
    public static func buildReceipt(root: String, proof: JSONValue, signer: CoseSigner, issuer: String? = nil) throws -> [UInt8] {
        guard let rootBytes = Base64URLStrict.decode(root, length: 32) else { throw JSError("scitt: tree root is not a 32-byte b64u hash") }
        var prot: [CborEntry] = [CborEntry(.int(HDR_ALG), .int(signer.alg.label)), CborEntry(.int(HDR_VDS), .int(VDS_RFC9162_SHA256))]
        if let iss = issuer { prot.append(CborEntry(.int(HDR_CWT_CLAIMS), .map([CborEntry(.int(CWT_ISS), .text(iss))]))) }
        let protectedBytes = try encode(.map(prot))
        let proofs: CborValue = .map([CborEntry(.int(PROOF_TYPE_INCLUSION), .array([.bytes(try encodeInclusionProof(proof))]))])
        let unprotected: CborValue = .map([CborEntry(.int(HDR_VDS_PROOFS), proofs)])
        let sig = try signBytes(signer, try sigStructure(protectedBytes, rootBytes))
        return try encode(.tag(COSE_SIGN1_TAG, .array([.bytes(protectedBytes), unprotected, .null, .bytes(sig)])))
    }

    /// Verify a COSE Receipt for a Signed Statement (never throws). All must hold: an anchor (`treeRoot` and/or `verificationKey`) is given;
    /// the receipt's TS signature over the root verifies (when `verificationKey`); the root equals the pinned `treeRoot`; the inclusion
    /// proof binds the EXACT statement bytes (leaf = SHA-256(0x00 || statement)) to that root; and the statement's own signature
    /// verifies (when `statementKey`).
    public static func verifyReceipt(_ receipt: [UInt8], _ statement: [UInt8], treeRoot: String? = nil, verificationKey: CoseVerifier? = nil,
                                     statementKey: CoseVerifier? = nil, allowHighS: Bool = false) -> Bool {
        if treeRoot == nil && verificationKey == nil { return false }
        guard let cose = try? decodeCoseSign1(receipt), cose.protectedMap.mapGet(.int(HDR_VDS)) == .int(VDS_RFC9162_SHA256) else { return false }
        if let p = cose.payload, p.count != 32 { return false }
        guard let proofsRaw = cose.unprotected.mapGet(.int(HDR_VDS_PROOFS)), case .map = proofsRaw,
              case let .array(inclusion)? = proofsRaw.mapGet(.int(PROOF_TYPE_INCLUSION)), let first = inclusion.first,
              case let .bytes(proofBytes) = first, let proof = try? decodeInclusionProof(proofBytes),
              let index = proof.get("index")?.safeInt, let size = proof.get("size")?.safeInt, let steps = proof.get("path")?.asArray else { return false }
        let hashes = steps.compactMap { $0.get("hash")?.asString.flatMap { Base64URLStrict.decode($0, length: 32) } }
        guard hashes.count == steps.count,
              let root = PCARfc9162.rootFromInclusionPath(PCARfc9162.leafHash(statement), index, size, hashes) else { return false }
        if let p = cose.payload, p != root { return false }
        if let vk = verificationKey {
            guard let alg = try? algOf(cose.protectedMap), let msg = try? sigStructure(cose.protectedBytes, root),
                  verifyBytes(alg, vk, msg, cose.signature, allowHighS: allowHighS) else { return false }
        }
        if let t = treeRoot, !IV.same(t, Base64URLStrict.encode(root)) { return false }
        if let sk = statementKey, !verifyStatement(statement, sk, allowHighS: allowHighS) { return false }
        return true
    }

    /// Verify an RFC 9942 / RFC 9162 consistency proof `[oldSize, newSize, [hashes]]` between two pinned roots (b64u). Fail closed.
    public static func verifyConsistencyProof(_ proof: [UInt8], _ oldRoot: String, _ newRoot: String) -> Bool {
        guard case let .array(v)? = try? decode(proof), v.count == 3, case let .int(oldSize) = v[0], case let .int(newSize) = v[1], case let .array(items) = v[2] else { return false }
        var path: [[UInt8]] = []
        for i in items { guard case let .bytes(b) = i else { return false }; path.append(b) }
        guard let r1 = Base64URLStrict.decode(oldRoot, length: 32), let r2 = Base64URLStrict.decode(newRoot, length: 32) else { return false }
        return PCARfc9162.verifyConsistencyPath(oldSize, newSize, r1, r2, path)
    }
}
