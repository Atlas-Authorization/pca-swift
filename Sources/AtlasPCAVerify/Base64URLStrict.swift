import Foundation

/// STRICT base64url (RFC 4648 §5, NO padding), matching `hash.ts` `decodeB64uStrict` / the Rust
/// `decode_b64u_strict`: alphabet `[A-Za-z0-9_-]` only, no whitespace, no `=`, `len % 4 != 1`, and the
/// unused trailing bits of the last character MUST be zero (re-encoding reproduces the input). When
/// `length` is given the DECODED length must equal it. Returns nil on ANY deviation.
enum Base64URLStrict {
    private static let alphabet: [UInt8] = Array("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_".utf8)
    private static let reverse: [Int8] = {
        var r = [Int8](repeating: -1, count: 256)
        for (i, c) in alphabet.enumerated() { r[Int(c)] = Int8(i) }
        return r
    }()

    static func encode(_ bytes: [UInt8]) -> String {
        var out = [UInt8]()
        out.reserveCapacity((bytes.count * 4 + 2) / 3)
        var i = 0
        while i < bytes.count {
            let b0 = UInt32(bytes[i])
            let b1 = i + 1 < bytes.count ? UInt32(bytes[i + 1]) : 0
            let b2 = i + 2 < bytes.count ? UInt32(bytes[i + 2]) : 0
            let n = (b0 << 16) | (b1 << 8) | b2
            out.append(alphabet[Int((n >> 18) & 0x3f)])
            out.append(alphabet[Int((n >> 12) & 0x3f)])
            if i + 1 < bytes.count { out.append(alphabet[Int((n >> 6) & 0x3f)]) }
            if i + 2 < bytes.count { out.append(alphabet[Int(n & 0x3f)]) }
            i += 3
        }
        return String(decoding: out, as: UTF8.self)
    }

    /// Encoded (unpadded) length of `n` bytes.
    static func encodedLength(_ n: Int) -> Int { (n * 4 + 2) / 3 }

    static func decode(_ s: String, length: Int? = nil) -> [UInt8]? {
        let b = Array(s.utf8)
        for c in b where reverse[Int(c)] < 0 { return nil }
        if b.count % 4 == 1 { return nil }
        if let n = length, b.count != encodedLength(n) { return nil }
        var out = [UInt8]()
        var acc: UInt32 = 0
        var bits = 0
        for c in b {
            acc = (acc << 6) | UInt32(reverse[Int(c)])
            bits += 6
            if bits >= 8 {
                bits -= 8
                out.append(UInt8((acc >> UInt32(bits)) & 0xff))
            }
        }
        if encode(out) != s { return nil } // non-canonical trailing bits
        if let n = length, out.count != n { return nil }
        return out
    }

    static func isValid(_ s: String, length: Int? = nil) -> Bool { decode(s, length: length) != nil }
}
