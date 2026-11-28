import Foundation
import CBlst

/// The pairing target group GT as 576-byte canonical Fp12 encodings (12 coordinates, 48 bytes big-endian each), through the
/// shim over blst's public API. Every operation returns nil on malformed input (non-canonical coordinate, bad point, identity).
public enum Gt {
    public static let size = 576

    public static func mul(_ a: [UInt8], _ b: [UInt8]) -> [UInt8]? {
        guard a.count == size, b.count == size else { return nil }
        var out = [UInt8](repeating: 0, count: size)
        return withBytes(a) { pa in withBytes(b) { pb in pca_gt_mul(&out, pa, pb) } } == 1 ? out : nil
    }

    /// a^k for a 32-byte big-endian exponent (all 256 bits processed).
    public static func pow(_ a: [UInt8], _ k: [UInt8]) -> [UInt8]? {
        guard a.count == size, k.count == 32 else { return nil }
        var out = [UInt8](repeating: 0, count: size)
        return withBytes(a) { pa in withBytes(k) { pk in pca_gt_pow(&out, pa, pk) } } == 1 ? out : nil
    }

    /// A canonical encoding of an element of the order-r subgroup other than the identity.
    public static func isElement(_ a: [UInt8]) -> Bool { a.count == size && withBytes(a) { pca_gt_is_element($0) } == 1 }

    /// prod_i e(g1s[i], g2s[i]) with one final exponentiation; points are canonical compressed non-identity prime-order points.
    public static func pairing(_ g1s: [[UInt8]], _ g2s: [[UInt8]]) -> [UInt8]? {
        let n = g1s.count
        guard n > 0, g2s.count == n, g1s.allSatisfy({ $0.count == 48 }), g2s.allSatisfy({ $0.count == 96 }) else { return nil }
        let f1 = Array(g1s.joined()), f2 = Array(g2s.joined())
        var out = [UInt8](repeating: 0, count: size)
        return withBytes(f1) { p1 in withBytes(f2) { p2 in pca_gt_pairing(&out, p1, p2, n) } } == 1 ? out : nil
    }
}
