import Foundation
import CryptoKit
import AtlasPCAVerify
import AtlasPCAMpc

/// The structured abort of the networked runner (blames a party only when the evidence names one).
public typealias NetAbort = PCAMpc.NetWire.NetAbort
/// A refusal that is not a protocol abort (bad configuration, misuse of the API).
public struct NetError: Error, CustomStringConvertible {
    public let description: String
    public init(_ m: String) { description = m }
}

extension JSONValue {
    var jStr: String? { if case let .string(s) = self { return s } else { return nil } }
    var jObj: JObject? { if case let .object(o) = self { return o } else { return nil } }
    var jArr: [JSONValue]? { if case let .array(a) = self { return a } else { return nil } }
    func jGet(_ key: String) -> JSONValue? { jObj?[JKey(key)] }
}

public enum NetUtil {
    /// A small non-negative-or-negative integer carried as a JSON number (what the reference accepts as an id / count); nil otherwise.
    static func int(_ v: JSONValue?) -> Int? {
        guard let d = IV.num(v), d.isFinite, d == d.rounded(), abs(d) < 1e9, !(d == 0 && d.sign == .minus) else { return nil }
        return Int(d)
    }

    static func hex(_ b: [UInt8]) -> String { b.map { String(format: "%02x", $0) }.joined() }

    static func unhex(_ s: String) -> [UInt8]? {
        let u = Array(s.utf8)
        guard u.count % 2 == 0 else { return nil }
        var out: [UInt8] = []
        out.reserveCapacity(u.count / 2)
        func nib(_ c: UInt8) -> UInt8? { c >= 48 && c <= 57 ? c - 48 : (c >= 97 && c <= 102 ? c - 87 : nil) }
        var i = 0
        while i < u.count {
            guard let a = nib(u[i]), let b = nib(u[i + 1]) else { return nil }
            out.append(a << 4 | b)
            i += 2
        }
        return out
    }

    /// Exactly `len` lowercase hex digits.
    static func isHex(_ s: String?, _ len: Int) -> Bool {
        guard let s = s, s.utf8.count == len else { return false }
        return s.utf8.allSatisfy { ($0 >= 48 && $0 <= 57) || ($0 >= 97 && $0 <= 102) }
    }

    static func sha256(_ parts: [[UInt8]]) -> [UInt8] {
        var h = SHA256()
        for p in parts { h.update(data: p) }
        return Array(h.finalize())
    }

    /// SHA-256 over the parts, each followed by one zero byte (the reference's domain separation of variable-length parts).
    static func shaZ(_ parts: [[UInt8]]) -> [UInt8] { sha256(parts.flatMap { [$0, [0]] }) }

    static func random(_ n: Int) -> [UInt8] {
        var g = SystemRandomNumberGenerator()
        return (0..<n).map { _ in UInt8.random(in: 0...255, using: &g) }
    }

    public static func utf8(_ s: String) -> [UInt8] { Array(s.utf8) }

    /// Printable-ASCII, length-capped copy of untrusted text (no control characters, no log forging).
    static func sanitize(_ x: String, _ max: Int) -> String {
        let s = String(String.UnicodeScalarView(x.unicodeScalars.map { $0.value >= 0x20 && $0.value <= 0x7e ? $0 : "?" }))
        return s.count > max ? String(s.prefix(max)) : s
    }

    static func hx(_ x: UInt64) -> String { PCAMpc.NetWire.hx(x) }
    static func hxList(_ xs: [UInt64]) -> JSONValue { .array(xs.map { .string(hx($0)) }) }
}
