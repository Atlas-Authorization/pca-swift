import Foundation
import CryptoKit

/// SHA-3 (FIPS 202) digests. Linux: swift-crypto. Apple: CryptoKit, which has SHA-3 only from OS 26 (and an SDK with Swift 6.2);
/// anywhere else `digest` returns nil and callers refuse, never fall back to another hash.
enum Sha3 {
    static let names = ["sha3-256", "sha3-512"]

    static func digest(_ name: String, _ b: [UInt8]) -> [UInt8]? {
        #if os(Linux)
        return hash(name, b)
        #elseif compiler(>=6.2)
        if #available(macOS 26.0, iOS 26.0, tvOS 26.0, watchOS 26.0, *) { return hash(name, b) }
        return nil
        #else
        return nil
        #endif
    }

    #if os(Linux) || compiler(>=6.2)
    #if !os(Linux)
    @available(macOS 26.0, iOS 26.0, tvOS 26.0, watchOS 26.0, *)
    #endif
    private static func hash(_ name: String, _ b: [UInt8]) -> [UInt8]? {
        switch name {
        case "sha3-256": return Array(SHA3_256.hash(data: Data(b)))
        case "sha3-512": return Array(SHA3_512.hash(data: Data(b)))
        default: return nil
        }
    }
    #endif
}
