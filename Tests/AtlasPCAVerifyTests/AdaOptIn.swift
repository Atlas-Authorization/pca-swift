import Foundation
#if canImport(AtlasPCAAda)
import AtlasPCAAda
#endif

/// With the opt-in AtlasPCAAda product linked (see Package.swift) the verifier tests register its UTS 46 domain-to-ASCII, so the IDN corpus cases run
/// instead of being skipped; without it this is a no-op.
enum AdaOptIn {
    static var linked: Bool {
        #if canImport(AtlasPCAAda)
        return true
        #else
        return false
        #endif
    }

    static func register() {
        #if canImport(AtlasPCAAda)
        PCAAda.register()
        #endif
    }
}
