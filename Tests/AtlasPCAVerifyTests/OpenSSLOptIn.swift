import Foundation
#if canImport(AtlasPCAOpenSSL)
import AtlasPCAOpenSSL
#endif

/// With ATLAS_PCA_OPENSSL=1 the verifier tests link the opt-in AtlasPCAOpenSSL product and its signers / verifiers replace the natively
/// refused (skipped) cases; without it this is a no-op.
enum OpenSSLOptIn {
    static var linked: Bool {
        #if canImport(AtlasPCAOpenSSL)
        return true
        #else
        return false
        #endif
    }

    static func register() {
        #if canImport(AtlasPCAOpenSSL)
        PCAOpenSSL.register()
        #endif
    }
}
