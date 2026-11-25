import Foundation
import CAda
import AtlasPCAVerify

/// IDNA host parity: the WHATWG URL host parser's domain-to-ASCII on Ada (the parser Node's URL uses), registered into the verifier's seam so a
/// non-ASCII host (`WhatwgURL`, the VC and web-bot-auth URL checks) and a CIBA payee word get the reference's A-label instead of a refusal or the
/// built-in approximation. Opt-in: AtlasPCAVerify builds and runs without it.
public enum PCAAda {
    /// Registers `domainToASCII` with the verifier.
    public static func register() {
        PCAExtraCrypto.domainToASCII = { domainToASCII($0) }
    }

    /// The host as Node's `url.domainToASCII` returns it; nil where that is the empty string (the host is refused).
    public static func domainToASCII(_ host: String) -> String? {
        let bytes = Array(host.utf8)
        var out = [UInt8](repeating: 0, count: 2048)
        var n = 0
        guard atlas_ada_domain_to_ascii(bytes, bytes.count, &out, out.count, &n) == 1, n > 0, n <= out.count else { return nil }
        return String(decoding: out[0..<n], as: UTF8.self)
    }
}
