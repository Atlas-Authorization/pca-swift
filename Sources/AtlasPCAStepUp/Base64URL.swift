import Foundation

/// Unpadded base64url (RFC 4648 §5), the encoding PCA uses for keys, signatures and messages.
enum Base64URL {
    static func encode(_ data: Data) -> String {
        data.base64EncodedString()
            .replacingOccurrences(of: "+", with: "-")
            .replacingOccurrences(of: "/", with: "_")
            .replacingOccurrences(of: "=", with: "")
    }

    /// Returns nil for malformed input (also tolerates padded input).
    static func decode(_ string: String) -> Data? {
        var s = string.replacingOccurrences(of: "-", with: "+").replacingOccurrences(of: "_", with: "/")
        s = s.trimmingCharacters(in: CharacterSet(charactersIn: "="))
        switch s.count % 4 {
        case 0: break
        case 2: s += "=="
        case 3: s += "="
        default: return nil
        }
        return Data(base64Encoded: s)
    }
}
