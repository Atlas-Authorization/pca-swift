import Foundation

/// What the platform URL class reports beyond `WhatwgURL.parse`: the bare hostname and port, and whether the userinfo or the fragment
/// is non-empty (an `@` with nothing before it, or a `#` with nothing after it, reports empty). Additive; the parser is untouched.
extension WhatwgURL {
    /// `hostname` (IPv6 without brackets) and the explicit port, nil when it is the scheme's default (the platform class reports "").
    var hostnameAndPort: (hostname: String, port: Int?) {
        if host.hasPrefix("["), let end = host.firstIndex(of: "]") {
            let name = String(host[host.index(after: host.startIndex)..<end])
            let rest = host[host.index(after: end)...]
            return (name, rest.hasPrefix(":") ? Int(rest.dropFirst()) : nil)
        }
        guard let c = host.lastIndex(of: ":") else { return (host, nil) }
        return (String(host[..<c]), Int(host[host.index(after: c)...]))
    }

    /// (userinfo non-empty, fragment non-empty) of the raw text. A special scheme reads its authority after any run of slashes; another
    /// scheme has one only after `//` (otherwise it has no userinfo).
    static func userinfoAndFragment(_ input: String) -> (userinfo: Bool, fragment: Bool) {
        var s = Array(input.unicodeScalars)
        while let f = s.first, f.value <= 0x20 { s.removeFirst() }
        while let l = s.last, l.value <= 0x20 { s.removeLast() }
        s.removeAll { $0 == "\t" || $0 == "\n" || $0 == "\r" }
        guard let colon = s.firstIndex(of: ":") else { return (false, false) }
        let scheme = String(String.UnicodeScalarView(s[..<colon])).lowercased()
        var rest = Array(s[(colon + 1)...])
        var fragment = false
        if let h = rest.firstIndex(of: "#") {
            fragment = h + 1 < rest.count
            rest = Array(rest[..<h])
        }
        if let q = rest.firstIndex(of: "?") { rest = Array(rest[..<q]) }
        if special[scheme] != nil {
            while let c = rest.first, c == "/" || c == "\\" { rest.removeFirst() }
        } else {
            guard rest.count >= 2, rest[0] == "/", rest[1] == "/" else { return (false, fragment) }
            rest = Array(rest[2...])
        }
        let authority = rest.firstIndex(where: { $0 == "/" || ($0 == "\\" && special[scheme] != nil) }).map { Array(rest[..<$0]) } ?? rest
        guard let at = authority.lastIndex(of: "@") else { return (false, fragment) }
        let info = authority[..<at]
        return (!(info.isEmpty || info.elementsEqual([":"])), fragment) // user and password both empty <=> "" or ":"
    }
}
