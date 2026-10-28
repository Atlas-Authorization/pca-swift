import Foundation

// A small XML reader and a canonicaliser (inclusive C14N; identical to C14N 1.1 for documents without xml:* attributes, which the
// RIM profile refuses) for the NVIDIA RIM XMLDSig check. Only the subset the profile needs is supported: elements, attributes,
// namespaces, text, CDATA and the predefined and numeric character references. A comment, processing instruction or DOCTYPE is
// not interpreted: the first of them (in document order) is recorded as a profile violation, and the verifier refuses the
// document before any cryptography.

struct XmlAttr {
    var name = "", prefix = "", local = "", ns = "", value = ""
}

struct XmlDecl {
    var prefix: String
    var uri: String
}

final class XmlNode {
    var elem = false
    var name = "", prefix = "", local = "", ns = ""
    var attrs: [XmlAttr] = []
    var decls: [XmlDecl] = []
    var children: [XmlNode] = []
    var text = ""
    weak var parent: XmlNode?

    init(elem: Bool = false, text: String = "") {
        self.elem = elem
        self.text = text
    }

    /// Resolves a prefix ("" is the default namespace) through the element's ancestors.
    func lookupNS(_ prefix: String) -> String? {
        var e: XmlNode? = self
        while let x = e {
            for d in x.decls where d.prefix == prefix { return d.uri }
            e = x.parent
        }
        return nil
    }

    func appendText(_ t: String) {
        if let last = children.last, !last.elem {
            last.text += t
            return
        }
        let n = XmlNode(elem: false, text: t)
        n.parent = self
        children.append(n)
    }

    /// Binds the element's and its attributes' prefixes (the declarations of the element itself are in scope).
    func resolveNames() throws {
        if let i = name.firstIndex(of: ":") {
            prefix = String(name[name.startIndex..<i])
            local = String(name[name.index(after: i)...])
        } else {
            prefix = ""
            local = name
        }
        let uri = lookupNS(prefix)
        if !prefix.isEmpty && uri == nil { throw AttestError("namespace prefix \(prefix) is not bound") }
        ns = uri ?? ""
        for i in 0..<attrs.count {
            if attrs[i].prefix.isEmpty { continue }
            guard let u = lookupNS(attrs[i].prefix) else { throw AttestError("namespace prefix \(attrs[i].prefix) is not bound") }
            attrs[i].ns = u
        }
    }

    func attr(_ name: String) -> String { attrs.first { $0.name == name }?.value ?? "" }

    func textContent() -> String {
        if !elem { return text }
        return children.map { $0.textContent() }.joined()
    }

    func elementChildren() -> [XmlNode] { children.filter { $0.elem } }

    func elementChildrenNS(_ ns: String, _ local: String) -> [XmlNode] { elementChildren().filter { $0.ns == ns && $0.local == local } }

    /// The descendant elements with the given namespace and local name.
    func descendantsNS(_ ns: String, _ local: String) -> Int {
        var total = 0
        for c in elementChildren() {
            if c.ns == ns && c.local == local { total += 1 }
            total += c.descendantsNS(ns, local)
        }
        return total
    }

    /// The in-scope namespace bindings of the element (its own declarations included).
    func scope() -> [String: String] {
        var chain: [XmlNode] = []
        var e: XmlNode? = self
        while let x = e {
            chain.append(x)
            e = x.parent
        }
        var out: [String: String] = [:]
        for x in chain.reversed() { for d in x.decls { out[d.prefix] = d.uri } }
        return out
    }
}

struct XmlDoc {
    var root: XmlNode?
    var violation = ""
}

enum XML {
    static func isSpace(_ c: UInt8) -> Bool { c == 0x20 || c == 0x09 || c == 0x0a || c == 0x0d }

    /// Decodes the predefined and numeric character references.
    static func decode(_ s: ArraySlice<UInt8>) throws -> String {
        if !s.contains(0x26) { return String(decoding: s, as: UTF8.self) }
        var out = String.UnicodeScalarView()
        var buf: [UInt8] = []
        func flush() {
            if !buf.isEmpty {
                out.append(contentsOf: String(decoding: buf, as: UTF8.self).unicodeScalars)
                buf = []
            }
        }
        var i = s.startIndex
        while i < s.endIndex {
            if s[i] != 0x26 {
                buf.append(s[i])
                i += 1
                continue
            }
            guard let j = s[i...].firstIndex(of: 0x3b) else { throw AttestError("unterminated entity reference") }
            let ent = String(decoding: s[(i + 1)..<j], as: UTF8.self)
            i = j + 1
            flush()
            switch ent {
            case "lt": out.append("<")
            case "gt": out.append(">")
            case "amp": out.append("&")
            case "quot": out.append("\"")
            case "apos": out.append("'")
            default:
                guard ent.hasPrefix("#") else { throw AttestError("undefined entity &\(ent);") }
                let n: Int64?
                if ent.hasPrefix("#x") { n = Int64(ent.dropFirst(2), radix: 16) } else { n = Int64(ent.dropFirst(1), radix: 10) }
                guard let v = n, v >= 0, v <= 0x10ffff, v == 0x9 || v == 0xa || v == 0xd || (v >= 0x20 && v <= 0xd7ff) || (v >= 0xe000 && v <= 0xfffd) || v >= 0x10000,
                      let u = Unicode.Scalar(UInt32(v)) else { throw AttestError("invalid character reference &\(ent);") }
                out.append(u)
            }
        }
        flush()
        return String(out)
    }

    static func index(of needle: [UInt8], in s: [UInt8], from: Int) -> Int? {
        if needle.isEmpty || s.count - from < needle.count || from < 0 { return nil }
        var i = from
        while i + needle.count <= s.count {
            if s[i] == needle[0] {
                var ok = true
                for k in 1..<needle.count where s[i + k] != needle[k] {
                    ok = false
                    break
                }
                if ok { return i }
            }
            i += 1
        }
        return nil
    }

    static func hasPrefix(_ s: [UInt8], _ at: Int, _ p: String) -> Bool {
        let pb = Array(p.utf8)
        if at + pb.count > s.count { return false }
        for k in 0..<pb.count where s[at + k] != pb[k] { return false }
        return true
    }

    static func parse(_ text: String) throws -> XmlDoc {
        var doc = XmlDoc()
        func note(_ v: String) { if doc.violation.isEmpty { doc.violation = v } }
        let s = Array(text.utf8)
        var cur: XmlNode?
        var i = 0
        while i < s.count {
            if s[i] != 0x3c {
                var end = i
                while end < s.count && s[end] != 0x3c { end += 1 }
                let txt = s[i..<end]
                i = end
                guard let c = cur else {
                    if txt.contains(where: { !isSpace($0) }) { throw AttestError("text outside the document element") }
                    continue
                }
                c.appendText(try decode(txt))
                continue
            }
            if hasPrefix(s, i, "<!--") {
                guard let j = index(of: Array("-->".utf8), in: s, from: i + 4) else { throw AttestError("unterminated comment") }
                note("XML comments are not permitted")
                i = j + 3
            } else if hasPrefix(s, i, "<?") {
                guard let j = index(of: Array("?>".utf8), in: s, from: i) else { throw AttestError("unterminated processing instruction") }
                note("XML processing instructions are not permitted")
                i = j + 2
            } else if hasPrefix(s, i, "<![CDATA[") {
                guard let j = index(of: Array("]]>".utf8), in: s, from: i), let c = cur else { throw AttestError("misplaced or unterminated CDATA section") }
                c.appendText(String(decoding: s[(i + 9)..<max(i + 9, j)], as: UTF8.self))
                i = j + 3
            } else if hasPrefix(s, i, "<!DOCTYPE") {
                var depth = 0
                var j = i
                while j < s.count {
                    if s[j] == 0x5b { depth += 1 } else if s[j] == 0x5d { depth -= 1 } else if s[j] == 0x3e && depth <= 0 { break }
                    j += 1
                }
                if j >= s.count { throw AttestError("unterminated DOCTYPE") }
                note("DTD / DOCTYPE is not permitted")
                i = j + 1
            } else if hasPrefix(s, i, "</") {
                guard let j = index(of: [0x3e], in: s, from: i), let c = cur else { throw AttestError("unexpected end tag") }
                var nameBytes = Array(s[(i + 2)..<j])
                while let l = nameBytes.last, isSpace(l) { nameBytes.removeLast() }
                let name = String(decoding: nameBytes, as: UTF8.self)
                if name != c.name { throw AttestError("end tag </\(name)> does not match <\(c.name)>") }
                cur = c.parent
                i = j + 1
            } else {
                let (node, selfClose, n) = try parseStartTag(s, i, note)
                i += n
                node.parent = cur
                if let c = cur {
                    c.children.append(node)
                } else {
                    if doc.root != nil { throw AttestError("more than one document element") }
                    doc.root = node
                }
                try node.resolveNames()
                if !selfClose { cur = node }
            }
        }
        if let c = cur { throw AttestError("element <\(c.name)> is not closed") }
        if doc.root == nil { throw AttestError("no document element") }
        return doc
    }

    /// One start tag at `at`; n is the number of bytes consumed.
    static func parseStartTag(_ s: [UInt8], _ at: Int, _ note: (String) -> Void) throws -> (XmlNode, Bool, Int) {
        var i = at + 1
        var j = i
        while j < s.count && !isSpace(s[j]) && s[j] != 0x2f && s[j] != 0x3e { j += 1 }
        let name = String(decoding: s[i..<j], as: UTF8.self)
        if name.isEmpty { throw AttestError("malformed start tag") }
        let node = XmlNode(elem: true)
        node.name = name
        var seen = Set<String>()
        i = j
        while true {
            while i < s.count && isSpace(s[i]) { i += 1 }
            if i >= s.count { throw AttestError("unterminated start tag") }
            if s[i] == 0x3e { return (node, false, i + 1 - at) }
            if s[i] == 0x2f {
                if i + 1 < s.count && s[i + 1] == 0x3e { return (node, true, i + 2 - at) }
                throw AttestError("malformed start tag")
            }
            var k = i
            while k < s.count && !isSpace(s[k]) && s[k] != 0x3d && s[k] != 0x3e && s[k] != 0x2f { k += 1 }
            let aname = String(decoding: s[i..<k], as: UTF8.self)
            while k < s.count && isSpace(s[k]) { k += 1 }
            if aname.isEmpty || k >= s.count || s[k] != 0x3d { throw AttestError("malformed attribute") }
            k += 1
            while k < s.count && isSpace(s[k]) { k += 1 }
            if k >= s.count || (s[k] != 0x22 && s[k] != 0x27) { throw AttestError("unquoted attribute value") }
            let q = s[k]
            guard let e = s[(k + 1)...].firstIndex(of: q) else { throw AttestError("unterminated attribute value") }
            let raw = s[(k + 1)..<e]
            if raw.contains(0x3c) { throw AttestError("'<' in an attribute value") }
            let val = try decode(raw)
            i = e + 1
            if seen.contains(aname) { throw AttestError("attribute \(aname) is repeated") }
            seen.insert(aname)
            if aname.lowercased().hasPrefix("xml:") { note("xml:* attribute '\(aname)' is not permitted (C14N 1.1 profile)") }
            if aname == "xmlns" {
                node.decls.append(XmlDecl(prefix: "", uri: val))
            } else if aname.hasPrefix("xmlns:") {
                node.decls.append(XmlDecl(prefix: String(aname.dropFirst(6)), uri: val))
            } else {
                var a = XmlAttr()
                a.name = aname
                if let c = aname.firstIndex(of: ":") {
                    a.prefix = String(aname[aname.startIndex..<c])
                    a.local = String(aname[aname.index(after: c)...])
                } else {
                    a.local = aname
                }
                a.value = val
                node.attrs.append(a)
            }
        }
    }

    static func escapeText(_ s: String) -> String {
        var out = ""
        for r in s.unicodeScalars {
            switch r {
            case "&": out += "&amp;"
            case "<": out += "&lt;"
            case ">": out += "&gt;"
            case "\r": out += "&#xD;"
            default: out.unicodeScalars.append(r)
            }
        }
        return out
    }

    static func escapeAttr(_ s: String) -> String {
        var out = ""
        for r in s.unicodeScalars {
            switch r {
            case "&": out += "&amp;"
            case "<": out += "&lt;"
            case "\"": out += "&quot;"
            case "\t": out += "&#x9;"
            case "\n": out += "&#xA;"
            case "\r": out += "&#xD;"
            default: out.unicodeScalars.append(r)
            }
        }
        return out
    }

    /// The inclusive canonical form of the subtree at `n`, omitting the subtree `skip` (the enveloped-signature transform).
    /// `parentScope` is the in-scope bindings of n's ancestors: an apex element renders every in-scope namespace.
    static func canonicalize(_ n: XmlNode, _ parentScope: [String: String], _ skip: XmlNode?) -> String {
        var out = ""
        c14n(&out, n, parentScope, [:], skip)
        return out
    }

    static func c14n(_ sb: inout String, _ n: XmlNode, _ parentScope: [String: String], _ rendered: [String: String], _ skip: XmlNode?) {
        var scope = parentScope
        for d in n.decls { scope[d.prefix] = d.uri }
        var emit: [String] = []
        for (p, uri) in scope {
            if p == "xml" || (uri.isEmpty && !p.isEmpty) { continue }
            if (rendered[p] ?? "") == uri { continue }
            emit.append(p)
        }
        emit.sort { IV.utf8Less($0, $1) }
        var newRendered = rendered
        sb += "<" + n.name
        for p in emit {
            if p.isEmpty { sb += " xmlns=\"" + escapeAttr(scope[p] ?? "") + "\"" } else { sb += " xmlns:" + p + "=\"" + escapeAttr(scope[p] ?? "") + "\"" }
            newRendered[p] = scope[p]
        }
        let attrs = n.attrs.enumerated().sorted { l, r in
            let a = l.element, b = r.element
            if a.ns.isEmpty != b.ns.isEmpty { return a.ns.isEmpty }
            let ka = a.ns + a.local, kb = b.ns + b.local
            return ka == kb ? l.offset < r.offset : IV.utf8Less(ka, kb)
        }.map { $0.element }
        for a in attrs { sb += " " + a.name + "=\"" + escapeAttr(a.value) + "\"" }
        sb += ">"
        for c in n.children {
            if let sk = skip, c === sk { continue }
            if c.elem { c14n(&sb, c, scope, newRendered, skip) } else { sb += escapeText(c.text) }
        }
        sb += "</" + n.name + ">"
    }
}
