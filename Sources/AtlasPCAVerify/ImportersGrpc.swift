import Foundation

private func utf8Less(_ a: String, _ b: String) -> Bool { Array(a.utf8).lexicographicallyPrecedes(Array(b.utf8)) }

/// Protobuf services to drafts, from `.proto` text or a binary FileDescriptorSet. `service.method` becomes the verb; `google.api.http` gives method and
/// path; `idempotency_level` gives read / idempotent; field behavior refines params; streaming methods get `pca.bulk`. Offline, bounded; the descriptor
/// wire format is read by hand (no protobuf dependency).
public enum GrpcImporter {
    // ---- model ----

    public struct PField {
        public var name = "", type = "", scope = ""
        public var repeated = false, optional = false
        public var map: (String, String)?
        public var behavior: [String] = []
        func toJson() -> JSONValue {
            var m = Jx.obj(["name": .string(name), "type": .string(type), "scope": .string(scope), "repeated": .bool(repeated), "optional": .bool(optional)])
            if let mp = map { m[o: "map"] = .array([.string(mp.0), .string(mp.1)]) }
            m[o: "behavior"] = Jx.strs(behavior)
            return .object(m)
        }
    }

    public final class PMsg {
        public var full = ""
        public var fields: [PField] = []
        public var mapEntry = false
    }

    public final class PEnum {
        public var full = ""
        public var values: [String] = []
    }

    public final class PHttp {
        public var method: String?
        public var path: String?
        public var body: String?
    }

    public final class PMethod {
        public var name = "", input = "", output = "", scope = ""
        public var idem: String?
        public var cs = false, ss = false
        public var http: PHttp?
    }

    public final class PService {
        public var full = "", name = ""
        public var methods: [PMethod] = []
    }

    public final class ProtoModel {
        public private(set) var msgOrder: [String] = []
        public private(set) var messages: [JKey: PMsg] = [:]
        public private(set) var enumOrder: [String] = []
        public private(set) var enums: [JKey: PEnum] = [:]
        public var services: [PService] = []

        func putMsg(_ full: String, _ m: PMsg) { if messages[JKey(full)] == nil { msgOrder.append(full) }; messages[JKey(full)] = m }
        func putEnum(_ full: String, _ e: PEnum) { if enums[JKey(full)] == nil { enumOrder.append(full) }; enums[JKey(full)] = e }

        /// `{messages: [[full, {...}]...], enums: [[full, [values]]...], services: [{...}]}`.
        public func toJson() -> JSONValue {
            let ms: [JSONValue] = msgOrder.map { k in
                let m = messages[JKey(k)]!
                return .array([.string(m.full), AK.obj(["full": .string(m.full), "fields": .array(m.fields.map { $0.toJson() }), "mapEntry": .bool(m.mapEntry)])])
            }
            let es: [JSONValue] = enumOrder.map { k in let e = enums[JKey(k)]!; return .array([.string(e.full), Jx.strs(e.values)]) }
            let ss: [JSONValue] = services.map { s in
                let mm: [JSONValue] = s.methods.map { x in
                    var o = Jx.obj(["name": .string(x.name), "input": .string(x.input), "output": .string(x.output), "cs": .bool(x.cs), "ss": .bool(x.ss), "scope": .string(x.scope)])
                    if let hx = x.http {
                        var h = Jx.obj(["method": hx.method.map { .string($0) } ?? .null, "path": hx.path.map { .string($0) } ?? .null])
                        if let b = hx.body { h[o: "body"] = .string(b) }
                        o[o: "http"] = .object(h)
                    }
                    if let i = x.idem { o[o: "idem"] = .string(i) }
                    return .object(o)
                }
                return AK.obj(["full": .string(s.full), "name": .string(s.name), "methods": .array(mm)])
            }
            return AK.obj(["messages": .array(ms), "enums": .array(es), "services": .array(ss)])
        }
    }

    private static let SCALAR_NAMES: Set<String> = ["double", "float", "int32", "int64", "uint32", "uint64", "sint32", "sint64", "fixed32", "fixed64", "sfixed32", "sfixed64", "bool", "string", "bytes"]

    // ---- .proto text ----

    private struct Tok { let t: String; let v: String }

    private static func idStart(_ c: UInt16) -> Bool { (c >= 65 && c <= 90) || (c >= 97 && c <= 122) || c == 0x5F || c == 0x2E }
    private static func idChar(_ c: UInt16) -> Bool { idStart(c) || (c >= 48 && c <= 57) }
    private static func numChar(_ c: UInt16) -> Bool { c == 0x2D || c == 0x2B || c == 0x2E || (c >= 48 && c <= 57) || (c >= 65 && c <= 90) || (c >= 97 && c <= 122) }
    private static func starts(_ u: [UInt16], _ s: String, _ i: Int) -> Bool {
        let p = Array(s.utf16)
        return i + p.count <= u.count && Array(u[i..<(i + p.count)]) == p
    }

    private static func lex(_ src: String, _ maxTokens: Int) throws -> [Tok] {
        var out: [Tok] = []
        let u = Array(src.utf16)
        let n = u.count
        var i = 0
        while i < n {
            let ch = u[i]
            let push: Tok
            if let sc = Unicode.Scalar(ch), Jx.jsSpace(sc) { i += 1; continue }
            if starts(u, "//", i) { while i < n && u[i] != 0x0A { i += 1 }; continue }
            if starts(u, "/*", i) {
                var j = i + 2
                var found = -1
                while j + 1 < n { if u[j] == 0x2A && u[j + 1] == 0x2F { found = j; break }; j += 1 }
                if found < 0 { throw ActionKitError(code: "bad_source", message: "unterminated comment in proto source") }
                i = found + 2
                continue
            }
            if ch == 0x22 || ch == 0x27 {
                var j = i + 1
                var s: [UInt16] = []
                while j < n && u[j] != ch {
                    if u[j] == 0x0A { throw ActionKitError(code: "bad_source", message: "unterminated string in proto source") }
                    if u[j] == 0x5C { if j + 1 < n { s.append(u[j + 1]) }; j += 2 } else { s.append(u[j]); j += 1 }
                }
                if j >= n { throw ActionKitError(code: "bad_source", message: "unterminated string in proto source") }
                push = Tok(t: "str", v: String(decoding: s, as: UTF16.self))
                i = j + 1
            } else if idStart(ch) {
                var j = i + 1
                while j < n && idChar(u[j]) { j += 1 }
                push = Tok(t: "id", v: String(decoding: u[i..<j], as: UTF16.self))
                i = j
            } else if ch == 0x2D || (ch >= 48 && ch <= 57) {
                var j = i + 1
                while j < n && numChar(u[j]) { j += 1 }
                push = Tok(t: "num", v: String(decoding: u[i..<j], as: UTF16.self))
                i = j
            } else if "{}[]()<>=;,:".utf16.contains(ch) { push = Tok(t: "p", v: String(decoding: [ch], as: UTF16.self)); i += 1 }
            else { throw ActionKitError(code: "bad_source", message: "unexpected character in proto source at offset \(i)") }
            if out.count >= maxTokens { throw ActionKitError(code: "import_limit", message: "the proto source has too many tokens") }
            out.append(push)
        }
        return out
    }

    private static let HTTP_VERBS = ["get", "put", "post", "delete", "patch"]

    private final class PP {
        let toks: [Tok]
        let m: ProtoModel
        let maxDepth: Int
        var i = 0
        var pkg = ""
        init(_ toks: [Tok], _ m: ProtoModel, _ maxDepth: Int) { self.toks = toks; self.m = m; self.maxDepth = maxDepth }

        func cur() -> Tok? { i < toks.count ? toks[i] : nil }
        func isV(_ v: String) -> Bool { if let t = cur() { return t.t != "str" && t.v == v }; return false }
        @discardableResult func eat(_ v: String) -> Bool { if isV(v) { i += 1; return true }; return false }
        func fail(_ msg: String) -> ActionKitError { ActionKitError(code: "bad_source", message: "proto parse error: \(msg) near '\(ImportCommon.clip(.string(cur()?.v ?? "<end>"), 30))'") }
        func expect(_ v: String) throws { if !eat(v) { throw fail("expected '\(v)'") } }
        func id() throws -> String { guard let t = cur(), t.t == "id" else { throw fail("expected an identifier") }; i += 1; return t.v }

        /// Skip to the matching close of an already-opened bracket.
        func skipTo(_ open: String, _ close: String) throws {
            var depth = 1
            while depth > 0 {
                let t = i < toks.count ? toks[i] : nil
                i += 1
                guard let tt = t else { throw fail("unterminated block") }
                if tt.t == "p" { if tt.v == open { depth += 1 } else if tt.v == close { depth -= 1 } }
            }
        }

        func skipStatement() throws {
            while cur() != nil && !isV(";") {
                if isV("{") { i += 1; try skipTo("{", "}"); return }
                i += 1
            }
            eat(";")
        }

        func file() throws {
            while cur() != nil {
                if eat(";") { continue }
                let kw = try id()
                if kw == "package" { pkg = try id(); try expect(";") }
                else if kw == "message" { try message(pkg, 0) }
                else if kw == "enum" { try enumDef(pkg) }
                else if kw == "service" { try service() }
                else if kw == "extend" { _ = try id(); try expect("{"); try skipTo("{", "}") }
                else { try skipStatement() }
            }
        }

        func qual(_ scope: String, _ name: String) -> String { scope.isEmpty ? name : "\(scope).\(name)" }

        func enumDef(_ scope: String) throws {
            let name = try id()
            let full = qual(scope, name)
            try expect("{")
            var values: [String] = []
            while !isV("}") {
                if cur() == nil { throw fail("unterminated enum") }
                if isV("option") || isV("reserved") { try skipStatement(); continue }
                values.append(try id())
                try skipStatement()
            }
            try expect("}")
            let e = PEnum()
            e.full = full
            e.values = values
            m.putEnum(full, e)
        }

        /// Field options: collect `field_behavior` names; everything else is skipped.
        func fieldOptions() throws -> [String] {
            var behavior: [String] = []
            if !eat("[") { return behavior }
            var depth = 1
            var inBehavior = false
            while depth > 0 {
                let t = i < toks.count ? toks[i] : nil
                i += 1
                guard let tt = t else { throw fail("unterminated field options") }
                if tt.t == "p" {
                    if tt.v == "[" || tt.v == "{" { depth += 1 }
                    else if tt.v == "]" || tt.v == "}" { depth -= 1 }
                    else if tt.v == "," { inBehavior = false }
                } else if tt.t == "id" {
                    if tt.v.hasSuffix("field_behavior") { inBehavior = true }
                    else if inBehavior && Actions.fullMatch("[A-Z_]+", tt.v) { behavior.append(tt.v) }
                }
            }
            return behavior
        }

        func field(_ msg: PMsg, _ full: String, _ label: String?, _ oneof: Bool) throws {
            var repeated = label == "repeated"
            var type = try id()
            var map: (String, String)? = nil
            if type == "map" && eat("<") { let k = try id(); try expect(","); let v = try id(); try expect(">"); map = (k, v); type = "map"; repeated = false }
            let fname = try id()
            try expect("=")
            i += 1 // field number
            let behavior = try fieldOptions()
            try expect(";")
            var f = PField()
            f.name = fname; f.type = type; f.scope = full; f.repeated = repeated; f.optional = label == "optional" || oneof; f.map = map; f.behavior = behavior
            msg.fields.append(f)
        }

        func message(_ scope: String, _ depth: Int) throws {
            if depth > maxDepth { throw ActionKitError(code: "import_limit", message: "proto message nesting is too deep") }
            let name = try id()
            let full = qual(scope, name)
            let msg = PMsg()
            msg.full = full
            m.putMsg(full, msg)
            try expect("{")
            while !isV("}") {
                guard let ct = cur() else { throw fail("unterminated message") }
                if eat(";") { continue }
                let kw = ct.t == "id" ? ct.v : ""
                if kw == "message" { i += 1; try message(full, depth + 1); continue }
                if kw == "enum" { i += 1; try enumDef(full); continue }
                if kw == "oneof" {
                    i += 1; _ = try id(); try expect("{")
                    while !isV("}") {
                        if cur() == nil { throw fail("unterminated oneof") }
                        if isV("option") { try skipStatement(); continue }
                        try field(msg, full, nil, true)
                    }
                    try expect("}")
                    continue
                }
                if kw == "option" || kw == "reserved" || kw == "extensions" { try skipStatement(); continue }
                if kw == "extend" { i += 1; _ = try id(); try expect("{"); try skipTo("{", "}"); continue }
                if kw == "group" { try skipStatement(); continue }
                if kw == "repeated" || kw == "optional" || kw == "required" { i += 1; try field(msg, full, kw, false); continue }
                try field(msg, full, nil, false)
            }
            try expect("}")
        }

        func streamKw() -> Bool { if let t = cur(), t.v == "stream", t.t == "id" { i += 1; return true }; return false }

        func service() throws {
            let name = try id()
            let full = qual(pkg, name)
            let svc = PService()
            svc.full = full
            svc.name = name
            try expect("{")
            while !isV("}") {
                if cur() == nil { throw fail("unterminated service") }
                if eat(";") { continue }
                let kw = try id()
                if kw != "rpc" { try skipStatement(); continue }
                let mname = try id()
                try expect("(")
                let cs = streamKw()
                let input = try id()
                try expect(")")
                if try id() != "returns" { throw fail("expected 'returns'") }
                try expect("(")
                let ss = streamKw()
                let output = try id()
                try expect(")")
                let me = PMethod()
                me.name = mname; me.input = input; me.output = output; me.cs = cs; me.ss = ss; me.scope = pkg
                if eat("{") {
                    while !isV("}") {
                        if cur() == nil { throw fail("unterminated rpc body") }
                        if !isV("option") { try skipStatement(); continue }
                        i += 1
                        let oname: String
                        if eat("(") { oname = try id(); try expect(")") } else { oname = try id() }
                        try expect("=")
                        if isV("{") {
                            i += 1
                            var depth = 1
                            while depth > 0 {
                                let t = i < toks.count ? toks[i] : nil
                                i += 1
                                guard let tt = t else { throw fail("unterminated option") }
                                if tt.t == "p" { if tt.v == "{" { depth += 1 } else if tt.v == "}" { depth -= 1 }; continue }
                                if depth == 1 && oname.hasSuffix("http") && tt.t == "id" && HTTP_VERBS.contains(tt.v) && isV(":") {
                                    i += 1
                                    let c1 = cur()
                                    let path = c1 != nil && c1!.t == "str" ? c1!.v : ""
                                    i += 1
                                    if me.http == nil { let h = PHttp(); h.method = tt.v.uppercased(); h.path = path; me.http = h }
                                } else if depth == 1 && oname.hasSuffix("http") && tt.t == "id" && tt.v == "body" && isV(":") {
                                    i += 1
                                    let c1 = cur()
                                    if let c = c1, c.t == "str", let h = me.http { h.body = c.v }
                                    i += 1
                                }
                            }
                            eat(";")
                        } else {
                            let v = cur()
                            i += 1
                            if oname.hasSuffix("idempotency_level"), let vv = v { me.idem = vv.v }
                            eat(";")
                        }
                    }
                    try expect("}")
                    eat(";")
                } else { try expect(";") }
                svc.methods.append(me)
            }
            try expect("}")
            m.services.append(svc)
        }
    }

    public static func parseProto(_ src: String, _ maxTokens: Int = 2_000_000) throws -> ProtoModel {
        let m = ProtoModel()
        try PP(try lex(src, maxTokens), m, 32).file()
        return m
    }

    // ---- binary descriptor set ----

    private final class Reader {
        let b: [UInt8]
        var p: Int
        let end: Int
        init(_ b: [UInt8], _ p: Int, _ end: Int) { self.b = b; self.p = p; self.end = end }
        func more() -> Bool { p < end }

        func varint() throws -> Double {
            var r = 0.0, mul = 1.0
            for _ in 0..<10 {
                if p >= end { throw ActionKitError(code: "bad_source", message: "truncated descriptor") }
                let by = Int(b[p]); p += 1
                r += Double(by & 0x7f) * mul
                if (by & 0x80) == 0 { return r }
                mul *= 128
            }
            throw ActionKitError(code: "bad_source", message: "overlong varint in descriptor")
        }

        @discardableResult func len() throws -> Reader {
            let n = try varint()
            if n > Double(end - p) { throw ActionKitError(code: "bad_source", message: "descriptor length exceeds the buffer") }
            let r = Reader(b, p, p + Int(n))
            p += Int(n)
            return r
        }

        func skip(_ wt: Double) throws {
            if wt == 0 { _ = try varint() }
            else if wt == 1 { try adv(8) }
            else if wt == 2 { try len() }
            else if wt == 5 { try adv(4) }
            else { throw ActionKitError(code: "bad_source", message: "unsupported wire type \(JS.number(wt)) in descriptor") }
        }

        func adv(_ n: Int) throws { if n > end - p { throw ActionKitError(code: "bad_source", message: "truncated descriptor") }; p += n }
        func str() throws -> String { let r = try len(); return GrpcImporter.decodeUtf8(b, r.p, r.end) }
    }

    /// TextDecoder('utf-8') without fatal: maximal-subpart replacement, and a leading byte order mark is dropped.
    static func decodeUtf8(_ b: [UInt8], _ from: Int, _ to: Int) -> String {
        var s = String(decoding: b[from..<to], as: UTF8.self)
        if s.unicodeScalars.first == "\u{FEFF}" { s.unicodeScalars.removeFirst() }
        return s
    }

    private static let FTYPES: [Int: String] = [1: "double", 2: "float", 3: "int64", 4: "uint64", 5: "int32", 6: "fixed64", 7: "fixed32", 8: "bool", 9: "string",
                                                 12: "bytes", 13: "uint32", 15: "sfixed32", 16: "sfixed64", 17: "sint32", 18: "sint64"]

    private static func tag(_ r: Reader) throws -> (f: Double, wt: Double) { let t = try r.varint(); return ((t / 8).rounded(.down), t.truncatingRemainder(dividingBy: 8)) }

    private struct FieldDesc { var name = "", typeName = ""; var type = 0.0, label = 1.0; var proto3opt = false; var behavior: [Double] = [] }

    private static func readEnum(_ m: ProtoModel, _ r: Reader, _ scope: String) throws {
        var name = ""
        var values: [String] = []
        while r.more() {
            let g = try tag(r)
            if g.f == 1 && g.wt == 2 { name = try r.str() }
            else if g.f == 2 && g.wt == 2 {
                let v = try r.len()
                while v.more() { let vg = try tag(v); if vg.f == 1 && vg.wt == 2 { values.append(try v.str()) } else { try v.skip(vg.wt) } }
            } else { try r.skip(g.wt) }
        }
        let full = scope.isEmpty ? name : "\(scope).\(name)"
        let e = PEnum()
        e.full = full
        e.values = values
        m.putEnum(full, e)
    }

    private static func behaviorName(_ b: Double) -> String { b == 2 ? "REQUIRED" : b == 3 ? "OUTPUT_ONLY" : b == 4 ? "INPUT_ONLY" : b == 5 ? "IMMUTABLE" : "" }

    private static func readMsg(_ m: ProtoModel, _ r: Reader, _ scope: String, _ depth: Int) throws {
        if depth > 32 { throw ActionKitError(code: "import_limit", message: "descriptor message nesting is too deep") }
        var name = ""
        var fields: [FieldDesc] = []
        var nested: [Reader] = [], enums: [Reader] = []
        var mapEntry = false
        while r.more() {
            let g = try tag(r)
            if g.f == 1 && g.wt == 2 { name = try r.str() }
            else if g.f == 2 && g.wt == 2 {
                let fr = try r.len()
                var fd = FieldDesc()
                while fr.more() {
                    let fg = try tag(fr)
                    if fg.f == 1 && fg.wt == 2 { fd.name = try fr.str() }
                    else if fg.f == 4 && fg.wt == 0 { fd.label = try fr.varint() }
                    else if fg.f == 5 && fg.wt == 0 { fd.type = try fr.varint() }
                    else if fg.f == 6 && fg.wt == 2 { fd.typeName = try fr.str() }
                    else if fg.f == 17 && fg.wt == 0 { fd.proto3opt = try fr.varint() == 1 }
                    else if fg.f == 8 && fg.wt == 2 {
                        let o = try fr.len()
                        while o.more() {
                            let og = try tag(o)
                            if og.f == 1052 && og.wt == 0 { fd.behavior.append(try o.varint()) }
                            else if og.f == 1052 && og.wt == 2 { let pk = try o.len(); while pk.more() { fd.behavior.append(try pk.varint()) } }
                            else { try o.skip(og.wt) }
                        }
                    } else { try fr.skip(fg.wt) }
                }
                fields.append(fd)
            } else if g.f == 3 && g.wt == 2 { nested.append(try r.len()) }
            else if g.f == 4 && g.wt == 2 { enums.append(try r.len()) }
            else if g.f == 7 && g.wt == 2 {
                let o = try r.len()
                while o.more() { let og = try tag(o); if og.f == 7 && og.wt == 0 { mapEntry = try o.varint() == 1 } else { try o.skip(og.wt) } }
            } else { try r.skip(g.wt) }
        }
        let full = scope.isEmpty ? name : "\(scope).\(name)"
        let msg = PMsg()
        msg.full = full
        msg.mapEntry = mapEntry
        for f in fields {
            var pf = PField()
            pf.name = f.name; pf.scope = full; pf.repeated = f.label == 3; pf.optional = f.proto3opt
            if !f.typeName.isEmpty { pf.type = f.typeName }
            else if f.type >= 1 && f.type <= 18 && f.type == f.type.rounded(), let t = FTYPES[Int(f.type)] { pf.type = t }
            else { pf.type = "bytes" }
            for b in f.behavior { pf.behavior.append(behaviorName(b)) }
            msg.fields.append(pf)
        }
        m.putMsg(full, msg)
        for n in nested { try readMsg(m, n, full, depth + 1) }
        for e in enums { try readEnum(m, e, full) }
    }

    public static func parseDescriptorSet(_ bytes: [UInt8]) throws -> ProtoModel {
        let m = ProtoModel()
        let top = Reader(bytes, 0, bytes.count)
        while top.more() {
            let g = try tag(top)
            if g.f != 1 || g.wt != 2 { try top.skip(g.wt); continue }
            let fr = try top.len()
            var pkg = ""
            var msgs: [Reader] = [], enums: [Reader] = [], svcs: [Reader] = []
            // package may follow the messages in the wire order: collect first, then resolve scopes
            while fr.more() {
                let fg = try tag(fr)
                if fg.f == 2 && fg.wt == 2 { pkg = try fr.str() }
                else if fg.f == 4 && fg.wt == 2 { msgs.append(try fr.len()) }
                else if fg.f == 5 && fg.wt == 2 { enums.append(try fr.len()) }
                else if fg.f == 6 && fg.wt == 2 { svcs.append(try fr.len()) }
                else { try fr.skip(fg.wt) }
            }
            for r in msgs { try readMsg(m, r, pkg, 0) }
            for r in enums { try readEnum(m, r, pkg) }
            for r in svcs {
                var name = ""
                var methods: [PMethod] = []
                while r.more() {
                    let sg = try tag(r)
                    if sg.f == 1 && sg.wt == 2 { name = try r.str() }
                    else if sg.f == 2 && sg.wt == 2 {
                        let mr = try r.len()
                        let me = PMethod()
                        me.scope = pkg
                        while mr.more() {
                            let mg = try tag(mr)
                            if mg.f == 1 && mg.wt == 2 { me.name = try mr.str() }
                            else if mg.f == 2 && mg.wt == 2 { me.input = try mr.str() }
                            else if mg.f == 3 && mg.wt == 2 { me.output = try mr.str() }
                            else if mg.f == 5 && mg.wt == 0 { me.cs = try mr.varint() == 1 }
                            else if mg.f == 6 && mg.wt == 0 { me.ss = try mr.varint() == 1 }
                            else if mg.f == 4 && mg.wt == 2 {
                                let o = try mr.len()
                                while o.more() {
                                    let og = try tag(o)
                                    if og.f == 34 && og.wt == 0 { let lv = try o.varint(); me.idem = lv == 1 ? "NO_SIDE_EFFECTS" : lv == 2 ? "IDEMPOTENT" : "IDEMPOTENCY_UNKNOWN" }
                                    else if og.f == 72295728 && og.wt == 2 {
                                        let h = try o.len()
                                        while h.more() {
                                            let hg = try tag(h)
                                            let verb: String? = hg.f == 2 ? "GET" : hg.f == 3 ? "PUT" : hg.f == 4 ? "POST" : hg.f == 5 ? "DELETE" : hg.f == 6 ? "PATCH" : nil
                                            if let v = verb, hg.wt == 2 {
                                                if me.http == nil { let hh = PHttp(); hh.method = v; hh.path = try h.str(); me.http = hh } else { _ = try h.str() }
                                            } else if hg.f == 7 && hg.wt == 2 { let bd = try h.str(); if let hh = me.http { hh.body = bd } }
                                            else { try h.skip(hg.wt) }
                                        }
                                    } else { try o.skip(og.wt) }
                                }
                            } else { try mr.skip(mg.wt) }
                        }
                        methods.append(me)
                    } else { try r.skip(sg.wt) }
                }
                let s = PService()
                s.full = pkg.isEmpty ? name : "\(pkg).\(name)"
                s.name = name
                s.methods = methods
                m.services.append(s)
            }
        }
        return m
    }

    // ---- model to params ----

    private static func resolveName(_ m: ProtoModel, _ name: String, _ scope: String) -> String? {
        if name.hasPrefix(".") { return String(name.dropFirst()) }
        let parts = scope.isEmpty ? [] : scope.components(separatedBy: ".")
        for k in stride(from: parts.count, through: 0, by: -1) {
            let cs = parts[0..<k].map { $0 + "." }.joined() + name
            if m.messages[JKey(cs)] != nil || m.enums[JKey(cs)] != nil { return cs }
        }
        return m.messages[JKey(name)] != nil || m.enums[JKey(name)] != nil ? name : nil
    }

    private static let WKT_STRING: Set<String> = ["google.protobuf.StringValue", "google.protobuf.BytesValue"]
    private static let WKT_INT: Set<String> = ["google.protobuf.Int32Value", "google.protobuf.Int64Value", "google.protobuf.UInt32Value", "google.protobuf.UInt64Value"]

    private static func one(_ m: ProtoModel, _ type: String, _ scope: String, _ c: ImportCommon.Ctx, _ stack: [String], _ where_: String, _ budget: inout Int) -> JObject {
        if SCALAR_NAMES.contains(type) {
            if type.contains("int") || type.contains("fixed") { return Jx.obj(["type": .string("integer"), "format": .string("int64")]) }
            if type == "bool" { return Jx.obj(["type": .string("boolean")]) }
            if type == "string" || type == "bytes" { return Jx.obj(["type": .string("string")]) }
            return Jx.obj(["type": .string("number")])
        }
        let abs: String? = type.hasPrefix(".") ? String(type.dropFirst()) : nil
        let eff = abs ?? type
        if abs == "google.protobuf.Timestamp" || type == "google.protobuf.Timestamp" { return Jx.obj(["type": .string("string"), "format": .string("date-time")]) }
        if WKT_STRING.contains(eff) { return Jx.obj(["type": .string("string")]) }
        if WKT_INT.contains(eff) { return Jx.obj(["type": .string("integer"), "format": .string("int64")]) }
        if eff == "google.protobuf.BoolValue" { return Jx.obj(["type": .string("boolean")]) }
        if eff.hasPrefix("google.protobuf.") { return [:] }
        guard let full = resolveName(m, type, scope) else {
            ImportCommon.addTodo(c, where_, "unknown_type", "type '\(ImportCommon.clip(.string(type), 60))' is not defined in the proto source (declared string)")
            return [:]
        }
        if let en = m.enums[JKey(full)] {
            var vs: [JSONValue] = []
            for v in en.values where !vs.contains(.string(v)) { vs.append(.string(v)) }
            return Jx.obj(["type": .string("string"), "enum": .array(vs)])
        }
        return msgSchema(m, full, c, stack, where_, &budget)
    }

    private static func fieldSchema(_ m: ProtoModel, _ f: PField, _ c: ImportCommon.Ctx, _ stack: [String], _ where_: String, _ budget: inout Int) -> JObject {
        if f.map != nil { return Jx.obj(["type": .string("object")]) }
        let s = one(m, f.type, f.scope, c, stack, where_, &budget)
        return f.repeated ? Jx.obj(["type": .string("array"), "items": .object(s)]) : s
    }

    private static func msgSchema(_ m: ProtoModel, _ full: String, _ c: ImportCommon.Ctx, _ stack: [String], _ where_: String, _ budget: inout Int) -> JObject {
        guard let msg = m.messages[JKey(full)] else { return [:] }
        if stack.contains(full) { ImportCommon.addTodo(c, where_, "cyclic_ref", "message '\(ImportCommon.clip(.string(full), 80))' is recursive (declared string; refine or drop)"); return [:] }
        var stop = Int64(stack.count) > c.lim.maxRefDepth
        if !stop { budget -= 1; stop = budget <= 0 }
        if stop { ImportCommon.addTodo(c, where_, "ref_budget", "message expansion stopped at the bound (declared string; refine or drop)"); return [:] }
        var properties: JObject = [:]
        var required: [JSONValue] = []
        let ns = stack + [full]
        for f in msg.fields {
            if f.behavior.contains("OUTPUT_ONLY") { continue }
            ImportCommon.putProp(&properties, f.name, .object(fieldSchema(m, f, c, ns, where_ + "." + f.name, &budget)))
            if f.behavior.contains("REQUIRED") { required.append(.string(f.name)) }
        }
        return Jx.obj(["type": .string("object"), "properties": .object(properties), "required": .array(required)])
    }

    private static let CAMEL = try! NSRegularExpression(pattern: "([a-z0-9])([A-Z])")

    /// `source` is `.proto` text (a string) or, with `bytes`, a binary FileDescriptorSet.
    public static func importGrpc(_ source: JSONValue?, _ opts: JObject?, bytes: [UInt8]? = nil) throws -> JObject {
        let c = try ImportCommon.newCtx("grpc", source, opts, bytes: bytes)
        let m: ProtoModel
        if let b = bytes { m = try parseDescriptorSet(b) }
        else if case let .string(s)? = source { m = try parseProto(s) }
        else { throw ActionKitError(code: "bad_source", message: "a gRPC source is .proto text or a binary FileDescriptorSet") }
        for svc in m.services.sorted(by: { utf8Less($0.full, $1.full) }) {
            for me in svc.methods.sorted(by: { utf8Less($0.name, $1.name) }) {
                let where_ = svc.name + "/" + me.name
                c.root = nil
                let bud = ImportCommon.newBudget(c)
                let rn = resolveName(m, me.input, me.scope)
                let input = rn ?? (me.input.hasPrefix(".") ? String(me.input.dropFirst()) : me.input)
                var budget = Int(c.lim.maxRefNodes)
                let schema = msgSchema(m, input, c, [], where_, &budget)
                var params: JObject = [:]
                if schema[JKey("properties")] != nil { try ImportCommon.flattenObject(schema, c, bud, where_, &params) }
                else if m.messages[JKey(input)] == nil && !input.hasPrefix("google.protobuf.") { ImportCommon.addTodo(c, where_, "unknown_type", "request type '\(ImportCommon.clip(.string(me.input), 60))' is not defined in the source (no parameters)") }
                let hx = me.http
                let hm = hx?.method
                let eff = hm == "GET" ? "read" : hm == "DELETE" ? "delete" : hm == "POST" ? "create" : (hm == "PUT" || hm == "PATCH") ? "update" : me.idem == "NO_SIDE_EFFECTS" ? "read" : "update"
                let natural = me.idem == "NO_SIDE_EFFECTS" || me.idem == "IDEMPOTENT" || hm == "GET" || hm == "PUT" || hm == "DELETE"
                var traits: [String]? = nil
                if me.cs || me.ss { traits = ImportCommon.withTrait(traits, "pca.bulk"); ImportCommon.addTodo(c, where_, "streaming", "a streaming method: acts on many messages (pca.bulk added)") }
                var d = ImportCommon.Draft()
                d.name = .string(svc.name + " " + me.name)
                d.title = .string(CAMEL.stringByReplacingMatches(in: me.name, range: NSRange(location: 0, length: me.name.utf16.count), withTemplate: "$1 $2"))
                d.effects = [eff]
                d.scope = "one"
                d.params = params
                if natural { d.idempotency = Jx.obj(["mode": .string("natural")]) }
                if let t = traits { d.traits = t }
                var b = Jx.obj(["grpc": .object(Jx.obj(["service": .string(ImportCommon.clip(.string(svc.full), 250)), "method": .string(ImportCommon.clip(.string(me.name), 250))]))])
                if let h = hx, let p = h.path, !p.isEmpty { b[o: "http"] = .object(Jx.obj(["method": h.method.map { .string($0) } ?? .null, "path": .string(ImportCommon.clip(.string(p), 250))])) }
                d.bindings = b
                try ImportCommon.emitDef(c, d)
            }
        }
        return ImportCommon.finish(c)
    }
}
