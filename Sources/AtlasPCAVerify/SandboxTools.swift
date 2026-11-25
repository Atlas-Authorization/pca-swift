import Foundation

/// Hand-assembled core-WebAssembly modules (and the matching component text) for tests and demos of a sandbox host: no toolchain
/// needed to see the capability handles work. Byte-identical to the reference builders, quirks included (a string's length prefix counts
/// UTF-16 code units, like the reference, so a non-ASCII import name yields a module no engine accepts).
extension PCASandbox {
    public struct ToolCall { public var handle: Int; public var ptr: Int; public var cap: Int
        public init(handle: Int, ptr: Int, cap: Int) { self.handle = handle; self.ptr = ptr; self.cap = cap } }

    /// What a built tool does: calls to `pca:act.invoke(handle, ptr, cap)` in order, then returns the last call's return code ("last",
    /// the default) or the first byte of linear memory ("byte0").
    public struct ToolSpec {
        public var calls: [ToolCall]
        public var returns: String?
        /// Extra imports the tool asks for (ambient authority); a host must refuse the module.
        public var extraImports: [(module: String, name: String)]
        /// Linear memory `[min, max]` in pages; `max: nil` declares none. Default 1, 1.
        public var memory: (min: Int, max: Int?)
        /// Loop forever after the calls (a tool that never returns).
        public var spin: Bool
        public init(calls: [ToolCall], returns: String? = nil, extraImports: [(module: String, name: String)] = [], memory: (min: Int, max: Int?) = (1, 1), spin: Bool = false) {
            self.calls = calls
            self.returns = returns
            self.extraImports = extraImports
            self.memory = memory
            self.spin = spin
        }
    }

    private static func leb(_ value: Int) -> [UInt8] {
        var n = value, out: [UInt8] = []
        repeat {
            var b = UInt8(n & 0x7F)
            n /= 128
            if n > 0 { b |= 0x80 }
            out.append(b)
        } while n > 0
        return out
    }

    /// Signed LEB128 on a 32-bit operand (the reference shifts with JS `>>`).
    private static func sleb(_ value: Int) -> [UInt8] {
        var n = Int32(truncatingIfNeeded: value), out: [UInt8] = []
        while true {
            let b = UInt8(n & 0x7F)
            n >>= 7
            if (n == 0 && b & 0x40 == 0) || (n == -1 && b & 0x40 != 0) { return out + [b] }
            out.append(b | 0x80)
        }
    }

    private static func i32c(_ n: Int) -> [UInt8] { [0x41] + sleb(n) }
    private static func wstr(_ x: String) -> [UInt8] { leb(x.utf16.count) + Array(x.utf8) }
    private static func section(_ id: UInt8, _ body: [UInt8]) -> [UInt8] { [id] + leb(body.count) + body }
    private static func vec(_ items: [[UInt8]]) -> [UInt8] { leb(items.count) + items.flatMap { $0 } }
    private static let wasmHeader: [UInt8] = [0, 0x61, 0x73, 0x6D, 1, 0, 0, 0]

    public static func buildTool(_ spec: ToolSpec) -> [UInt8] {
        // types: 0 = (i32,i32,i32)->i32, 1 = ()->i32, 2 = (i32,i32,i32,i32)->i32
        let types = vec([[0x60, 3, 0x7F, 0x7F, 0x7F, 1, 0x7F], [0x60, 0, 1, 0x7F], [0x60, 4, 0x7F, 0x7F, 0x7F, 0x7F, 1, 0x7F]])
        let imports = vec([wstr("pca:act") + wstr("invoke") + [0, 0]] + spec.extraImports.map { wstr($0.module) + wstr($0.name) + [0, 2] })
        let memory = vec([spec.memory.max.map { [1] + leb(spec.memory.min) + leb($0) } ?? [0] + leb(spec.memory.min)])
        let runIndex = 1 + spec.extraImports.count
        let returns = spec.returns ?? "last"
        var body: [UInt8] = [0] // no locals
        for (i, c) in spec.calls.enumerated() {
            body += i32c(c.handle) + i32c(c.ptr) + i32c(c.cap) + [0x10, 0]
            if !(i == spec.calls.count - 1 && returns == "last") { body.append(0x1A) }
        }
        if spec.spin { body += [0x03, 0x40, 0x0C, 0x00, 0x0B] }
        if spec.returns == "byte0" { body += i32c(0) + [0x2D, 0, 0] }
        if spec.calls.isEmpty { body += i32c(0) }
        body.append(0x0B)
        let exports = vec([wstr("memory") + [2, 0], wstr("run") + [0] + leb(runIndex)])
        return wasmHeader + section(1, types) + section(2, imports) + section(3, vec([[1]])) + section(5, memory) + section(7, exports) + section(10, vec([leb(body.count) + body]))
    }

    /// A tool that asks the table what it holds: returns `handle_count() * 256 + first byte of handle 1's verb` (the verb window is `cap` bytes).
    public static func buildProbeTool(cap: Int = 64) -> [UInt8] {
        let types = vec([[0x60, 3, 0x7F, 0x7F, 0x7F, 1, 0x7F], [0x60, 0, 1, 0x7F]])
        let imports = vec([wstr("pca:act") + wstr("invoke") + [0, 0], wstr("pca:act") + wstr("handle_count") + [0, 1], wstr("pca:act") + wstr("handle_verb") + [0, 0]])
        var body: [UInt8] = [0]
        body += i32c(1); body += i32c(0); body += i32c(cap)
        body += [0x10, 2, 0x1A, 0x10, 1]
        body += i32c(256); body += [0x6C]; body += i32c(0)
        body += [0x2D, 0, 0, 0x6A, 0x0B]
        let exports = vec([wstr("memory") + [2, 0], wstr("run") + [0, 3]])
        var out: [UInt8] = wasmHeader
        out += section(1, types); out += section(2, imports); out += section(3, vec([[1]]))
        out += section(5, vec([[1, 1, 1]])); out += section(7, exports)
        out += section(10, vec([leb(body.count) + body]))
        return out
    }

    /// The reference tool as a component in the WebAssembly text format. `handle` defaults to 1; `spin` makes `run` loop forever;
    /// a non-empty `extraImport` adds an import a host must refuse.
    public static func referenceComponentWat(handle: Int? = nil, spin: Bool = false, extraImport: String? = nil) -> String {
        let extra = (extraImport?.isEmpty == false) ? "(import \"\(extraImport!)\" (instance (export \"get-arguments\" (func (result (list string))))))" : ""
        let body = spin ? "(loop $l (br $l)) (i32.const 0)" : [
            "(call $invoke (i32.const \(handle ?? 1)) (i32.const 16))",
            "       (if (result i32) (i32.load8_u (i32.const 16))",
            "         (then (i32.load (i32.const 20)))",
            "         (else (i32.load8_u (i32.load (i32.const 20)))))",
        ].joined(separator: "\n")
        return [
            "(component",
            "  (import \"pca:act/invoke@0.1.0\" (instance $inv",
            "    (export \"handle-count\" (func (result u32)))",
            "    (export \"invoke\" (func (param \"handle\" u32) (result (result (list u8) (error s32)))))))",
            "  \(extra)",
            "  (core module $libc",
            "    (memory (export \"memory\") 1 1)",
            "    (global $bump (mut i32) (i32.const 1024))",
            "    (func (export \"realloc\") (param $old i32) (param $oldsz i32) (param $align i32) (param $new i32) (result i32)",
            "      (local $p i32)",
            "      (local.set $p (global.get $bump))",
            "      (global.set $bump (i32.add (local.get $p) (local.get $new)))",
            "      (local.get $p)))",
            "  (core instance $libc (instantiate $libc))",
            "  (alias core export $libc \"memory\" (core memory $mem))",
            "  (alias core export $libc \"realloc\" (core func $realloc))",
            "  (core func $count (canon lower (func $inv \"handle-count\")))",
            "  (core func $invoke (canon lower (func $inv \"invoke\") (memory $mem) (realloc $realloc)))",
            "  (core module $main",
            "    (import \"libc\" \"memory\" (memory 1))",
            "    (import \"host\" \"count\" (func $count (result i32)))",
            "    (import \"host\" \"invoke\" (func $invoke (param i32 i32)))",
            "    (func (export \"run\") (result i32)",
            "      \(body)))",
            "  (core instance $host (export \"count\" (func $count)) (export \"invoke\" (func $invoke)))",
            "  (core instance $main (instantiate $main (with \"libc\" (instance $libc)) (with \"host\" (instance $host))))",
            "  (alias core export $main \"run\" (core func $run))",
            "  (func $lifted (result s32) (canon lift (core func $run)))",
            "  (export \"run\" (func $lifted)))",
            "",
        ].joined(separator: "\n")
    }
}
