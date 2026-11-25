import Foundation
import AtlasPCAVerify
import WasmKit
import WasmParser

/// In-process core-module WebAssembly host on WasmKit (opt-in product AtlasPCAWasm). The tool is a core module whose only import is
/// `pca:act.{invoke,handle_count,handle_verb}`: no WASI is linked, so it has no filesystem, network, clock, random or environment access.
///
/// Limits, and what WasmKit lets us enforce (checked against the 0.4.2 source):
///  - instruction budget: enforced. `EngineConfiguration.fuelMetering` plus `Store.fuel`; running out traps with "out of fuel" -> `fuel_exhausted`.
///  - memory: enforced. One declared-maximum non-shared 32-bit memory within `maxMemoryPages` is required before compiling, and the engine never grows
///    a memory past its declared maximum, so the cap is hard. (`Store.resourceLimiter` is SPI-only in 0.4.2, so it is not used.)
///  - wall clock: NOT interruptible in WasmKit 0.4.2 (no epoch, deadline or cancel API; only host calls can observe time). The run happens on its own
///    thread and the caller gets `timeout` on time, and the guest's next host call traps, but a guest that makes no host calls keeps burning CPU on the
///    abandoned thread until its fuel is gone, so fuel is the CPU bound here. Where a hard wall-clock stop matters, use
///    `PCASandbox.runCoreSubprocess` (the pinned reference host, epoch interruption).
///  - no ambient authority: every import outside `pca:act` is refused as `ambient_import:<module>.<name>` before instantiation.
/// After a `timeout` the handle table is no longer touched by the abandoned run.
extension PCASandbox {
    public struct CoreOptions {
        /// Required: a budget is a decision.
        public var fuel: Int
        public var timeoutMs = 5000
        public var maxModuleBytes = 1 << 20
        /// Largest linear memory a tool may declare, in 64 KiB pages.
        public var maxMemoryPages = 256
        public var maxResultBytes = 1 << 20
        public init(fuel: Int) { self.fuel = fuel }
    }

    /// Parse only the memory section (so a non-exported memory is seen too): nil = unparseable, .some(nil) = no memory, else (count, min, max, shared).
    /// A flag above 3 (memory64 and newer) reports as shared, which is refused.
    static func memoryLimits(_ b: [UInt8]) -> (count: UInt64, min: UInt64, max: UInt64?, shared: Bool)?? {
        guard b.count >= 8, b[0] == 0, b[1] == 0x61, b[2] == 0x73, b[3] == 0x6D else { return nil }
        var o = 8
        func leb() -> UInt64? {
            var r: UInt64 = 0
            for shift in stride(from: 0, to: 35, by: 7) {
                guard o < b.count else { return nil }
                let x = b[o]
                o += 1
                r += UInt64(x & 0x7F) << UInt64(shift)
                if x & 0x80 == 0 { return r }
            }
            return nil
        }
        while o < b.count {
            let id = b[o]
            o += 1
            guard let size = leb(), size <= UInt64(b.count), o + Int(size) <= b.count else { return nil }
            let end = o + Int(size)
            if id == 5 {
                guard let count = leb() else { return nil }
                if count == 0 { return .some(nil) }
                guard o < b.count else { return nil }
                let flag = b[o]
                o += 1
                if flag > 3 { return .some((count, UInt64.max, nil, true)) }
                guard let min = leb() else { return nil }
                var max: UInt64?
                if flag & 1 != 0 { guard let m = leb() else { return nil }; max = m }
                return .some((count, min, max, flag & 2 != 0))
            }
            o = end
        }
        return .some(nil)
    }

    private struct Stop: Error {}

    private final class Run: @unchecked Sendable {
        let table: HandleTable
        let maxResult: Int
        let deadline: Date
        let lock = NSLock()
        var cancelled = false
        init(_ t: HandleTable, _ m: Int, _ d: Date) { table = t; maxResult = m; deadline = d }
        /// Every table access goes through here: refuses once the run was abandoned or its deadline passed.
        func withTable<T>(_ body: (HandleTable) throws -> T) throws -> T {
            lock.lock(); defer { lock.unlock() }
            if cancelled || Date() > deadline { throw Stop() }
            return try body(table)
        }
    }

    private static func code(_ f: UseFailure) -> UInt32 { UInt32(bitPattern: Int32(USE_ERR.first { $0.0 == f.rawValue }?.1 ?? -5)) }
    private static func word(_ v: Value) -> UInt32 { if case .i32(let x) = v { return x }; return 0 }

    /// The guest's window [ptr, ptr+len) as unsigned 32-bit values, inside its memory export.
    private static func window(_ c: borrowing Caller, _ ptr: UInt32, _ len: UInt32) -> WasmKit.Memory? {
        guard let m = c.instance?.exports[memory: "memory"], UInt64(ptr) + UInt64(len) <= UInt64(m.byteCount) else { return nil }
        return m
    }

    private static func put(_ m: WasmKit.Memory, _ ptr: UInt32, _ bytes: [UInt8]) {
        guard !bytes.isEmpty else { return }
        m.withUnsafeMutableBufferPointer(offset: UInt(ptr), count: bytes.count) { $0.copyBytes(from: bytes) }
    }

    /// Run `bytes` (a core module) and call its export `entry` (no parameters) over `table`.
    public static func runCore(_ table: HandleTable, _ bytes: [UInt8], entry: String = "run", options o: CoreOptions) -> RunResult {
        if o.fuel < 1 { return .failed("bad_fuel") }
        if o.maxMemoryPages < 1 || o.timeoutMs < 1 { return .failed("bad_limits") }
        if bytes.isEmpty || bytes.count > o.maxModuleBytes { return .failed("module_size") }
        guard let mem = memoryLimits(bytes) else { return .failed("malformed_module") }
        if let m = mem {
            let cap = UInt64(o.maxMemoryPages)
            if m.count > 1 || m.shared || m.max == nil || m.min > cap || m.max! > cap { return .failed("memory_limits") }
        }
        guard let module = try? parseWasm(bytes: bytes) else { return .failed("malformed_module") }
        for i in module.imports {
            guard i.module == IMPORT_MODULE, case .function = i.descriptor, ALLOWED_IMPORTS.contains(i.name) else { return .failed("ambient_import:\(i.module).\(i.name)") }
        }
        let engine = Engine(configuration: EngineConfiguration(compilationMode: .eager, memoryBoundsChecking: .software, fuelMetering: true))
        let store = Store(engine: engine)
        store.fuel = Fuel(remaining: UInt64(o.fuel))
        guard store.fuel?.remaining == UInt64(o.fuel) else { return .failed("limit_unenforceable:fuel") }
        let run = Run(table, o.maxResultBytes, Date().addingTimeInterval(Double(o.timeoutMs) / 1000))
        var imports = Imports()
        imports.define(module: IMPORT_MODULE, name: "handle_count", Function(store: store, parameters: [], results: [.i32]) { _, _ in
            let n = try run.withTable { $0.size }
            return [.i32(UInt32(truncatingIfNeeded: n))]
        })
        imports.define(module: IMPORT_MODULE, name: "handle_verb", Function(store: store, parameters: [.i32, .i32, .i32], results: [.i32]) { c, a in
            let (h, ptr, cap) = (word(a[0]), word(a[1]), word(a[2]))
            guard let verb = try run.withTable({ $0.verbOf(Double(Int32(bitPattern: h))) }) else { return [.i32(code(.unknown_handle))] }
            guard let m = window(c, ptr, cap) else { return [.i32(code(.bad_memory))] }
            let enc = Array(verb.utf8)
            if UInt64(enc.count) > UInt64(cap) { return [.i32(code(.out_too_small))] }
            put(m, ptr, enc)
            return [.i32(UInt32(enc.count))]
        })
        imports.define(module: IMPORT_MODULE, name: "invoke", Function(store: store, parameters: [.i32, .i32, .i32], results: [.i32]) { c, a in
            let (h, ptr, cap) = (word(a[0]), word(a[1]), word(a[2]))
            // validate the guest's output window before spending the use
            guard let m = window(c, ptr, cap) else { return [.i32(code(.bad_memory))] }
            let r = try run.withTable { t in try t.use(Double(Int32(bitPattern: h))) }
            switch r {
            case .failed(let f): return [.i32(code(f))]
            case .ok(let b):
                if b.count > run.maxResult || UInt64(b.count) > UInt64(cap) { return [.i32(code(.out_too_small))] }
                put(m, ptr, b)
                return [.i32(UInt32(b.count))]
            }
        })

        final class Box: @unchecked Sendable { var result: RunResult = .failed("trap:RuntimeError") }
        let box = Box(), done = DispatchSemaphore(value: 0)
        let work: () -> RunResult = {
            let instance: Instance
            do { instance = try module.instantiate(store: store, imports: imports) } catch { return RunResult.failed("trap:LinkError") }
            guard let f = instance.exports[function: entry], f.type.parameters.isEmpty else { return RunResult.failed("no_entry") }
            do {
                let out = try f.invoke([])
                if case .i32(let v)? = out.first { return RunResult.ok(Int(Int32(bitPattern: v))) }
                return RunResult.ok(0)
            } catch is Stop {
                return RunResult.failed("timeout")
            } catch {
                if String(describing: error).contains("out of fuel") { return RunResult.failed("fuel_exhausted") }
                return RunResult.failed(run.cancelled || Date() > run.deadline ? "timeout" : "trap:RuntimeError")
            }
        }
        // the interpreter has a native recursion depth of its own: give it a roomy stack
        let t = Thread { box.result = work(); done.signal() }
        t.stackSize = 16 << 20
        t.start()
        if done.wait(timeout: .now() + .milliseconds(o.timeoutMs)) == .timedOut {
            run.lock.lock(); run.cancelled = true; run.lock.unlock() // waits out an executor already running, then the guest can no longer reach the table
            return .failed("timeout")
        }
        return box.result
    }
}
