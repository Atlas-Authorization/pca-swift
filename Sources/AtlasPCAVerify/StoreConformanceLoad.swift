import Foundation

extension PCAStoreConformance {
    private final class Registry: @unchecked Sendable {
        let lock = NSLock()
        var factories: [String: ([String: String]) throws -> any StoreAdapter] = [:]
    }
    private static let registry = Registry()

    /// Register a host adapter under a name so `loadAdapter("registered:<name>", ...)` finds it (Swift has no run-time module import; the host links its adapter and
    /// registers it here).
    public static func registerAdapter(_ name: String, _ factory: @escaping ([String: String]) throws -> any StoreAdapter) {
        registry.lock.lock(); registry.factories[name] = factory; registry.lock.unlock()
    }

    /// Load a store adapter from a built-in name (`builtin:<name>`, see `REFERENCE_ADAPTERS`) or a registered one (`registered:<name>`); `options` are the
    /// `--option k=v` pairs. Anything else, or an unknown name, is refused naming what is known.
    public static func loadAdapter(_ spec: String, _ options: [String: String] = [:]) throws -> any StoreAdapter {
        if spec.hasPrefix("builtin:") {
            let name = String(spec.dropFirst("builtin:".count))
            guard let f = REFERENCE_ADAPTERS[name] else { throw JSError("unknown built-in adapter '\(name)' (known: \(REFERENCE_ADAPTERS.keys.sorted().joined(separator: ", ")))") }
            return f(options)
        }
        if spec.hasPrefix("registered:") {
            let name = String(spec.dropFirst("registered:".count))
            registry.lock.lock(); let f = registry.factories[name]; let known = registry.factories.keys.sorted(); registry.lock.unlock()
            guard let make = f else { throw JSError("unknown registered adapter '\(name)' (known: \(known.joined(separator: ", ")))") }
            return try make(options)
        }
        throw JSError("\(spec): not an adapter spec (use builtin:<name> or registered:<name>)")
    }
}
