import Foundation

/// Agent blueprints (verification side): a record signed by an operator for a blueprint KEY; an instance is a chain with a hop
/// issued by that key. `BlueprintRegistry` keeps the newest record per key (pinned operators, a strictly higher epoch replaces,
/// the same epoch with different content is a fork). A non-empty ceiling is never evaluated here: it denies
/// (`ceiling_unevaluable`), and so does a record with `runtime_pins` (`admission_required`: admission is not implemented here), so this
/// verifier never allows past a constraint it cannot read. Total.
public enum Blueprint {
    public static let DOMAIN = "atlas-pca/agent-blueprint/v1\u{0}"
    static let BODY_KEYS = ["v", "id", "key", "ceiling", "max_depth", "expires_at", "runtime_pins", "epoch", "status", "issued_at", "operator"]
    static let PIN_KEYS = ["runtime_measurement", "model_id", "weights_digest", "operator", "spiffe_id"]

    static func wellFormed(_ v: JSONValue?) -> JObject? {
        guard let b = v?.asObject, b[JKey("v")]?.safeInt == 1,
              K3Sig.str(b[JKey("id")], 128) != nil, K3Sig.str(b[JKey("key")], 128) != nil, K3Sig.str(b[JKey("operator")], 128) != nil,
              K3Sig.safeInt(b[JKey("epoch")]) != nil, K3Sig.safeInt(b[JKey("issued_at")]) != nil,
              let st = b[JKey("status")]?.asString, st == "active" || st == "disabled" else { return nil }
        if let d = b[JKey("max_depth")], (K3Sig.safeInt(d) ?? 0) < 1 { return nil }
        if let e = b[JKey("expires_at")], K3Sig.safeInt(e) == nil { return nil }
        if let p = b[JKey("runtime_pins")] {
            guard let a = p.asArray, (1...16).contains(a.count), a.allSatisfy({ x in
                guard let o = x.asObject, !o.isEmpty else { return false }
                return o.allSatisfy { kv in PIN_KEYS.contains(where: { IV.same($0, kv.key.s) }) && K3Sig.str(kv.value, 256) != nil }
            }) else { return nil }
        }
        guard let c = b[JKey("ceiling")]?.asArray, c.count <= 32,
              c.allSatisfy({ $0.asObject?[JKey("type")]?.asString != nil }) else { return nil }
        return b
    }

    public static func verify(_ v: JSONValue?) -> Bool {
        guard let b = wellFormed(v), let op = b[JKey("operator")]?.asString else { return false }
        return K3Sig.verifyBody(DOMAIN, .object(K3Sig.pick(b, BODY_KEYS)), signer: op, sig: b[JKey("sig")])
    }

    public struct Accept: Equatable { public let ok: Bool; public let replaced: Bool; public let code: String? }

    /// The durable home of the accepted records. A disabled blueprint must stay disabled across a restart, so the registry REQUIRES one.
    /// `MemoryBlueprintStore` is for tests and single-process use; `KVBlueprintStore` keeps the records in an `AtomicKV`.
    public protocol Store: Sendable {
        func get(_ key: String) throws -> JObject?
        func put(_ b: JObject) throws
        /// The highest epoch across every stored record (0 when empty).
        func maxEpoch() throws -> Int64
    }

    /// Process-local store (tests, single-process use): its records die with the process.
    public final class MemoryStore: Store, @unchecked Sendable {
        private var records: [String: JObject] = [:]
        let lock = PCALock()
        public init() {}
        public func get(_ key: String) throws -> JObject? { lock.lock(); defer { lock.unlock() }; return records[key] }
        public func put(_ b: JObject) throws { lock.lock(); defer { lock.unlock() }; records[K3Sig.str(b[JKey("key")], 128) ?? ""] = b }
        public func maxEpoch() throws -> Int64 {
            lock.lock()
            defer { lock.unlock() }
            return records.values.compactMap { K3Sig.safeInt($0[JKey("epoch")]) }.max() ?? 0
        }
    }

    /// Records in an `AtomicKV`: one key per blueprint key plus the running maximum epoch.
    public final class KVStore: Store, @unchecked Sendable {
        let kv: any AtomicKV
        public init(kv: any AtomicKV) { self.kv = kv }
        static func recKey(_ k: String) -> String { "blueprint/rec/" + k }
        static let maxKey = "blueprint/max-epoch"
        public func get(_ key: String) throws -> JObject? { try kv.get(Self.recKey(key))?.asObject }
        public func put(_ b: JObject) throws {
            let key = K3Sig.str(b[JKey("key")], 128) ?? ""
            let epoch = K3Sig.safeInt(b[JKey("epoch")]) ?? 0
            // never lowers a record: another instance sharing the store may have stored a newer epoch since this one read it
            try kv.update(Self.recKey(key)) { prev in
                if let cur = prev?.asObject, let ce = K3Sig.safeInt(cur[JKey("epoch")]), ce >= epoch { return nil }
                return .object(b)
            }
            try kv.update(Self.maxKey) { prev in
                let cur = prev?.safeInt ?? 0
                return epoch > cur ? .int(epoch) : nil
            }
        }
        public func maxEpoch() throws -> Int64 { try kv.get(Self.maxKey)?.safeInt ?? 0 }
    }

    public final class Registry {
        let operators: [String]
        let store: any Store
        let lock = PCALock() // serialises accept in this process; the store is the durable truth

        public init(operators: [String], store: any Store) {
            self.operators = operators
            self.store = store
        }

        public func accept(_ v: JSONValue?) -> Accept {
            lock.lock()
            defer { lock.unlock() }
            guard Blueprint.verify(v), let b = Blueprint.wellFormed(v), let key = b[JKey("key")]?.asString,
                  let op = b[JKey("operator")]?.asString, let epoch = K3Sig.safeInt(b[JKey("epoch")]) else {
                return Accept(ok: false, replaced: false, code: "bad_record")
            }
            if !operators.contains(where: { K3Sig.eq(op, $0) }) { return Accept(ok: false, replaced: false, code: "unknown_operator") }
            do {
                if let cur = try store.get(key) {
                    if cur[JKey("operator")]?.asString != op { return Accept(ok: false, replaced: false, code: "operator_changed") }
                    let ce = K3Sig.safeInt(cur[JKey("epoch")]) ?? 0
                    if epoch < ce { return Accept(ok: false, replaced: false, code: "stale_epoch") }
                    if epoch == ce {
                        return cur[JKey("sig")] == b[JKey("sig")] ? Accept(ok: true, replaced: false, code: nil) : Accept(ok: false, replaced: false, code: "epoch_fork")
                    }
                }
                try store.put(b)
            } catch {
                return Accept(ok: false, replaced: false, code: "store_unreachable")
            }
            return Accept(ok: true, replaced: true, code: nil)
        }

        /// The highest blueprint epoch this verifier has accepted; throws when the store cannot answer.
        func epochOrThrow() throws -> Int64 { try store.maxEpoch() }

        public var epoch: Int64 { (try? store.maxEpoch()) ?? 0 }

        func get(_ key: String) throws -> JObject? { try store.get(key) }
    }

    public struct Decision: Equatable {
        public var decision: String
        public var code: String? = nil
        public var blueprint: String? = nil
        public var governed: [String] = []
        public var have: Int64 = 0
        public var need: Int64 = 0
    }

    static func deny(_ code: String, _ bp: String? = nil) -> Decision { Decision(decision: "deny", code: code, blueprint: bp) }

    /// Gate a chain (`[{issuer, holder}]`, root first). `mode` is "require" or "any"; `minEpoch` is the `revocation_epoch` of the newest `fresh_at` token shown.
    public static func check(chain: JSONValue?, registry: Registry, now: JSONValue?, mode: String, minEpoch: Int64? = nil,
                             admitted: ((String, JObject) throws -> Bool)? = nil) -> Decision {
        guard let hops = chain?.asArray, !hops.isEmpty, let nowMs = K3Sig.safeInt(now) else { return deny("bad_input") }
        var hs: [(issuer: String, holder: String)] = []
        for h in hops {
            guard let i = K3Sig.str(h.get("issuer"), 128), let o = K3Sig.str(h.get("holder"), 128) else { return deny("bad_input") }
            hs.append((i, o))
        }
        if let m = minEpoch {
            let have: Int64
            do { have = try registry.epochOrThrow() } catch { return deny("store_unreachable") }
            if have < m { return Decision(decision: "escalate", code: "stale_blueprint_state", have: have, need: m) }
        }
        var governed: [String] = []
        for (i, h) in hs.enumerated() {
            let found: JObject?
            do { found = try registry.get(h.issuer) } catch { return deny("store_unreachable") }
            guard let bp = found else { continue }
            let id = bp[JKey("id")]?.asString ?? ""
            if i == 0 || hs[i - 1].holder != bp[JKey("key")]?.asString { return deny("broken_link", id) }
            if bp[JKey("status")]?.asString != "active" { return deny("blueprint_disabled", id) }
            if let e = bp[JKey("expires_at")], nowMs >= (K3Sig.safeInt(e) ?? 0) { return deny("blueprint_expired", id) }
            if let d = bp[JKey("max_depth")], Int64(hs.count - i) > (K3Sig.safeInt(d) ?? 0) { return deny("too_deep", id) }
            if bp[JKey("runtime_pins")] != nil {
                guard let hook = admitted else { return deny("admission_required", id) }
                // false or a throw: the instance is not admitted under this record
                if (try? hook(h.holder, bp)) != true { return deny("not_admitted", id) }
            }
            if let c = bp[JKey("ceiling")]?.asArray, !c.isEmpty { return deny("ceiling_unevaluable", id) }
            governed.append(id)
        }
        if governed.isEmpty && mode == "require" { return deny("no_blueprint") }
        return Decision(decision: "allow", governed: governed)
    }
}
