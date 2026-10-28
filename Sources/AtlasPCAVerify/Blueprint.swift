import Foundation

/// Agent blueprints (verification side): a record signed by an operator for a blueprint KEY; an instance is a chain with a hop
/// issued by that key. `BlueprintRegistry` keeps the newest record per key (pinned operators, a strictly higher epoch replaces,
/// the same epoch with different content is a fork). A non-empty ceiling is never evaluated here: it denies
/// (`ceiling_unevaluable`), so this verifier never allows past a ceiling it cannot read. Total.
public enum Blueprint {
    public static let DOMAIN = "atlas-pca/agent-blueprint/v1\u{0}"
    static let BODY_KEYS = ["v", "id", "key", "ceiling", "max_depth", "expires_at", "epoch", "status", "issued_at", "operator"]

    static func wellFormed(_ v: JSONValue?) -> JObject? {
        guard let b = v?.asObject, b[JKey("v")]?.safeInt == 1,
              K3Sig.str(b[JKey("id")], 128) != nil, K3Sig.str(b[JKey("key")], 128) != nil, K3Sig.str(b[JKey("operator")], 128) != nil,
              K3Sig.safeInt(b[JKey("epoch")]) != nil, K3Sig.safeInt(b[JKey("issued_at")]) != nil,
              let st = b[JKey("status")]?.asString, st == "active" || st == "disabled" else { return nil }
        if let d = b[JKey("max_depth")], (K3Sig.safeInt(d) ?? 0) < 1 { return nil }
        if let e = b[JKey("expires_at")], K3Sig.safeInt(e) == nil { return nil }
        guard let c = b[JKey("ceiling")]?.asArray, c.count <= 32,
              c.allSatisfy({ $0.asObject?[JKey("type")]?.asString != nil }) else { return nil }
        return b
    }

    public static func verify(_ v: JSONValue?) -> Bool {
        guard let b = wellFormed(v), let op = b[JKey("operator")]?.asString else { return false }
        return K3Sig.verifyBody(DOMAIN, .object(K3Sig.pick(b, BODY_KEYS)), signer: op, sig: b[JKey("sig")])
    }

    public struct Accept: Equatable { public let ok: Bool; public let replaced: Bool; public let code: String? }

    public final class Registry {
        let operators: [String]
        var store: [String: JObject] = [:]
        public init(operators: [String]) { self.operators = operators }

        public func accept(_ v: JSONValue?) -> Accept {
            guard Blueprint.verify(v), let b = Blueprint.wellFormed(v), let key = b[JKey("key")]?.asString,
                  let op = b[JKey("operator")]?.asString, let epoch = K3Sig.safeInt(b[JKey("epoch")]) else {
                return Accept(ok: false, replaced: false, code: "bad_record")
            }
            if !operators.contains(where: { K3Sig.eq(op, $0) }) { return Accept(ok: false, replaced: false, code: "unknown_operator") }
            if let cur = store[key] {
                if cur[JKey("operator")]?.asString != op { return Accept(ok: false, replaced: false, code: "operator_changed") }
                let ce = K3Sig.safeInt(cur[JKey("epoch")]) ?? 0
                if epoch < ce { return Accept(ok: false, replaced: false, code: "stale_epoch") }
                if epoch == ce {
                    return cur[JKey("sig")] == b[JKey("sig")] ? Accept(ok: true, replaced: false, code: nil) : Accept(ok: false, replaced: false, code: "epoch_fork")
                }
            }
            store[key] = b
            return Accept(ok: true, replaced: true, code: nil)
        }

        public var epoch: Int64 { store.values.compactMap { K3Sig.safeInt($0[JKey("epoch")]) }.max() ?? 0 }
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
    public static func check(chain: JSONValue?, registry: Registry, now: JSONValue?, mode: String, minEpoch: Int64? = nil) -> Decision {
        guard let hops = chain?.asArray, !hops.isEmpty, let nowMs = K3Sig.safeInt(now) else { return deny("bad_input") }
        var hs: [(issuer: String, holder: String)] = []
        for h in hops {
            guard let i = K3Sig.str(h.get("issuer"), 128), let o = K3Sig.str(h.get("holder"), 128) else { return deny("bad_input") }
            hs.append((i, o))
        }
        if let m = minEpoch, registry.epoch < m { return Decision(decision: "escalate", code: "stale_blueprint_state", have: registry.epoch, need: m) }
        var governed: [String] = []
        for (i, h) in hs.enumerated() {
            guard let bp = registry.store[h.issuer] else { continue }
            let id = bp[JKey("id")]?.asString ?? ""
            if i == 0 || hs[i - 1].holder != bp[JKey("key")]?.asString { return deny("broken_link", id) }
            if bp[JKey("status")]?.asString != "active" { return deny("blueprint_disabled", id) }
            if let e = bp[JKey("expires_at")], nowMs >= (K3Sig.safeInt(e) ?? 0) { return deny("blueprint_expired", id) }
            if let d = bp[JKey("max_depth")], Int64(hs.count - i) > (K3Sig.safeInt(d) ?? 0) { return deny("too_deep", id) }
            if let c = bp[JKey("ceiling")]?.asArray, !c.isEmpty { return deny("ceiling_unevaluable", id) }
            governed.append(id)
        }
        if governed.isEmpty && mode == "require" { return deny("no_blueprint") }
        return Decision(decision: "allow", governed: governed)
    }
}
