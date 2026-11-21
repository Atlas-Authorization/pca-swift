import Foundation

/// The agent passport's binding match, its coarse trust score and the id-indexed registry: JSON-level counterparts of `matchesBinding`, `trustScore` and
/// `buildRegistry` of the reference. The match uses the same allowlist semantics as the attestation verifier, including the strict SVN bound.
extension PCA {
    /// An id-indexed passport set; a later passport with the same id replaces the earlier one in place (first-appearance order).
    public final class PassportRegistry {
        private var order: [[UInt16]] = []
        private var byId: [[UInt16]: JSONValue] = [:]
        public init(_ passports: [JSONValue]) {
            for p in passports {
                let k = Array((p.get("id")?.asString ?? "undefined").utf16)
                if byId.updateValue(p, forKey: k) == nil { order.append(k) }
            }
        }
        public func get(_ id: String) -> JSONValue? { byId[Array(id.utf16)] }
        public func has(_ id: String) -> Bool { byId[Array(id.utf16)] != nil }
        public func all() -> [JSONValue] { order.compactMap { byId[$0] } }
    }

    public static func buildPassportRegistry(_ passports: [JSONValue]) -> PassportRegistry { PassportRegistry(passports) }

    private static func jsPresent(_ v: JSONValue?) -> Bool { v != nil }

    /// `{ok, reasons}`: why a passport does not satisfy a grant's agent binding (empty when it does). Throws on a null passport or binding.
    public static func matchesBinding(_ passport: JSONValue?, _ binding: JSONValue?) throws -> (ok: Bool, reasons: [String]) {
        guard let p = passport, !p.isNull else { throw JSError("Cannot read properties of \(passport == nil ? "undefined" : "null")") }
        guard let b = binding, !b.isNull else { throw JSError("Cannot read properties of \(binding == nil ? "undefined" : "null")") }
        var reasons: [String] = []
        func str(_ v: JSONValue?) -> String { JS.toString(v) }
        func lengthPositive(_ l: JSONValue?) -> Bool {
            switch l { case let .array(a)?: return !a.isEmpty; case let .string(s)?: return !s.isEmpty; default: return false }
        }
        func includes(_ l: JSONValue?, _ v: JSONValue?) throws -> Bool {
            switch l {
            case let .array(a)?: return a.contains { x in
                switch (x, v) {
                case let (.string(p), .string(q)?): return IV.same(p, q)
                case (.null, .null?): return true
                case let (.bool(p), .bool(q)?): return p == q
                default: if let n = IV.num(x), let m = IV.num(v) { return n == m || (n.isNaN && m.isNaN) }; return false
                }
            }
            case let .string(s)?: return s.contains(str(v))
            default: throw JSError("list.includes is not a function")
            }
        }
        func need(_ list: JSONValue?, _ value: JSONValue?, _ label: String) throws {
            guard JS.truthy(list) else { return }
            if case let .array(a)? = list, a.isEmpty { return }
            if case let .string(s)? = list, s.isEmpty { return }
            if value == nil { reasons.append("\(label) required by binding but absent from passport") }
            else if !(try includes(list, value)) { reasons.append("\(label) '\(str(value))' not in allowlist") }
        }
        let ml = b.get("model_allowlist")
        if JS.truthy(ml), lengthPositive(ml), !(try includes(ml, p.get("model_id"))) { reasons.append("model_id '\(str(p.get("model_id")))' not in allowlist") }
        try need(b.get("weights_allowlist"), p.get("weights_digest"), "weights_digest")
        try need(b.get("system_prompt_allowlist"), p.get("system_prompt_digest"), "system_prompt_digest")
        try need(b.get("tool_manifest_allowlist"), p.get("tool_manifest_digest"), "tool_manifest_digest")
        if let op = b.get("operator"), !(p.get("operator").map { x in x.asString.map { y in op.asString.map { IV.same(y, $0) } ?? false } ?? false } ?? false) {
            reasons.append("operator '\(str(p.get("operator")))' != required '\(str(op))'")
        }
        if JS.truthy(b.get("require_hardware")) && !JS.truthy(p.get("hardware_rooted")) { reasons.append("binding requires a hardware-rooted attestation") }
        if JS.truthy(b.get("require_measured_weights")) && !JS.truthy(p.get("weights_measured")) { reasons.append("binding requires hardware-measured weights") }
        if let mm = b.get("min_measurement") {
            if case let .string(want) = mm {
                if !(p.get("runtime_measurement")?.asString.map { IV.same($0, want) } ?? false) { reasons.append("runtime_measurement does not equal the pinned measurement") }
            } else {
                var bound: Double?
                if case let .object(o) = mm, o.count == 1, let n = IV.num(o["svn"]), n.isFinite, n.rounded() == n, abs(n) <= IV.MAX_SAFE, n >= 0, !(n == 0 && n.sign == .minus) { bound = n }
                if let bound = bound {
                    let rm = p.get("runtime_measurement")
                    var svn = Double.nan
                    if case let .string(s)? = rm {
                        let u = Array(s.unicodeScalars)
                        if !u.isEmpty, u.allSatisfy({ $0.value >= 48 && $0.value <= 57 }), u.count == 1 || u[0].value != 48, u.count <= 19, let v = UInt64(s), v <= UInt64(Canonical.MAX_SAFE) { svn = Double(v) }
                    }
                    if !(svn.isFinite) || svn < bound { reasons.append("runtime SVN \(str(rm)) < required \(JS.number(bound))") }
                } else {
                    reasons.append("min_measurement is malformed: it must be a non-empty string or {svn: n} with n a non-negative safe integer (fail closed)")
                }
            }
        }
        return (reasons.isEmpty, reasons)
    }

    /// A coarse identity-assurance score in [0, 1] from the passport's own completeness (not behavioural reputation): a hardware root, measured weights and
    /// the other pinned digests add confidence, as does an operator in `knownOperators`.
    public static func trustScore(_ passport: JSONValue, knownOperators: [String]? = nil) -> Double {
        var s = 0.0
        if JS.truthy(passport.get("hardware_rooted")) { s += 0.4 }
        if JS.truthy(passport.get("weights_digest")) { s += JS.truthy(passport.get("weights_measured")) ? 0.2 : 0.1 }
        if JS.truthy(passport.get("system_prompt_digest")) { s += 0.1 }
        if JS.truthy(passport.get("tool_manifest_digest")) { s += 0.1 }
        if let op = passport.get("operator")?.asString, (knownOperators ?? []).contains(where: { IV.same($0, op) }) { s += 0.2 }
        return Swift.max(0, Swift.min(1, s))
    }
}
