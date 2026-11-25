import Foundation

/// ERC-7715 (`wallet_requestExecutionPermissions`) for PCA grants: map a grant envelope to a permission request, filter by the
/// wallet's supported permissions, build revoke params, and verify what the wallet granted never exceeds the request or the grant
/// (reduce only; an unknown permission or rule type, a widening, a missing expiry, another chain / account / manager is refused).
/// Pure mapping, no chain access. Amounts: grant minor units times an explicit integer `baseUnitsPerMinor` (no price oracle).
public enum Erc7715 {
    static func isHex(_ s: String, len: Int? = nil) -> Bool {
        let b = Array(s.utf8)
        guard b.count > 2, b[0] == 0x30, b[1] == 0x78 else { return false }
        if let n = len, b.count != n + 2 { return false }
        return b[2...].allSatisfy { WhatwgURL.hexVal($0) != nil }
    }
    static func isAddress(_ s: String) -> Bool { isHex(s, len: 40) }
    /// ^0x(0|[1-9a-fA-F][0-9a-fA-F]*)$
    static func isQuantity(_ s: String) -> Bool { isHex(s) && (s.utf8.count == 3 || Array(s.utf8)[2] != 0x30) }
    /// ^(0|[1-9][0-9]*)$
    static func isDecimal(_ s: String) -> Bool {
        let b = Array(s.utf8)
        return !b.isEmpty && b.allSatisfy { $0 >= 0x30 && $0 <= 0x39 } && (b.count == 1 || b[0] != 0x30)
    }
    static func lower(_ v: JSONValue?) -> String { JS.toString(v).lowercased() }

    /// The ERC-7715 request for a grant envelope {grantDigest, capMinor, expiresAtSec}. Options: chainId (decimal string),
    /// sessionAccount, tokenAddress? (erc20-token-allowance, a PCA profile), baseUnitsPerMinor (positive integer string), from?,
    /// isAdjustmentAllowed? (default true). Throws on a bad envelope, address, ratio or chain.
    public static func grantToPermissionRequest(_ g: JSONValue?, _ o: JObject) throws -> JSONValue {
        guard let g = g?.asObject, let cap = g["capMinor"]?.safeInt, cap > 0, let exp = g["expiresAtSec"]?.safeInt, exp > 0 else {
            throw JSError("grantToPermissionRequest: bad envelope")
        }
        // the reference tests the string form of the value (an array of one address passes) and keeps the value itself
        guard isAddress(JS.toString(o["sessionAccount"])), o["from"].map({ isAddress(JS.toString($0)) }) ?? true,
              o["tokenAddress"].map({ isAddress(JS.toString($0)) }) ?? true else { throw JSError("grantToPermissionRequest: bad address") }
        let ratio = JS.toString(o["baseUnitsPerMinor"])
        guard isDecimal(ratio), o["baseUnitsPerMinor"] != .string("0") else {
            throw JSError("grantToPermissionRequest: baseUnitsPerMinor must be a positive integer string")
        }
        guard let chainText = o["chainId"]?.asString, let chain = JSBigInt.parse(chainText), !chain.neg, !chain.mag.isZero else {
            throw JSError("grantToPermissionRequest: bad chain")
        }
        let allowance = "0x" + JSBigInt.hex(BigUInt(UInt64(cap)) * BigUInt(decimal: ratio))
        let adj = JS.present(o["isAdjustmentAllowed"]) ?? .bool(true)
        var data: JObject = ["allowance": .string(allowance)]
        let type: String
        if let t = o["tokenAddress"] { data["tokenAddress"] = t; type = "erc20-token-allowance" } else { type = "native-token-allowance" }
        var r: JObject = [
            "chainId": .string("0x" + JSBigInt.hex(chain.mag)),
            "to": o["sessionAccount"]!,
            "permission": .object(["type": .string(type), "isAdjustmentAllowed": adj, "data": .object(data)]),
            "rules": .array([.object(["type": .string("expiry"), "data": .object(["timestamp": .int(exp)])])]),
        ]
        if let f = o["from"] { r["from"] = f }
        return .object(r)
    }

    /// Does the wallet's `wallet_getSupportedExecutionPermissions` answer cover the request's permission type, chain and rule types?
    public static func supportsRequest(_ supported: JSONValue?, _ req: JSONValue?) -> Bool {
        guard let perm = req?.get("permission"), perm != .null else { return false }
        guard let s = supported?.asObject?[JKey(JS.toString(perm.get("type")))]?.asObject else { return false }
        guard let chains = s["chainIds"]?.asArray, chains.allSatisfy({ $0.asString != nil }) else { return false }
        guard let chain = req?.get("chainId")?.asString, chains.contains(where: { lower($0) == chain.lowercased() }) else { return false }
        let rt = JS.present(s["ruleTypes"]) ?? s["rulesTypes"]
        let rules: [JSONValue]
        switch req?.get("rules") {
        case nil, .null?: rules = []
        case let .array(a)?: rules = a
        default: return false
        }
        return rules.allSatisfy { r in
            guard r != .null, let types = rt?.asArray, let t = r.get("type") else { return false }
            return types.contains(t)
        }
    }

    public static func revokeParams(_ context: JSONValue?) -> JSONValue {
        guard let c = context else { return .object([:]) }
        return .object(["permissionContext": c])
    }

    /// nil when the granted permission stays within the request and the grant, else the reason. `contextOwner` maps a permission
    /// context to the grant digest it is bound to (nil = unknown). A grant without a numeric `expiresAtSec` refuses as
    /// `expiry_extended` (the reference compares against undefined and passes: fail closed here).
    public static func verifyGrantedPermission(_ g: JSONValue?, _ sent: JSONValue?, _ got: JSONValue?, allowedManagers: JSONValue?,
                                               contextOwner: ((String) -> JSONValue?)? = nil) -> String? {
        let malformed = "response_malformed"
        guard let r = got?.asObject, let perm = r["permission"], perm.isObject || perm.isArray else { return malformed }
        guard let ctx = r["context"]?.asString, isHex(ctx) else { return "context_malformed" }
        if let owner = contextOwner?(ctx) {
            guard let gObj = g?.asObject else { return malformed }
            if owner != (gObj["grantDigest"] ?? .null) || gObj["grantDigest"] == nil { return "context_bound_to_other_grant" }
        }
        guard let dm = r["delegationManager"]?.asString, isAddress(dm) else { return "delegation_manager_not_allowed" }
        guard let managers = allowedManagers?.asArray else { return malformed }
        guard managers.allSatisfy({ $0.asString != nil }) else { return malformed }
        if !managers.contains(where: { lower($0) == dm.lowercased() }) { return "delegation_manager_not_allowed" }
        // the reference lower-cases the sent values: a non-string there throws (caught as malformed), in this order
        guard let s = sent?.asObject, let sentChain = s["chainId"]?.asString else { return malformed }
        if lower(r["chainId"]) != sentChain.lowercased() { return "chain_mismatch" }
        guard let sentTo = s["to"]?.asString else { return malformed }
        if lower(r["to"]) != sentTo.lowercased() { return "recipient_mismatch" }
        if let f = s["from"] {
            guard let fs = f.asString else { return malformed }
            if lower(r["from"]) != fs.lowercased() { return "from_mismatch" }
        }
        guard let sp = s["permission"]?.asObject else { return malformed }
        let type = perm.get("type")
        if type != sp["type"] || (type != .string("native-token-allowance") && type != .string("erc20-token-allowance")) { return "permission_type_mismatch" }
        guard let dv = perm.get("data"), dv != .null else { return malformed }
        guard let sd = sp["data"], sd != .null else { return malformed }
        if lower(JS.present(dv.get("tokenAddress")) ?? .string("")) != lower(JS.present(sd.get("tokenAddress")) ?? .string("")) { return "token_mismatch" }
        guard let amount = dv.get("allowance")?.asString, isQuantity(amount), let have = JSBigInt.parse(amount) else { return "amount_malformed" }
        guard let limit = JSBigInt.of(sd.get("allowance")) else { return malformed }
        if have > limit { return "amount_widened" }
        if perm.get("isAdjustmentAllowed") == .bool(true) && sp["isAdjustmentAllowed"] != .bool(true) { return "adjustment_widened" }
        guard let rules = r["rules"]?.asArray else { return "expiry_missing" }
        var expiry: Int64? = nil
        for rule in rules {
            if rule.get("type") != .string("expiry") { return "unknown_rule_type" }
            if expiry != nil { return "duplicate_expiry" }
            guard let data = rule.get("data"), data != .null else { return malformed }
            guard let ts = data.get("timestamp"), !(IV.num(ts).map { IV.isNegZero($0) } ?? false), let t = ts.safeInt else { return "expiry_malformed" }
            expiry = t
        }
        guard let e = expiry else { return "expiry_missing" }
        guard let gObj = g?.asObject else { return malformed }
        guard let ge = IV.num(gObj["expiresAtSec"]) else { return "expiry_extended" }
        // a grant expiry that is not a safe integer bounds nothing
        if !(ge.isFinite && ge.rounded() == ge && abs(ge) <= IV.MAX_SAFE && Double(e) <= ge) { return "expiry_extended" }
        return nil
    }

    /// hashCanonical(grant) (strict profile); nil where the reference throws.
    public static func grantDigestOf(_ grant: JSONValue) -> String? { IV.strictHash(grant) }
}
