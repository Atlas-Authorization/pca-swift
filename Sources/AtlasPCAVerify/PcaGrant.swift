import Foundation

/// The `pca_grant` OAuth authorization-details type (RFC 9396): validation and the resource-server presentation check. The type is a
/// pointer to a PCA grant, not authority: a verified per-action PCActn is still required. Every function is total.
public enum PcaGrant {
    public static let TYPE = "pca_grant"
    public static let DOMAIN = "atlas-pca/pca-grant-chain/v1"
    static let MEMBERS: Set<String> = ["type", "chain_digest", "chain_len", "chain_ref", "bundle_revision", "locations"]
    static let REFUSED: Set<String> = ["actions", "datatypes", "identifier", "privileges"]

    /// https://, printable ASCII without '#' or '\', at most 2048 characters, non-empty authority (to the first '/' or '?') without '@'.
    public static func isHttpsUrl(_ v: JSONValue?) -> Bool {
        guard let u = v?.asString else { return false }
        let b = Array(u.utf8)
        guard b.count <= 2048, u.hasPrefix("https://") else { return false }
        for c in b where c < 0x21 || c > 0x7e || c == 0x23 || c == 0x5c { return false }
        let rest = b[8...]
        let end = rest.firstIndex(where: { $0 == 0x2f || $0 == 0x3f }) ?? rest.endIndex
        let authority = rest[rest.startIndex..<end]
        return !authority.isEmpty && !authority.contains(0x40)
    }

    public static func chainDigest(_ ids: [String]) -> String {
        Canonical.hashCanonical(.object([JKey("d"): .string(DOMAIN), JKey("ids"): .array(ids.map { JSONValue.string($0) })]))
    }

    /// nil when accepted, else the refusal code.
    public static func validate(_ x: JSONValue?) -> String? {
        guard let m = x?.asObject else { return "bad_entry" }
        guard m[JKey("type")]?.asString == TYPE else { return "bad_type" }
        for k in m.keys {
            if REFUSED.contains(k.s) { return "refused_member" }
            if !MEMBERS.contains(k.s) { return "unknown_member" }
        }
        guard let d = m[JKey("chain_digest")]?.asString, Base64URLStrict.decode(d, length: 32) != nil else { return "bad_chain_digest" }
        guard let n = m[JKey("chain_len")]?.safeInt, n >= 1, n <= 16 else { return "bad_chain_len" }
        if let r = m[JKey("chain_ref")], !isHttpsUrl(r) { return "bad_chain_ref" }
        if let b = m[JKey("bundle_revision")], K3Sig.safeInt(b) == nil { return "bad_bundle_revision" }
        if let l = m[JKey("locations")] {
            guard let a = l.asArray, !a.isEmpty, a.count <= 8, a.allSatisfy({ isHttpsUrl($0) }) else { return "bad_locations" }
        }
        return nil
    }

    /// The `pca_grant` entries of an `authorization_details` array, or the refusal code.
    public static func parse(_ arr: JSONValue?) -> (details: [JSONValue], code: String?) {
        guard let a = arr?.asArray else { return ([], "not_an_array") }
        if a.count > 16 { return ([], "too_many_details") }
        var out: [JSONValue] = []
        for e in a {
            guard let t = e.get("type")?.asString else { return ([], "bad_entry") }
            if t != TYPE { continue }
            if let code = validate(e) { return ([], code) }
            out.append(e)
        }
        return (out, nil)
    }

    /// Allow only with a verified per-action proof and a detail naming a prefix of the presented chain (and this resource).
    /// Returns the passing detail's index, or the deny code.
    public static func check(details: [JSONValue], resource: String, chainIds: [String], proofVerified: Bool) -> (index: Int?, code: String?) {
        if details.isEmpty { return (nil, "no_detail") }
        if !proofVerified { return (nil, "proof_required") }
        var reason = "chain_mismatch"
        for (i, d) in details.enumerated() {
            guard let n64 = d.get("chain_len")?.safeInt else { continue }
            let n = Int(n64)
            if chainIds.count < n || chainDigest(Array(chainIds[0..<n])) != d.get("chain_digest")?.asString { continue }
            if let loc = d.get("locations")?.asArray, !loc.contains(where: { $0.asString == resource }) {
                reason = "wrong_location"
                continue
            }
            return (i, nil)
        }
        return (nil, reason)
    }
}
