import Foundation

// Linked policy templates, authoring side: the constants of the template protocol, the slot and link digests and the reference builder (`createLink`).
extension PCA {
    public static let TEMPLATE_VERSION: Int64 = 1
    public static let TEMPLATE_KIND = "pca-policy-template"
    public static let TEMPLATE_SIG_DOMAIN = "atlas-pca/policy-template/v1\u{0}"
    public static let TIGHTEN_KIND = "pca-template-tighten"
    public static let TIGHTEN_SIG_DOMAIN = "atlas-pca/template-tighten/v1\u{0}"
    public static let MAX_SLOTS = 32
    public static let MAX_SLOT_STRING = 256
    public static let MAX_SLOT_SET = 64

    /// The digest a `bind_params_digest` reference cites: the strict `hashCanonical` of the slot object. Throws outside the strict profile.
    public static func slotsDigest(_ slots: JSONValue) throws -> String {
        guard let h = IV.strictHash(slots) else { throw JSError("hashCanonical: value outside the strict profile") }
        return h
    }

    /// The content address of a template reference.
    public static func linkDigest(_ ref: JSONValue) throws -> String { try slotsDigest(ref) }

    /// A template reference `{template_id, version_digest, slots}` for `def` filled with `slots`; with `bindParams` only the slots' digest travels
    /// (`bind_params_digest`). Throws when the slots do not instantiate the template.
    public static func createLink(_ def: JSONValue, _ slots: JSONValue, bindParams: Bool = false) throws -> JSONValue {
        let r = instantiateTemplate(def, slots)
        if let why = r.reason { throw JSError("createLink: \(why)") }
        guard let digest = templateDigest(def) else { throw JSError("createLink: the template is outside the strict profile") }
        var ref: [(String, JSONValue)] = [("template_id", def.get("id") ?? .null), ("version_digest", .string(digest))]
        if bindParams { ref.append(("bind_params_digest", .string(try slotsDigest(slots)))) } else { ref.append(("slots", slots)) }
        return PCAApprovalChannels.obj(ref)
    }
}
