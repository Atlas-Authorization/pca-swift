import Foundation

/// Append a signed pack to a SCITT transparency log (RFC 9943) and verify the receipt. The statement is a COSE Signed Statement over
/// `{ns, version, digest, root, prev}`; a verifier holding the pinned log key and tree root can show that this exact pack version was published.
extension ActionTransparency {
    /// What `appendPackToLog` returns.
    public struct PackLogEntry {
        public let statement: [UInt8]
        public let receipt: [UInt8]
        public let index: Int64
        public let root: String
    }

    /// The statement payload as the reference canonicalizes it: a pack with no `ns`, `version`, `root` or `prev` has an `undefined` member there,
    /// which the canonical form refuses.
    static func checkedStatementPayload(_ pack: JObject) throws -> JSONValue {
        let payload = packStatementPayload(pack)
        if ["ns", "version", "root", "prev"].contains(where: { pack[JKey($0)] == nil }) { throw JSError("canonicalize: unsupported type undefined") }
        return payload
    }

    /// Sign the pack's statement with the registry's COSE key and register it.
    public static func appendPackToLog(_ pack: JObject, _ service: PCAScittMemoryService, _ signer: PCAScitt.CoseSigner, _ issuer: String) throws -> PackLogEntry {
        let r = try service.appendAndReceipt(try checkedStatementPayload(pack), signer: signer, issuer: issuer,
                                             subject: "\(JS.toString(pack["ns"]))@\(JS.toString(pack["version"]))", contentType: PACK_STATEMENT_CONTENT_TYPE)
        return PackLogEntry(statement: r.statement, receipt: r.registration.receipt, index: r.registration.index, root: r.registration.root)
    }

    /// Does the entry prove `pack` is in the log? The statement must be the pack's own and signed by the registry, the receipt by the log. Never throws.
    public static func verifyPackLogEntry(_ pack: JObject, _ statement: [UInt8], _ receipt: [UInt8], _ registry: PCAScitt.CoseVerifier, _ log: PCAScitt.CoseVerifier, _ treeRoot: String? = nil) -> Bool {
        guard PCAScitt.verifyReceipt(receipt, statement, treeRoot: treeRoot, verificationKey: log, statementKey: registry),
              let got = try? PCAScitt.statementPayload(statement), let want = try? checkedStatementPayload(pack) else { return false }
        return got == Canonical.utf8(Canonical.canonicalize(want))
    }
}
