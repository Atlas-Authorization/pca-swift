import Foundation

/// The reference's file-based identity helpers: a fresh P-256 key and self-signed certificate per node, written to `<dir>/key.pem` and
/// `<dir>/cert.pem` (the key readable by its owner only).
extension NetCerts {
    public struct NodeIdentity: Equatable {
        public let keyPath: String
        public let certPath: String
    }

    /// Generates `<dir>/key.pem` and `<dir>/cert.pem` for `cn` (valid two days: per run, throw-away).
    public static func generateIdentity(_ dir: String, _ cn: String) throws -> NodeIdentity {
        let ident = try generate(cn: cn)
        let d = URL(fileURLWithPath: dir)
        try FileManager.default.createDirectory(at: d, withIntermediateDirectories: true, attributes: [.posixPermissions: 0o700])
        let k = d.appendingPathComponent("key.pem"), c = d.appendingPathComponent("cert.pem")
        try Data(ident.keyPem.utf8).write(to: k)
        try FileManager.default.setAttributes([.posixPermissions: 0o600], ofItemAtPath: k.path)
        try Data(ident.certPem.utf8).write(to: c)
        return NodeIdentity(keyPath: k.path, certPath: c.path)
    }

    /// A PEM file's text.
    public static func readPem(_ path: String) throws -> String { try String(contentsOfFile: path, encoding: .utf8) }
}
