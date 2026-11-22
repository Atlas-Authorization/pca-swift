import Foundation

/// A durable revocation store backed by one JSON file (the reference's `FileRevocationStore`). Every change is written to a temporary file, flushed to
/// disk, then renamed over the real file, so a crash leaves either the old or the new contents, never a torn file. Single process: two processes must not
/// share one file. Fail closed: a file that exists but cannot be read or does not hold a valid list of entries makes the initializer throw (silently
/// starting empty would un-revoke everything).
extension PCARevoke {
    public final class FileRevocationStore: Store, @unchecked Sendable {
        private let path: String
        private var entries: [(key: [UInt8], value: JSONValue)] = []
        private let lock = NSLock()

        public init(path: String) throws {
            self.path = path
            guard FileManager.default.fileExists(atPath: path) else { return }
            guard let data = FileManager.default.contents(atPath: path), let text = String(data: data, encoding: .utf8), let parsed = try? StrictJSON.parseLenient(text) else {
                throw JSError("FileRevocationStore: the revocation file cannot be read as JSON; refusing to start empty")
            }
            guard let list = parsed.get("entries")?.asArray, list.allSatisfy(Self.validEntry) else {
                throw JSError("FileRevocationStore: the revocation file is not a valid entry list; refusing to start empty")
            }
            for e in list { put(e) }
        }

        static let KINDS = ["cap", "holder", "issuer", "prefix"]

        static func validEntry(_ e: JSONValue) -> Bool {
            guard e.isObject, let kind = e.get("kind")?.asString, KINDS.contains(kind), let value = e.get("value")?.asString, !value.isEmpty,
                  e.get("reason")?.asString != nil, let at = IV.num(e.get("revokedAt")), at.isFinite else { return false }
            if let nb = e.get("notBefore") { guard let n = IV.num(nb), n.isFinite else { return false } }
            if kind == "prefix" {
                guard let p = e.get("prefix")?.asArray, !p.isEmpty else { return false }
                let parts = p.compactMap { $0.asString }
                guard parts.count == p.count, parts.allSatisfy({ !$0.isEmpty }), parts.joined(separator: ",") == value else { return false }
            }
            return true
        }

        private func put(_ entry: JSONValue) {
            let key = InMemoryStore.storeKey(JS.toString(PCARevoke.member(entry, "kind")), JS.toString(PCARevoke.member(entry, "value")))
            if let i = entries.firstIndex(where: { $0.key == key }) { entries[i].value = entry } else { entries.append((key, entry)) }
        }

        private func flush() throws {
            let tmp = path + ".tmp"
            let body = JS.stringify(.object(["v": .int(1), "entries": .array(entries.map { $0.value })]))
            guard FileManager.default.createFile(atPath: tmp, contents: Data(body.utf8), attributes: [.posixPermissions: 0o600]) else {
                throw JSError("FileRevocationStore: cannot write \(tmp)")
            }
            let h = try FileHandle(forWritingTo: URL(fileURLWithPath: tmp))
            do { try h.synchronize(); try h.close() } catch { try? h.close(); throw error }
            guard rename(tmp, path) == 0 else { throw JSError("FileRevocationStore: cannot replace \(path)") }
        }

        /// Apply `change` to memory and flush; on a failed flush put memory back, so memory never claims more than disk.
        private func write<T>(_ change: () -> T) throws -> T {
            lock.lock(); defer { lock.unlock() }
            let before = entries
            let out = change()
            do { try flush() } catch { entries = before; throw error }
            return out
        }

        public func add(_ entry: JSONValue) throws { try write { put(entry) } }

        public func remove(_ kind: String, _ value: String) throws -> Bool {
            let key = InMemoryStore.storeKey(kind, value)
            return try write { let n = entries.count; entries.removeAll { $0.key == key }; return entries.count != n }
        }

        public func get(_ kind: String, _ value: String) throws -> JSONValue? {
            let key = InMemoryStore.storeKey(kind, value)
            lock.lock(); defer { lock.unlock() }
            return entries.first { $0.key == key }?.value
        }

        public func all() throws -> [JSONValue] { lock.lock(); defer { lock.unlock() }; return entries.map { $0.value } }

        public func clear() throws { try write { entries.removeAll() } }
    }
}
