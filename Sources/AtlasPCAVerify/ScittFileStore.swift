import Foundation

/// A file-backed `ScittLogStore`: one append-only file of checksummed transactions (entry plus its new subtree hashes), synced before
/// `append` returns, so a crash leaves either the whole transaction or none of it. A torn final record is discarded on open; corruption
/// anywhere else throws `store_corrupt`. SINGLE PROCESS: the file is not locked, so run one writer per file (use a database-backed
/// store for a fleet). Memory use is the 32-byte hash of every subtree plus one offset per entry; entry bytes are read on demand.
///
/// Record: `len(4, BE) || payload || sha256(payload)`; payload = `entryLen(4) || entry || count(2) || count * (level(1) || index(4) || 3 zero bytes || hash(32))`.
public final class FileScittLogStore: ScittLogStore {
    private var nodes: [String: [UInt8]] = [:]
    private var offsets: [(at: Int, len: Int)] = []
    private var end = 0
    private let fh: FileHandle

    private init(_ fh: FileHandle) { self.fh = fh }

    private static func corrupt(_ m: String) -> JSError { JSError(m, code: PCAScittLogError.storeCorrupt) }

    /// Open (creating if absent) the log file at `path` and rebuild the index.
    public static func open(_ path: String) throws -> FileScittLogStore {
        if !FileManager.default.fileExists(atPath: path), !FileManager.default.createFile(atPath: path, contents: nil) { throw JSError("cannot create \(path)") }
        guard let fh = FileHandle(forUpdatingAtPath: path) else { throw JSError("cannot open \(path)") }
        let s = FileScittLogStore(fh)
        do { try s.load() } catch { try? fh.close(); throw error }
        return s
    }

    public func close() { try? fh.close() }

    private func read(_ at: Int, _ len: Int) throws -> [UInt8] {
        if len <= 0 { return [] }
        try fh.seek(toOffset: UInt64(at))
        return Array(try fh.read(upToCount: len) ?? Data())
    }

    private func be32(_ b: [UInt8], _ p: Int) -> Int { (Int(b[p]) << 24) | (Int(b[p + 1]) << 16) | (Int(b[p + 2]) << 8) | Int(b[p + 3]) }

    private func load() throws {
        let total = Int(try fh.seekToEnd())
        var pos = 0
        while pos < total {
            let head = try read(pos, 4)
            let len = head.count == 4 ? be32(head, 0) : -1
            let recEnd = pos + 4 + len + 32
            if len < 6 || recEnd > total {
                try discardTail(pos, recEnd > total)
                return
            }
            let payload = try read(pos + 4, len)
            let sum = try read(pos + 4 + len, 32)
            if payload.count != len || Canonical.sha256(payload) != sum {
                try discardTail(pos, recEnd == total)
                return
            }
            let entryLen = be32(payload, 0)
            var p = 4 + entryLen
            guard p + 2 <= payload.count else { throw JSError("the attempt to read outside the record is out of range") }
            let count = (Int(payload[p]) << 8) | Int(payload[p + 1])
            p += 2
            if p + count * 40 != len { throw Self.corrupt("a log record has an inconsistent length") }
            offsets.append((pos + 8, entryLen))
            for _ in 0..<count {
                nodes["\(payload[p]):\(be32(payload, p + 1))"] = Array(payload[(p + 8)..<(p + 40)])
                p += 40
            }
            pos = recEnd
        }
        end = pos
    }

    private func discardTail(_ pos: Int, _ isTail: Bool) throws {
        if !isTail { throw Self.corrupt("the log file is corrupt at offset \(pos)") }
        try fh.truncate(atOffset: UInt64(pos))
        try fh.synchronize()
        end = pos
    }

    public func size() throws -> Int64 { Int64(offsets.count) }

    public func getEntry(_ index: Int64) throws -> [UInt8]? {
        guard index >= 0, index < Int64(offsets.count) else { return nil }
        let o = offsets[Int(index)]
        return try read(o.at, o.len)
    }

    public func getNode(_ level: Int, _ index: Int64) throws -> [UInt8]? { nodes["\(level):\(index)"] }

    public func append(expectedSize: Int64, entry: [UInt8], nodes ns: [ScittStoredNode]) throws -> Bool {
        if Int64(offsets.count) != expectedSize { return false }
        for n in ns where n.level < 0 || n.level > 255 || n.index < 0 || n.index > 0xffff_ffff || n.hash.count != 32 {
            throw Self.corrupt("a subtree node is malformed")
        }
        guard ns.count <= 0xffff, entry.count <= 0xffff_ffff else { throw Self.corrupt("the record is too large") }
        func be(_ v: Int, _ n: Int) -> [UInt8] { (0..<n).reversed().map { UInt8((v >> (8 * $0)) & 0xff) } }
        var payload = be(entry.count, 4) + entry + be(ns.count, 2)
        for n in ns { payload += [UInt8(n.level)] + be(Int(n.index), 4) + [0, 0, 0] + n.hash }
        let record = be(payload.count, 4) + payload + Canonical.sha256(payload)
        try fh.seek(toOffset: UInt64(end))
        try fh.write(contentsOf: Data(record))
        try fh.synchronize()
        offsets.append((end + 8, entry.count))
        for n in ns { nodes["\(n.level):\(n.index)"] = n.hash }
        end += record.count
        return true
    }
}
