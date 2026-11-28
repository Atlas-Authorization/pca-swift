import Foundation
#if canImport(Darwin)
import Darwin
#elseif canImport(Glibc)
import Glibc
#endif

private func sysClose(_ fd: Int32) { _ = close(fd) }

// The transports of networked FROST that carry a signer service: the in-process handle, and JSON over loopback HTTP (`startSignerHttpServer` for the
// process that holds ONE share, `httpSignerTransport` for the coordinator). Plaintext HTTP, as in the reference: the channel's confidentiality and
// availability stay the deployment's; the protocol's defenses are on content (forged keys, equivocation, stale sessions).
extension PCAFrostNet {
    /// A signer service behind the transport interface: genuine state isolation (a separate object), one address space.
    public struct InProcessTransport: PCAFrostSignerTransport {
        let service: GuardianSignerService
        public var identifier: Int64 { service.identifier }
        public func round1(_ req: JSONValue) throws -> JSONValue { service.round1(req) }
        public func round2(_ req: JSONValue) throws -> JSONValue { service.round2(req) }
    }

    public static func inProcessTransport(_ service: GuardianSignerService) -> PCAFrostSignerTransport { InProcessTransport(service: service) }

    /// An HTTP signer server for ONE signer service: `POST /round1`, `POST /round2`, JSON in and out, bound to the loopback interface by default and an
    /// ephemeral port. A handler error answers a refusal, never a stack or a share.
    public final class SignerHttpServer: @unchecked Sendable {
        public let url: String
        public let port: UInt16
        private let service: GuardianSignerService
        private var fd: Int32
        private let lock = NSLock()
        private var stopped = false
        private var live = Set<Int32>()

        static let MAX_BODY = 1 << 20

        init(service: GuardianSignerService, host: String, port: UInt16) throws {
            self.service = service
            let h = host == "localhost" ? "127.0.0.1" : host
            #if os(Linux)
            let stream = Int32(SOCK_STREAM.rawValue)
            #else
            let stream = SOCK_STREAM
            #endif
            let s = socket(AF_INET, stream, 0)
            if s < 0 { throw JSError("startSignerHttpServer: cannot create a socket") }
            var yes: Int32 = 1
            setsockopt(s, SOL_SOCKET, SO_REUSEADDR, &yes, socklen_t(MemoryLayout<Int32>.size))
            var addr = sockaddr_in()
            addr.sin_family = sa_family_t(AF_INET)
            addr.sin_port = port.bigEndian
            #if canImport(Darwin)
            addr.sin_len = UInt8(MemoryLayout<sockaddr_in>.size)
            #endif
            guard inet_pton(AF_INET, h, &addr.sin_addr) == 1 else { sysClose(s); throw JSError("startSignerHttpServer: host must be an IPv4 address") }
            let bound = withUnsafePointer(to: &addr) { $0.withMemoryRebound(to: sockaddr.self, capacity: 1) { bind(s, $0, socklen_t(MemoryLayout<sockaddr_in>.size)) } }
            if bound != 0 || listen(s, 16) != 0 { sysClose(s); throw JSError("startSignerHttpServer: cannot listen on \(h):\(port)") }
            var got = sockaddr_in()
            var len = socklen_t(MemoryLayout<sockaddr_in>.size)
            let named = withUnsafeMutablePointer(to: &got) { $0.withMemoryRebound(to: sockaddr.self, capacity: 1) { getsockname(s, $0, &len) } }
            if named != 0 { sysClose(s); throw JSError("could not determine server address") }
            self.fd = s
            self.port = UInt16(bigEndian: got.sin_port)
            self.url = "http://\(h):\(self.port)"
            Thread.detachNewThread { [self] in acceptLoop() }
        }

        private func isStopped() -> Bool { lock.lock(); defer { lock.unlock() }; return stopped }

        private func acceptLoop() {
            while !isStopped() {
                var p = pollfd(fd: fd, events: Int16(POLLIN), revents: 0)
                let r = poll(&p, 1, 200)
                if r <= 0 { continue }
                let c = accept(fd, nil, nil)
                if c < 0 { continue }
                lock.lock(); live.insert(c); lock.unlock()
                Thread.detachNewThread { [self] in
                    serve(c)
                    lock.lock(); live.remove(c); lock.unlock()
                    sysClose(c)
                }
            }
        }

        private func serve(_ c: Int32) {
            #if canImport(Darwin)
            var one: Int32 = 1
            setsockopt(c, SOL_SOCKET, SO_NOSIGPIPE, &one, socklen_t(MemoryLayout<Int32>.size))
            #endif
            var tv = timeval(tv_sec: 10, tv_usec: 0)
            setsockopt(c, SOL_SOCKET, SO_RCVTIMEO, &tv, socklen_t(MemoryLayout<timeval>.size))
            func reply(_ code: Int, _ body: JSONValue) {
                let text = Canonical.canonicalize(body)
                let reason = [200: "OK", 400: "Bad Request", 404: "Not Found", 405: "Method Not Allowed"][code] ?? "Error"
                let head = "HTTP/1.1 \(code) \(reason)\r\ncontent-type: application/json\r\ncontent-length: \(text.utf8.count)\r\nconnection: close\r\n\r\n"
                Self.writeAll(c, Array((head + text).utf8))
            }
            var buf: [UInt8] = []
            var headEnd: Int?
            let sep: [UInt8] = [13, 10, 13, 10]
            while headEnd == nil {
                guard Self.fill(c, &buf), buf.count <= 16 * 1024 else { return reply(400, refusal("bad request")) }
                headEnd = Self.find(buf, sep)
            }
            let head = String(decoding: buf[..<headEnd!], as: UTF8.self)
            let lines = head.components(separatedBy: "\r\n")
            let first = (lines.first ?? "").split(separator: " ", omittingEmptySubsequences: true).map(String.init)
            guard first.count >= 2 else { return reply(400, refusal("bad request")) }
            guard first[0] == "POST" else { return reply(405, .object(["ok": .bool(false), "reason": .string("method not allowed")])) }
            var length = 0
            for l in lines.dropFirst() {
                let parts = l.split(separator: ":", maxSplits: 1).map { $0.trimmingCharacters(in: .whitespaces) }
                if parts.count == 2, parts[0].lowercased() == "content-length" { length = Int(parts[1]) ?? -1 }
            }
            if length < 0 || length > Self.MAX_BODY { return reply(400, refusal("request body too large")) }
            var body = Array(buf[(headEnd! + 4)...])
            while body.count < length {
                guard Self.fill(c, &body) else { return reply(400, refusal("bad request")) }
            }
            body = Array(body.prefix(length))
            let path = first[1]
            guard path == "/round1" || path == "/round2" else { return reply(404, .object(["ok": .bool(false), "reason": .string("not found")])) }
            var parsed: JSONValue = .object([:])
            if !body.isEmpty {
                guard let v = JSONValue.parse(String(decoding: body, as: UTF8.self)) else { return reply(400, refusal("bad request")) }
                parsed = v
            }
            reply(200, path == "/round1" ? service.round1(parsed) : service.round2(parsed))
        }

        private func refusal(_ why: String) -> JSONValue {
            .object(["ok": .bool(false), "identifier": .int(service.identifier), "refused": .bool(true), "reason": .string(why)])
        }

        private static func fill(_ c: Int32, _ buf: inout [UInt8]) -> Bool {
            var tmp = [UInt8](repeating: 0, count: 4096)
            let n = recv(c, &tmp, tmp.count, 0)
            if n <= 0 { return false }
            buf.append(contentsOf: tmp[0..<n])
            return true
        }

        private static func find(_ hay: [UInt8], _ needle: [UInt8]) -> Int? {
            guard hay.count >= needle.count else { return nil }
            for i in 0...(hay.count - needle.count) where Array(hay[i..<(i + needle.count)]) == needle { return i }
            return nil
        }

        private static func writeAll(_ c: Int32, _ bytes: [UInt8]) {
            var off = 0
            #if os(Linux)
            let flags = Int32(MSG_NOSIGNAL)
            #else
            let flags: Int32 = 0
            #endif
            while off < bytes.count {
                let n = bytes[off...].withUnsafeBytes { send(c, $0.baseAddress, $0.count, flags) }
                if n <= 0 { return }
                off += n
            }
        }

        /// Stops accepting and drops the open connections.
        public func close() {
            lock.lock()
            if stopped { lock.unlock(); return }
            stopped = true
            let open = live
            lock.unlock()
            for c in open { shutdown(c, Int32(SHUT_RDWR)) }
            sysClose(fd)
        }
    }

    /// Start the HTTP server of one signer service (IPv4 host; port 0 = an ephemeral one, read `port`).
    public static func startSignerHttpServer(_ service: GuardianSignerService, port: UInt16 = 0, host: String = "127.0.0.1") throws -> SignerHttpServer {
        try SignerHttpServer(service: service, host: host, port: port)
    }

    /// The transport of a remote signer's HTTP server: a POST per round with a bounded timeout. A refusal or an unreachable server is what the
    /// coordinator sees as a failed signer.
    public struct HttpSignerTransport: PCAFrostSignerTransport {
        public let identifier: Int64
        let baseUrl: String
        let timeoutMs: Double

        func post(_ path: String, _ req: JSONValue) throws -> JSONValue {
            let r = try PCACiba.urlSessionFetch(baseUrl + path, ["content-type": "application/json"], Canonical.canonicalize(req), timeoutMs)
            guard let v = JSONValue.parse(r.body) else { throw JSError("the signer reply was not JSON") }
            return v
        }
        public func round1(_ req: JSONValue) throws -> JSONValue { try post("/round1", req) }
        public func round2(_ req: JSONValue) throws -> JSONValue { try post("/round2", req) }
    }

    public static func httpSignerTransport(baseUrl: String, identifier: Int64, timeoutMs: Double = 10_000) -> PCAFrostSignerTransport {
        HttpSignerTransport(identifier: identifier, baseUrl: baseUrl, timeoutMs: timeoutMs)
    }
}

extension PCAFrostNet.CoordinatorError {
    /// The reference's `CoordinatorTimeoutError`: the signing window closed before the threshold was reached (one error type here, a subclass there).
    public var isTimeout: Bool { timeoutMs != nil }
}
