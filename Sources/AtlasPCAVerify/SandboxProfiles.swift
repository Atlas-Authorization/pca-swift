import Foundation

/// The OS policy compiled from what was actually authorized, and the profile generators (seccomp, Landlock, macOS SBPL, the confine
/// helper's flags). Paths and hosts are validated strictly (refused, never escaped); duplicates merge; output is sorted so the same
/// grant gives the same bytes.
extension PCASandbox {
    public struct Policy: Equatable {
        public var read: [String]
        public var write: [String]
        public var exec: [String]
        /// The only network route is the egress proxy (loopback host, port); nil = no network.
        public var proxy: (host: String, port: Int)?
        /// What the proxy will be asked to admit (documentation, not enforcement here).
        public var hosts: [String]

        public static func == (a: Policy, b: Policy) -> Bool {
            a.read == b.read && a.write == b.write && a.exec == b.exec && a.hosts == b.hosts && a.proxy?.host == b.proxy?.host && a.proxy?.port == b.proxy?.port
        }

        public init(read: [String] = [], write: [String] = [], exec: [String] = [], proxy: (host: String, port: Int)? = nil, hosts: [String] = []) {
            self.read = read
            self.write = write
            self.exec = exec
            self.proxy = proxy
            self.hosts = hosts
        }

        /// A policy from its JSON form `{v: 1, fs: {read, write, exec}, net: {proxy: {host, port}|null, hosts}}`; nil if malformed.
        public init?(json: JSONValue) {
            guard let o = json.asObject, IV.num(o[JKey("v")]) == 1, let fs = o[JKey("fs")]?.asObject, let net = o[JKey("net")]?.asObject,
                  let r = Self.strings(fs[JKey("read")]), let w = Self.strings(fs[JKey("write")]), let x = Self.strings(fs[JKey("exec")]),
                  let h = Self.strings(net[JKey("hosts")]) else { return nil }
            var proxy: (host: String, port: Int)?
            if let p = net[JKey("proxy")], !p.isNull {
                guard let host = p.get("host")?.asString, host == "127.0.0.1" || host == "::1", let port = p.get("port")?.safeInt, port >= 1, port <= 65535 else { return nil }
                proxy = (host, Int(port))
            }
            self.init(read: r, write: w, exec: x, proxy: proxy, hosts: h)
        }

        static func strings(_ v: JSONValue?) -> [String]? {
            guard let a = v?.asArray else { return nil }
            var out: [String] = []
            for x in a { guard let s = x.asString else { return nil }; out.append(s) }
            return out
        }

        public var json: JSONValue {
            func arr(_ x: [String]) -> JSONValue { .array(x.map { .string($0) }) }
            let proxyJSON: JSONValue = proxy.map { .object(["host": .string($0.host), "port": .int(Int64($0.port))]) } ?? .null
            return .object(["v": .int(1), "fs": .object(["read": arr(read), "write": arr(write), "exec": arr(exec)]),
                            "net": .object(["proxy": proxyJSON, "hosts": arr(hosts)])])
        }
    }

    static func isPathScalar(_ c: Unicode.Scalar) -> Bool {
        (c.value >= 0x30 && c.value <= 0x39) || (c.value >= 0x41 && c.value <= 0x5A) || (c.value >= 0x61 && c.value <= 0x7A) || "._+@=,:~ /-".unicodeScalars.contains(c)
    }

    /// Absolute, normalized, and only characters that need no escaping in a seccomp/Landlock/SBPL string.
    static func checkPath(_ v: JSONValue?) throws -> String {
        guard let p = v?.asString, p.unicodeScalars.first == "/", p.unicodeScalars.allSatisfy(isPathScalar), !p.contains("//"),
              !(p.count > 1 && p.hasSuffix("/")), !p.split(separator: "/", omittingEmptySubsequences: false).contains(where: { $0 == "." || $0 == ".." }) else {
            throw SandboxError("bad_path")
        }
        return p
    }

    static func isHost(_ h: String) -> Bool {
        let u = Array(h.unicodeScalars)
        func alnum(_ c: Unicode.Scalar) -> Bool { (c.value >= 0x30 && c.value <= 0x39) || (c.value >= 0x61 && c.value <= 0x7A) }
        guard let f = u.first, let l = u.last, alnum(f), alnum(l) else { return false }
        return u.allSatisfy { alnum($0) || $0 == "." || $0 == "-" }
    }

    static func sorted(_ s: Set<String>) -> [String] { s.sorted { $0.utf8.lexicographicallyPrecedes($1.utf8) } }

    /// Items of a `needs` member the way `for (const x of v)` reads them: an array's elements, nothing for a missing / empty one; anything
    /// else (a non-empty string iterates characters that are not objects, a number or object is not iterable) is refused.
    private static func iterate(_ v: JSONValue?) throws -> [JSONValue] {
        switch v {
        case nil, .null?: return []
        case let .array(a)?: return a
        case let .string(s)? where s.isEmpty: return []
        default: throw SandboxError("not iterable")
        }
    }

    /// Validate, merge and sort a list of needs `{fs?: [{path, mode: 'r'|'rw'|'x'}], net?: [{host, port}]}` into a policy. `proxyPort` is
    /// null/absent for none. Network needs exist only through the egress proxy, so they require one.
    public static func policyFromNeeds(_ needs: JSONValue, proxyPort: JSONValue? = nil) throws -> Policy {
        guard let list = needs.asArray else { throw SandboxError("needs is not an array") }
        var read = Set<String>(), write = Set<String>(), exec = Set<String>(), hosts = Set<String>()
        for n in list {
            if n.isNull { throw SandboxError("null need") }
            for f in try iterate(n.get("fs")) {
                let p = try checkPath(f.get("path"))
                switch f.get("mode")?.asString {
                case "x"?: exec.insert(p)
                case "r"?: read.insert(p)
                case "rw"?: read.insert(p); write.insert(p)
                default: throw SandboxError("bad_mode")
                }
            }
            for h in try iterate(n.get("net")) {
                guard let host = h.get("host")?.asString, isHost(host), let port = IV.safe(h.get("port")), port >= 1, port <= 65535 else { throw SandboxError("bad_net_need") }
                hosts.insert("\(host):\(Int(port))")
            }
        }
        var proxy: Int?
        if let pp = proxyPort, !pp.isNull {
            guard let d = IV.safe(pp), d >= 1, d <= 65535 else { throw SandboxError("bad_proxy_port") }
            proxy = Int(d)
        }
        if !hosts.isEmpty && proxy == nil { throw SandboxError("net_needs_proxy: network access exists only through the egress proxy; pass its port") }
        return Policy(read: sorted(read), write: sorted(write), exec: sorted(exec), proxy: proxy.map { (host: "127.0.0.1", port: $0) }, hosts: sorted(hosts))
    }

    /// Compile the OS policy from what was actually authorized: only operations whose grant allows exactly that operation contribute (a
    /// denied or unrelated one throws). `needsOf` is the tool author's mapping from an operation to what it needs.
    public static func compilePolicy(_ items: [(grant: Grant, operation: PCA.Operation)], needsOf: (PCA.Operation) -> JSONValue?, proxyPort: JSONValue? = nil) throws -> Policy {
        var needs: [JSONValue] = []
        for (g, op) in items {
            guard g.authorizes(op) else { throw SandboxError("not_authorized: result does not allow exactly this operation") }
            if let n = needsOf(op), !n.isNull { needs.append(n) }
        }
        return try policyFromNeeds(.array(needs), proxyPort: proxyPort)
    }

    // MARK: generators

    /// Syscalls for a statically linked tool that reads, computes and exits. A starting point: confirm with your tool under strace.
    static let BASE = ["read", "write", "close", "fstat", "newfstatat", "statx", "lseek", "mmap", "mprotect", "munmap", "mremap", "brk", "madvise", "rt_sigaction", "rt_sigprocmask", "rt_sigreturn", "sigaltstack", "pread64", "pwrite64", "readv", "writev", "openat", "getdents64", "fcntl", "getcwd", "readlink", "readlinkat", "dup", "dup3", "pipe2", "poll", "ppoll", "epoll_create1", "epoll_ctl", "epoll_pwait", "eventfd2", "futex", "set_tid_address", "set_robust_list", "rseq", "arch_prctl", "prlimit64", "sched_yield", "nanosleep", "clock_nanosleep", "clock_gettime", "gettimeofday", "getrandom", "getpid", "gettid", "getuid", "geteuid", "getgid", "getegid", "uname", "tgkill", "exit", "exit_group"]
    static let NET = ["connect", "getsockopt", "setsockopt", "getsockname", "getpeername", "sendto", "recvfrom", "sendmsg", "recvmsg", "shutdown"]
    static let EXEC = ["execve", "execveat"]

    private static func strs(_ a: [String]) -> JSONValue { .array(a.map { .string($0) }) }
    private static func byUtf8(_ a: [String]) -> [String] { a.sorted { $0.utf8.lexicographicallyPrecedes($1.utf8) } }

    /// Docker/OCI-format seccomp profile: deny by default; network syscalls only when the policy has a proxy; `socket` only for
    /// AF_INET/AF_INET6; exec only when the grant names a binary. seccomp cannot see paths or addresses: pair it with the Landlock rules.
    public static func seccompProfile(_ p: Policy) -> JSONValue {
        var calls: [JSONValue] = [.object(["names": strs(byUtf8(BASE)), "action": .string("SCMP_ACT_ALLOW")])]
        if p.proxy != nil {
            calls.append(.object(["names": strs(byUtf8(NET)), "action": .string("SCMP_ACT_ALLOW")]))
            for d in [2, 10] {
                calls.append(.object(["names": strs(["socket"]), "action": .string("SCMP_ACT_ALLOW"),
                                      "args": .array([.object(["index": .int(0), "value": .int(Int64(d)), "op": .string("SCMP_CMP_EQ")])])]))
            }
        }
        if !p.exec.isEmpty { calls.append(.object(["names": strs(EXEC), "action": .string("SCMP_ACT_ALLOW")])) }
        return .object([
            "defaultAction": .string("SCMP_ACT_ERRNO"), "defaultErrnoRet": .int(1),
            "archMap": .array([.object(["architecture": .string("SCMP_ARCH_X86_64"), "subArchitectures": .array([])]),
                               .object(["architecture": .string("SCMP_ARCH_AARCH64"), "subArchitectures": .array([])])]),
            "syscalls": .array(calls),
        ])
    }

    /// Landlock ruleset (access-right names from the kernel UAPI; network rules need ABI 4). Handle every right, allow only what the grant names.
    public static func landlockRuleset(_ p: Policy) -> JSONValue {
        let handledFs = ["EXECUTE", "WRITE_FILE", "READ_FILE", "READ_DIR", "REMOVE_DIR", "REMOVE_FILE", "MAKE_CHAR", "MAKE_DIR", "MAKE_REG", "MAKE_SOCK", "MAKE_FIFO", "MAKE_BLOCK", "MAKE_SYM", "REFER", "TRUNCATE"].map { "LANDLOCK_ACCESS_FS_" + $0 }
        let paths = byUtf8(Array(Set(p.read + p.write + p.exec)))
        let fs: [JSONValue] = paths.map { path in
            var acc: [String] = []
            func add(_ xs: [String]) { for x in xs where !acc.contains(x) { acc.append(x) } }
            // execve opens the binary for reading, so the kernel also demands READ_FILE for an exec grant (EACCES otherwise)
            if p.exec.contains(path) { add(["EXECUTE", "READ_FILE"]) }
            if p.read.contains(path) { add(["READ_FILE", "READ_DIR"]) }
            if p.write.contains(path) { add(["WRITE_FILE", "TRUNCATE", "MAKE_REG", "MAKE_DIR", "REMOVE_FILE", "REMOVE_DIR"]) }
            return .object(["path": .string(path), "access": strs(acc.map { "LANDLOCK_ACCESS_FS_" + $0 })])
        }
        let net: [JSONValue] = p.proxy.map { [.object(["port": .int(Int64($0.port)), "access": strs(["LANDLOCK_ACCESS_NET_CONNECT_TCP"])])] } ?? []
        return .object(["v": .int(1), "abi_min": .int(4), "handled_access_fs": strs(handledFs),
                        "handled_access_net": strs(["LANDLOCK_ACCESS_NET_BIND_TCP", "LANDLOCK_ACCESS_NET_CONNECT_TCP"]),
                        "rules": .object(["fs": .array(fs), "net": .array(net)])])
    }

    /// macOS sandbox profile (SBPL for sandbox-exec(1), deprecated but present): deny by default; the base lines are what a dynamically
    /// linked binary needs to start.
    public static func macosProfile(_ p: Policy) -> String {
        func q(_ s: String) -> String { "\"\(s)\"" } // paths were validated to need no escaping
        var lines = [
            "(version 1)", "(deny default)", "(allow sysctl-read)", "(allow process-fork)", "(allow mach-lookup)", "(allow file-read-metadata)",
            "(allow file-read* (literal \"/\") (literal \"/dev/null\") (literal \"/dev/urandom\") (subpath \"/usr/lib\") (subpath \"/System/Library\") (subpath \"/private/var/db/dyld\") (subpath \"/System/Volumes/Preboot/Cryptexes\"))",
        ]
        for x in p.exec { lines.append("(allow process-exec (literal \(q(x))))"); lines.append("(allow file-read* (literal \(q(x))))") }
        for r in p.read { lines.append("(allow file-read* (subpath \(q(r))))") }
        for w in p.write { lines.append("(allow file-write* (subpath \(q(w))))") }
        if let pr = p.proxy { lines.append("(allow network-outbound (remote tcp \(q("localhost:\(pr.port)"))))") }
        return lines.joined(separator: "\n") + "\n"
    }

    /// Flatten the GENERATED seccomp and Landlock profiles into the flags of the reference confine helper, so what the helper enforces
    /// is exactly what the generators produced. Run it as `pca-confine <flags> -- <command>`.
    public static func confineArgs(_ p: Policy) -> [String] {
        let ll = landlockRuleset(p), sc = seccompProfile(p)
        func short(_ v: JSONValue) -> String { let s = v.asString ?? ""; return s.hasPrefix("LANDLOCK_ACCESS_") ? String(s.dropFirst("LANDLOCK_ACCESS_".count)) : s }
        func joined(_ v: JSONValue?) -> String { (v?.asArray ?? []).map(short).joined(separator: ",") }
        let rules = ll.get("rules")
        var args = ["--fs-handled", joined(ll.get("handled_access_fs"))]
        let netRules = rules?.get("net")?.asArray ?? []
        if !netRules.isEmpty || p.proxy != nil { args += ["--net-handled", joined(ll.get("handled_access_net"))] }
        for r in rules?.get("fs")?.asArray ?? [] { args += ["--fs", "\(r.get("path")?.asString ?? ""):\(joined(r.get("access")))"] }
        for r in netRules { args += ["--net", "\(r.get("port")?.safeInt ?? 0):\(joined(r.get("access")))"] }
        for s in sc.get("syscalls")?.asArray ?? [] {
            let names = (s.get("names")?.asArray ?? []).compactMap { $0.asString }
            if let a = s.get("args")?.asArray {
                for x in a { for n in names { args += ["--allow-arg", "\(n):\(x.get("index")?.safeInt ?? 0):\(x.get("value")?.safeInt ?? 0)"] } }
            } else {
                for n in names { args += ["--allow", n] }
            }
        }
        return args
    }
}
