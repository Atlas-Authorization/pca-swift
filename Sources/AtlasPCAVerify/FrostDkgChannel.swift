import Foundation

/// The wire of a FROST DKG ceremony: the strict envelope codec, the per-peer inbox (duplicates, equivocation and failures are sticky), an in-memory network, and the driver that
/// runs one party's whole ceremony over a channel. A TLS transport is an injected `PCADkgChannel`; only its frame rule (a 4-byte big-endian length, refused before any
/// allocation when it exceeds the cap) lives here.
public struct PCADkgChannelError: Error {
    public let code: String
    public let peer: Int64?
    /// The message without the `dkg channel (code, peer N): ` prefix.
    public let detail: String
    public init(_ code: String, _ peer: Int64?, _ detail: String) { self.code = code; self.peer = peer; self.detail = detail }
    public var message: String { "dkg channel (\(code)\(peer.map { ", peer \($0)" } ?? "")): \(detail)" }
}

public protocol PCADkgChannel {
    var selfId: Int64 { get }
    var peers: [Int64] { get }
    func broadcast(_ kind: String, _ body: JSONValue) throws
    func send(_ to: Int64, _ kind: String, _ body: JSONValue) throws
    func collect(_ kind: String, _ from: [Int64], timeoutMs: Double) throws -> [(Int64, JSONValue)]
    func close()
}

public enum PCAFrostDkgWire {
    public static let DKG_WIRE_VERSION = 1
    public static let DKG_MAX_MESSAGE_BYTES = 256 * 1024
    public static let DKG_MAX_PARTICIPANTS = 256
    public static let DKG_MESSAGE_KINDS = ["round1", "share", "complaints", "rebuttals", "echo"]
    /// The member order of every protocol body, so that a body built here writes the same bytes as the reference (one list, consistent for every kind).
    public static let BODY_ORDER = ["identifier", "from", "to", "accused", "accuser", "sessionId", "coefficientCommitments", "proofOfKnowledge", "R", "mu", "share", "revealedShare", "presentedShare",
                             "transcriptDigest", "shareSig", "sig", "complaints", "rebuttals"]

    private static func b64(_ b: [UInt8]) -> String { Base64URLStrict.encode(b) }
    private typealias E = PCADkgChannelError

    /// `JSON.stringify({v, sid, kind, body})` as UTF-8, refused above the cap. `order` fixes the member order of a body built in this SDK (a parsed body keeps its own).
    public static func encodeDkgMessage(_ sessionId: [UInt8], _ kind: String, _ body: JSONValue, order: [String] = []) throws -> [UInt8] {
        let text = "{\"v\":\(DKG_WIRE_VERSION),\"sid\":\(Canonical.canonicalize(.string(b64(sessionId)))),\"kind\":\(Canonical.canonicalize(.string(kind))),\"body\":\(JS.stringify(body, order: order))}"
        let bytes = Array(text.utf8)
        if bytes.count > DKG_MAX_MESSAGE_BYTES { throw E("oversize", nil, "message of \(bytes.count) bytes exceeds the cap") }
        return bytes
    }

    private static func record(_ x: JSONValue?, _ keys: [String], _ what: String) throws -> JObject {
        guard case let .object(o)? = x else { throw E("malformed", nil, "\(what) is not an object") }
        if o.count != keys.count || !keys.allSatisfy({ o[JKey($0)] != nil }) { throw E("malformed", nil, "\(what) has unexpected or missing members") }
        return o
    }
    private static func posInt(_ x: JSONValue?, _ what: String) throws -> Int64 {
        guard x?.isNumber == true, let d = IV.num(x), d == d.rounded(), d > 0, d <= 9_007_199_254_740_991 else { throw E("malformed", nil, "\(what) is not a positive integer") }
        return Int64(d)
    }
    private static func b64Field(_ x: JSONValue?, _ what: String, _ len: Int? = nil) throws -> String {
        guard case let .string(s)? = x, Base64URLStrict.decode(s, length: len) != nil else { throw E("malformed", nil, "\(what) is not canonical base64url") }
        return s
    }

    /// The kind and body of one envelope: strict JSON of exactly `{v, sid, kind, body}`, version 1, a known kind and this session.
    public static func decodeDkgMessage(_ bytes: [UInt8]?, _ sessionId: [UInt8]) throws -> (kind: String, body: JSONValue) {
        guard let bytes = bytes else { throw E("malformed", nil, "message is not bytes") }
        if bytes.count > DKG_MAX_MESSAGE_BYTES { throw E("oversize", nil, "message of \(bytes.count) bytes exceeds the cap") }
        // a byte order mark is not JSON: Foundation would drop it while decoding
        if bytes.starts(with: [0xef, 0xbb, 0xbf]) { throw E("malformed", nil, "message is not strict JSON") }
        guard let text = String(bytes: bytes, encoding: .utf8), let msg = try? StrictJSON.parse(text) else { throw E("malformed", nil, "message is not strict JSON") }
        let o = try record(msg, ["v", "sid", "kind", "body"], "envelope")
        if !(o["v"]?.isNumber == true && IV.num(o["v"]) == Double(DKG_WIRE_VERSION)) { throw E("malformed", nil, "unsupported wire version") }
        guard case let .string(kind)? = o["kind"], DKG_MESSAGE_KINDS.contains(where: { IV.same($0, kind) }) else { throw E("malformed", nil, "unknown message kind") }
        if !IV.same(o["sid"]?.asString, b64(sessionId)) { throw E("wrong-session", nil, "message names another session") }
        return (kind, o["body"] ?? .null)
    }

    public static func decodeDkgRound1Package(_ x: JSONValue?, t: JSONValue?) throws -> JSONValue {
        let o = try record(x, ["identifier", "sessionId", "coefficientCommitments", "proofOfKnowledge"], "round-1 package")
        let pok = try record(o["proofOfKnowledge"], ["R", "mu"], "proof of knowledge")
        guard case let .array(cc)? = o["coefficientCommitments"], IV.num(t) == Double(cc.count) else {
            throw E("malformed", nil, "round-1 package must commit to exactly t=\(JS.toString(t)) coefficients")
        }
        return .object(["identifier": .int(try posInt(o["identifier"], "identifier")), "sessionId": .string(try b64Field(o["sessionId"], "sessionId")),
                        "coefficientCommitments": .array(try cc.map { .string(try b64Field($0, "coefficient commitment", 32)) }),
                        "proofOfKnowledge": .object(["R": .string(try b64Field(pok["R"], "PoP R", 32)), "mu": .string(try b64Field(pok["mu"], "PoP mu", 32))])])
    }

    public static func decodeDkgShareMessage(_ x: JSONValue?) throws -> PCAFrostDkg.ShareToSend {
        let o = try record(x, ["from", "to", "sessionId", "share", "sig"], "share message")
        let from = try posInt(o["from"], "from"), to = try posInt(o["to"], "to")
        let sid = try b64Field(o["sessionId"], "sessionId")
        let share = Base64URLStrict.decode(try b64Field(o["share"], "share", 32))!
        return PCAFrostDkg.ShareToSend(from: from, to: to, sessionId: sid, share: share, sig: try b64Field(o["sig"], "share signature", 64))
    }

    private static func listOf(_ x: JSONValue?, _ key: String, _ one: (JSONValue) throws -> JSONValue) throws -> [JSONValue] {
        let o = try record(x, [key], key)
        guard case let .array(l)? = o[JKey(key)], l.count <= DKG_MAX_PARTICIPANTS else { throw E("malformed", nil, "\(key) is not a bounded list") }
        return try l.map(one)
    }
    private static func blame(_ x: JSONValue, _ what: String, _ shareKey: String) throws -> JSONValue {
        let o = try record(x, ["accused", "accuser", "sessionId", shareKey, "shareSig"], what)
        return .object(["accused": .int(try posInt(o["accused"], "accused")), "accuser": .int(try posInt(o["accuser"], "accuser")), "sessionId": .string(try b64Field(o["sessionId"], "sessionId")),
                        JKey(shareKey): .string(try b64Field(o[JKey(shareKey)], shareKey == "revealedShare" ? "revealed share" : "presented share", 32)), "shareSig": .string(try b64Field(o["shareSig"], "share signature", 64))])
    }
    public static func decodeDkgComplaints(_ x: JSONValue?) throws -> [JSONValue] { try listOf(x, "complaints") { try blame($0, "complaint", "revealedShare") } }
    public static func decodeDkgRebuttals(_ x: JSONValue?) throws -> [JSONValue] { try listOf(x, "rebuttals") { try blame($0, "rebuttal", "presentedShare") } }
    public static func decodeDkgEcho(_ x: JSONValue?) throws -> JSONValue {
        let o = try record(x, ["identifier", "sessionId", "transcriptDigest"], "echo")
        return .object(["identifier": .int(try posInt(o["identifier"], "identifier")), "sessionId": .string(try b64Field(o["sessionId"], "sessionId")),
                        "transcriptDigest": .string(try b64Field(o["transcriptDigest"], "transcript digest", 32))])
    }

    /// The TLS frame: a 4-byte big-endian length, then the payload.
    public static func tlsFrameEncode(_ payload: [UInt8]) -> [UInt8] {
        let n = payload.count
        return [UInt8((n >> 24) & 255), UInt8((n >> 16) & 255), UInt8((n >> 8) & 255), UInt8(n & 255)] + payload
    }

    /// Model of the receive loop of the TLS node: accumulates chunks and returns the complete frames; a length above the cap is `oversize`, refused before the payload is waited
    /// for, and stops everything after it.
    public static func tlsFrameDecode(_ chunks: [[UInt8]]) -> (accepted: [[UInt8]], error: String?, buffered: Int) {
        var buf: [UInt8] = []
        var accepted: [[UInt8]] = []
        var error: String? = nil
        for chunk in chunks {
            if error != nil { break }
            buf += chunk
            while true {
                if buf.count < 4 { break }
                let len = (Int(buf[0]) << 24) | (Int(buf[1]) << 16) | (Int(buf[2]) << 8) | Int(buf[3])
                if len > DKG_MAX_MESSAGE_BYTES { error = "oversize"; break }
                if buf.count < 4 + len { break }
                accepted.append(Array(buf[4..<(4 + len)]))
                buf = Array(buf[(4 + len)...])
            }
        }
        return (accepted, error, buf.count)
    }
}

/// What a participant has received: the first message of each kind from each peer, the first failure of each peer, whether a link ended, and whether the channel closed.
public final class PCADkgInbox {
    public let sessionId: [UInt8]
    public let peers: [Int64]
    private var seen: [String: (digest: String, body: JSONValue)] = [:]
    private var errors: [Int64: PCADkgChannelError] = [:]
    private var gone = Set<Int64>()
    private var closed = false
    private let cond = NSCondition()
    public init(sessionId: [UInt8], peers: [Int64]) { self.sessionId = sessionId; self.peers = peers }

    public func fail(_ peer: Int64, _ err: PCADkgChannelError) {
        cond.lock(); defer { cond.unlock() }
        if errors[peer] == nil { errors[peer] = PCADkgChannelError(err.code, peer, err.detail) }
        cond.broadcast()
    }
    public func accept(_ sender: Int64, _ bytes: [UInt8]) {
        guard peers.contains(sender) else { return }
        do {
            let (kind, body) = try PCAFrostDkgWire.decodeDkgMessage(bytes, sessionId)
            cond.lock()
            let key = "\(kind)\u{0}\(sender)", digest = Base64URLStrict.encode(bytes)
            if let prev = seen[key] {
                cond.unlock()
                throw PCADkgChannelError(prev.digest == digest ? "duplicate" : "equivocation", sender, "second \(kind) message")
            }
            seen[key] = (digest, body)
            cond.broadcast(); cond.unlock()
        } catch let e as PCADkgChannelError { fail(sender, e) } catch { fail(sender, PCADkgChannelError("malformed", sender, "undecodable message")) }
    }
    public func peerGone(_ peer: Int64) { cond.lock(); gone.insert(peer); cond.broadcast(); cond.unlock() }
    public func close() { cond.lock(); closed = true; cond.broadcast(); cond.unlock() }

    /// The bodies of `kind` from every id in `from` (ascending), waiting up to `timeoutMs`; a recorded failure of any of them, a closed channel or an ended link throws.
    public func collect(_ kind: String, _ from: [Int64], timeoutMs: Double) throws -> [(Int64, JSONValue)] {
        let want = from.sorted()
        let deadline = Date().addingTimeInterval(timeoutMs / 1000)
        cond.lock(); defer { cond.unlock() }
        while true {
            for id in want { if let e = errors[id] { throw e } }
            var out: [(Int64, JSONValue)] = []
            for id in want { if let m = seen["\(kind)\u{0}\(id)"] { out.append((id, m.body)) } }
            if out.count == want.count { return out }
            if closed { throw PCADkgChannelError("closed", nil, "channel closed before all messages arrived") }
            if let g = want.first(where: { id in !out.contains { $0.0 == id } && gone.contains(id) }) { throw PCADkgChannelError("closed", g, "link ended before its \(kind) message arrived") }
            let left = deadline.timeIntervalSinceNow
            if !(left > 0) {
                let missing = want.filter { id in !out.contains { $0.0 == id } }
                throw PCADkgChannelError("timeout", missing.first, "no \(kind) message from \(missing.map(String.init).joined(separator: ","))")
            }
            _ = cond.wait(until: Date().addingTimeInterval(left))
        }
    }
}

public final class PCAMemoryDkgNetwork {
    public private(set) var channels: [Int64: PCADkgChannel] = [:]
    private var inboxes: [Int64: PCADkgInbox] = [:]
    public func deliver(_ from: Int64, _ to: Int64, _ bytes: [UInt8]) { inboxes[to]?.accept(from, bytes) }

    final class Channel: PCADkgChannel {
        let selfId: Int64
        let peers: [Int64]
        unowned let net: PCAMemoryDkgNetwork
        let sessionId: [UInt8]
        let intercept: ((_ from: Int64, _ to: Int64, _ kind: String, _ bytes: [UInt8]) -> [UInt8]?)?
        init(_ s: Int64, _ p: [Int64], _ n: PCAMemoryDkgNetwork, _ sid: [UInt8], _ i: ((Int64, Int64, String, [UInt8]) -> [UInt8]?)?) { selfId = s; peers = p; net = n; sessionId = sid; intercept = i }
        func route(_ to: Int64, _ kind: String, _ body: JSONValue) throws {
            let bytes = try PCAFrostDkgWire.encodeDkgMessage(sessionId, kind, body, order: PCAFrostDkgWire.BODY_ORDER)
            let out = intercept.map { $0(selfId, to, kind, bytes) } ?? bytes
            if let o = out { net.deliver(selfId, to, o) }
        }
        func broadcast(_ kind: String, _ body: JSONValue) throws { for p in peers { try route(p, kind, body) } }
        func send(_ to: Int64, _ kind: String, _ body: JSONValue) throws {
            guard peers.contains(to) else { throw PCADkgChannelError("identity", to, "not a connected peer") }
            try route(to, kind, body)
        }
        func collect(_ kind: String, _ from: [Int64], timeoutMs: Double) throws -> [(Int64, JSONValue)] { try net.inboxes[selfId]!.collect(kind, from, timeoutMs: timeoutMs) }
        func close() { net.inboxes[selfId]!.close() }
    }

    public init(ids: [Int64], sessionId: [UInt8], intercept: ((_ from: Int64, _ to: Int64, _ kind: String, _ bytes: [UInt8]) -> [UInt8]?)? = nil) {
        let sorted = ids.sorted()
        for id in sorted { inboxes[id] = PCADkgInbox(sessionId: sessionId, peers: sorted.filter { $0 != id }) }
        for s in sorted { channels[s] = Channel(s, sorted.filter { $0 != s }, self, sessionId, intercept) }
    }
}

extension PCAFrostDkg {
    public struct RunResult { public let keyPackage: KeyPackage; public let qualified: [Int64]; public let complaints: [JSONValue] }

    /// One party's whole ceremony over a channel. Every peer message is checked against the claimed sender, the session and the protocol; a share that fails verification must be
    /// admissible blame (a share the sender signed that fails the commitments) or the run is aborted.
    public static func runDkgOverChannel(_ ch: PCADkgChannel, t tIn: JSONValue?, participants: JSONValue?, sessionId sid: [UInt8], timeoutMs: Double? = nil, coefficients: [[UInt8]]? = nil,
                                         random: PCAFrostNet.RandomBytes = PCAFrostNet.systemRandom) throws -> RunResult {
        typealias E = PCADkgChannelError
        let me = ch.selfId
        func bind<T>(_ peer: Int64, _ f: () throws -> T) throws -> T {
            do { return try f() } catch let e as E { throw E(e.code, peer, e.detail) }
        }
        let raw = participants?.asArray ?? []
        let safe = raw.compactMap { v -> Int64? in IV.safe(v).flatMap { $0 == $0.rounded() && abs($0) <= 9_007_199_254_740_991 ? Int64($0) : nil } }
        let sortedIds = safe.sorted()
        if raw.count > PCAFrostDkgWire.DKG_MAX_PARTICIPANTS || safe.count != raw.count || sortedIds.enumerated().contains(where: { k, i in i <= 0 || (k > 0 && sortedIds[k - 1] == i) }) {
            throw E("protocol", nil, "participants must be distinct positive integers within the cap")
        }
        let ids = sortedIds
        if !ids.contains(me) { throw E("protocol", nil, "this participant is not in the participant list") }
        guard let t = IV.safe(tIn), t == t.rounded(), t >= 1, t <= Double(ids.count) else { throw E("protocol", nil, "need 1 <= t <= n") }
        let others = ids.filter { $0 != me }
        if ch.peers.count != others.count || !zip(others, ch.peers).allSatisfy({ $0 == $1 }) { throw E("protocol", nil, "the channel peers are not exactly the other participants") }
        let sidB64 = Base64URLStrict.encode(sid)
        let tmo = timeoutMs ?? 30_000
        let order = PCAFrostDkgWire.BODY_ORDER
        let r1 = try dkgRound1(identifier: me, t: Int64(t), n: Int64(ids.count), sessionId: sid, coefficients: coefficients, random: random)
        try ch.broadcast("round1", r1.package)
        var pkgs: [JSONValue] = [r1.package]
        for (from, body) in try ch.collect("round1", others, timeoutMs: tmo) {
            let p = try bind(from) { try PCAFrostDkgWire.decodeDkgRound1Package(body, t: .int(Int64(t))) }
            if posIdOrAny(p.get("identifier")) != from { throw E("identity", from, "package claims identifier \(JS.toString(p.get("identifier")))") }
            if !IV.same(p.get("sessionId")?.asString, sidB64) { throw E("wrong-session", from, "package names another session") }
            pkgs.append(p)
        }
        var byId: [Int64: JSONValue] = [:]
        for p in pkgs { if let i = posIdOrAny(p.get("identifier")) { byId[i] = p } }
        let pok = pkgs.filter { dkgVerifyRound1(posIdOrAny($0.get("identifier")) ?? 0, $0, sid) }
        let okPeers = others.filter { o in pok.contains { posIdOrAny($0.get("identifier")) == o } }
        for s in try dkgRound2(r1.state, .array(pok)) {
            try ch.send(s.to, "share", .object(["from": .int(s.from), "to": .int(s.to), "sessionId": .string(s.sessionId), "share": .string(Base64URLStrict.encode(s.share)), "sig": .string(s.sig)]))
        }
        _ = order
        var inbox: [ReceivedShare] = []
        var mine: [JSONValue] = []
        for (from, body) in try ch.collect("share", okPeers, timeoutMs: tmo) {
            let m = try bind(from) { try PCAFrostDkgWire.decodeDkgShareMessage(body) }
            if m.from != from { throw E("identity", from, "share claims sender \(m.from)") }
            if m.to != me { throw E("identity", from, "share is addressed to \(m.to)") }
            if m.sessionId != sidB64 { throw E("wrong-session", from, "share names another session") }
            let sender = byId[from]!
            if dkgVerifyShare(from: from, share: m.share, sig: .string(m.sig), senderPackage: sender, myIdentifier: me, sessionId: sid) {
                inbox.append(ReceivedShare(from: from, sessionId: m.sessionId, share: m.share, sig: m.sig))
                continue
            }
            let c = try dkgFileComplaint(accused: from, accuser: me, receivedShare: m.share, shareSig: .string(m.sig), sessionId: sid)
            if dkgVerifyComplaint(c, .array(pkgs)).get("justified") != .bool(true) { throw E("protocol", from, "share failed verification and is not admissible blame") }
            mine.append(c)
        }
        try ch.broadcast("complaints", .object(["complaints": .array(mine)]))
        var complaints = mine
        for (from, body) in try ch.collect("complaints", others, timeoutMs: tmo) {
            let list = try bind(from) { try PCAFrostDkgWire.decodeDkgComplaints(body) }
            var pairs = Set<Int64>()
            for c in list {
                let accuser = posIdOrAny(c.get("accuser")) ?? 0, accused = posIdOrAny(c.get("accused")) ?? 0
                if accuser != from { throw E("identity", from, "complaint filed as \(accuser)") }
                if !IV.same(c.get("sessionId")?.asString, sidB64) { throw E("wrong-session", from, "complaint names another session") }
                if accused == from || !ids.contains(accused) { throw E("protocol", from, "complaint names an invalid accused") }
                if pairs.contains(accused) { throw E("duplicate", from, "two complaints against one accused") }
                pairs.insert(accused)
                complaints.append(c)
            }
        }
        var rebuttals: [JSONValue] = []
        for c in complaints where posIdOrAny(c.get("accused")) == me { rebuttals.append(try dkgRebut(accused: me, complaint: c, state: r1.state)) }
        try ch.broadcast("rebuttals", .object(["rebuttals": .array(rebuttals)]))
        var allRebuttals = rebuttals
        for (from, body) in try ch.collect("rebuttals", others, timeoutMs: tmo) {
            for r in try bind(from, { try PCAFrostDkgWire.decodeDkgRebuttals(body) }) {
                if posIdOrAny(r.get("accused")) != from { throw E("identity", from, "rebuttal made as \(JS.toString(r.get("accused")))") }
                if !IV.same(r.get("sessionId")?.asString, sidB64) { throw E("wrong-session", from, "rebuttal names another session") }
                allRebuttals.append(r)
            }
        }
        let qualified = try dkgQualifiedSet(ids, complaints, pkgs, allRebuttals)
        if !qualified.contains(me) { throw E("disqualified", me, "this participant was disqualified by the blame round") }
        if Double(qualified.count) < t { throw E("protocol", nil, "fewer than t participants remain qualified") }
        let echo = try dkgEcho(identifier: me, round1Packages: pkgs, complaints: complaints, qualified: qualified, sessionId: sid)
        try ch.broadcast("echo", echo)
        var echoes: [JSONValue] = [echo]
        for (from, body) in try ch.collect("echo", qualified.filter { $0 != me }, timeoutMs: tmo) {
            let e = try bind(from) { try PCAFrostDkgWire.decodeDkgEcho(body) }
            if posIdOrAny(e.get("identifier")) != from { throw E("identity", from, "echo claims identifier \(JS.toString(e.get("identifier")))") }
            echoes.append(e)
        }
        let agreement = dkgCheckEchoes(qualified, .array(echoes), sid)
        if agreement.get("agreed") != .bool(true) { throw E("equivocation", nil, agreement.get("reason")?.asString ?? "") }
        let kp = try dkgFinalize(myIdentifier: me, state: r1.state, receivedShares: inbox, allCommitments: pkgs, qualified: qualified, agreementEchoes: .array(echoes), agreementComplaints: complaints)
        return RunResult(keyPackage: kp, qualified: qualified, complaints: complaints)
    }
}
