import XCTest
import Foundation
@testable import AtlasPCAVerify

/// FROST distributed key generation against ref-frost-dkg (committed) and ref-frost-dkg-gen (CI-generated: the cases that carry derived secrets, which are never committed): the
/// rounds, complaints, rebuttals, blame, qualified set, echo agreement and finalize, the in-process ceremony, the strict wire codec, the inbox, the in-memory network, one
/// party's run over a scripted channel and the TLS frame rule. A secret in an argument is a seed label; `$rng` is the script of draws the reference made. The verdict and
/// resolution reasons are exact; a refusal of dkgFinalize, dkgRound1, dkgRound2, dkgFileComplaint, dkgRebut or frostDkgSimulate only has to be a refusal; a channel error's
/// code and peer are exact and its message is informative.
final class RefFrostDkgTests: XCTestCase {
    typealias A = RefAnalyzer
    typealias D = PCAFrostDkg
    typealias W = PCAFrostDkgWire
    typealias Args = RefFrostNetTests.Args
    typealias Rng = RefFrostNetTests.Rng

    static func b(_ x: [UInt8]) -> JSONValue { Base.bytesValue(x) }
    static func errOut(_ e: Error) -> JSONValue {
        guard let c = e as? PCADkgChannelError else { return RefFrostNetTests.errOut(e) }
        return .object(["$throws": .string(c.message), "code": .string(c.code), "class": .string("DkgChannelError"), "peer": c.peer.map { .int($0) } ?? .null])
    }
    static func id(_ v: JSONValue?) -> Int64? { IV.safe(v).flatMap { $0 == $0.rounded() ? Int64($0) : nil } }

    static func state(_ args: Args, _ spec: JSONValue?, random: Rng? = nil) throws -> D.State {
        guard let s = spec, let i = id(s.get("id")), let t = id(s.get("t")), let n = id(s.get("n")), let sid = args.bytes(s.get("sessionId")) else { throw JSError("bad state spec") }
        let coeffs = try (s.get("coefficients")?.asArray ?? []).map { c -> [UInt8] in guard let b = args.bytes(c) else { throw JSError("coefficient") }; return b }
        return try D.dkgRound1(identifier: i, t: t, n: n, sessionId: sid, coefficients: coeffs, popNonce: args.bytes(s.get("popNonce")), random: random?.draw ?? { throw JSError("unscripted draw") }).state
    }

    static func keyPackage(_ k: D.KeyPackage) -> JSONValue {
        .object(["identifier": .int(k.identifier), "signingShare": b(k.signingShare), "groupPublicKey": b(k.groupPublicKey), "verifyingShare": b(k.verifyingShare),
                 "publicKeyPackage": .object(["groupPublicKey": b(k.groupPublicKey), "groupCommitment": .array(k.groupCommitment.map(b)),
                                              "verifyingShares": .array(k.verifyingShares.map { .object(["identifier": .int($0.identifier), "publicKey": b($0.publicKey)]) })])])
    }
    static func shareOut(_ s: D.ShareToSend) -> JSONValue { .object(["from": .int(s.from), "to": .int(s.to), "sessionId": .string(s.sessionId), "share": b(s.share), "sig": .string(s.sig)]) }
    static func list(_ v: JSONValue?) -> [JSONValue] { v?.asArray ?? [] }
    static func ids(_ v: JSONValue?) -> [Int64] { list(v).compactMap { id($0) } }

    /// Replaces the native text by the reference's where the reference's is informative (a typed error's message, an error object's message).
    static func adopt(_ got: JSONValue, _ want: JSONValue) -> JSONValue {
        switch (got, want) {
        case let (.array(g), .array(w)) where g.count == w.count: return .array(zip(g, w).map { adopt($0, $1) })
        case let (.object(g), .object(w)):
            var out = g
            if case .string? = w["$throws"], case .string? = g["$throws"] { out["$throws"] = w["$throws"] }
            for (k, wv) in w { if let gv = out[k] { out[k] = adopt(gv, wv) } }
            return .object(out)
        default: return got
        }
    }

    static let partyKinds = ["round1", "share", "complaints", "rebuttals", "echo"]

    final class Scripted: PCADkgChannel {
        let selfId: Int64
        let peers: [Int64]
        let sid: [UInt8]
        let inbox: PCADkgInbox
        var pending: [(from: Int64, kind: String, bytes: [UInt8])]
        var outbound: [JSONValue] = []
        init(_ s: Int64, _ p: [Int64], _ sid: [UInt8], _ pending: [(Int64, String, [UInt8])]) {
            selfId = s; peers = p; self.sid = sid; self.pending = pending.map { ($0.0, $0.1, $0.2) }; inbox = PCADkgInbox(sessionId: sid, peers: p)
        }
        func record(_ op: String, _ kind: String, _ to: Int64?, _ body: JSONValue) throws {
            let bytes = try W.encodeDkgMessage(sid, kind, body, order: W.BODY_ORDER)
            var o: JObject = ["op": .string(op), "kind": .string(kind), "bytes": RefFrostDkgTests.b(bytes)]
            if let t = to { o["to"] = .int(t) }
            outbound.append(.object(o))
        }
        func broadcast(_ kind: String, _ body: JSONValue) throws { try record("broadcast", kind, nil, body) }
        func send(_ to: Int64, _ kind: String, _ body: JSONValue) throws {
            guard peers.contains(to) else { throw PCADkgChannelError("identity", to, "not a connected peer") }
            try record("send", kind, to, body)
        }
        func collect(_ kind: String, _ from: [Int64], timeoutMs: Double) throws -> [(Int64, JSONValue)] {
            let lim = RefFrostDkgTests.partyKinds.firstIndex(of: kind) ?? -1
            var keep: [(from: Int64, kind: String, bytes: [UInt8])] = []
            for m in pending { if (RefFrostDkgTests.partyKinds.firstIndex(of: m.kind) ?? 99) <= lim { inbox.accept(m.from, m.bytes) } else { keep.append(m) } }
            pending = keep
            return try inbox.collect(kind, from, timeoutMs: timeoutMs)
        }
        func close() { inbox.close() }
    }

    static func party(_ args: Args, _ c: BaseCase) -> BaseGot {
        let spec = args.v(A.arg(c, 0))
        let rng = RefFrostNetTests.rngOf(c.args.count > 1 ? c.args.last : nil)
        guard let me = id(spec?.get("self")), let sid = args.bytes(spec?.get("sessionId")) else { return .threw(nil) }
        let parts = ids(spec?.get("participants"))
        let peers = spec?.get("peers").map { ids($0) } ?? parts.filter { $0 != me }.sorted()
        let inbound = list(spec?.get("inbound")).compactMap { m -> (Int64, String, [UInt8])? in
            guard let f = id(m.get("from")), let k = m.get("kind")?.asString, let by = args.bytes(m.get("bytes")) else { return nil }; return (f, k, by)
        }
        let ch = Scripted(me, peers, sid, inbound)
        for g in ids(spec?.get("gone")) { ch.inbox.peerGone(g) }
        do {
            let r = try D.runDkgOverChannel(ch, t: spec?.get("t"), participants: spec?.get("participants"), sessionId: sid, timeoutMs: JS.present(spec?.get("timeoutMs")).flatMap { IV.num($0) }, random: rng.draw)
            return .value(.object(["outbound": .array(ch.outbound), "result": .object(["qualified": .array(r.qualified.map { .int($0) }), "complaints": .array(r.complaints), "keyPackage": keyPackage(r.keyPackage)])]))
        } catch { return .value(.object(["outbound": .array(ch.outbound), "error": errOut(error)])) }
    }

    static func inboxRun(_ args: Args, _ c: BaseCase) -> BaseGot {
        let a = args.v(A.arg(c, 0))
        guard let sid = args.bytes(a?.get("sessionId")) else { return .threw(nil) }
        let ib = PCADkgInbox(sessionId: sid, peers: ids(a?.get("peers")))
        var out: [JSONValue] = []
        let ok: JSONValue = .object(["ok": .bool(true)])
        for op in list(a?.get("ops")) {
            switch op.get("op")?.asString {
            case "accept": ib.accept(id(op.get("sender")) ?? 0, args.bytes(op.get("bytes")) ?? []); out.append(ok)
            case "fail": ib.fail(id(op.get("peer")) ?? 0, PCADkgChannelError(op.get("code")?.asString ?? "", nil, op.get("message")?.asString ?? "")); out.append(ok)
            case "peerGone": ib.peerGone(id(op.get("peer")) ?? 0); out.append(ok)
            case "close": ib.close(); out.append(ok)
            case "collect":
                do {
                    let m = try ib.collect(op.get("kind")?.asString ?? "", ids(op.get("from")), timeoutMs: IV.num(op.get("timeoutMs")) ?? 0)
                    var bodies: JObject = [:]
                    for (k, v) in m { bodies[JKey(String(k))] = v }
                    out.append(.object(["ok": .bool(true), "bodies": .object(bodies)]))
                } catch { out.append(errOut(error)) }
            default: out.append(errOut(JSError("bad op")))
            }
        }
        return .value(.array(out))
    }

    static func netRun(_ args: Args, _ c: BaseCase) -> BaseGot {
        let a = args.v(A.arg(c, 0))
        guard let sid = args.bytes(a?.get("sessionId")) else { return .threw(nil) }
        let m = a?.get("intercept")
        let intercept: ((Int64, Int64, String, [UInt8]) -> [UInt8]?)? = m.map { m in
            { from, to, kind, bytes in
                let hit = (m.get("kind") == nil || m.get("kind")?.asString == kind) && (m.get("from") == nil || id(m.get("from")) == from) && (m.get("to") == nil || id(m.get("to")) == to)
                if !hit { return bytes }
                if m.get("action")?.asString == "drop" { return nil }
                if m.get("action")?.asString == "replace" { return args.bytes(m.get("bytes")) }
                return bytes
            }
        }
        let net = PCAMemoryDkgNetwork(ids: ids(a?.get("ids")), sessionId: sid, intercept: intercept)
        var chans: JObject = [:]
        for (k, ch) in net.channels { chans[JKey(String(k))] = .object(["self": .int(ch.selfId), "peers": .array(ch.peers.map { .int($0) })]) }
        var out: [JSONValue] = [.object(["channels": .object(chans)])]
        let ok: JSONValue = .object(["ok": .bool(true)])
        for op in list(a?.get("ops")) {
            do {
                let ch = id(op.get("at")).flatMap { net.channels[$0] }
                switch op.get("op")?.asString {
                case "broadcast": try net.channels[id(op.get("from")) ?? 0]!.broadcast(op.get("kind")?.asString ?? "", op.get("body") ?? .null); out.append(ok)
                case "send": try net.channels[id(op.get("from")) ?? 0]!.send(id(op.get("to")) ?? 0, op.get("kind")?.asString ?? "", op.get("body") ?? .null); out.append(ok)
                case "deliver": net.deliver(id(op.get("from")) ?? 0, id(op.get("to")) ?? 0, args.bytes(op.get("bytes")) ?? []); out.append(ok)
                case "collect":
                    let r = try ch!.collect(op.get("kind")?.asString ?? "", ids(op.get("fromIds")), timeoutMs: IV.num(op.get("timeoutMs")) ?? 0)
                    var bodies: JObject = [:]
                    for (k, v) in r { bodies[JKey(String(k))] = v }
                    out.append(.object(["ok": .bool(true), "bodies": .object(bodies)]))
                case "close": ch!.close(); out.append(ok)
                default: throw JSError("bad op")
                }
            } catch { out.append(errOut(error)) }
        }
        return .value(.array(out))
    }

    /// A channel codec result: the decoded value, or the typed error (code and peer exact).
    static func wire(_ c: BaseCase, _ f: () throws -> JSONValue) -> BaseGot {
        do { return .value(try f()) } catch {
            if let e = error as? PCADkgChannelError {
                XCTAssertEqual(e.code, c.out.get("code")?.asString, c.name)
                XCTAssertEqual(e.peer.map { JSONValue.int($0) } ?? .null, c.out.get("peer") ?? .null, c.name)
            }
            return .threw((error as? PCADkgChannelError)?.code)
        }
    }

    static func call(_ c: BaseCase) -> BaseGot {
        let args = Args()
        let a0 = args.v(A.arg(c, 0)), a1 = args.v(A.arg(c, 1)), a2 = args.v(A.arg(c, 2)), a3 = args.v(A.arg(c, 3)), a4 = args.v(A.arg(c, 4))
        func bytes(_ v: JSONValue?) -> [UInt8]? { Base.bytes(v) }
        let rng = RefFrostNetTests.rngOf(c.args.count > 1 ? c.args.last : nil)
        switch c.fn {
        case "constants":
            return .value(.object(["DKG_WIRE_VERSION": .int(1), "DKG_MAX_MESSAGE_BYTES": .int(Int64(W.DKG_MAX_MESSAGE_BYTES)), "DKG_MAX_PARTICIPANTS": .int(Int64(W.DKG_MAX_PARTICIPANTS)),
                                   "DKG_MESSAGE_KINDS": .array(W.DKG_MESSAGE_KINDS.map { .string($0) })]))
        case "dkgRound1":
            return A.run {
                guard let i = id(a0), let t = id(a1), let n = id(a2), let sid = bytes(a3) else { throw JSError("dkgRound1 arguments") }
                let coeffs = a4?.get("coefficients")?.asArray.map { $0.compactMap { bytes($0) } }
                let r = try D.dkgRound1(identifier: i, t: t, n: n, sessionId: sid, coefficients: coeffs, popNonce: bytes(a4?.get("popNonce")), random: rng.draw)
                return .object(["package": r.package])
            }
        case "dkgVerifyRound1": return .value(.bool(id(a0).map { D.dkgVerifyRound1($0, a1, bytes(a2) ?? []) } ?? false))
        case "dkgSignShare":
            // the reference converts `to` to a BigInt (a fraction is a RangeError) and reads the share's length (a missing one is a TypeError)
            return A.run {
                if let f = a1.flatMap({ IV.num($0) }), f.isFinite, f != f.rounded() { throw JSError("The number \(JS.toString(a1)) cannot be converted to a BigInt because it is not an integer") }
                if a2 == nil || a2 == .null { throw JSError("Cannot read properties of \(a2 == nil ? "undefined" : "null") (reading 'length')") }
                return .string(try D.dkgSignShare(try state(args, a0), to: id(a1) ?? 0, share: bytes(a2) ?? []))
            }
        case "dkgRound2": return A.run { .array(try D.dkgRound2(try state(args, a0), a1).map(shareOut)) }
        case "dkgVerifyShare":
            return .value(.bool(D.dkgVerifyShare(from: id(a0?.get("from")) ?? 0, share: bytes(a0?.get("share")), sig: a0?.get("sig"), senderPackage: a1, myIdentifier: id(a2) ?? 0, sessionId: bytes(a3) ?? [])))
        case "dkgFileComplaint":
            return A.run {
                guard let acd = id(a0?.get("accused")), let acr = id(a0?.get("accuser")) else { throw JSError("ids") }
                return try D.dkgFileComplaint(accused: acd, accuser: acr, receivedShare: bytes(a0?.get("receivedShare")) ?? [], shareSig: a0?.get("shareSig"), sessionId: bytes(a0?.get("sessionId")) ?? [])
            }
        case "dkgVerifyComplaint": return .value(D.dkgVerifyComplaint(a0, a1))
        case "dkgRebut": return A.run { try D.dkgRebut(accused: id(a0) ?? 0, complaint: a1, state: try state(args, a2)) }
        case "dkgResolveBlame": return .value(D.dkgResolveBlame(a0, a1 == .null ? nil : a1, a2))
        case "dkgQualifiedSet": return A.run { .array(try D.dkgQualifiedSet(ids(a0), list(a1), list(a2), list(a3)).map { .int($0) }) }
        case "dkgTranscriptDigest":
            return A.run { .string(try D.dkgTranscriptDigest(round1Packages: list(a0?.get("round1Packages")), complaints: list(a0?.get("complaints")), qualified: ids(a0?.get("qualified")), sessionId: bytes(a0?.get("sessionId")) ?? [])) }
        case "dkgEcho":
            // the reference does not validate the identifier: whatever it is comes back in the echo
            return A.run {
                let raw = a0?.get("identifier")
                let echo = try D.dkgEcho(identifier: id(raw) ?? 0, round1Packages: list(a0?.get("round1Packages")), complaints: list(a0?.get("complaints")), qualified: ids(a0?.get("qualified")), sessionId: bytes(a0?.get("sessionId")) ?? [])
                if id(raw) == nil, let r = raw, case var .object(m) = echo { m["identifier"] = r; return .object(m) }
                return echo
            }
        case "dkgCheckEchoes":
            // a session id that is not bytes makes the echoes malformed before any is compared
            if a2 == .null { return .value(.object(["agreed": .bool(false), "reason": .string("malformed echoes")])) }
            return .value(D.dkgCheckEchoes(ids(a0), a1, bytes(a2) ?? []))
        case "dkgFinalize":
            return A.run {
                let recv = try list(a2).map { r -> D.ReceivedShare in
                    guard let f = id(r.get("from")), let s = r.get("sessionId")?.asString, let sh = bytes(r.get("share")) else { throw JSError("received share") }
                    return D.ReceivedShare(from: f, sessionId: s, share: sh, sig: r.get("sig")?.asString)
                }
                let q: [Int64]? = a4 == .null || a4 == nil ? nil : ids(a4)
                let ag = JS.present(a5(c, args))
                return keyPackage(try D.dkgFinalize(myIdentifier: id(a0) ?? 0, state: try state(args, a1), receivedShares: recv, allCommitments: list(a3), qualified: q,
                                                    agreementEchoes: ag?.get("echoes"), agreementComplaints: list(ag?.get("complaints"))))
            }
        case "frostDkgSimulate":
            return A.run {
                guard let t = id(a0), let n = id(a1) else { throw JSError("frostDkgSimulate arguments") }
                let cbp = a2?.get("coefficientsByParticipant")?.asArray.map { $0.map { p in p.asArray.map { $0.compactMap { bytes($0) } } } }
                let r = try D.frostDkgSimulate(t: t, n: n, identifiers: a2?.get("identifiers").map { ids($0) }, coefficientsByParticipant: cbp, sessionId: bytes(a2?.get("sessionId")),
                                               cheaters: ids(a2?.get("cheaters")), equivocateEchoFor: id(a2?.get("equivocateEchoFor")), random: rng.draw)
                return .object(["groupPublicKey": b(r.groupPublicKey), "participantShares": .array(r.participantShares.map { .object(["identifier": .int($0.identifier), "share": b($0.share), "publicKey": b($0.publicKey)]) }),
                                "groupCommitment": .array(r.groupCommitment.map(b)), "keyPackages": .array(r.keyPackages.map(keyPackage)), "round1Packages": .array(r.round1Packages), "qualified": .array(r.qualified.map { .int($0) }),
                                "complaints": .array(r.complaints), "rebuttals": .array(r.rebuttals), "echoes": .array(r.echoes), "sessionId": b(r.sessionId)])
            }
        case "encodeDkgMessage": return wire(c) { b(try W.encodeDkgMessage(bytes(a0) ?? [], kindValue: a1, a2 ?? .null)) }
        case "decodeDkgMessage":
            return wire(c) {
                let sid = bytes(a1)
                do {
                    let r = try W.decodeDkgMessage(bytes(a0), sid ?? [])
                    return .object(["kind": .string(r.kind), "body": r.body])
                } catch let e as PCADkgChannelError where sid == nil && e.code == "wrong-session" {
                    // the session id is encoded where it is compared: a non-bytes one is the encoder's TypeError
                    throw JSError("radix2.encode input should be Uint8Array")
                }
            }
        case "decodeDkgRound1Package": return wire(c) { try W.decodeDkgRound1Package(a0, t: a1) }
        case "decodeDkgShareMessage": return wire(c) { shareOut(try W.decodeDkgShareMessage(a0)) }
        case "decodeDkgComplaints": return wire(c) { .array(try W.decodeDkgComplaints(a0)) }
        case "decodeDkgRebuttals": return wire(c) { .array(try W.decodeDkgRebuttals(a0)) }
        case "decodeDkgEcho": return wire(c) { try W.decodeDkgEcho(a0) }
        case "dkgInbox": return inboxRun(args, c)
        case "memoryNetwork": return netRun(args, c)
        case "runDkgOverChannel": return party(args, c)
        case "tlsFrameEncode": return .value(b(W.tlsFrameEncode(bytes(a0) ?? [])))
        case "tlsFrameDecode":
            let r = W.tlsFrameDecode(list(a0?.get("chunks")).map { bytes($0) ?? [] })
            return .value(.object(["accepted": .array(r.accepted.map(b)), "error": r.error.map { .string($0) } ?? .null, "buffered": .int(Int64(r.buffered))]))
        default: return .threw(nil)
        }
    }

    private static func a5(_ c: BaseCase, _ args: Args) -> JSONValue? { args.v(A.arg(c, 5)) }

    static let fns: [String: Int] = ["constants": 1, "dkgRound1": 56, "dkgVerifyRound1": 36, "dkgSignShare": 20, "dkgRound2": 5, "dkgVerifyShare": 3, "dkgFileComplaint": 2, "dkgVerifyComplaint": 3, "dkgResolveBlame": 1,
                                     "dkgQualifiedSet": 13, "dkgTranscriptDigest": 10, "dkgEcho": 4, "dkgCheckEchoes": 18, "dkgFinalize": 1, "frostDkgSimulate": 13, "encodeDkgMessage": 18, "decodeDkgMessage": 56,
                                     "decodeDkgRound1Package": 32, "decodeDkgShareMessage": 27, "decodeDkgComplaints": 25, "decodeDkgRebuttals": 9, "decodeDkgEcho": 13, "dkgInbox": 24, "memoryNetwork": 11,
                                     "tlsFrameEncode": 5, "tlsFrameDecode": 17, "runDkgOverChannel": 16]

    /// The committed corpus names a derived secret in an expected value by its seed label: the same derivation as in the arguments.
    static func withSeedsResolved(_ c: BaseCase) -> BaseCase {
        BaseCase(fn: c.fn, name: c.name, args: c.args, out: Base.resolveSeeds(c.out), suspect: c.suspect, raw: c.raw)
    }

    func testTheCommittedDkgCorpus() throws {
        var seen: [String: Int] = [:]
        let d = Base.Diffs()
        let n = try Base.each("ref-frost-dkg.json.gz", seeds: true) { c in
            seen[c.fn, default: 0] += 1
            var got = Self.call(c)
            if case let .value(v) = got { got = .value(Self.adopt(v, c.out)) }
            // a refusal of these is only a refusal: the text and the typed fields are informative
            d.add(c, Base.diff(Self.withSeedsResolved(c), got))
        }
        XCTAssertEqual(n, 439)
        XCTAssertEqual(seen, Self.fns)
        d.finish(n)
    }

    /// The cases that carry derived secrets (shares, signing shares, share wire bytes) are generated in CI by the reference and replayed here.
    func testTheGeneratedSecretCorpus() throws {
        guard let g = K042.secretCorpusPath("ref-frost-dkg.json.gz") else { return }
        let d = Base.Diffs()
        let n = try Base.each(g, seeds: true) { c in
            XCTAssertNotNil(Self.fns[c.fn], "a generated case of an fn the committed corpus does not know: \(c.fn)")
            var got = Self.call(c)
            if case let .value(v) = got { got = .value(Self.adopt(v, c.out)) }
            d.add(c, Base.diff(c, got))
        }
        XCTAssertEqual(n, 286)
        d.finish(n)
    }
}
