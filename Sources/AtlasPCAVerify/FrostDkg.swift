import Foundation

/// Distributed key generation for FROST(Ed25519), Pedersen style with Feldman commitments: round 1 (commitments to the polynomial plus a proof of knowledge of the constant
/// term), round 2 (one signed share per peer, non-repudiable under the sender's first commitment), complaints, rebuttals, blame resolution, the qualified set, echo
/// agreement on the transcript, and finalize. A share a sender signed that fails the verifiable-secret-sharing check disqualifies the sender and nobody else: an
/// accuser cannot frame an honest party. The wire objects are the JSON of the protocol (base64url strings).
public enum PCAFrostDkg {
    public struct State {
        public let identifier: Int64
        public let t: Int64
        public let n: Int64
        public let sessionId: [UInt8]
        public let coefficients: [[UInt8]]
        public let package: JSONValue
    }
    public struct ShareToSend { public let from: Int64; public let to: Int64; public let sessionId: String; public let share: [UInt8]; public let sig: String }
    public struct ReceivedShare { public var from: Int64; public var sessionId: String; public var share: [UInt8]; public var sig: String? ; public init(from: Int64, sessionId: String, share: [UInt8], sig: String?) { self.from = from; self.sessionId = sessionId; self.share = share; self.sig = sig } }
    public struct KeyPackage {
        public let identifier: Int64
        public let signingShare: [UInt8]
        public let groupPublicKey: [UInt8]
        public let verifyingShare: [UInt8]
        public let groupCommitment: [[UInt8]]
        public let verifyingShares: [(identifier: Int64, publicKey: [UInt8])]
    }

    typealias F = PCAFrost
    private static let CTX = F.CTX
    private static func b64(_ b: [UInt8]) -> String { Base64URLStrict.encode(b) }
    private static func utf(_ s: String) -> [UInt8] { Array(s.utf8) }
    private static func posInt(_ v: JSONValue?) -> Int64? { IV.safe(v).flatMap { $0 == $0.rounded() && $0 > 0 && $0 <= 9_007_199_254_740_991 ? Int64($0) : nil } }
    private static func idScalar(_ id: Int64) -> [UInt8] { F.scalarOf(id: id) }
    private static func u32(_ n: Int) -> [UInt8] { [UInt8((n >> 24) & 255), UInt8((n >> 16) & 255), UInt8((n >> 8) & 255), UInt8(n & 255)] }
    private static func err(_ m: String) -> JSError { JSError(m) }
    private static func canonicalScalar(_ b: [UInt8]) throws -> [UInt8] {
        guard F.isCanonicalScalar(b) else { throw err("dkg: scalar must be 32 bytes and < the group order") }
        return try F.bytesToScalar(b)
    }
    private static func decode(_ s: JSONValue?) throws -> [UInt8] {
        guard case let .string(t)? = s, let b = Base64URLStrict.decode(t) else { throw err("base64url") }
        return b
    }
    private static func hashToScalar(_ m: [UInt8]) throws -> [UInt8] { try F.hashToScalar(m) }

    private struct CommitVec { let c0: [UInt8]; let bytes: [UInt8] }
    private static func commitVec(_ commitments: JSONValue?) throws -> CommitVec {
        guard case let .array(a)? = commitments, !a.isEmpty else { throw err("dkg: empty commitment vector") }
        let pts = try a.map { try F.decodeSafePoint(try decode($0)) }
        return CommitVec(c0: pts[0], bytes: u32(pts.count) + pts.flatMap { $0 })
    }

    private static func evalPoly(_ coeffs: [[UInt8]], _ x: Int64) -> [UInt8] {
        let xb = idScalar(x)
        var acc = [UInt8](repeating: 0, count: 32)
        for c in coeffs.reversed() { acc = F.sAdd(F.sMul(acc, xb), c) }
        return acc
    }

    private static func vssCheck(_ share: [UInt8], _ commitments: JSONValue?, _ atId: Int64) throws -> Bool {
        guard case let .array(cs)? = commitments, !cs.isEmpty else { return false }
        let lhs = F.mulBase(share)
        var rhs = F.identity
        let x = idScalar(atId)
        var xk = idScalar(1)
        for c in cs {
            rhs = try F.add(rhs, try F.mulPoint(try F.decodeSafePoint(try decode(c)), xk))
            xk = F.sMul(xk, x)
        }
        return lhs == rhs
    }

    private static func popChallenge(_ sid: [UInt8], _ id: Int64, _ cv: CommitVec, _ r: [UInt8]) throws -> [UInt8] {
        try hashToScalar(CTX + utf("dkg-pop") + sid + idScalar(id) + cv.bytes + r)
    }
    private static func shareChallenge(_ sid: [UInt8], _ from: Int64, _ to: Int64, _ share: [UInt8], _ cv: CommitVec, _ rs: [UInt8]) throws -> [UInt8] {
        try hashToScalar(CTX + utf("dkg-share") + sid + idScalar(from) + idScalar(to) + share + cv.bytes + rs)
    }
    private static func shareNonce(_ a0: [UInt8], _ sid: [UInt8], _ from: Int64, _ to: Int64, _ share: [UInt8], _ cv: CommitVec) throws -> [UInt8] {
        try hashToScalar(CTX + utf("dkg-share-nonce") + a0 + sid + idScalar(from) + idScalar(to) + share + cv.bytes)
    }
    private static func signShareScalar(_ a0: [UInt8], _ cv: CommitVec, _ sid: [UInt8], _ from: Int64, _ to: Int64, _ share: [UInt8]) throws -> String {
        let k = try shareNonce(a0, sid, from, to, share, cv)
        let rs = F.mulBase(k)
        let e = try shareChallenge(sid, from, to, share, cv, rs)
        return b64(rs + F.sAdd(k, F.sMul(a0, e)))
    }
    private static func verifyShareSig(_ sig: String, _ sid: [UInt8], _ from: Int64, _ to: Int64, _ share: [UInt8], _ cv: CommitVec) -> Bool {
        do {
            guard let raw = Base64URLStrict.decode(sig), raw.count == 64 else { return false }
            let rs = try F.decodeSafePoint(Array(raw[0..<32]))
            let s = try canonicalScalar(Array(raw[32..<64]))
            let e = try shareChallenge(sid, from, to, share, cv, rs)
            return F.mulBase(s) == (try F.add(rs, try F.mulPoint(cv.c0, e)))
        } catch { return false }
    }
    private static func verifyShareSigAgainstPackage(_ sig: JSONValue?, _ sid: [UInt8], _ from: Int64, _ to: Int64, _ share: [UInt8], _ pkg: JSONValue?) -> Bool {
        guard case let .string(s)? = sig, let cc = pkg?.get("coefficientCommitments"), case let .array(a) = cc, !a.isEmpty, let cv = try? commitVec(cc) else { return false }
        return verifyShareSig(s, sid, from, to, share, cv)
    }

    /// The signature a participant puts on a share for `to`: `b64url(R_s || s)` under its first commitment (any share bytes, not only a polynomial value).
    public static func dkgSignShare(_ state: State, to: Int64, share: [UInt8]) throws -> String {
        let a0 = try F.bytesToScalar(state.coefficients[0])
        return try signShareScalar(a0, try commitVec(state.package.get("coefficientCommitments")), state.sessionId, state.identifier, to, share)
    }

    /// Round 1: draws `t` coefficients (unless given) and one proof-of-knowledge nonce (unless given) from `random`.
    public static func dkgRound1(identifier: Int64, t: Int64, n: Int64, sessionId: [UInt8], coefficients: [[UInt8]]? = nil, popNonce: [UInt8]? = nil,
                                 random: PCAFrostNet.RandomBytes = PCAFrostNet.systemRandom) throws -> (package: JSONValue, state: State) {
        if identifier <= 0 { throw err("dkgRound1: identifier must be a positive integer") }
        if t < 1 || n < t { throw err("dkgRound1: need 1 <= t <= n (got t=\(t), n=\(n))") }
        if sessionId.isEmpty { throw err("dkgRound1: sessionId must be a non-empty byte string") }
        var coeffs: [[UInt8]] = []
        if let given = coefficients {
            if Int64(given.count) != t { throw err("dkgRound1: coefficients.length must equal t (\(t))") }
            coeffs = try given.map { try F.bytesToScalar($0) }
        } else {
            for _ in 0..<t { coeffs.append(try F.bytesToScalar(try random())) }
        }
        let commitments = coeffs.map { F.mulBase($0) }
        let commitStrings: [JSONValue] = commitments.map { .string(b64($0)) }
        let cv = try commitVec(.array(commitStrings))
        let k = try popNonce.map { try F.bytesToScalar($0) } ?? (try F.bytesToScalar(try random()))
        let r = F.mulBase(k)
        let c = try popChallenge(sessionId, identifier, cv, r)
        let mu = F.sAdd(k, F.sMul(coeffs[0], c))
        let pkg: JSONValue = .object(["identifier": .int(identifier), "sessionId": .string(b64(sessionId)), "coefficientCommitments": .array(commitStrings),
                                      "proofOfKnowledge": .object(["R": .string(b64(r)), "mu": .string(b64(mu))])])
        return (pkg, State(identifier: identifier, t: t, n: n, sessionId: sessionId, coefficients: coeffs, package: pkg))
    }

    /// Whether a round-1 package is for this session and its proof of knowledge of the constant term verifies. Never throws.
    public static func dkgVerifyRound1(_ fromIdentifier: Int64, _ pkg: JSONValue?, _ sessionId: [UInt8]) -> Bool {
        guard pkg?.isObject == true, IV.same(pkg?.get("sessionId")?.asString, b64(sessionId)), fromIdentifier >= 0 else { return false }
        do {
            let cv = try commitVec(pkg?.get("coefficientCommitments"))
            let r = try F.decodeSafePoint(try decode(pkg?.get("proofOfKnowledge")?.get("R")))
            let mu = try canonicalScalar(try decode(pkg?.get("proofOfKnowledge")?.get("mu")))
            let c = try popChallenge(sessionId, fromIdentifier, cv, r)
            return F.mulBase(mu) == (try F.add(r, try F.mulPoint(cv.c0, c)))
        } catch { return false }
    }

    private static func ids(of packages: JSONValue?) throws -> [Int64] {
        guard case let .array(a)? = packages else { throw err("round-1 packages must be a list") }
        return try a.map { p in guard let i = posIdOrAny(p.get("identifier")) else { throw err("bad identifier") }; return i }
    }
    static func posIdOrAny(_ v: JSONValue?) -> Int64? { IV.safe(v).flatMap { $0 == $0.rounded() ? Int64($0) : nil } }

    /// Round 2: the signed share for every other participant, in package order.
    public static func dkgRound2(_ state: State, _ packages: JSONValue?) throws -> [ShareToSend] {
        let idl = try ids(of: packages)
        if Set(idl).count != idl.count { throw err("dkgRound2: duplicate identifiers in round-1 packages") }
        if !idl.contains(state.identifier) { throw err("dkgRound2: my own round-1 package is missing") }
        let sid = b64(state.sessionId)
        for p in packages?.asArray ?? [] where !IV.same(p.get("sessionId")?.asString, sid) {
            throw err("dkgRound2: participant \(JS.toString(p.get("identifier"))) round-1 package is from a different session")
        }
        let a0 = try F.bytesToScalar(state.coefficients[0])
        let cv = try commitVec(state.package.get("coefficientCommitments"))
        var out: [ShareToSend] = []
        for j in idl where j != state.identifier {
            let share = evalPoly(try state.coefficients.map { try F.bytesToScalar($0) }, j)
            out.append(ShareToSend(from: state.identifier, to: j, sessionId: sid, share: share, sig: try signShareScalar(a0, cv, state.sessionId, state.identifier, j, share)))
        }
        return out
    }

    /// Whether a received share is signed by the sender for this recipient and consistent with the sender's commitments. Never throws.
    public static func dkgVerifyShare(from: Int64, share: [UInt8]?, sig: JSONValue?, senderPackage: JSONValue?, myIdentifier: Int64, sessionId: [UInt8]) -> Bool {
        guard let share = share, let sender = posIdOrAny(senderPackage?.get("identifier")) else { return false }
        if !dkgVerifyRound1(sender, senderPackage, sessionId) { return false }
        if !verifyShareSigAgainstPackage(sig, sessionId, from, myIdentifier, share, senderPackage) { return false }
        guard let s = try? canonicalScalar(share) else { return false }
        return (try? vssCheck(s, senderPackage?.get("coefficientCommitments"), myIdentifier)) ?? false
    }

    public static func dkgFileComplaint(accused: Int64, accuser: Int64, receivedShare: [UInt8], shareSig: JSONValue?, sessionId: [UInt8]) throws -> JSONValue {
        if accused <= 0 { throw err("dkgFileComplaint: accused must be a positive integer") }
        if accuser <= 0 { throw err("dkgFileComplaint: accuser must be a positive integer") }
        if accused == accuser { throw err("dkgFileComplaint: cannot file a complaint against yourself") }
        guard case let .string(sig)? = shareSig, !sig.isEmpty else { throw err("dkgFileComplaint: shareSig (the accused-signed share) is required") }
        if sessionId.isEmpty { throw err("dkgFileComplaint: sessionId must be a non-empty byte string") }
        return .object(["accused": .int(accused), "accuser": .int(accuser), "sessionId": .string(b64(sessionId)), "revealedShare": .string(b64(try F.bytesToScalar(receivedShare))), "shareSig": .string(sig)])
    }

    private static func package(for id: JSONValue?, in packages: JSONValue?) throws -> JSONValue? {
        guard case let .array(a)? = packages else { throw err("packages") }
        for p in a {
            if p == .null { throw err("null package") }
            if let pid = p.get("identifier"), IV.num(pid) != nil, IV.num(pid) == IV.num(id), pid.isNumber, id?.isNumber == true { return p }
        }
        return nil
    }

    public static func dkgVerifyComplaint(_ complaint: JSONValue?, _ packages: JSONValue?) -> JSONValue {
        func verdict(_ justified: Bool, _ reason: String, disqualify: JSONValue? = nil, atFault: JSONValue? = nil) -> JSONValue {
            PCAFrostNet.present([("justified", .bool(justified)), ("disqualify", disqualify), ("atFault", atFault), ("reason", .string(reason))])
        }
        do {
            guard complaint?.isObject == true else { throw err("malformed") }
            guard let pkg = try package(for: complaint?.get("accused"), in: packages) else { return verdict(false, "accused \(JS.toString(complaint?.get("accused"))) has no round-1 package to adjudicate against") }
            if !IV.same(pkg.get("sessionId")?.asString, complaint?.get("sessionId")?.asString) { return verdict(false, "complaint sessionId does not match the accused round-1 package session") }
            let sid = try decode(complaint?.get("sessionId")), share = try decode(complaint?.get("revealedShare"))
            guard let accused = posIdOrAny(complaint?.get("accused")), let accuser = posIdOrAny(complaint?.get("accuser")) else { throw err("ids") }
            if !verifyShareSigAgainstPackage(complaint?.get("shareSig"), sid, accused, accuser, share, pkg) {
                return verdict(false, "revealed share is not validly signed by the accused \u{2014} inadmissible (cannot frame an honest party)", atFault: complaint?.get("accuser"))
            }
            if try vssCheck(try canonicalScalar(share), pkg.get("coefficientCommitments"), accuser) {
                return verdict(false, "accused-signed share is VALID against the accused commitments \u{2014} false accusation", atFault: complaint?.get("accuser"))
            }
            return verdict(true, "accused non-repudiably signed a share that FAILS VSS against its broadcast commitments", disqualify: complaint?.get("accused"))
        } catch { return verdict(false, "malformed complaint") }
    }

    public static func dkgRebut(accused: Int64, complaint: JSONValue?, state: State) throws -> JSONValue {
        if state.identifier != accused { throw err("dkgRebut: myRound2State is not the accused") }
        if posIdOrAny(complaint?.get("accused")) != accused { throw err("dkgRebut: complaint does not name this accused") }
        if !IV.same(complaint?.get("sessionId")?.asString, b64(state.sessionId)) { throw err("dkgRebut: complaint is scoped to a different session than my state") }
        guard let accuser = posIdOrAny(complaint?.get("accuser")) else { throw err("dkgRebut: bad accuser") }
        let share = evalPoly(try state.coefficients.map { try F.bytesToScalar($0) }, accuser)
        let sig = try dkgSignShare(state, to: accuser, share: share)
        return .object(["accused": .int(accused), "accuser": .int(accuser), "sessionId": complaint?.get("sessionId") ?? .null, "presentedShare": .string(b64(share)), "shareSig": .string(sig)])
    }

    public static func dkgResolveBlame(_ complaint: JSONValue?, _ rebuttal: JSONValue?, _ packages: JSONValue?) -> JSONValue {
        func res(_ guilty: JSONValue?, _ reason: String) -> JSONValue { PCAFrostNet.present([("guilty", guilty), ("reason", .string(reason))]) }
        do {
            guard complaint?.isObject == true else { throw err("malformed") }
            guard let pkg = try package(for: complaint?.get("accused"), in: packages) else { return res(complaint?.get("accused"), "accused \(JS.toString(complaint?.get("accused"))) has no round-1 package to defend with") }
            if !IV.same(pkg.get("sessionId")?.asString, complaint?.get("sessionId")?.asString) { return res(complaint?.get("accuser"), "complaint names a session the accused did not run \u{2014} inadmissible") }
            let sid = try decode(complaint?.get("sessionId")), share = try decode(complaint?.get("revealedShare"))
            guard let accused = posIdOrAny(complaint?.get("accused")), let accuser = posIdOrAny(complaint?.get("accuser")) else { throw err("ids") }
            if verifyShareSigAgainstPackage(complaint?.get("shareSig"), sid, accused, accuser, share, pkg) {
                if !(try vssCheck(try canonicalScalar(share), pkg.get("coefficientCommitments"), accuser)) { return res(complaint?.get("accused"), "accused non-repudiably signed a share that fails VSS") }
                return res(complaint?.get("accuser"), "accused-signed share is valid against its commitments \u{2014} false accusation")
            }
            if let r = rebuttal, r.isObject, IV.num(r.get("accused")) == IV.num(complaint?.get("accused")), IV.num(r.get("accuser")) == IV.num(complaint?.get("accuser")),
               IV.same(r.get("sessionId")?.asString, complaint?.get("sessionId")?.asString) {
                let rShare = try decode(r.get("presentedShare"))
                let valid = try verifyShareSigAgainstPackage(r.get("shareSig"), sid, accused, accuser, rShare, pkg) && (try vssCheck(try canonicalScalar(rShare), pkg.get("coefficientCommitments"), accuser))
                if valid { return res(complaint?.get("accuser"), "accused produced a validly-signed, VSS-correct share for the recipient \u{2014} the non-receipt/fabrication complaint is refuted") }
                return res(complaint?.get("accused"), "accused could not present a validly-signed, VSS-correct share on rebuttal")
            }
            return res(complaint?.get("accuser"), "complaint carries no accused-signed share and the accused offered no rebuttal \u{2014} inadmissible, cannot frame the accused")
        } catch { return res(complaint?.get("accuser"), "malformed complaint \u{2014} inadmissible") }
    }

    /// The participants that sent a valid round-1 package for the session most packages are for and are not found guilty by any complaint, ascending.
    public static func dkgQualifiedSet(_ participants: [Int64], _ complaints: [JSONValue], _ packages: [JSONValue], _ rebuttals: [JSONValue] = []) throws -> [Int64] {
        var byId: [Int64: JSONValue] = [:]
        for p in packages {
            guard p != .null, let i = posIdOrAny(p.get("identifier")) else { if p == .null { throw err("null package") }; continue }
            byId[i] = p
        }
        var counts: [(String, Int)] = []
        for p in packages {
            let s = p.get("sessionId").map { JS.toString($0) } ?? "undefined"
            if let i = counts.firstIndex(where: { $0.0 == s }) { counts[i].1 += 1 } else { counts.append((s, 1)) }
        }
        var run = "", best = -1
        for (s, c) in counts where c > best { best = c; run = s }
        var qualified = Set<Int64>()
        for p in participants {
            guard let pkg = byId[p], IV.same(pkg.get("sessionId")?.asString, run), let sid = try? decode(pkg.get("sessionId")) else { continue }
            if dkgVerifyRound1(p, pkg, sid) { qualified.insert(p) }
        }
        for c in complaints {
            let reb = rebuttals.first { r in IV.num(r.get("accused")) == IV.num(c.get("accused")) && IV.num(r.get("accuser")) == IV.num(c.get("accuser")) && IV.same(r.get("sessionId")?.asString, c.get("sessionId")?.asString) }
            let res = dkgResolveBlame(c, reb, .array(packages))
            if let g = posIdOrAny(res.get("guilty")), g == posIdOrAny(c.get("accused")) { qualified.remove(g) }
        }
        return qualified.sorted()
    }

    // ---- transcript and echo agreement ----

    private static func hashCanonical(_ v: JSONValue) throws -> String { b64(Canonical.sha256(try PCAFrostNet.canonicalLenient(v))) }
    private static func round1Digest(_ p: JSONValue) throws -> String {
        try hashCanonical(PCAFrostNet.present([("identifier", p.get("identifier")), ("sessionId", p.get("sessionId")), ("coefficientCommitments", p.get("coefficientCommitments")),
                                               ("proofOfKnowledge", PCAFrostNet.present([("R", p.get("proofOfKnowledge")?.get("R")), ("mu", p.get("proofOfKnowledge")?.get("mu"))]))]))
    }
    private static func complaintDigest(_ c: JSONValue) throws -> String {
        try hashCanonical(PCAFrostNet.present(["accused", "accuser", "sessionId", "revealedShare", "shareSig"].map { ($0, c.get($0)) }))
    }

    public static func dkgTranscriptDigest(round1Packages: [JSONValue], complaints: [JSONValue], qualified: [Int64], sessionId: [UInt8]) throws -> String {
        let r1 = try round1Packages.map(round1Digest).sorted { Array($0.utf16).lexicographicallyPrecedes(Array($1.utf16)) }
        let cs = try complaints.map(complaintDigest).sorted { Array($0.utf16).lexicographicallyPrecedes(Array($1.utf16)) }
        return try hashCanonical(.object(["sessionId": .string(b64(sessionId)), "round1": .array(r1.map { .string($0) }), "complaints": .array(cs.map { .string($0) }), "qualified": .array(qualified.sorted().map { .int($0) })]))
    }

    public static func dkgEcho(identifier: Int64, round1Packages: [JSONValue], complaints: [JSONValue], qualified: [Int64], sessionId: [UInt8]) throws -> JSONValue {
        .object(["identifier": .int(identifier), "sessionId": .string(b64(sessionId)),
                 "transcriptDigest": .string(try dkgTranscriptDigest(round1Packages: round1Packages, complaints: complaints, qualified: qualified, sessionId: sessionId))])
    }

    /// `{agreed, digest?, reason?}`: every qualified participant echoed once, for this session, the same transcript digest.
    public static func dkgCheckEchoes(_ qualified: [Int64], _ echoes: JSONValue?, _ sessionId: [UInt8]) -> JSONValue {
        func no(_ r: String) -> JSONValue { .object(["agreed": .bool(false), "reason": .string(r)]) }
        guard case let .array(list)? = echoes else { return no("malformed echoes") }
        let sid = b64(sessionId)
        let qSet = Set(qualified)
        var byId: [Int64: JSONValue] = [:]
        for e in list {
            guard e != .null else { return no("malformed echoes") }
            guard let id = posIdOrAny(e.get("identifier")), qSet.contains(id) else { continue }
            if !IV.same(e.get("sessionId")?.asString, sid) { return no("echo from \(id) is bound to a different session") }
            if byId[id] != nil { return no("duplicate echo from qualified participant \(id)") }
            byId[id] = e
        }
        var agreed: JSONValue? = nil
        var order: [Int64] = []
        for q in qualified where !order.contains(q) { order.append(q) }
        for j in order {
            guard let e = byId[j] else { return no("missing echo from qualified participant \(j)") }
            if agreed == nil { agreed = e.get("transcriptDigest") ?? .null }
            else if e.get("transcriptDigest") != agreed { return no("qualified participant \(j) echoed a DIFFERENT transcript (equivocation detected)") }
        }
        guard let d = agreed else { return no("no qualified echoes to agree on") }
        return .object(["agreed": .bool(true), "digest": d])
    }

    /// The signing share and group key of one participant: sums the received shares of the qualified set and the participant's own polynomial value, checks it against
    /// the group commitment, and (when an agreement is given) requires the echo digest to match its own view of the transcript.
    public static func dkgFinalize(myIdentifier: Int64, state: State, receivedShares: [ReceivedShare], allCommitments: [JSONValue], qualified: [Int64]? = nil,
                                   agreementEchoes: JSONValue? = nil, agreementComplaints: [JSONValue] = []) throws -> KeyPackage {
        if state.identifier != myIdentifier { throw err("dkgFinalize: myState.identifier != myIdentifier") }
        let idl = try ids(of: .array(allCommitments))
        if Set(idl).count != idl.count { throw err("dkgFinalize: duplicate identifiers in commitments") }
        if !idl.contains(myIdentifier) { throw err("dkgFinalize: my own package is missing from allCommitments") }
        let sid = b64(state.sessionId)
        for p in allCommitments where !IV.same(p.get("sessionId")?.asString, sid) { throw err("dkgFinalize: participant \(JS.toString(p.get("identifier"))) round-1 package is from a different session") }
        let qset = (qualified ?? idl).filter { idl.contains($0) }
        let qSet = Set(qset)
        if !qSet.contains(myIdentifier) { throw err("dkgFinalize: myIdentifier is not in the qualified set") }
        if Int64(qSet.count) < state.t { throw err("dkgFinalize: qualified set (\(qSet.count)) is smaller than the threshold t=\(state.t)") }
        let t = Int(state.t)
        for p in allCommitments {
            guard let i = posIdOrAny(p.get("identifier")), qSet.contains(i) else { continue }
            let n = p.get("coefficientCommitments")?.asArray?.count
            if n != t { throw err("dkgFinalize: participant \(i) committed to \(n.map(String.init) ?? "undefined") coefficients, expected t=\(t)") }
        }
        if let echoes = agreementEchoes {
            let qs = qSet.sorted()
            let check = dkgCheckEchoes(qs, echoes, state.sessionId)
            if check.get("agreed") != .bool(true) { throw err("dkgFinalize: echo-broadcast agreement failed \u{2014} \(check.get("reason")?.asString ?? "")") }
            let mine = try dkgTranscriptDigest(round1Packages: allCommitments, complaints: agreementComplaints, qualified: qs, sessionId: state.sessionId)
            if !IV.same(check.get("digest")?.asString, mine) {
                throw err("dkgFinalize: echo-broadcast agreement failed \u{2014} my transcript view diverges from the agreed echo digest (equivocation)")
            }
        }
        var recv: [Int64: [UInt8]] = [:]
        var order: [Int64] = []
        for r in receivedShares {
            if r.from == myIdentifier || !qSet.contains(r.from) { continue }
            if r.sessionId != sid { throw err("dkgFinalize: received share from \(r.from) is from a different session") }
            if recv[r.from] != nil { throw err("dkgFinalize: duplicate received share from \(r.from)") }
            recv[r.from] = r.share; order.append(r.from)
        }
        for j in qset where j != myIdentifier && recv[j] == nil { throw err("dkgFinalize: missing received share from qualified participant \(j)") }
        var signing = evalPoly(try state.coefficients.map { try F.bytesToScalar($0) }, myIdentifier)
        for from in order { signing = F.sAdd(signing, try F.bytesToScalar(recv[from]!)) }
        var coeffPoints: [[UInt8]] = []
        for k in 0..<t {
            var acc = F.identity
            for p in allCommitments {
                guard let i = posIdOrAny(p.get("identifier")), qSet.contains(i) else { continue }
                acc = try F.add(acc, try F.decodeSafePoint(try decode(p.get("coefficientCommitments")?.asArray?[k])))
            }
            coeffPoints.append(acc)
        }
        var vshares: [(identifier: Int64, publicKey: [UInt8])] = []
        for j in qset {
            var acc = F.identity
            let x = idScalar(j)
            var xk = idScalar(1)
            for phi in coeffPoints { acc = try F.add(acc, try F.mulPoint(phi, xk)); xk = F.sMul(xk, x) }
            vshares.append((j, acc))
        }
        let vs = F.mulBase(signing)
        guard let mine = vshares.first(where: { $0.identifier == myIdentifier }), vs == (try F.decodeSafePoint(mine.publicKey)) else {
            throw err("dkgFinalize: signing share is inconsistent with the group verifying share (bad dealer share)")
        }
        return KeyPackage(identifier: myIdentifier, signingShare: signing, groupPublicKey: coeffPoints[0], verifyingShare: vs, groupCommitment: coeffPoints, verifyingShares: vshares)
    }
}

extension PCAFrostDkg {
    public struct Simulation {
        public let groupPublicKey: [UInt8]
        public let participantShares: [(identifier: Int64, share: [UInt8], publicKey: [UInt8])]
        public let groupCommitment: [[UInt8]]
        public let keyPackages: [KeyPackage]
        public let round1Packages: [JSONValue]
        public let qualified: [Int64]
        public let complaints: [JSONValue]
        public let rebuttals: [JSONValue]
        public let echoes: [JSONValue]
        public let sessionId: [UInt8]
    }

    /// The whole ceremony in one process: every participant's round 1, every share checked and complained about when it fails, the blame round, the qualified set, the echo
    /// agreement and every qualified participant's finalize. `cheaters` send a share that fails the commitments (signed, so non-repudiable); `equivocateEchoFor` echoes a
    /// different transcript, which aborts. Draws the session id (unless given) and then each participant's coefficients and proof nonce from `random`.
    public static func frostDkgSimulate(t: Int64, n: Int64, identifiers: [Int64]? = nil, coefficientsByParticipant: [[[UInt8]]?]? = nil, sessionId: [UInt8]? = nil, cheaters: [Int64] = [],
                                        equivocateEchoFor: Int64? = nil, random: PCAFrostNet.RandomBytes = PCAFrostNet.systemRandom) throws -> Simulation {
        func e(_ m: String) -> JSError { JSError(m) }
        if t < 1 || n < t { throw e("frostDkgSimulate: need 1 <= t <= n (got t=\(t), n=\(n))") }
        let ids = identifiers ?? (1...Int64(n)).map { $0 }
        if Int64(ids.count) != n { throw e("frostDkgSimulate: identifiers.length must equal n") }
        if Set(ids).count != Int(n) { throw e("frostDkgSimulate: identifiers must be distinct") }
        if ids.contains(where: { $0 <= 0 }) { throw e("frostDkgSimulate: identifiers must be positive integers") }
        let sid = try sessionId ?? random()
        let cheat = Set(cheaters)
        var states: [State] = []
        for (idx, id) in ids.enumerated() {
            let given = (coefficientsByParticipant.flatMap { idx < $0.count ? $0[idx] : nil })
            states.append(try dkgRound1(identifier: id, t: t, n: n, sessionId: sid, coefficients: given, random: random).state)
        }
        let round1 = states.map { $0.package }
        for p in round1 where !dkgVerifyRound1(posIdOrAny(p.get("identifier")) ?? 0, p, sid) { throw e("frostDkgSimulate: PoP verification failed for participant \(JS.toString(p.get("identifier")))") }
        var inbox: [Int64: [ReceivedShare]] = Dictionary(uniqueKeysWithValues: ids.map { ($0, []) })
        var complaints: [JSONValue] = []
        let stateById = Dictionary(uniqueKeysWithValues: states.map { ($0.identifier, $0) })
        for st in states {
            for out in try dkgRound2(st, .array(round1)) {
                var share = out.share, sig = out.sig
                if cheat.contains(out.from) {
                    share[0] ^= 1
                    sig = try dkgSignShare(st, to: out.to, share: share)
                }
                let senderPkg = round1.first { posIdOrAny($0.get("identifier")) == out.from }!
                if dkgVerifyShare(from: out.from, share: share, sig: .string(sig), senderPackage: senderPkg, myIdentifier: out.to, sessionId: sid) {
                    inbox[out.to]!.append(ReceivedShare(from: out.from, sessionId: out.sessionId, share: share, sig: sig))
                } else {
                    complaints.append(try dkgFileComplaint(accused: out.from, accuser: out.to, receivedShare: share, shareSig: .string(sig), sessionId: sid))
                }
            }
        }
        let rebuttals = try complaints.map { c in try dkgRebut(accused: posIdOrAny(c.get("accused")) ?? 0, complaint: c, state: stateById[posIdOrAny(c.get("accused")) ?? 0]!) }
        let qualified = try dkgQualifiedSet(ids, complaints, round1, rebuttals)
        if Int64(qualified.count) < t { throw e("frostDkgSimulate: only \(qualified.count) qualified participants (< t=\(t)) after the blame round") }
        let echoes: [JSONValue] = try qualified.map { id in
            let view = id == equivocateEchoFor ? qualified.filter { $0 != qualified.last! } : qualified
            return try dkgEcho(identifier: id, round1Packages: round1, complaints: complaints, qualified: view, sessionId: sid)
        }
        var keyPackages: [KeyPackage] = []
        for st in states where qualified.contains(st.identifier) {
            keyPackages.append(try dkgFinalize(myIdentifier: st.identifier, state: st, receivedShares: inbox[st.identifier]!, allCommitments: round1, qualified: qualified,
                                               agreementEchoes: .array(echoes), agreementComplaints: complaints))
        }
        let gpk = keyPackages[0].groupPublicKey
        for kp in keyPackages where kp.groupPublicKey != gpk { throw e("frostDkgSimulate: participants disagree on the group public key") }
        return Simulation(groupPublicKey: gpk, participantShares: keyPackages.map { ($0.identifier, $0.signingShare, $0.verifyingShare) }, groupCommitment: keyPackages[0].groupCommitment,
                          keyPackages: keyPackages, round1Packages: round1, qualified: qualified, complaints: complaints, rebuttals: rebuttals, echoes: echoes, sessionId: sid)
    }
}
