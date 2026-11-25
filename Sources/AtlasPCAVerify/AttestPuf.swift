import Foundation
#if canImport(FoundationNetworking)
import FoundationNetworking
#endif

/// A PUF device: an id and its response to a challenge (one 0/1 per byte).
public protocol PCAPufProvider {
    var id: String { get }
    func response(_ challenge: [UInt8]) throws -> [UInt8]
}

/// The PUF (physically unclonable function) attestation root: a repetition-code fuzzy extractor (code-offset secure sketch plus an HKDF-SHA256 extractor),
/// a simulated PUF for tests, a TPM endorsement-key PUF provider over an injectable tpm2-tools runner, enrollment (a device key derived from the extracted
/// secret: Ed25519 or ML-DSA), the device attestor, the enrollment registry and the verifier. A PUF response is one 0/1 value per byte. Enrollments,
/// helper data and statements are the language-neutral JSON of the wire.
public enum PCAAttestPuf {
    public static let PUF_EXTRACT_INFO = "atlas-pca/puf-extract/v1"
    public static let PUF_ATTEST_DOMAIN = "atlas-pca/attest-puf/v1\u{0}"
    public static let PUF_KEY_BYTES = 32
    public static let TPM_EK_PUF_DOMAIN = "atlas-pca/puf-tpm-ek/v1"

    private static func err(_ m: String) -> JSError { JSError(m) }
    private static func b64u(_ b: [UInt8]) -> String { Base64URLStrict.encode(b) }
    private static func hashStrict(_ v: JSONValue) throws -> String { Base64URLStrict.encode(Canonical.sha256(try Canonical.canonicalBytes(v))) }
    private static func isInt(_ v: JSONValue?) -> Double? { IV.num(v).flatMap { $0.isFinite && $0.rounded() == $0 ? $0 : nil } }

    /// The number of simple errors per block a repetition code of this length corrects: floor((rep - 1) / 2).
    public static func repetitionCorrectionBound(_ rep: Int) -> Int { Int((Double(rep - 1) / 2).rounded(.down)) }

    /// `repetitionCorrectionBound` over any number (the reference takes a JavaScript number: 1.5 corrects 0 bits, 3.9 corrects 1); NaN stays NaN.
    public static func repetitionCorrectionBound(number rep: Double) -> Double { ((rep - 1) / 2).rounded(.down) }

    // MARK: bit helpers

    private static func assertBits(_ b: [UInt8], _ whereFn: String) throws { if b.contains(where: { $0 > 1 }) { throw err("\(whereFn): response must be a 0/1 bit array") } }
    private static func xorBits(_ a: [UInt8], _ b: [UInt8]) -> [UInt8] { (0..<a.count).map { (a[$0] ^ b[$0]) & 1 } }
    private static func repEncode(_ m: [UInt8], _ rep: Int) -> [UInt8] { m.flatMap { [UInt8](repeating: $0 & 1, count: rep) } }
    private static func repDecode(_ code: [UInt8], _ rep: Int) -> [UInt8] {
        (0..<(code.count / rep)).map { i in
            let ones = (0..<rep).reduce(0) { $0 + Int(code[i * rep + $1] & 1) }
            return ones * 2 > rep ? 1 : 0 // strict majority; ties (even rep) resolve to 0: use an ODD rep
        }
    }
    private static func packBits(_ bits: [UInt8]) -> [UInt8] {
        var out = [UInt8](repeating: 0, count: (bits.count + 7) / 8)
        for i in 0..<bits.count where bits[i] & 1 != 0 { out[i >> 3] |= UInt8(1 << (i & 7)) }
        return out
    }
    private static func unpackBits(_ packed: [UInt8], _ n: Int) -> [UInt8] { (0..<n).map { (packed[$0 >> 3] >> UInt8($0 & 7)) & 1 } }
    private static func extractKey(_ bits: [UInt8], _ salt: [UInt8]) -> [UInt8] {
        PCAEntropy.hkdfSha256(ikm: packBits(bits), salt: salt, info: Array(PUF_EXTRACT_INFO.utf8), length: PUF_KEY_BYTES)
    }

    // MARK: the fuzzy extractor

    /// Enrolls a response: a random message is repetition-encoded and XORed with the response (the sketch); the key is HKDF(response, salt). `randomBytes`
    /// is asked for `messageBits` bytes (their low bits are the message) and then for 32 (the salt). Returns the 32-byte key and the helper data
    /// `{sketch, salt, rep, messageBits, n}`. Throws on an even or non-positive `rep`, a non-positive `messageBits`, a response of the wrong length or a
    /// value other than 0 or 1.
    public static func fuzzyEnroll(_ response: [UInt8], rep: Double, messageBits: Double, randomBytes: (Int) -> [UInt8]) throws -> (key: [UInt8], helper: JSONValue) {
        guard rep.isFinite, rep.rounded() == rep, rep >= 1, rep.truncatingRemainder(dividingBy: 2) != 0 else { throw err("fuzzyEnroll: rep must be an odd positive integer") }
        guard messageBits.isFinite, messageBits.rounded() == messageBits, messageBits >= 1 else { throw err("fuzzyEnroll: messageBits must be a positive integer") }
        let n = rep * messageBits
        guard Double(response.count) == n else { throw err("fuzzyEnroll: response length \(response.count) != rep*messageBits \(JS.number(n))") }
        try assertBits(response, "fuzzyEnroll")
        let r = Int(rep), mb = Int(messageBits)
        let mr = randomBytes(mb)
        let m = (0..<mb).map { $0 < mr.count ? mr[$0] & 1 : 0 }
        let sketch = xorBits(repEncode(m, r), response) // C xor W
        let salt = randomBytes(32)
        let key = extractKey(response, salt)
        let helper: JSONValue = .object(["sketch": .string(b64u(packBits(sketch))), "salt": .string(b64u(salt)), "rep": .int(Int64(r)), "messageBits": .int(Int64(mb)), "n": .int(Int64(r * mb))])
        return (key, helper)
    }

    /// Reproduces the key from a (noisy) response and the helper data: majority-decodes `response xor sketch`, re-encodes and recovers the enrolled
    /// response when at most `repetitionCorrectionBound(rep)` bits per block flipped. Throws on malformed helper data or a response of the wrong length.
    public static func fuzzyReproduce(_ response: [UInt8], _ helper: JSONValue?) throws -> [UInt8] {
        guard let h = helper, let rep = isInt(h.get("rep")), let mb = isInt(h.get("messageBits")), rep >= 1, rep.truncatingRemainder(dividingBy: 2) != 0 else {
            throw err("fuzzyReproduce: malformed helper params")
        }
        let n = rep * mb
        guard IV.num(h.get("n")) == n else { throw err("fuzzyReproduce: helper.n inconsistent with rep*messageBits") }
        guard Double(response.count) == n else { throw err("fuzzyReproduce: response length \(response.count) != \(JS.number(n))") }
        try assertBits(response, "fuzzyReproduce")
        guard case let .string(sk)? = h.get("sketch"), case let .string(sl)? = h.get("salt") else { throw err("fuzzyReproduce: helper data missing sketch or salt") }
        guard let packed = Base64URLStrict.decode(sk), let salt = Base64URLStrict.decode(sl) else { throw err("fuzzyReproduce: helper sketch or salt is not canonical base64url") }
        let nn = Int(n)
        guard packed.count == (nn + 7) / 8 else { throw err("fuzzyReproduce: helper sketch has the wrong length") }
        guard salt.count == 32 else { throw err("fuzzyReproduce: helper salt has the wrong length") }
        let r = Int(rep)
        let sketchBits = unpackBits(packed, nn)
        let mHat = repDecode(xorBits(response, sketchBits), r)
        let wRec = xorBits(repEncode(mHat, r), sketchBits)
        return extractKey(wRec, salt)
    }

    // MARK: PUF providers

    public typealias Provider = PCAPufProvider

    /// A deterministic simulated PUF: bit i of SHA-256(seed || challenge || u32be(block)) blocks; `flip` positions (those inside the response) are inverted
    /// to model noise.
    public struct SimulatedPuf: Provider {
        public let id: String
        let seed: [UInt8]
        let length: Int
        let flips: Set<Int>

        public func response(_ challenge: [UInt8]) throws -> [UInt8] {
            var stream: [UInt8] = []
            let blocks = ((length + 7) / 8 + 31) / 32
            for blk in 0..<blocks {
                let ctr = [UInt8(blk >> 24 & 0xff), UInt8(blk >> 16 & 0xff), UInt8(blk >> 8 & 0xff), UInt8(blk & 0xff)]
                stream += Canonical.sha256(seed + challenge + ctr)
            }
            var bits = (0..<length).map { (stream[$0 >> 3] >> UInt8($0 & 7)) & 1 }
            for p in flips where p >= 0 && p < bits.count { bits[p] ^= 1 }
            return bits
        }
    }

    public static func createSimulatedPuf(id: String, seed: [UInt8], length: Int, flip: [Int] = []) -> SimulatedPuf {
        SimulatedPuf(id: id, seed: seed, length: Swift.max(0, length), flips: Set(flip))
    }

    /// What a tpm2-tools invocation produced.
    public struct TpmCommandResult {
        public var status: Int?
        public var stdout: [UInt8]
        public var stderr: String?
        public var error: String?
        public init(status: Int?, stdout: [UInt8], stderr: String? = nil, error: String? = nil) { self.status = status; self.stdout = stdout; self.stderr = stderr; self.error = error }
    }

    public typealias TpmCommandRunner = (String, [String]) throws -> TpmCommandResult?

    /// Runs the command (resolved through `PATH`) with a 15 second timeout; a missing tool is a result with `error`, never a throw.
    public static func defaultTpmCommandRunner(_ command: String, _ args: [String]) -> TpmCommandResult? {
        #if os(macOS) || os(Linux)
        let p = Process()
        p.executableURL = URL(fileURLWithPath: "/usr/bin/env")
        p.arguments = [command] + args
        let out = Pipe(), errp = Pipe()
        p.standardOutput = out
        p.standardError = errp
        p.standardInput = FileHandle.nullDevice
        do { try p.run() } catch { return TpmCommandResult(status: nil, stdout: [], stderr: "\(error)", error: "\(command): spawn failed") }
        let deadline = Date().addingTimeInterval(15)
        while p.isRunning && Date() < deadline { Thread.sleep(forTimeInterval: 0.01) }
        if p.isRunning { p.terminate(); return TpmCommandResult(status: nil, stdout: [], stderr: nil, error: "\(command): ETIMEDOUT") }
        let o = [UInt8](out.fileHandleForReading.readDataToEndOfFile()), e = String(decoding: errp.fileHandleForReading.readDataToEndOfFile(), as: UTF8.self)
        return TpmCommandResult(status: Int(p.terminationStatus), stdout: o, stderr: e.isEmpty ? nil : e)
        #else
        return TpmCommandResult(status: nil, stdout: [], stderr: nil, error: "\(command): no process support on this platform")
        #endif
    }

    /// A PUF from the TPM's endorsement key: the response is HKDF(EK public, salt = domain, info = challenge) expanded to `length` bits. Every failure
    /// of the tool is a refusal (fail closed).
    public final class TpmEkProvider: Provider {
        public let id: String
        private let length: Int
        private let run: TpmCommandRunner
        private let tool: String
        private let args: [String]
        private let minEkBytes: Int

        public init(id: String, length: Int, run: TpmCommandRunner? = nil, tool: String? = nil, ekHandle: String? = nil, args: [String]? = nil, minEkBytes: Int? = nil) throws {
            if id.isEmpty { throw JSError("TpmEkPufProvider: id must be a non-empty string") }
            if length < 1 { throw JSError("TpmEkPufProvider: length must be a positive integer (= enrolled rep*messageBits)") }
            if let m = minEkBytes, m < 1 { throw JSError("TpmEkPufProvider: minEkBytes must be a positive integer") }
            self.id = id
            self.length = length
            self.run = run ?? { c, a in PCAAttestPuf.defaultTpmCommandRunner(c, a) }
            self.tool = (tool?.isEmpty == false) ? tool! : "tpm2_readpublic"
            let handle = (ekHandle?.isEmpty == false) ? ekHandle! : "0x81010001"
            self.args = args ?? ["-c", handle, "-f", "der", "-o", "/dev/stdout", "-Q"]
            self.minEkBytes = minEkBytes ?? 64
        }

        public func readEkPublic() throws -> [UInt8] {
            let res: TpmCommandResult?
            do { res = try run(tool, args) } catch {
                throw JSError("TpmEkPufProvider: tpm2-tools invocation threw (fail closed): \((error as? JSError)?.message ?? "\(error)")")
            }
            guard let r = res else { throw JSError("TpmEkPufProvider: command runner returned no result (fail closed)") }
            if let e = r.error, !e.isEmpty { throw JSError("TpmEkPufProvider: tpm2-tools unavailable (fail closed): \(e)") }
            if r.status != 0 {
                var m = "TpmEkPufProvider: '\(tool)' exited with status \(r.status.map { String($0) } ?? "null") (fail closed)"
                if let s = r.stderr, !s.isEmpty { m += ": " + Attest.jsTrim(s) }
                throw JSError(m)
            }
            if r.stdout.count < minEkBytes {
                throw JSError("TpmEkPufProvider: EK public too short (\(r.stdout.count) < \(minEkBytes) bytes) \u{2014} TPM unavailable or wrong handle (fail closed)")
            }
            return r.stdout
        }

        public func response(_ challenge: [UInt8]) throws -> [UInt8] {
            let ek = try readEkPublic()
            let secret = PCAEntropy.hkdfSha256(ikm: ek, salt: Array(TPM_EK_PUF_DOMAIN.utf8), info: challenge, length: 32)
            let blocks = Swift.max(1, ((length + 7) / 8 + 31) / 32)
            var stream: [UInt8] = []
            for blk in 0..<blocks { stream += Canonical.sha256(secret + [UInt8(blk >> 24 & 0xff), UInt8(blk >> 16 & 0xff), UInt8(blk >> 8 & 0xff), UInt8(blk & 0xff)]) }
            return (0..<length).map { (stream[$0 >> 3] >> UInt8($0 & 7)) & 1 }
        }
    }

    // MARK: the device key

    /// ML-DSA key derivation from the 32-byte seed (default: the platform's; pass a deterministic backend for byte-exact signatures).
    public typealias PqKeyFromSeed = (PCAMLDSALevel, [UInt8]) throws -> PCAPQKey

    private static func assertSuite(_ alg: JSONValue?) throws -> String {
        guard case let .string(a)? = alg, a == "ed25519" || a == "ml-dsa-65" || a == "ml-dsa-87" else {
            throw err("PUF root: unsupported derived suite '\(JS.toString(alg))' (use ed25519, ml-dsa-65 or ml-dsa-87)")
        }
        return a
    }

    private static func deviceKey(_ alg: String, _ seed: [UInt8], _ pq: PqKeyFromSeed?) throws -> (publicKey: String, key: PCASuiteKey) {
        if alg == "ed25519" {
            let ed = try Ed25519Deterministic.key(seed: seed)
            return (b64u(ed.pub), .ed25519(ed))
        }
        let k = try (pq ?? { try PCAPQKey.fromSeed($0, seed: $1) })(alg == "ml-dsa-87" ? .mlDsa87 : .mlDsa65, seed)
        return (k.pkB64u, try PCASuiteKey(alg: alg, ed: nil, pq: k))
    }

    // MARK: enrollment and attestation

    /// Enrolls a device: the challenge is answered, the fuzzy extractor yields the device key (the signing seed of `alg`, default ml-dsa-65) and the helper
    /// data. Returns `{providerId, challenge, alg, publicKey, helper, helperCommitment}`; the key itself is never returned.
    public static func enrollPuf(provider: Provider, challenge: [UInt8], rep: Double, messageBits: Double, alg: JSONValue? = nil, randomBytes: ((Int) -> [UInt8])? = nil,
                                 pqKey: PqKeyFromSeed? = nil) throws -> JSONValue {
        let a = try assertSuite(JS.present(alg) ?? .string("ml-dsa-65"))
        let rnd = randomBytes ?? { n in (0..<n).map { _ in UInt8.random(in: 0...255) } }
        let bits = try provider.response(challenge)
        let (key, helper) = try fuzzyEnroll(bits, rep: rep, messageBits: messageBits, randomBytes: rnd)
        let signer = try deviceKey(a, key, pqKey)
        return .object(["providerId": .string(provider.id), "challenge": .string(b64u(challenge)), "alg": .string(a), "publicKey": .string(signer.publicKey), "helper": helper,
                        "helperCommitment": .string(try hashStrict(helper))])
    }

    /// The device attestor: re-derives the device key from the (noisy) response and signs statements.
    public struct Attestor {
        let provider: Provider
        let enrollment: JSONValue
        let alg: String
        let challenge: [UInt8]
        let pqKey: PqKeyFromSeed?

        /// `{measurement, holder_pub, grant_ref, epoch, nonce}` plus the optional `weights_digest`: a statement `{provider_id, measurement, binding, alg,
        /// weights_digest?, sig, pq_sig?}` signed as canonical JSON under the domain, bound to holder, grant, epoch and nonce.
        public func attest(_ claims: JSONValue) throws -> JSONValue {
            let key = try fuzzyReproduce(try provider.response(challenge), enrollment.get("helper"))
            let signer = try deviceKey(alg, key, pqKey)
            let binding = try PCAAttestation.attestationBindingB64u(.object(["holderPub": claims.get("holder_pub") ?? .null, "grantRef": claims.get("grant_ref") ?? .null,
                                                                             "epoch": claims.get("epoch") ?? .null, "nonce": claims.get("nonce") ?? .null]))
            guard let measurement = claims.get("measurement") else { throw JSError("canonicalize: unsupported type undefined") }
            var body: JObject = ["provider_id": .string(provider.id), "measurement": measurement, "binding": .string(binding), "alg": .string(alg)]
            if let w = claims.get("weights_digest") { body["weights_digest"] = w }
            let parts = try signer.key.sign(try PCAIntentKit.message(PUF_ATTEST_DOMAIN, .object(body)))
            var out = body
            out["sig"] = .string(parts.sig)
            if let q = parts.pqSig { out["pq_sig"] = .string(q) }
            return .object(out)
        }
    }

    public static func createPufAttestor(provider: Provider, enrollment: JSONValue, pqKey: PqKeyFromSeed? = nil) throws -> Attestor {
        let alg = try assertSuite(enrollment.get("alg"))
        guard case let .string(c)? = enrollment.get("challenge"), let challenge = Base64URLStrict.decode(c) else { throw err("base64url: not canonical") }
        return Attestor(provider: provider, enrollment: enrollment, alg: alg, challenge: challenge, pqKey: pqKey)
    }

    // MARK: the enrollment registry

    /// Enrollments by provider id (a later one replaces an earlier one) with a revocation set; a revoked id is never resolved, and re-registering it does
    /// not un-revoke it.
    public final class EnrollmentRegistry {
        private var byId: [[UInt16]: JSONValue] = [:]
        private var revoked = Set<[UInt16]>()
        private let lock = NSLock()

        public init(_ enrollments: JSONValue? = nil) { if case let .array(a)? = enrollments { for e in a { register(e) } } }

        public func register(_ e: JSONValue?) {
            lock.lock(); defer { lock.unlock() }
            if let e = e, case let .string(id)? = e.get("providerId") { byId[Array(id.utf16)] = e }
        }

        public func lookup(_ id: String) -> JSONValue? {
            lock.lock(); defer { lock.unlock() }
            let k = Array(id.utf16)
            return revoked.contains(k) ? nil : byId[k]
        }

        public func revoke(_ id: String) { lock.lock(); revoked.insert(Array(id.utf16)); lock.unlock() }
        public func isRevoked(_ id: String) -> Bool { lock.lock(); defer { lock.unlock() }; return revoked.contains(Array(id.utf16)) }
    }

    // MARK: the verifier

    public struct Policy {
        /// The allowed measurements: NON-EMPTY (accept-all is not permitted).
        public var measurements: [String]
        public var weightsMeasurements: [String]?
        /// Builds the measured identity from the statement and its enrollment (default: `defaultIdentity`).
        public var deriveIdentity: ((JSONValue, JSONValue) -> JSONValue)?
        public init(measurements: [String], weightsMeasurements: [String]? = nil, deriveIdentity: ((JSONValue, JSONValue) -> JSONValue)? = nil) {
            self.measurements = measurements; self.weightsMeasurements = weightsMeasurements; self.deriveIdentity = deriveIdentity
        }
    }

    public struct VerifierOptions {
        public var resolveEnrollment: ((String, JSONValue, JSONValue) throws -> JSONValue?)?
        public var policy: Policy
        public var requirePq: Bool
        public var isRevoked: ((String) throws -> Bool)?
        public var resolveEvidence: ((JSONValue, JSONValue) throws -> JSONValue?)?
        public init(policy: Policy, resolveEnrollment: ((String, JSONValue, JSONValue) throws -> JSONValue?)? = nil, requirePq: Bool = false, isRevoked: ((String) throws -> Bool)? = nil,
                    resolveEvidence: ((JSONValue, JSONValue) throws -> JSONValue?)? = nil) {
            self.policy = policy; self.resolveEnrollment = resolveEnrollment; self.requirePq = requirePq; self.isRevoked = isRevoked; self.resolveEvidence = resolveEvidence
        }
    }

    /// The default identity of a verified statement: the measurement is the runtime measurement; the weights are never marked hardware-measured.
    public static func defaultIdentity(_ st: JSONValue, _ enr: JSONValue) -> JSONValue {
        .object(["model_id": .string(""), "weights_digest": .string(st.get("weights_digest")?.asString ?? ""), "weights_measured": .bool(false),
                 "runtime_measurement": st.get("measurement") ?? .null, "operator": .string("")])
    }

    /// The verifier, as a hardware verifier (software assurance, vendor `puf`).
    public final class Verifier: PCAAttestationHardwareVerifier, AssuranceLabeled {
        private let o: VerifierOptions
        public let assuranceLabel = AssuranceLabel(level: "software", vendor: "puf")
        init(_ o: VerifierOptions) { self.o = o }

        public func verify(document: JSONValue, ctx: JSONValue, nowMs: Double, expected: JSONValue) throws -> PCAAttestation.HardwareResult {
            func fail(_ r: String) -> PCAAttestation.HardwareResult { PCAAttestation.HardwareResult(ok: false, reason: r) }
            do {
                guard let resolveEvidence = o.resolveEvidence else { return fail("no PUF evidence resolver configured (fail closed)") }
                guard let st = try resolveEvidence(document, ctx), st.isObject, let pid = st.get("provider_id")?.asString, let alg = st.get("alg")?.asString else {
                    return fail("no PUF attestation statement for this action")
                }
                if let rev = o.isRevoked, try rev(pid) { return fail("PUF enrollment for provider '\(pid)' is revoked") }
                guard let enr = try o.resolveEnrollment?(pid, document, ctx), JS.truthy(enr) else { return fail("no PUF enrollment registered for provider '\(pid)'") }
                if let na = enr.get("notAfter"), !(nowMs.isFinite && nowMs < PCAAttestation.toNumber(na)) { return fail("PUF enrollment has expired") }
                guard let commit = enr.get("helperCommitment")?.asString, IV.same(commit, try PCAAttestPuf.hashStrict(enr.get("helper") ?? .null)) else {
                    return fail("PUF enrollment helper commitment mismatch (helper tampered)")
                }
                if !(enr.get("alg")?.asString.map { IV.same($0, alg) } ?? false) { return fail("PUF statement suite '\(alg)' does not match the enrolled suite '\(JS.toString(enr.get("alg")))'") }
                guard let suite = PQ.resolve(alg) else { return fail("PUF statement declares an unknown signature alg '\(alg)'") }
                if o.requirePq && !(suite.pq != nil || suite.slh != nil) { return fail("PQ required: PUF-derived suite '\(suite.alg.rawValue)' is classical") }

                var body = st.asObject ?? [:]
                body["sig"] = nil
                body["pq_sig"] = nil
                let msg = try PCAIntentKit.message(PUF_ATTEST_DOMAIN, .object(body))
                let pub = enr.get("publicKey")?.asString
                // the enrolled public key is the Ed25519 identity of an ed25519 statement and the pinned PQ key of an ML-DSA one
                let ok: Bool
                if case .string? = st.get("sig"), let p = pub {
                    ok = IV.verifyPinned(alg: .string(alg), identity: p, artifactPqPk: suite.needsPqPk ? .string(p) : nil, msg: msg, sig: st.get("sig"), pqSig: st.get("pq_sig"),
                                         pin: suite.needsPqPk ? p : nil) == .valid
                } else { ok = false }
                if !ok { return fail("PUF statement signature does not verify under the enrolled public key (wrong/cloned device or excessive noise)") }

                guard JS.truthy(expected) else { return fail("no expected attestation binding supplied") }
                let want: String
                do { want = try PCAAttestation.attestationBindingB64u(expected) } catch { return fail("binding not constructible: \((error as? JSError)?.message ?? "invalid")") }
                guard let b = st.get("binding")?.asString, IV.same(b, want) else { return fail("PUF statement binding mismatch (holder/grant/epoch/nonce)") }
                guard let m = st.get("measurement")?.asString, o.policy.measurements.contains(where: { IV.same($0, m) }) else { return fail("measurement not in policy allowlist") }
                if let w = o.policy.weightsMeasurements, !w.isEmpty {
                    guard let d = st.get("weights_digest")?.asString, w.contains(where: { IV.same($0, d) }) else { return fail("measured weights digest not in policy allowlist") }
                }
                let measured = (o.policy.deriveIdentity ?? PCAAttestPuf.defaultIdentity)(st, enr)
                return PCAAttestation.HardwareResult(ok: true, measured: measured, bound: true, hostAsserted: ["provider_id": pid, "suite": suite.alg.rawValue])
            } catch {
                return fail("puf verification error (fail closed): \((error as? JSError)?.message ?? "unknown")")
            }
        }
    }

    /// Builds the verifier. Throws on an empty measurement allowlist (accept-all is not permitted) and on a missing `resolveEnrollment`.
    public static func createPufVerifier(_ o: VerifierOptions) throws -> Verifier {
        if o.policy.measurements.isEmpty { throw JSError("createPufVerifier: policy.measurements must be a NON-EMPTY allowlist (accept-all is not permitted)") }
        if o.resolveEnrollment == nil { throw JSError("createPufVerifier: resolveEnrollment is required") }
        return Verifier(o)
    }
}
