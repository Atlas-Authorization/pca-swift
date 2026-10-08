import XCTest
import Foundation
@testable import AtlasPCAVerify

/// Runs the SHARED PCA conformance corpus (packages/pca/conformance/vectors.json) against the native Swift
/// verifier. The file is loaded by a path relative to this source file (never copied). Every vector's `allow`
/// and every listed `check` must match; the primitive tables (canonical JSON, strict JSON parse, strict
/// base64url, Merkle, threshold shares) are asserted too.
final class ConformanceTests: XCTestCase {
    /// packages/pca/conformance/ resolved relative to this source file.
    static let conformanceDir: URL = {
        URL(fileURLWithPath: #filePath)
            .deletingLastPathComponent()           // .../AtlasPCAVerifyTests
            .deletingLastPathComponent()           // .../Tests
            .deletingLastPathComponent()           // repo root (mirror: <root>/Tests/AtlasPCAVerifyTests/ConformanceTests.swift)
            .appendingPathComponent("conformance", isDirectory: true)
    }()

    // ---- lone-surrogate sanitation (Swift Strings cannot hold a lone surrogate) ----

    static let SENTINEL = Canonical.LONE_SURROGATE_SENTINEL

    /// Replace each LONE surrogate `\uXXXX` escape (at the vectors.json level) with the sentinel scalar, so
    /// `JSONSerialization` can load the file; object-form vectors carrying the sentinel are treated as a
    /// `wire` failure. Valid surrogate PAIRS (astral chars) and escaped backslashes are left untouched.
    static func sanitizeLoneSurrogates(_ text: String) -> String {
        let cs = Array(text.unicodeScalars)
        func hex(_ at: Int) -> UInt32? {
            guard at + 4 <= cs.count else { return nil }
            var v: UInt32 = 0
            for k in 0..<4 {
                let c = cs[at + k].value
                let d: UInt32
                switch c {
                case 48...57: d = c - 48
                case 97...102: d = c - 87
                case 65...70: d = c - 55
                default: return nil
                }
                v = (v << 4) | d
            }
            return v
        }
        var out = String.UnicodeScalarView()
        var i = 0
        var inStr = false
        let bs = Unicode.Scalar(0x5c)!, q = Unicode.Scalar(0x22)!, u = Unicode.Scalar(0x75)!
        while i < cs.count {
            let c = cs[i]
            if !inStr {
                inStr = (c == q)
                out.append(c); i += 1
            } else if c == q {
                inStr = false; out.append(c); i += 1
            } else if c == bs {
                if i + 1 < cs.count, cs[i + 1] == u, let hi = hex(i + 2) {
                    if (0xD800...0xDBFF).contains(hi) {
                        let paired = i + 7 < cs.count && cs[i + 6] == bs && cs[i + 7] == u
                            && (hex(i + 8).map { (0xDC00...0xDFFF).contains($0) } ?? false)
                        if paired { out.append(contentsOf: cs[i..<(i + 12)]); i += 12 }
                        else { out.append(SENTINEL); i += 6 }
                    } else if (0xDC00...0xDFFF).contains(hi) {
                        out.append(SENTINEL); i += 6
                    } else {
                        out.append(contentsOf: cs[i..<min(i + 2, cs.count)]); i += 2
                    }
                } else {
                    out.append(contentsOf: cs[i..<min(i + 2, cs.count)]); i += 2
                }
            } else {
                out.append(c); i += 1
            }
        }
        return String(out)
    }

    /// Load JSON with the lenient parser (byte-exact strings, lexeme int/double) after substituting lone
    /// surrogates — never `JSONSerialization`, which strips a leading U+FEFF from string values (corrupting
    /// the BOM vector's raw `pcactn_json`) and loses int-vs-double classification.
    static func loadText(_ text: String) throws -> JSONValue {
        try StrictJSON.parseLenient(sanitizeLoneSurrogates(text))
    }

    /// Read a file's exact UTF-8 bytes. NOT `String(contentsOf:encoding:.utf8)`, which strips a U+FEFF BOM
    /// (even mid-content) and would drop the BOM from the BOM vector's raw `pcactn_json` / json_parse input.
    static func readText(_ url: URL) throws -> String {
        String(decoding: try Data(contentsOf: url), as: UTF8.self)
    }

    static func load(_ name: String) throws -> JSONValue {
        try loadText(readText(conformanceDir.appendingPathComponent(name)))
    }

    static func hasSentinel(_ v: JSONValue) -> Bool {
        switch v {
        case let .string(s): return Canonical.hasLoneSurrogate(s)
        case let .array(a): return a.contains(where: hasSentinel)
        case let .object(o): return o.contains { Canonical.hasLoneSurrogate($0.key) || hasSentinel($0.value) }
        default: return false
        }
    }

    // ---- suite-aware skip (B4 post-quantum crypto-agility) ----

    /// The signature suites this Swift verifier implements for a GENUINE crypto verdict — on the leaf
    /// (`requires:"pq"`), on non-leaf capability-chain hops (`requires:"pq-nonleaf"`), the threshold-share
    /// binding, and the PQ transparency artifacts. These are the THREE CROSS-IMPL suites every conformant
    /// verifier must agree on: classical Ed25519, the pure lattice ML-DSA-65 (FIPS-204, via CryptoKit's
    /// `MLDSA65`), and the hybrid Ed25519 + ML-DSA-65. The other 7 registered suites (ml-dsa-87,
    /// slh-dsa-sha2-128f/256s, their hybrids, and the SUF-CMA nested hybrid) are NOT wired in Swift, so a
    /// vector needing a real signature verdict under them is skipped EXPLICITLY — never silently passed.
    static let SUPPORTED_SUITES: Set<String> = ["ed25519", "ml-dsa-65", "hybrid-ed25519-ml-dsa-65"]

    /// The concrete suite a vector exercises that this verifier does NOT implement, if any: the leaf `alg`
    /// for `requires:"pq"`, or the first non-supported capability-hop `alg` for `requires:"pq-nonleaf"`.
    /// `nil` for core vectors and for vectors that stay entirely within `SUPPORTED_SUITES`.
    static func unsupportedSuite(_ v: JSONValue) -> String? {
        guard let p = v.get("pcactn")?.asObject else { return nil } // raw-json (wire) + core vectors
        func alg(_ o: [String: JSONValue]) -> String { o["alg"]?.asString ?? "ed25519" }
        switch v.get("requires")?.asString {
        case "pq":
            let a = alg(p)
            return SUPPORTED_SUITES.contains(a) ? nil : a
        case "pq-nonleaf":
            guard let chain = p["cap_chain"]?.asArray else { return nil }
            for h in chain {
                if let o = h.asObject {
                    let a = alg(o)
                    if !SUPPORTED_SUITES.contains(a) { return a }
                }
            }
            return nil
        default:
            return nil
        }
    }

    /// Whether the EXPECTED verdict is a terminal `{wire:false}` — a wire failure is suite-AGNOSTIC (an
    /// unknown `alg`, or a `pq_sig` whose size the suite cannot admit, is rejected at the wire stage whether
    /// or not we implement the suite), so these negatives still RUN and pass even for an unimplemented suite.
    static func terminalWireFalse(_ checks: [String: JSONValue]) -> Bool {
        guard checks.count == 1, case .bool(false)? = checks["wire"] else { return false }
        return true
    }

    // ---- the verdict corpus ----

    func testVectors() throws {
        let doc = try Self.load("vectors.json")
        XCTAssertEqual(doc.get("format")?.safeInt, 2)
        guard let vectors = doc.get("vectors")?.asArray else { return XCTFail("no vectors") }
        XCTAssertFalse(vectors.isEmpty)

        var failures: [String] = []
        var skippedBySuite: [String: Int] = [:]
        for v in vectors {
            guard let name = v.get("name")?.asString,
                  let now = v.get("context")?.get("now")?.safeInt,
                  let aud = v.get("context")?.get("aud")?.asString else {
                failures.append("<malformed vector>"); continue
            }
            guard let expect = v.get("expect"),
                  let wantAllow = { () -> Bool? in if case let .bool(b) = expect.get("allow") { return b }; return nil }(),
                  let wantChecks = expect.get("checks")?.asObject else {
                failures.append("\(name): malformed expect"); continue
            }
            // SUITE-AWARE skip: skip ONLY a vector whose expected verdict needs a genuine crypto verdict under
            // a suite Swift does not implement. A terminal {wire:false} negative (suite-agnostic) still runs.
            if let suite = Self.unsupportedSuite(v), !Self.terminalWireFalse(wantChecks) {
                skippedBySuite[suite, default: 0] += 1
                continue
            }
            let grant = v.get("grant") ?? .null

            let got: PCA.Verdict
            if let raw = v.get("pcactn_json")?.asString {
                got = PCA.verify(json: raw, grant: grant, now: now, audience: aud)
            } else if let obj = v.get("pcactn"), Self.hasSentinel(obj) {
                got = PCA.Verdict(allow: false, checks: ["wire": false], reason: "wire: lone surrogate")
            } else {
                got = PCA.verify(pcactn: v.get("pcactn") ?? .null, grant: grant, now: now, audience: aud)
            }

            if got.allow != wantAllow {
                failures.append("\(name): allow = \(got.allow), want \(wantAllow) (\(got.reason))")
            }
            if got.checks.count != wantChecks.count {
                failures.append("\(name): checks \(got.checks) want \(wantChecks.keys.sorted())")
            }
            for (k, wv) in wantChecks {
                let want: Bool? = { if case let .bool(b) = wv { return b }; return nil }()
                if got.checks[k] != want {
                    failures.append("\(name): check \(k) = \(String(describing: got.checks[k])), want \(String(describing: want)) (\(got.reason))")
                }
            }
        }
        let skipped = skippedBySuite.values.reduce(0, +)
        let ran = vectors.count - skipped
        if !failures.isEmpty {
            XCTFail("\(failures.count) of \(ran) run vectors failed:\n" + failures.joined(separator: "\n"))
        } else {
            print("PCA conformance: \(ran)/\(vectors.count) vectors passed; \(skipped) skipped (suites not in Swift)")
            for s in skippedBySuite.keys.sorted() {
                print("  skipped \(skippedBySuite[s]!) vector(s) requiring unimplemented suite \"\(s)\"")
            }
        }
    }

    // ---- primitive tables ----

    func testCanonicalAndHash() throws {
        let doc = try Self.load("vectors.json")
        let prim = doc.get("primitives")!
        var bad: [String] = []
        for c in prim.get("canonical")!.asArray! {
            let value = c.get("value")!
            let canon = try Canonical.canonicalizeStrict(value)
            if canon != c.get("expect")?.asString { bad.append("canonical \(canon) != \(c.get("expect")?.asString ?? "?")") }
            if Canonical.hashCanonical(value) != c.get("hash")?.asString { bad.append("hash mismatch for \(canon)") }
        }
        XCTAssertTrue(bad.isEmpty, bad.joined(separator: "\n"))
    }

    func testJSONParseTable() throws {
        let doc = try Self.load("vectors.json")
        var bad: [String] = []
        for t in doc.get("primitives")!.get("json_parse")!.asArray! {
            guard let input = t.get("input")?.asString,
                  case let .bool(accept) = (t.get("accept") ?? .null) else { continue }
            do {
                let v = try StrictJSON.parse(input)
                if !accept { bad.append("\(input): accepted, want reject") }
                else if let c = t.get("canonical")?.asString {
                    let got = try Canonical.canonicalizeStrict(v)
                    if got != c { bad.append("\(input): canonical \(got), want \(c)") }
                }
            } catch {
                if accept { bad.append("\(input): rejected (\(error)), want accept") }
            }
        }
        XCTAssertTrue(bad.isEmpty, "\(bad.count) json_parse rows failed:\n" + bad.joined(separator: "\n"))
    }

    func testB64uTable() throws {
        let doc = try Self.load("vectors.json")
        var bad: [String] = []
        for t in doc.get("primitives")!.get("b64u")!.asArray! {
            guard let input = t.get("input")?.asString,
                  case let .bool(valid) = (t.get("valid") ?? .null) else { continue }
            let len = t.get("len")?.safeInt.map { Int($0) }
            if Base64URLStrict.isValid(input, length: len) != valid {
                bad.append("\(input) (len \(String(describing: len))): want valid=\(valid)")
            }
        }
        XCTAssertTrue(bad.isEmpty, bad.joined(separator: "\n"))
    }

    func testMerklePrimitives() throws {
        let doc = try Self.load("vectors.json")
        let prim = doc.get("primitives")!
        for m in prim.get("merkle")!.asArray! {
            let leaves = m.get("leaves")!.asArray!
            let root = Merkle.merkleRoot(leaves)
            XCTAssertEqual(root, m.get("root")?.asString)
            for (i, p) in m.get("proofs")!.asArray!.enumerated() {
                XCTAssertTrue(Merkle.verifyInclusion(root ?? "", p.asObject, leaves[i]), "proof \(i)")
            }
        }
        XCTAssertEqual(Merkle.paramsDigest(nil), prim.get("params_digest_empty")?.asString)
    }

    /// v2.1 agent-leaf threshold-share binding. Every `primitives.threshold_share[]` entry must verify over
    /// the `signerSetHash‖t`-bound share message (`Threshold.verifyShare` RECOMPUTES the bound message, with
    /// `signerSetHash` recomputed from the signer set — it never trusts the stored `share_message`) iff
    /// `valid`. In particular the PRE-v2.1 bare agent share and a cross-signer-set replay MUST be REJECTED,
    /// and the bound shares ACCEPTED. The computation of `signerSetHash` / `shareMessage` is sanity-checked
    /// against the stored values too. All corpus share vectors are Ed25519 (no PQ suite needed).
    func testThresholdShares() throws {
        let doc = try Self.load("vectors.json")
        guard let shares = doc.get("primitives")?.get("threshold_share")?.asArray, !shares.isEmpty else {
            return XCTFail("no threshold_share primitives")
        }
        var failures: [String] = []
        var accepted = 0, rejected = 0
        var bareRejected = false, wrongSetRejected = false
        for ts in shares {
            let name = ts.get("name")?.asString ?? ts.get("role")?.asString ?? "<unnamed>"
            let want: Bool = { if case let .bool(b)? = ts.get("valid") { return b }; return true }()

            // sanity: signerSetHash + bound shareMessage are recomputed byte-for-byte from the signer set.
            if let roleStr = ts.get("role")?.asString, let role = Threshold.Role(rawValue: roleStr),
               let t = ts.get("t")?.safeInt,
               let setArr = ts.get("signer_set")?.asArray,
               let msg = ts.get("threshold_message")?.asString.flatMap({ Base64URLStrict.decode($0) }),
               let setHash = ts.get("signer_set_hash")?.asString.flatMap({ Base64URLStrict.decode($0) }),
               let shareMsg = ts.get("share_message")?.asString.flatMap({ Base64URLStrict.decode($0) }) {
                let signerSet = setArr.compactMap { s -> Threshold.Signer? in
                    guard let r = s.get("role")?.asString, let role = Threshold.Role(rawValue: r),
                          let pk = s.get("publicKey")?.asString else { return nil }
                    return Threshold.Signer(role: role, publicKey: pk)
                }
                if Threshold.signerSetHash(signerSet) != setHash { failures.append("\(name): signerSetHash mismatch") }
                if Threshold.shareMessage(role, msg, signerSet, Int(t)) != shareMsg { failures.append("\(name): shareMessage mismatch") }
            } else {
                failures.append("\(name): malformed threshold_share vector")
            }

            // the fail-closed v2.1 verdict.
            let got = Threshold.verifyShare(ts)
            if got != want { failures.append("\(name): share verified = \(got), want valid = \(want)") }
            if want { accepted += 1 } else { rejected += 1 }
            if name == "agent-bare-rejected" && !got { bareRejected = true }
            if name == "agent-bound-wrong-set" && !got { wrongSetRejected = true }
        }
        XCTAssertTrue(failures.isEmpty, failures.joined(separator: "\n"))
        XCTAssertTrue(bareRejected, "v2.1 binding: the pre-v2.1 bare agent share (agent-bare-rejected) MUST be rejected")
        XCTAssertTrue(wrongSetRejected, "v2.1 binding: a cross-signer-set agent share replay (agent-bound-wrong-set) MUST be rejected")
        print("PCA threshold shares: \(accepted) valid accepted, \(rejected) invalid rejected "
            + "(incl. v2.1 bare-agent-share + cross-signer-set replay)")
    }

    /// The post-quantum transparency / authority artifacts (`primitives.pq_artifact[]`) — `sth`, `revocation`,
    /// `beacon`, `bond-settlement`, `safety-certificate`, `judge-verdict`, `software-attestation`. They route
    /// through the SAME `PQ.verifyLeaf` agility seam as the leaf, so an IMPLEMENTED suite yields a genuine
    /// verdict (signature over `message` under the suite `alg` must equal `valid`) and an unimplemented suite
    /// is skipped EXPLICITLY, per suite.
    func testPQArtifact() throws {
        let doc = try Self.load("vectors.json")
        guard let arts = doc.get("primitives")?.get("pq_artifact")?.asArray, !arts.isEmpty else {
            return XCTFail("no pq_artifact primitives")
        }
        var failures: [String] = []
        var ran = 0
        var skippedBySuite: [String: Int] = [:]
        for a in arts {
            let alg = a.get("alg")?.asString ?? "ed25519"
            let artifact = a.get("artifact")?.asString ?? "?"
            if !Self.SUPPORTED_SUITES.contains(alg) {
                skippedBySuite[alg, default: 0] += 1
                continue
            }
            guard let msg = a.get("message")?.asString.flatMap({ Base64URLStrict.decode($0) }) else {
                failures.append("\(artifact)/\(alg): message not canonical base64url"); continue
            }
            let edPub = a.get("ed_pub")?.asString ?? ""
            let got = PQ.verifyLeaf(alg: alg, holder: edPub, pqPublicKey: a.get("pq_pk")?.asString,
                                    message: msg, sig: a.get("sig")?.asString, pqSig: a.get("pq_sig")?.asString)
            let want: Bool = { if case let .bool(b)? = a.get("valid") { return b }; return true }()
            if got != want { failures.append("\(artifact)/\(alg): verified = \(got), want \(want)") }
            ran += 1
        }
        XCTAssertTrue(failures.isEmpty, failures.joined(separator: "\n"))
        print("PCA pq artifacts: ran \(ran), skipped \(skippedBySuite.values.reduce(0, +))")
        for s in skippedBySuite.keys.sorted() {
            print("  skipped \(skippedBySuite[s]!) pq artifact(s) under unimplemented suite \"\(s)\"")
        }
    }

    /// The fuzz-found adversarial counterexamples (tools/pca-diff-fuzz/counterexamples). The expected
    /// verdict for each is in INDEX.json; several are the small-order / non-canonical-point forgeries that
    /// exercise the strict RFC 8032 Ed25519 checks.
    func testCounterexamples() throws {
        let fuzzDir = URL(fileURLWithPath: #filePath)
            .deletingLastPathComponent().deletingLastPathComponent().deletingLastPathComponent()
            .deletingLastPathComponent().deletingLastPathComponent()
            .appendingPathComponent("tools/pca-diff-fuzz/counterexamples", isDirectory: true)
        let indexURL = fuzzDir.appendingPathComponent("INDEX.json")
        guard (try? Data(contentsOf: indexURL)) != nil else { throw XCTSkip("counterexamples not present") }
        let index = try Self.loadText(Self.readText(indexURL))
        guard let entries = index.asArray else { return XCTFail("bad INDEX.json") }

        var failures: [String] = []
        for e in entries {
            guard let file = e.get("file")?.asString,
                  case let .bool(wantAllow) = (e.get("allow") ?? .null) else { continue }
            let doc = try Self.loadText(Self.readText(fuzzDir.appendingPathComponent(file)))
            let now = doc.get("context")?.get("now")?.safeInt ?? 0
            let aud = doc.get("context")?.get("aud")?.asString ?? ""
            // In the counterexamples, `grant` is raw JSON TEXT (not a parsed object) — parse it.
            let grant: JSONValue = doc.get("grant").flatMap { g in
                if let s = g.asString { return (try? StrictJSON.parseLenient(s)) ?? g }
                return g
            } ?? .null
            let got: PCA.Verdict
            if let rawJson = doc.get("pcactn_json")?.asString {
                got = PCA.verify(json: rawJson, grant: grant, now: now, audience: aud)
            } else {
                got = PCA.verify(pcactn: doc.get("pcactn") ?? .null, grant: grant, now: now, audience: aud)
            }
            if got.allow != wantAllow {
                failures.append("\(file): allow = \(got.allow), want \(wantAllow) (\(got.reason))")
            }
        }
        if !failures.isEmpty {
            XCTFail("\(failures.count) of \(entries.count) counterexamples failed:\n" + failures.joined(separator: "\n"))
        } else {
            print("PCA counterexamples: \(entries.count)/\(entries.count) passed")
        }
    }

    func testKeysConsistent() throws {
        // Sanity: fixed conformance public keys are canonical prime-order points.
        let keys = try Self.load("keys.json")
        for (_, k) in keys.asObject ?? [:] {
            guard let pub = k.get("public")?.asString, let raw = Base64URLStrict.decode(pub, length: 32) else {
                XCTFail("bad key"); continue
            }
            XCTAssertTrue(Ed25519Strict.isStrictPoint(raw))
        }
    }
}
