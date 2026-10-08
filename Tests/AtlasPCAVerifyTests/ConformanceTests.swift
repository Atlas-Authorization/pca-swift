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

    // ---- the verdict corpus ----

    func testVectors() throws {
        let doc = try Self.load("vectors.json")
        XCTAssertEqual(doc.get("format")?.safeInt, 2)
        guard let vectors = doc.get("vectors")?.asArray else { return XCTFail("no vectors") }
        XCTAssertFalse(vectors.isEmpty)

        var failures: [String] = []
        for v in vectors {
            guard let name = v.get("name")?.asString,
                  let now = v.get("context")?.get("now")?.safeInt,
                  let aud = v.get("context")?.get("aud")?.asString else {
                failures.append("<malformed vector>"); continue
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

            guard let expect = v.get("expect"),
                  let wantAllow = { () -> Bool? in if case let .bool(b) = expect.get("allow") { return b }; return nil }(),
                  let wantChecks = expect.get("checks")?.asObject else {
                failures.append("\(name): malformed expect"); continue
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
        if !failures.isEmpty {
            XCTFail("\(failures.count) of \(vectors.count) vectors failed:\n" + failures.joined(separator: "\n"))
        } else {
            print("PCA conformance: \(vectors.count)/\(vectors.count) vectors passed")
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

    func testThresholdSharePrimitives() throws {
        let doc = try Self.load("vectors.json")
        guard let shares = doc.get("primitives")?.get("threshold_share")?.asArray else { return }
        for ts in shares {
            guard let roleStr = ts.get("role")?.asString, let role = Threshold.Role(rawValue: roleStr),
                  let t = ts.get("t")?.safeInt,
                  let setArr = ts.get("signer_set")?.asArray,
                  let msgB64 = ts.get("threshold_message")?.asString,
                  let msg = Base64URLStrict.decode(msgB64),
                  let setHashB64 = ts.get("signer_set_hash")?.asString,
                  let setHash = Base64URLStrict.decode(setHashB64),
                  let shareMsgB64 = ts.get("share_message")?.asString,
                  let shareMsg = Base64URLStrict.decode(shareMsgB64) else {
                XCTFail("malformed threshold_share vector"); continue
            }
            let signerSet = setArr.compactMap { s -> Threshold.Signer? in
                guard let r = s.get("role")?.asString, let role = Threshold.Role(rawValue: r),
                      let pk = s.get("publicKey")?.asString else { return nil }
                return Threshold.Signer(role: role, publicKey: pk)
            }
            XCTAssertEqual(Threshold.signerSetHash(signerSet), setHash, "signerSetHash for role \(roleStr)")
            XCTAssertEqual(Threshold.shareMessage(role, msg, signerSet, Int(t)), shareMsg, "shareMessage for role \(roleStr)")
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
