import XCTest
import Foundation
@testable import AtlasPCAVerify

/// Differential replay of PCAAttestEat against the reference (@atlasauth/pca-attest-eat): the EAT build and verify, the freshness and
/// channel-binding gates, the RATS appraisal, the tolerant SEV-SNP report parse, the AMD silicon verification, the composed
/// fresh-token pipeline, the post-quantum co-signature of a verdict, the admission evidence and the artifact discharge. The corpus
/// carries every signing key as a seed label ({"$seed": label}); the keys are derived here from the label.
///
/// Not compared (counted as skipped in the log):
///  - the SLH-DSA co-signing suites (no vetted SLH-DSA implementation: signing them is refused as unsupported_suite, and a valid
///    SLH-DSA co-signature cannot be verified, so those cases are skipped; their refusal cases still run);
///  - the ML-DSA suites on a platform without ML-DSA (none now: the vendored CMLDSA target covers every platform CryptoKit does not);
///  - (none depend on the clock: a case the header names in `clockCases` runs with the default clock set to the header's `clockMs`).
/// Compared differently:
///  - ML-DSA signatures: the platform's signer may be hedged, so the produced co-signature is compared in everything but the
///    post-quantum signature bytes, and both it and the reference's artifact must verify under the native verifier;
///  - the two OpenSSL-specific refusal codes of a mismatched key type (any native refusal stands for them).
/// Stricter than the corpus (the current reference refuses these too; the corpus predates that fix): a present clock skew that is
/// not a finite number, an admission minimum tier other than affirming / affirming-hw-rooted (each listed in `stricter`, must
/// refuse), and a debug requirement against a dbgstat outside the RFC 9711 values (fails closed as rejected).
final class RefAttestEatTests: XCTestCase {
    static let file = "ref-attest-eat.json.gz"
    /// The clock the corpus generator ran under (`clockMs`) and the cases whose result carries it (`clockCases`), both from the corpus header: such a case runs with the
    /// default clock set to `clockMs`. Set per corpus file before it is replayed.
    nonisolated(unsafe) static var clockMs: Double?
    nonisolated(unsafe) static var clockCases: Set<String> = []

    /// The header members of a corpus file (the text before its `"cases":[` member).
    static func clockHeader(_ file: String) -> (ms: Double?, cases: Set<String>) {
        guard let data = try? K042.bytes(file), let text = String(data: data, encoding: .utf8), let at = text.range(of: ",\"cases\":[") else { return (nil, []) }
        let head = K042.parse(String(text[..<at.lowerBound]) + "}")
        return (IV.num(head.get("clockMs")), Set((head.get("clockCases")?.asArray ?? []).compactMap { $0.asString }))
    }
    static let stricter: Set<String> = [
        "verifyFreshness/skew junk string", "verifyFreshness/skew junk stale", "verifyFreshness/skew string number", "verifyFreshness/skew null",
        "verifyFreshness/skew true", "verifyFreshAttestedEAT/amd skew junk", "eatAdmissionEvidence/min tier unknown", "eatAdmissionEvidence/min tier null",
    ]
    static let dbgstat = ["enabled", "disabled", "disabled-since-boot", "disabled-permanently", "disabled-fully-and-permanently"]

    /// A verifying key spec: {alg: "EdDSA", pub} or {alg: "ES256", x, y}.
    static func verifyKey(_ spec: JSONValue?) throws -> Jose.Key {
        guard let alg = spec?.get("alg")?.asString else { throw JSError("no key spec") }
        if alg == "EdDSA" {
            guard let pub = spec?.get("pub")?.asString.flatMap({ Base64URLStrict.decode($0, length: 32) }) else { throw JSError("bad Ed25519 key") }
            return .ed25519(pub)
        }
        guard alg == "ES256", let x = spec?.get("x")?.asString.flatMap({ Base64URLStrict.decode($0, length: 32) }),
              let y = spec?.get("y")?.asString.flatMap({ Base64URLStrict.decode($0, length: 32) }) else { throw JSError("bad ES256 key") }
        return .ec(curve: "P-256", point: [0x04] + x + y)
    }

    static func coSignKeys(_ spec: JSONValue?) throws -> PCAAttestEat.CoSignKeys {
        var k = PCAAttestEat.CoSignKeys()
        if let e = spec?.get("ed") { k.ed = try RefKeys.edKey(e) }
        if let p = spec?.get("pq") {
            guard let prim = p.get("prim")?.asString, let label = p.get("seed")?.get("$seed")?.asString else { throw JSError("bad pq key") }
            let level: PCAMLDSALevel
            switch prim {
            case "ml-dsa-65": level = .mlDsa65
            case "ml-dsa-87": level = .mlDsa87
            default: throw JSError("unsupported_suite: \(prim)")
            }
            k.pq = try PCAPQKey.fromSeed(level, seed: RefKeys.seed(label))
        }
        return k
    }

    /// The co-signed artifact compared without its post-quantum signature bytes (which the platform may hedge), plus both
    /// artifacts verified natively.
    static func coSignDiff(_ c: BaseCase, _ got: BaseGot) -> String? {
        guard case let .value(g) = got, !c.threw else { return Base.diff(c, got) }
        let want = c.out
        let hybrid = (want.get("suite")?.asString ?? "").hasPrefix("hybrid")
        func strip(_ v: JSONValue) -> JSONValue {
            var o = v.asObject ?? [:]
            var cs = o["cosig"]?.asObject ?? [:]
            if hybrid { cs["pq_sig"] = nil } else { cs["sig"] = nil }
            o["cosig"] = .object(cs)
            return .object(o)
        }
        if Base.canon(strip(g)) != Base.canon(strip(want)) { return "\(c.name): want \(Base.firstDiff(strip(want), strip(g), "@"))" }
        let at: JSONValue = want.get("cosig")?.get("cosignedAt") ?? .null
        for (label, v) in [("native", g), ("reference", want)] {
            let r = PCAAttestEat.verifyCoSignedAttestation(v, .object(["now": at]))
            if r.get("ok") != JSONValue.bool(true) { return "\(c.name): the \(label) co-signature does not verify: \(Base.canon(r))" }
        }
        return nil
    }

    /// A debug requirement against a dbgstat outside the RFC 9711 values: the reference reads it as disabled, the port fails closed.
    static func stricterDebug(_ c: BaseCase, _ v: JSONValue) -> Bool {
        guard let dbg = c.arg(0)?.get("dbgstat"), !(dbg.asString.map { dbgstat.contains($0) } ?? false),
              c.arg(1)?.get("requireDebugDisabled") == JSONValue.bool(true), v.get("tier") == JSONValue.string("rejected") else { return false }
        return v.get("reasons")?.asArray?.last == JSONValue.string("debug status unknown \u{2014} failing closed")
    }

    static func constantsJSON() -> JSONValue {
        var o: JObject = [:]
        o["EAT_TYP"] = .string(PCAAttestEat.EAT_TYP)
        o["DEFAULT_EAT_ALG"] = .string(PCAAttestEat.DEFAULT_EAT_ALG)
        o["DEFAULT_MAX_AGE_MS"] = .int(Int64(PCAAttestEat.DEFAULT_MAX_AGE_MS))
        o["CHANNEL_BINDING_DOMAIN"] = .string(PCAAttestEat.CHANNEL_BINDING_DOMAIN)
        o["AMD_SEV_SNP_SIGNED_REGION_END"] = .int(Int64(PCAAttestEat.AMD_SEV_SNP_SIGNED_REGION_END))
        o["AMD_SEV_SNP_HARDWARE_ROOT_LABEL"] = .string(PCAAttestEat.AMD_SEV_SNP_HARDWARE_ROOT_LABEL)
        o["KNOWN_REPORT_VERSIONS"] = .array(PCAAttestEat.KNOWN_REPORT_VERSIONS.map { JSONValue.int(Int64($0)) })
        var pins: JObject = [:]
        for (k, v) in PCAAttestEat.KNOWN_AMD_ARK_SPKI_SHA384 { pins[JKey(k)] = .string(v) }
        o["KNOWN_AMD_ARK_SPKI_SHA384"] = .object(pins)
        o["AMD_MILAN_ARK_SPKI_SHA384"] = .string(PCAAttestEat.AMD_MILAN_ARK_SPKI_SHA384)
        o["PQCOSIGN_DOMAIN"] = .string(PCAAttestEat.PQCOSIGN_DOMAIN)
        o["DEFAULT_PQ_COSIGN_SUITE"] = .string(PCAAttestEat.DEFAULT_PQ_COSIGN_SUITE)
        o["PQ_COSIGN_SUITES"] = .array(PCAAttestEat.PQ_COSIGN_SUITES.map { JSONValue.string($0) })
        return .object(o)
    }

    static func replay(_ d: Base.Diffs) throws {
        let dischargeNonce = Base64URLStrict.encode(Array(Canonical.sha256(Array("eat-oracle-nonce/0".utf8)).prefix(16)))
        let body: (BaseCase) throws -> Void = { c in
            EatJS.clockOverrideMs = clockCases.contains(c.name) ? clockMs : nil
            defer { EatJS.clockOverrideMs = nil }
            let a0 = c.arg(0), a1 = c.arg(1), a2 = c.arg(2), a3 = c.arg(3)
            let codeOf: (Error) -> String? = { e in Ref.code(e) ?? c.code }
            func run(_ f: () throws -> JSONValue) -> BaseGot { Base.run(codeOf, f) }
            let got: BaseGot
            switch c.fn {
            case "constants": got = .value(constantsJSON())
            case "deriveChannelCnf": got = run { try PCAAttestEat.deriveChannelCnf(a0, a1) }
            case "bindChannel": got = run { try PCAAttestEat.bindChannel(a0, a1, a2) }
            case "buildEAT":
                let spec = a0?.get("key")
                got = run {
                    .string(try PCAAttestEat.buildEAT(a0, sign: { alg, input in
                        guard alg == "EdDSA", spec?.get("alg")?.asString == "EdDSA" else { throw JSError("invalid digest", code: "ERR_OSSL_INVALID_DIGEST") }
                        return try RefKeys.edKey(spec?.get("seed")).sign(input)
                    }))
                }
            case "verifyEAT": got = run { try PCAAttestEat.verifyEAT(a0, key: try verifyKey(a1), a2) }
            case "verifyFreshness": got = run { try PCAAttestEat.verifyFreshness(a0, a1) }
            case "verifyChannelBinding": got = run { try PCAAttestEat.verifyChannelBinding(a0, a1) }
            case "appraise": got = run { try PCAAttestEat.appraise(a0, a1, a2, a3) }
            case "parseReportTolerant":
                guard let b = Base.bytes(a0) else { d.skip("parseReportTolerant: not bytes"); return }
                got = .value(PCAAttestEat.parseReportTolerant(b))
            case "verifyAmdAttestation": got = .value(PCAAttestEat.verifyAmdAttestation(a0, a1))
            case "verifyFreshAttestedEAT": got = run { try PCAAttestEat.verifyFreshAttestedEAT(a0, verifyKey: try verifyKey(a1?.get("verifyKey")), a1) }
            case "canonicalVerdictBytes": got = run { PCAAttestEat.bytesValue(try PCAAttestEat.canonicalVerdictBytes(a0, a1)) }
            case "verdictFromAppraisal": got = run { try PCAAttestEat.verdictFromAppraisal(a0, a1) }
            case "isPqCoSignSuite": got = .value(.bool(PCAAttestEat.isPqCoSignSuite(a0)))
            case "coSignAttestation":
                let suite = a1?.get("suite")?.asString ?? PCAAttestEat.DEFAULT_PQ_COSIGN_SUITE
                let prim = a1?.get("key")?.get("pq")?.get("prim")?.asString ?? ""
                if !c.threw && (suite.contains("slh-dsa") || prim.contains("slh-dsa")) { d.skip("SLH-DSA is not implemented (unsupported_suite)"); return }
                if !c.threw && !PCAPQKey.signingAvailable { d.skip("ML-DSA signing is not available on this platform"); return }
                got = run { try PCAAttestEat.coSignAttestation(a0, suite: a1?.get("suite"), keys: try coSignKeys(a1?.get("key")), now: a1?.get("now")) }
            case "verifyCoSignedAttestation":
                let suite = a0?.get("suite")?.asString ?? ""
                if c.out.get("ok") == JSONValue.bool(true) {
                    if suite.contains("slh-dsa") { d.skip("SLH-DSA is not implemented (unsupported_suite)"); return }
                    if suite.contains("ml-dsa") && !MLDSA.available { d.skip("ML-DSA is not available on this platform"); return }
                }
                got = .value(PCAAttestEat.verifyCoSignedAttestation(a0, a1))
            case "ed25519Jkt": got = .value(.string(PCAAttestEat.ed25519Jkt(a0)))
            case "eatAdmissionEvidence": got = run { PCAAttestEat.eatAdmissionEvidence(a0, verifyKey: try verifyKey(a1?.get("verifyKey")), a1) }
            case "runtimeDigestFromEat": got = run { try PCAAttestEat.runtimeDigestFromEat(a0, a1) ?? .null }
            case "issueArtifactDischarge":
                got = run {
                    let roots = try PCA.parseSigstoreTrustedRoot(a0?.get("roots") ?? .null)
                    let issuer = PCASuiteKey.ed25519(try RefKeys.edKey(a0?.get("issuerKey")?.get("seed")))
                    return try PCAAttestEat.issueArtifactDischarge(a0, roots: roots, issuer: issuer, nonce: dischargeNonce)
                }
            default:
                d.skip("\(c.fn): not mapped"); return
            }
            var diff: String?
            if c.fn == "coSignAttestation" { diff = coSignDiff(c, got) } else { diff = Base.diff(c, got) }
            if diff != nil, c.fn == "appraise", case let .value(v) = got, stricterDebug(c, v) { diff = nil }
            if stricter.contains(c.name) {
                if case let .value(v) = got, v.get("ok") == JSONValue.bool(false) { diff = nil } else { diff = "\(c.name): the stricter port must refuse" }
            }
            d.add(c, diff)
        }
        (clockMs, clockCases) = { let h = clockHeader(file); return (h.ms, h.cases) }()
        try Base.each(file, nil, body)
        // the cases that carry private keys live in ref-attest-eat-gen.json.gz (CI-generated)
        if let g = K042.secretCorpusPath(file) {
            (clockMs, clockCases) = { let h = clockHeader(g); return (h.ms, h.cases) }()
            try Base.each(g, nil, body)
        }
    }

    func testAttestEat() throws {
        try K042.requireCovers(["AttestEat", "JSInterop", "Jose", "AttestAmd", "Sigstore", "ProvenanceGate", "PQ", "MLDSA"])
        let d = Base.Diffs()
        try Self.replay(d)
        d.finish(1300)
    }

    /// The corpus carries every signing key as a seed label, never as key material.
    func testCorpusCarriesNoPrivateKeys() throws {
        let text = String(decoding: try K042.bytes(Self.file), as: UTF8.self)
        for pattern in ["\"seed\":\"", "\"d\":\"[A-Za-z0-9_-]{40,}\""] {
            let re = try NSRegularExpression(pattern: pattern)
            XCTAssertNil(re.firstMatch(in: text, range: NSRange(text.startIndex..., in: text)), "the corpus carries a private key member (\(pattern))")
        }
    }

    func testNonFiniteClockSkewIsRefused() throws {
        let eat: JSONValue = .object(["eat_nonce": .string("n1"), "iat": .int(1_000_000_000)]) // decades stale: only an unbounded skew would admit it
        let base: JObject = ["expectedNonce": .string("n1"), "now": .int(1_800_000_000_000), "maxAgeMs": .int(60_000)]
        for skew: JSONValue in [.string("5"), .null, .bool(true), .double(.infinity), .double(.nan)] {
            var o = base
            o["clockSkewMs"] = skew
            let r = try PCAAttestEat.verifyFreshness(eat, .object(o))
            XCTAssertEqual(r, .object(["ok": .bool(false), "reason": .string("invalid clockSkewMs (must be a finite number)")]))
        }
        var o = base
        o["clockSkewMs"] = .int(5000)
        XCTAssertEqual(try PCAAttestEat.verifyFreshness(eat, .object(o)).get("ok"), JSONValue.bool(false))
    }

    func testUnknownMinTierIsRefused() throws {
        let key: Jose.Key = .ed25519([UInt8](repeating: 1, count: 32))
        for tier: JSONValue in [.string("warning"), .string("rejected"), .string("bogus"), .null, .int(2)] {
            let r = PCAAttestEat.eatAdmissionEvidence(.string("x"), verifyKey: key, .object(["instanceKey": .string("k"), "minTier": tier]))
            XCTAssertEqual(r, .object(["ok": .bool(false), "bound": .bool(false), "reason": .string("invalid minTier")]))
        }
    }

    func testSlhDsaSuitesAreRefusedAsUnsupported() throws {
        for suite in ["slh-dsa-sha2-128f", "slh-dsa-sha2-256s", "hybrid-ed25519-slh-dsa-sha2-128f", "hybrid-ed25519-slh-dsa-sha2-256s"] {
            XCTAssertTrue(PCAAttestEat.isPqCoSignSuite(.string(suite)))
            XCTAssertThrowsError(try PCAAttestEat.coSignAttestation(.object(["tier": .string("affirming"), "trustworthy": .bool(true)]), suite: .string(suite),
                                                                    keys: PCAAttestEat.CoSignKeys(ed: try RefKeys.edKey(.object(["$seed": .string("eat/pq-ed/1")])))))
        }
    }

    func testIssueNonceShape() throws {
        let n = PCAAttestEat.issueNonce(now: 1_800_000_000_000, bytes: 20)
        let parts = n.value.split(separator: ".", omittingEmptySubsequences: false).map(String.init)
        XCTAssertEqual(parts.count, 2)
        XCTAssertEqual(Int64(parts[1], radix: 36), 1_800_000_000_000)
        XCTAssertEqual(Base64URLStrict.decode(parts[0])?.count, 20)
        XCTAssertEqual(Base64URLStrict.decode(PCAAttestEat.issueNonce(bytes: 3).value.split(separator: ".")[0].description)?.count, 16)
        XCTAssertEqual(n.issuedAt, 1_800_000_000_000)
    }
}
