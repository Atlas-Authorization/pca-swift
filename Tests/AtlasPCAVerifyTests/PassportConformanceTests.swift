import XCTest
import Foundation
@testable import AtlasPCAVerify

/// Replays packages/pca/conformance/passport-vectors.json (signed agent passport): every signature suite this verifier
/// implements (a suite it does not implement must answer `unsupported_suite`), and the hardware branch through a stub vendor
/// verifier that answers what the vector says.
final class PassportConformanceTests: XCTestCase {
    struct StubDown: Error {}

    static func loadVectors() throws -> JSONValue { try ConformanceTests.load("passport-vectors.json") }

    /// Replays rows of one table; `docs` resolves `signed_ref`. Returns how many rows exercised a supported signature suite.
    @discardableResult
    static func replay(_ rows: [JSONValue], docs: inout [String: JSONValue], hardware: (JSONValue, inout PassportOptions) -> Void = { _, _ in }) -> (seenSuites: Int, bad: [String]) {
        var bad: [String] = []
        var seen = 0
        let supported = PCASuites.supported
        for v in rows {
            let name = v.get("name")?.asString ?? "?"
            var signed = v.get("signed")
            if let ref = v.get("signed_ref")?.asString { signed = docs[ref] }
            if let s = signed { docs[name] = s }
            let issuers = (v.get("trustedIssuers")?.asArray ?? []).compactMap { $0.asString }
            let revoked = (v.get("revoked")?.asArray ?? []).compactMap { $0.asString }
            var o = PassportOptions(trustedIssuers: issuers, nowMs: v.get("now")?.safeInt ?? 0, revoked: { id, _, _ in revoked.contains(id) })
            if let n = v.get("clockSkewMs")?.safeInt { o.clockSkewMs = n }
            if let n = v.get("maxEvidenceAgeMs")?.safeInt { o.maxEvidenceAgeMs = n }
            if let s = v.get("subject")?.asString { o.subject = s }
            for (k, p) in v.get("pqPins")?.asObject ?? [:] { if let ps = p.asString { o.pqPins[k.s] = ps } }
            let captured = BindingBox()
            if let h = v.get("hardware"), h.isObject {
                o.attest = { _, b in
                    captured.value = b
                    if h.get("throws") == .bool(true) { throw StubDown() }
                    return PassportAttestation(ok: h.get("ok") == .bool(true), bound: h.get("bound") == .bool(true), measured: h.get("measured")?.asObject)
                }
            }
            hardware(v, &o)
            let got = PCA.verifyPassport(signed, o)
            var want = v.get("expect")?.get("ok") == .bool(true) ? "" : (v.get("expect")?.get("reason")?.asString ?? "?")
            if let alg = signed?.get("alg")?.asString {
                if !supported.contains(alg) { want = "unsupported_suite" } else { seen += 1 }
            }
            if got.reason != want || got.ok != want.isEmpty { bad.append("\(name): got '\(got.reason)' want '\(want)'") }
            if let eb = v.get("expectBinding"), eb.isObject {
                let b = captured.value
                if b == nil || b?.holderPub != eb.get("holderPub")?.asString || b?.grantRef != eb.get("grantRef")?.asString
                    || b?.epoch != eb.get("epoch")?.safeInt || b?.nonce != eb.get("nonce")?.asString {
                    bad.append("\(name): the verifier was handed \(String(describing: b)) want \(Canonical.canonicalize(eb))")
                }
            }
        }
        return (seen, bad)
    }

    final class BindingBox { var value: PassportBinding? }

    func testPassportVectors() throws {
        let d = try Self.loadVectors()
        let rows = d.get("passport_vectors")?.asArray ?? []
        XCTAssertGreaterThanOrEqual(rows.count, 74)
        var docs: [String: JSONValue] = [:]
        let r = Self.replay(rows, docs: &docs)
        XCTAssertTrue(r.bad.isEmpty, r.bad.joined(separator: "\n"))
        // a build that implements a non-default suite (ML-DSA needs OS 26) must have exercised it; one that implements only ed25519 has nothing to exercise
        if PCASuites.supported.contains(where: { $0 != "ed25519" }) {
            XCTAssertGreaterThanOrEqual(r.seenSuites, 1, "no vector exercised a supported non-default suite")
        }
    }

    /// passport_hardware_vectors: hardware-rooted passports verified by the REAL vendor verifiers built from the vendor configuration
    /// (`VendorVerifier`), through the default-verifier seam of `verifyPassport`. The table is produced by the TypeScript generator
    /// (tsx scripts/gen-conformance-passport.ts in packages/pca); its absence is a failure, never a skip.
    func testPassportHardwareVectors() throws {
        let d = try Self.loadVectors()
        guard let rows = d.get("passport_hardware_vectors")?.asArray else {
            return XCTFail("passport-vectors.json has no passport_hardware_vectors table: regenerate it with the TypeScript reference (tsx scripts/gen-conformance-passport.ts in packages/pca)")
        }
        XCTAssertGreaterThanOrEqual(rows.count, 40)
        var docs: [String: JSONValue] = [:]
        var constructErrors: [String] = []
        let r = Self.replay(rows, docs: &docs) { v, o in
            guard let hv = v.get("hardware_verifier"), let vendor = hv.get("vendor")?.asString else { return }
            do {
                let ver = try VendorVerifier(vendor: vendor, config: hv.get("config")?.asObject)
                let ev = hv.get("evidence")
                o.defaultHardware = DefaultHardware(verifier: ver, evidence: { _ in ev })
            } catch { constructErrors.append("\(v.get("name")?.asString ?? "?"): \(error)") }
        }
        XCTAssertTrue(constructErrors.isEmpty, constructErrors.joined(separator: "\n"))
        XCTAssertTrue(r.bad.isEmpty, r.bad.joined(separator: "\n"))
    }

    // ---- exact outcomes beyond the vectors (a natively issued, signed passport) ----

    static let issuer = V2F.principal, agent = V2F.agent
    static let NOW: Int64 = 1_800_000_000_000

    static func passport(hardware: Bool = false) -> JObject {
        var p: JObject = ["model_id": .string("m1"), "operator": .string("acme"), "hardware_rooted": .bool(hardware), "issued_at": .int(NOW - 1_000)]
        p["id"] = .string(PCA.passportFingerprint(p)!)
        return p
    }

    static func sign(_ passport: JObject, exp: Int64 = NOW + 60_000, evidence: JSONValue? = nil, key: V2F.K = issuer) -> JSONValue {
        var body: JObject = ["typ": .string("atlas-pca/passport"), "ver": .int(1), "passport": .object(passport), "iss": .string(V2F.pub(key)),
                             "sub": .string(V2F.pub(agent)), "iat": .int(NOW - 1_000), "nbf": .int(NOW - 1_000), "exp": .int(exp)]
        if let e = evidence { body["evidence"] = e }
        body["sig"] = .string(V2F.sign(key, IV.message(PCA.PASSPORT_SIG_DOMAIN, .object(body))!))
        return .object(body)
    }

    static func opts(_ now: Int64 = NOW, revoked: Bool = false) -> PassportOptions {
        PassportOptions(trustedIssuers: [V2F.pub(issuer)], nowMs: now, revoked: { _, _, _ in revoked })
    }

    func testAnIssuedPassportVerifiesAndEveryReasonCodeIsReachable() {
        let sp = Self.sign(Self.passport())
        let ok = PCA.verifyPassport(sp, Self.opts())
        XCTAssertTrue(ok.ok)
        XCTAssertEqual(ok.sub, V2F.pub(Self.agent))
        XCTAssertEqual(ok.exp, Self.NOW + 60_000)
        XCTAssertFalse(ok.hardwareVerified)
        func reason(_ sp: JSONValue?, _ o: PassportOptions) -> String { PCA.verifyPassport(sp, o).reason }
        XCTAssertEqual(reason(.int(1), Self.opts()), "malformed")
        XCTAssertEqual(reason(nil, Self.opts()), "malformed")
        XCTAssertEqual(reason(sp.setting("ver", .int(2)), Self.opts()), "unsupported_version")
        XCTAssertEqual(reason(sp.setting("alg", .string("rot13")), Self.opts()), "unsupported_suite")
        var other = Self.opts()
        other.trustedIssuers = []
        XCTAssertEqual(reason(sp, other), "unknown_issuer")
        XCTAssertEqual(reason(sp.setting("sub", .string("someone-else")), Self.opts()), "bad_signature")
        XCTAssertEqual(reason(Self.sign(Self.passport()).setting("passport", .object(Self.passport().merging(["model_id": .string("m2")]))), Self.opts()), "bad_signature")
        // a validly signed passport whose id is not the fingerprint of its identity
        var wrongId = Self.passport()
        wrongId["id"] = .string(Base64URLStrict.encode([UInt8](repeating: 7, count: 32)))
        XCTAssertEqual(reason(Self.sign(wrongId), Self.opts()), "id_mismatch")
        XCTAssertEqual(reason(sp, Self.opts(Self.NOW - 2_000)), "not_yet_valid")
        XCTAssertEqual(reason(sp, Self.opts(Self.NOW + 60_000)), "expired") // exp is exclusive
        XCTAssertEqual(reason(sp, Self.opts(Self.NOW + 59_999)), "")
        var subj = Self.opts()
        subj.subject = "not-the-agent"
        XCTAssertEqual(reason(sp, subj), "subject_mismatch")
        XCTAssertEqual(reason(sp, Self.opts(revoked: true)), "revoked")
        var noRev = Self.opts()
        noRev.revoked = nil
        XCTAssertEqual(reason(sp, noRev), "revocation_unavailable")
        var throwing = Self.opts()
        throwing.revoked = { _, _, _ in throw PassportConformanceTests.StubDown() }
        XCTAssertEqual(reason(sp, throwing), "revocation_unavailable")
    }

    func testHardwareBranchChecksAgeBindingAndIdentity() {
        let hwp = Self.passport(hardware: true)
        let id = hwp["id"]!.asString!
        func ev(at: Int64?, nonce: String? = "n-1") -> JSONValue {
            var doc: JObject = [:]
            if let n = nonce { doc["nonce"] = .string(n) }
            var o: JObject = ["document": .object(doc)]
            if let a = at { o["at"] = .int(a) }
            return .object(o)
        }
        func good(_ m: JObject) -> (JSONValue, PassportBinding) throws -> PassportAttestation {
            return { _, _ in PassportAttestation(ok: true, bound: true, measured: m) }
        }
        let measured: JObject = ["model_id": .string("m1"), "operator": .string("acme")]
        func run(_ evidence: JSONValue?, _ edit: (inout PassportOptions) -> Void) -> String {
            var o = Self.opts()
            edit(&o)
            return PCA.verifyPassport(Self.sign(hwp, evidence: evidence), o).reason
        }
        XCTAssertEqual(run(nil) { _ in }, "hardware_evidence_missing")
        XCTAssertEqual(run(ev(at: Self.NOW - 500, nonce: nil)) { _ in }, "hardware_evidence_missing")
        XCTAssertEqual(run(ev(at: nil)) { _ in }, "hardware_evidence_missing")
        XCTAssertEqual(run(ev(at: Self.NOW - 25 * 3_600_000)) { _ in }, "hardware_evidence_stale")
        XCTAssertEqual(run(ev(at: Self.NOW - 2_000)) { $0.maxEvidenceAgeMs = 1_000 }, "hardware_evidence_stale")
        XCTAssertEqual(run(ev(at: Self.NOW + 5)) { _ in }, "hardware_evidence_stale") // future beyond a zero skew
        XCTAssertEqual(run(ev(at: Self.NOW - 500)) { _ in }, "hardware_verifier_missing")
        XCTAssertEqual(run(ev(at: Self.NOW - 500)) { $0.attest = good(measured) }, "")
        XCTAssertEqual(run(ev(at: Self.NOW - 500)) { $0.attest = { _, _ in PassportAttestation(ok: true, bound: false, measured: measured) } }, "hardware_attestation_failed")
        XCTAssertEqual(run(ev(at: Self.NOW - 500)) { $0.attest = { _, _ in throw StubDown() } }, "hardware_attestation_failed")
        XCTAssertEqual(run(ev(at: Self.NOW - 500)) { $0.attest = good(["model_id": .string("other"), "operator": .string("acme")]) }, "hardware_identity_mismatch")
        XCTAssertEqual(run(ev(at: Self.NOW - 500)) { $0.attest = good(["operator": .string("acme")]) }, "hardware_identity_mismatch")
        // the binding the verifier is handed: subject key, passport:<id>, epoch 0, the evidence nonce
        var handed: PassportBinding?
        XCTAssertEqual(run(ev(at: Self.NOW - 500)) { $0.attest = { _, b in handed = b; return PassportAttestation(ok: true, bound: true, measured: measured) } }, "")
        XCTAssertEqual(handed, PassportBinding(holderPub: V2F.pub(Self.agent), grantRef: "passport:\(id)", epoch: 0, nonce: "n-1"))
    }
}

extension JSONValue {
    /// A copy of an object value with one member replaced.
    func setting(_ k: String, _ v: JSONValue) -> JSONValue {
        guard case var .object(o) = self else { return self }
        o[JKey(k)] = v
        return .object(o)
    }
}

extension Dictionary where Key == JKey, Value == JSONValue {
    func merging(_ other: [String: JSONValue]) -> [JKey: JSONValue] {
        var o = self
        for (k, v) in other { o[JKey(k)] = v }
        return o
    }
}
