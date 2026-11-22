import XCTest
import Foundation
@testable import AtlasPCAVerify

/// The AMD SEV-SNP report helpers (parser, P-384 report signature incl. a high-S form, VCEK extension binding, policy gate, identity, KDS fetch over an
/// injected transport) against the reference corpus: every case, every fn. The whole-chain verifiers are exercised by the real Milan / Genoa chains of
/// the EAT corpus.
final class RefSevSnpHelpersTests: XCTestCase {
    typealias S = PCASevSnp
    typealias A = RefAnalyzer

    private static func bytes(_ v: JSONValue?) throws -> [UInt8] {
        guard let b = Base.bytes(v) else { throw JSError("expected bytes") }
        return b
    }

    private static func big(_ u: UInt64) -> JSONValue { .object(["$bigint": .string(String(u))]) }
    private static func unbig(_ v: JSONValue?) -> UInt64? { v?.get("$bigint")?.asString.flatMap { UInt64($0) } }
    private static func bv(_ b: [UInt8]) -> JSONValue { Base.bytesValue(b) }

    private static func reportJSON(_ r: S.Report) -> JSONValue {
        func ver(_ v: S.Version) -> JSONValue { .object(["major": .int(Int64(v.major)), "minor": .int(Int64(v.minor)), "build": .int(Int64(v.build))]) }
        return .object([
            "version": .int(Int64(r.version)), "guest_svn": .int(Int64(r.guestSvn)), "policy": big(r.policy), "family_id": bv(r.familyId), "image_id": bv(r.imageId),
            "vmpl": .int(Int64(r.vmpl)), "signature_algo": .int(Int64(r.signatureAlgo)), "current_tcb": big(r.currentTcb), "platform_info": big(r.platformInfo),
            "report_data": bv(r.reportData), "measurement": bv(r.measurement), "host_data": bv(r.hostData), "id_key_digest": bv(r.idKeyDigest),
            "author_key_digest": bv(r.authorKeyDigest), "report_id": bv(r.reportId), "report_id_ma": bv(r.reportIdMa), "reported_tcb": big(r.reportedTcb),
            "cpuid_fam_id": .int(Int64(r.cpuidFamId)), "cpuid_mod_id": .int(Int64(r.cpuidModId)), "cpuid_step": .int(Int64(r.cpuidStep)), "chip_id": bv(r.chipId),
            "committed_tcb": big(r.committedTcb), "current_version": ver(r.currentVersion), "committed_version": ver(r.committedVersion), "launch_tcb": big(r.launchTcb),
            "launch_mit_vector": big(r.launchMitVector), "current_mit_vector": big(r.currentMitVector),
            "signature": .object(["r": bv(r.signatureR), "s": bv(r.signatureS)]), "signed_len": .int(Int64(r.signed.count)),
            "signed_sha256": .string(ACrypto.hex(ACrypto.sha256(r.signed))), "raw_len": .int(Int64(r.raw.count))])
    }

    /// A policy of a case. Numbers where a bigint is expected are ignored (the reference tests `typeof === 'bigint'`); a list is only used when it is an
    /// array, and an element that is not a string throws (`toLowerCase`).
    private static func policy(_ v: JSONValue?) throws -> S.Policy {
        guard let p = v, p.isObject else { throw JSError("Cannot read properties of null (reading 'requireEcdsaP384')") }
        func list(_ k: String) throws -> [String]? {
            guard case let .array(a)? = p.get(k) else { return nil }
            return try a.map { guard let s = $0.asString else { throw JSError("x.toLowerCase is not a function") }; return s }
        }
        return S.Policy(measurements: try list("measurements"), hostData: try list("hostData"), chipIds: try list("chipIds"), allowDebug: p.get("allowDebug") == .bool(true),
                        requireEcdsaP384: p.get("requireEcdsaP384") != .bool(false), minGuestSvn: p.get("minGuestSvn").flatMap { IV.num($0) },
                        minReportedTcb: unbig(p.get("minReportedTcb")), minCommittedTcb: unbig(p.get("minCommittedTcb")), minLaunchTcb: unbig(p.get("minLaunchTcb")),
                        requireVmpl: p.get("requireVmpl"))
    }

    private static let malformed = "VCEK extensions malformed:"

    static func call(_ c: BaseCase) -> BaseGot? {
        let a0 = A.arg(c, 0), a1 = A.arg(c, 1), a2 = A.arg(c, 2)
        switch c.fn {
        case "toHex": return A.run { .string(S.toHex(try bytes(a0))) }
        case "splitPemCertificates": return A.run { .array(S.splitPemCertificates(a0?.asString ?? "").map { .string($0) }) }
        case "parseReport": return A.run { reportJSON(try S.parseSevSnpReport(try bytes(a0))) }
        case "ecdsaP384PublicKey": return A.run { .object(["point": bv(try S.ecdsaP384PublicKey(try bytes(a0)))]) }
        case "signatureToCompact": return A.run { bv(try S.sevSnpSignatureToCompact(r: try bytes(a0?.get("r")), s: try bytes(a0?.get("s")))) }
        case "verifyReportSignature":
            // never throws: a malformed report or key is a failed signature
            guard let raw = Base.bytes(a0), let rep = try? S.parseSevSnpReport(raw), let sec1 = Base.bytes(a1), let pt = try? S.ecdsaP384PublicKey(sec1) else { return .value(.bool(false)) }
            return .value(.bool(S.verifySevSnpReportSignature(rep, vcekPoint: pt)))
        case "checkPolicy": return A.run { S.checkSevSnpPolicy(try S.parseSevSnpReport(try bytes(a0)), try policy(a1)).map { .string($0) } ?? .null }
        case "deriveIdentity": return A.run { S.makeDefaultDeriveIdentity(weightsFromHostData: a1 == .bool(true))(try S.parseSevSnpReport(try bytes(a0))) }
        case "fetchVcek":
            return A.run {
                guard let tcb = unbig(a1), let o = a2 else { throw JSError("bad arguments") }
                // the reference's "no transport and no global fetch" has no counterpart here (the default transport is the network)
                if o.get("noFetch") == .bool(true) { throw JSError("fetchVcekFromKds: no fetch implementation available") }
                var url = ""
                let body = try bytes(o.get("body"))
                let status = Int(o.get("status")?.safeInt ?? 0)
                let got = try S.fetchVcekFromKds(chipId: try bytes(a0), reportedTcb: tcb, product: o.get("product")?.asString, baseUrl: o.get("baseUrl")?.asString,
                                                 fetch: { u in url = u; return S.KdsResponse(status: status, body: body) })
                return .object(["url": .string(url), "bytes": bv(got)])
            }
        case "extractTbsCertificate": return A.run { bv(try S.extractTbsCertificate(try bytes(a0))) }
        case "extractVcekPublicKey":
            return A.run {
                let r = try S.extractVcekPublicKey(try bytes(a0))
                return .object(["point": bv(r.point), "tbs": bv(r.tbs)])
            }
        case "checkVcekReportBinding": return A.run { S.checkVcekReportBinding(try bytes(a0), try S.parseSevSnpReport(try bytes(a1))).map { .string($0) } ?? .null }
        case "constants":
            return .value(.object(["SEV_SNP_SIG_ALGO_ECDSA_P384_SHA384": .int(Int64(S.SEV_SNP_SIG_ALGO_ECDSA_P384_SHA384)), "SEV_SNP_POLICY_DEBUG_BIT": big(S.SEV_SNP_POLICY_DEBUG_BIT),
                                   "AMD_MILAN_ARK_SPKI_SHA384": .string(S.AMD_MILAN_ARK_SPKI_SHA384)]))
        default: return nil
        }
    }

    /// The reason after "VCEK extensions malformed:" carries the platform parser's text: compared by prefix.
    private static func trim(_ v: JSONValue) -> JSONValue {
        if let s = v.asString, s.hasPrefix(malformed) { return .string(malformed) }
        return v
    }

    func testEveryCaseOfTheReferenceCorpus() throws {
        let d = Base.Diffs()
        var seen: [String: Int] = [:]
        let n = try Base.each("ref-sevsnp-helpers.json.gz") { c in
            seen[c.fn, default: 0] += 1
            guard let got = Self.call(c) else { XCTFail("unhandled fn \(c.fn)"); return }
            if c.fn == "checkVcekReportBinding", !c.threw, case let .value(v) = got {
                d.add(c, Base.canon(Self.trim(v)) == Base.canon(Self.trim(c.out)) ? nil : Base.diff(c, got))
            } else {
                d.add(c, Base.diff(c, got))
            }
        }
        XCTAssertEqual(n, 248)
        XCTAssertEqual(seen, ["checkVcekReportBinding": 75, "checkPolicy": 57, "parseReport": 17, "extractTbsCertificate": 16, "splitPemCertificates": 15, "fetchVcek": 14,
                              "verifyReportSignature": 13, "ecdsaP384PublicKey": 11, "signatureToCompact": 10, "deriveIdentity": 8, "extractVcekPublicKey": 7, "toHex": 4, "constants": 1])
        d.finish(248)
    }
}
