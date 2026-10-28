import XCTest
import Foundation
@testable import AtlasPCAVerify

/// Replays packages/pca/conformance/attestation-evidence-vectors.json: every vendor verifier answers exactly what the reference
/// verifiers answered when the file was generated (reason text included; an OpenSSL / node:crypto message is compared by its
/// stable prefix), and the strict X.509 readers answer every unit row. The file is produced by the TypeScript generator (tsx
/// scripts/gen-conformance-attestation.ts in packages/pca); a missing file FAILS the test (it is never skipped).
final class AttestVectorTests: XCTestCase {
    static func loadVectors() throws -> JSONValue {
        let url = ConformanceTests.conformanceDir.appendingPathComponent("attestation-evidence-vectors.json")
        guard FileManager.default.fileExists(atPath: url.path) else {
            throw NSError(domain: "attest", code: 1, userInfo: [NSLocalizedDescriptionKey: "conformance/attestation-evidence-vectors.json is missing: generate it with the TypeScript reference (tsx scripts/gen-conformance-attestation.ts in packages/pca)"])
        }
        return try ConformanceTests.load("attestation-evidence-vectors.json")
    }

    /// Replaces every {"$blob": id} with the string stored under blobs[id].
    static func hydrate(_ x: JSONValue, _ blobs: JObject) -> JSONValue {
        switch x {
        case let .array(a): return .array(a.map { hydrate($0, blobs) })
        case let .object(o):
            if o.count == 1, let id = o["$blob"]?.asString, let v = blobs[JKey(id)] { return v }
            return .object(o.mapValues { hydrate($0, blobs) })
        default: return x
        }
    }

    static func binding(_ v: JSONValue?) -> AttestationBinding? {
        guard case let .object(m)? = v else { return nil }
        return AttestationBinding(holderPub: m["holderPub"]?.asString ?? "", grantRef: m["grantRef"]?.asString ?? "", epoch: Attest.asFinite(m["epoch"]) ?? 0, nonce: m["nonce"]?.asString ?? "")
    }

    /// verifier_from_config + verify for one row: the wire result, or {"construct_error": text}.
    static func runRow(_ row: JSONValue) -> JSONValue {
        let vendor = row.get("vendor")?.asString ?? ""
        let ver: VendorVerifier
        do { ver = try VendorVerifier(vendor: vendor, config: row.get("config")?.asObject) } catch {
            return .object(["construct_error": .string((error as? AttestationConfigError)?.message ?? "\(error)")])
        }
        let ev = row.get("evidence")
        return ver.verify(evidence: ev, expected: binding(row.get("expected_binding")), nowMs: Int64(Attest.asFinite(row.get("now")) ?? 0)).wire
    }

    func testVendorVerifierSchemaAndSize() throws {
        let doc = try Self.loadVectors()
        let schema = doc.get("verifier_config_schema")?.asObject ?? [:]
        XCTAssertEqual(schema.keys.map { $0.s }.sorted(), AttestationVendors.all.sorted())
        let rows = doc.get("attestation_vectors")?.asArray ?? []
        XCTAssertGreaterThanOrEqual(rows.count, 750)
        var seen = Set<String>()
        var perVendor: [String: Int] = [:]
        for r in rows {
            let id = r.get("id")?.asString ?? ""
            XCTAssertTrue(seen.insert(id).inserted, "duplicate vector id \(id)")
            perVendor[r.get("vendor")?.asString ?? "", default: 0] += 1
        }
        for v in AttestationVendors.all { XCTAssertGreaterThan(perVendor[v] ?? 0, 0, "no vectors for \(v)") }
    }

    func runVendor(_ vendor: String) throws {
        let doc = try Self.loadVectors()
        let blobs = doc.get("blobs")?.asObject ?? [:]
        var bad: [String] = []
        var n = 0
        for r in doc.get("attestation_vectors")?.asArray ?? [] where r.get("vendor")?.asString == vendor {
            n += 1
            let row = Self.hydrate(r, blobs)
            let id = row.get("id")?.asString ?? "?"
            let got = Self.runRow(row)
            var expect = row.get("expect")?.asObject ?? [:]
            var gotObj = got.asObject ?? [:]
            if expect["reason_match"]?.asString == "prefix" {
                let prefix = expect["reason_prefix"]?.asString ?? ""
                let reason = gotObj["reason"]?.asString ?? ""
                if !IV.startsWith(reason, prefix) { bad.append("\(id): reason '\(reason)' does not start with '\(prefix)'") }
                gotObj["reason"] = nil
                expect["reason"] = nil
            }
            expect["reason_match"] = nil
            expect["reason_prefix"] = nil
            if Canonical.canonicalize(.object(gotObj)) != Canonical.canonicalize(.object(expect)) {
                bad.append("\(id) (\(row.get("intent")?.asString ?? "")):\n    got  \(Canonical.canonicalize(.object(gotObj)))\n    want \(Canonical.canonicalize(.object(expect)))")
            }
        }
        XCTAssertGreaterThan(n, 0, "no vectors for \(vendor)")
        XCTAssertTrue(bad.isEmpty, "\(bad.count)/\(n) divergent:\n" + bad.prefix(25).joined(separator: "\n"))
    }

    func testAmdSevSnpVectors() throws { try runVendor("amd-sev-snp") }
    func testIntelTdxDcapVectors() throws { try runVendor("intel-tdx-dcap") }
    func testAzureMaaVectors() throws { try runVendor("azure-maa") }
    func testGcpConfidentialSpaceVectors() throws { try runVendor("gcp-confidential-space") }
    func testNvidiaGpuVectors() throws { try runVendor("nvidia-gpu-spdm") }

    // ---- the strict X.509 readers ----

    static func b64(_ v: JSONValue?) -> [UInt8] { Attest.nodeB64(v?.asString ?? "") }

    /// {"ok": true, "value": V} or {"ok": false, "error": text}
    static func runX509(_ fn: String, _ input: JSONValue?) -> JSONValue {
        func ok(_ v: JSONValue) -> JSONValue { .object(["ok": .bool(true), "value": v]) }
        func bad(_ e: Error) -> JSONValue { .object(["ok": .bool(false), "error": .string((e as? AttestError)?.message ?? "\(e)")]) }
        func extList(_ t: DER.ExtTable) -> JSONValue {
            .array(t.oids.map { (oid: String) -> JSONValue in
                let e = t.m[oid]
                return JSONValue.object(["oid": .string(oid), "critical": .bool(e?.critical ?? false), "value": .string(ACrypto.hex(e?.value ?? []))])
            })
        }
        func instant(_ i: DER.Instant) -> JSONValue { i.map { JSONValue.int($0) } ?? JSONValue.null }
        do {
            switch fn {
            case "read_cert_role_info":
                let info = try DER.readCertRoleInfo(b64(input?.get("cert")))
                var m: JObject = ["hasBasicConstraints": .bool(info.hasBasicConstraints), "ca": .bool(info.ca), "hasKeyUsage": .bool(info.hasKeyUsage), "keyCertSign": .bool(info.keyCertSign)]
                if info.pathLen >= 0 { m["pathLen"] = .int(Int64(info.pathLen)) }
                return ok(.object(m))
            case "parse_cert_extensions": return ok(extList(try DER.parseCertExtensions(b64(input?.get("cert")))))
            case "parse_tbs_extensions": return ok(extList(try DER.parseTbsExtensions(b64(input?.get("tbs")))))
            case "tbs_of_certificate": return ok(.string(Attest.base64StdEncode(try DER.tbsOfCertificate(b64(input?.get("cert"))))))
            case "unrecognised_critical_extension":
                var rec: Set<String>?
                if case let .array(l)? = input?.get("recognised") { rec = Set(l.compactMap { $0.asString }) }
                if let oid = try DER.unrecognisedCriticalExtension(b64(input?.get("cert")), rec) { return ok(.string(oid)) }
                return ok(.null)
            case "check_chain_roles":
                let chain = (input?.get("chain")?.asArray ?? []).map { b64($0) }
                let why = DER.checkChainRoles(chain)
                return ok(why.isEmpty ? .null : .string(why))
            case "der_validity_ms":
                let (from, to) = DER.derValidity(b64(input?.get("cert")))
                return ok(.object(["from": instant(from), "to": instant(to)]))
            case "parse_der_time":
                return ok(instant(DER.parseDerTime(Int(Attest.asFinite(input?.get("tag")) ?? 0), Array((input?.get("text")?.asString ?? "").utf8))))
            default:
                return .object(["ok": .bool(false), "error": .string("unknown x509 function \(fn)")])
            }
        } catch { return bad(error) }
    }

    func testX509StrictVectors() throws {
        let doc = try Self.loadVectors()
        let blobs = doc.get("blobs")?.asObject ?? [:]
        let rows = doc.get("x509_vectors")?.asArray ?? []
        XCTAssertGreaterThanOrEqual(rows.count, 90)
        var bad: [String] = []
        for r in rows {
            let row = Self.hydrate(r, blobs)
            let got = Self.runX509(row.get("fn")?.asString ?? "", row.get("input"))
            if Canonical.canonicalize(got) != Canonical.canonicalize(row.get("expect") ?? .null) {
                bad.append("\(row.get("id")?.asString ?? "?"): got \(Canonical.canonicalize(got)) want \(Canonical.canonicalize(row.get("expect") ?? .null))")
            }
        }
        XCTAssertTrue(bad.isEmpty, "\(bad.count)/\(rows.count) divergent:\n" + bad.prefix(25).joined(separator: "\n"))
    }
}
