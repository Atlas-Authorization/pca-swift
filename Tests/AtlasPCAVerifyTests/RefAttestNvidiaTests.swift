import XCTest
import Foundation
import CryptoKit
@testable import AtlasPCAVerify

/// The per-function surface of the NVIDIA GPU-CC attestation modules against ref-attest-nvidia and ref-attest-nvidia-rim (the real public H100 / own-H100 / GB100 captures with
/// byte-level mutations, plus synthetic PKI forged with fixed public seeds). A corpus string over 400 characters lives in the top-level `blobs` table as {"$blob": id}; it is
/// hydrated before use. A failure reason that carries library text (an inner parser's or OCSP library's message) only has to be a refusal in the same place.
final class RefAttestNvidiaTests: XCTestCase {
    typealias N = PCAAttestNvidia
    static func b(_ x: [UInt8]) -> JSONValue { Base.bytesValue(x) }
    static func hex(_ x: [UInt8]) -> String { ACrypto.hex(x) }
    static func bytes(_ v: JSONValue?) -> [UInt8]? { Base.bytes(v) }

    static func reportSummary(_ r: N.Report, _ raw: [UInt8]) -> JSONValue {
        var opaque: JObject = [:]
        for (t, v) in r.opaque { opaque[JKey(String(t))] = b(v) }
        return .object(["request": .object(["version": .int(Int64(r.version)), "code": .int(Int64(r.code)), "param1": .int(Int64(r.param1)), "param2": .int(Int64(r.param2)), "nonce": b(r.nonce), "slot": .int(Int64(r.slot))]),
                        "response": .object(["version": .int(Int64(r.responseVersion)), "code": .int(Int64(r.responseCode)), "numBlocks": .int(Int64(r.numBlocks)),
                                             "measurements": .array(r.measurements.map { .object(["index": .int(Int64($0.index)), "valueType": .int(Int64($0.valueType)), "digest": b($0.digest)]) }),
                                             "responderNonce": b(r.responderNonce), "opaque": .object(opaque), "signature": b(r.signature)]),
                        "signedBytesLength": .int(Int64(r.signedBytes.count)), "signedBytesSha256": .string(hex(ACrypto.sha256(r.signedBytes)))])
    }

    static let libraryReason = ["device chain unparseable: ", "OCSP response rejected:"]
    /// Where the reference's reason is library text, the native's is replaced by it after checking the native refused with the same leading words.
    static func adopt(_ got: JSONValue, _ want: JSONValue) -> JSONValue {
        switch (got, want) {
        case let (.array(g), .array(w)) where g.count == w.count: return .array(zip(g, w).map { adopt($0, $1) })
        case let (.object(g), .object(w)):
            var out = g
            if let wr = w["reason"]?.asString, let gr = g["reason"]?.asString {
                if let p = libraryReason.first(where: { wr.hasPrefix($0) }), gr.hasPrefix(p) { out["reason"] = .string(wr) }
                // a chain reason that embeds a library message: same words up to it
                else if let r = wr.range(of: "OCSP response rejected:"), let g2 = gr.range(of: "OCSP response rejected:"), wr[..<r.lowerBound] == gr[..<g2.lowerBound] { out["reason"] = .string(wr) }
            }
            for (k, wv) in w { if let gv = out[k] { out[k] = adopt(gv, wv) } }
            return .object(out)
        default: return got
        }
    }

    static let ocspFns: Set<String> = ["ocspRequest", "ocspUrls", "ocspVerify", "ocspChain", "fetchOcsp", "asn1TimesWellFormed"]

    static func ocspCall(_ c: BaseCase) -> BaseGot? {
        let a0 = c.arg(0), a1 = c.arg(1), a2 = c.arg(2), a3 = c.arg(3)
        switch c.fn {
        case "ocspRequest": return Base.run { b(try N.ocspRequest(certPem: a0?.asString ?? "", issuerPem: a1?.asString ?? "", nonce: bytes(a2?.get("nonce")), hash: a2?.get("hash")?.asString)) }
        case "ocspUrls": return Base.run { .array(try N.ocspUrls(certPem: a0?.asString ?? "").map { .string($0) }) }
        case "asn1TimesWellFormed": return .value(.bool(N.asn1TimesWellFormed(bytes(a0) ?? [])))
        case "ocspVerify":
            return Base.run {
                guard let resp = bytes(a0) else { throw JSError("response") }
                return try N.ocspVerify(resp, chainPem: a1?.get("chainPem")?.asString ?? "", certIndex: a1?.get("certIndex"), issuerIndex: a1?.get("issuerIndex"), nowMs: IV.num(a1?.get("nowMs")) ?? 0,
                                        maxAgeMs: a1?.get("maxAgeMs"), expectedNonce: bytes(a1?.get("expectedNonce")), clockSkewMs: a1?.get("clockSkewMs"))
            }
        case "ocspChain":
            return Base.run {
                let nonces: [[UInt8]?] = (a3?.get("expectedNonces")?.asArray ?? []).map { bytes($0) }
                return try N.ocspChain(a0?.asString ?? "", (a1?.asArray ?? []).compactMap { bytes($0) }, Int64(IV.num(a2) ?? 0), a3, expectedNonces: nonces)
            }
        case "fetchOcsp":
            let (f, requests) = scriptedFetch(c.arg(0)?.get("response"))
            var out: JObject
            do {
                let r = try N.fetchOcsp(certPem: a0?.get("certPem")?.asString ?? "", issuerPem: a0?.get("issuerPem")?.asString ?? "", url: a0?.get("opts")?.get("url")?.asString, nonce: bytes(a0?.get("opts")?.get("nonce")), fetch: f)
                out = ["ok": .bool(true), "request": b(r.request), "response": b(r.response)]
            } catch { out = ["ok": .bool(false), "error": .string(PCAFrostNet.text(error))] }
            out["requests"] = .array(requests())
            return .value(.object(out))
        default: return nil
        }
    }

    static let rimFns: Set<String> = ["checkRevocation", "fetchRim", "fetchCrl"]
    static let rimCorpusFns: Set<String> = ["verifyRim", "collateralHook"]

    /// An injected fetch that records every request and answers from the case's script: `{status?, body (json) | bodyBytes, $throws?}`.
    static func scriptedFetch(_ r: JSONValue?) -> (N.Fetch, () -> [JSONValue]) {
        final class Log { var items: [JSONValue] = [] }
        let l = Log()
        let f: N.Fetch = { url, method, ct, body in
            var entry: JObject = ["url": .string(url), "method": .string(method), "contentType": ct.map { .string($0) } ?? .null]
            if let bd = body { entry["bodyBytes"] = .int(Int64(bd.count)) }
            l.items.append(.object(entry))
            if let t = r?.get("$throws")?.asString { throw JSError(t) }
            let body: [UInt8] = bytes(r?.get("bodyBytes")) ?? Array(JS.stringify(r?.get("body") ?? .null).utf8)
            return N.HttpResponse(status: Int(IV.num(r?.get("status")) ?? 200), body: body)
        }
        return (f, { l.items })
    }

    /// The fixed messages of the module itself are exact; any other error text (a JSON or network library's) is informative.
    static let fixedErrors = ["RIM fetch failed: HTTP", "fetchNvidiaRim: ", "RIM fetch: response has no rim field", "CRL fetch failed: HTTP", "fetchNvidiaCrl: "]

    static func fetchCall(_ c: BaseCase) -> BaseGot {
        let a = c.arg(0)
        let (f, requests) = scriptedFetch(a?.get("response"))
        var out: JObject
        do {
            switch c.fn {
            case "fetchRim": out = ["ok": .bool(true), "value": .string(try N.fetchRim(id: a?.get("id")?.asString ?? "", baseUrl: a?.get("baseUrl")?.asString, fetch: f))]
            default: out = ["ok": .bool(true), "value": b(try N.fetchCrl(url: a?.get("url")?.asString ?? "", fetch: f))]
            }
        } catch {
            var msg = PCAFrostNet.text(error)
            if !fixedErrors.contains(where: { msg.hasPrefix($0) }), let w = c.out.get("error")?.asString, !fixedErrors.contains(where: { w.hasPrefix($0) }) { msg = w }
            out = ["ok": .bool(false), "error": .string(msg)]
        }
        out["requests"] = .array(requests())
        return .value(.object(out))
    }

    static func wireBundle(_ v: JSONValue?) -> JSONValue? {
        guard let o = v?.asObject else { return nil }
        var out = o
        for k in ["crls", "ocsp"] { if let a = o[JKey(k)]?.asArray { out[JKey(k)] = .array(a.compactMap { bytes($0).map { .string(Base64URLStrict.encode($0)) } }) } }
        return .object(out)
    }

    static func rimCall(_ c: BaseCase) -> BaseGot? {
        let a0 = c.arg(0), a1 = c.arg(1), a2 = c.arg(2), a3 = c.arg(3), a4 = c.arg(4)
        switch c.fn {
        case "verifyRim":
            return .value(N.verifyRim(a0?.asString ?? "", (a1?.get("rimRootSpkiSha256")?.asArray ?? []).compactMap { $0.asString }, Int64(IV.num(a1?.get("nowMs")) ?? 0)))
        case "collateralHook":
            return Base.run {
                guard let ev = bytes(a0?.get("evidence")) else { throw JSError("evidence") }
                return try N.collateralHook(opts: a0?.get("opts"), bundle: wireBundle(a0?.get("bundle")), evidence: ev, chainPem: a0?.get("chainPem")?.asString ?? "", nowMs: Int64(IV.num(a0?.get("nowMs")) ?? 0))
            }
        case "checkRevocation":
            return Base.run {
                try N.checkRevocation(a0?.asString ?? "", (a1?.asArray ?? []).compactMap { bytes($0) }, Int64(IV.num(a2) ?? 0), (a3?.asArray ?? []).compactMap { $0.asString }, a4 ?? .string("cdp"))
            }
        case "fetchRim", "fetchCrl": return fetchCall(c)
        default: return nil
        }
    }

    static let spdmFns: Set<String> = ["constants", "parseReport", "formatVbiosVersion", "spkiSha256Hex", "parsePemChain", "verifyDeviceChain", "verifySpdmSignature", "spdmChallenge", "rimIds", "compareReport"]

    static func call(_ c: BaseCase) -> BaseGot? {
        let a0 = c.arg(0), a1 = c.arg(1), a2 = c.arg(2)
        switch c.fn {
        case "constants":
            func strs(_ a: [String]) -> JSONValue { .array(a.map { .string($0) }) }
            var op: JObject = [:]
            for (k, v) in N.NVIDIA_OPAQUE { op[JKey(k)] = .int(Int64(v)) }
            return .value(.object(["NVIDIA_SPDM_SUITE": .string(N.NVIDIA_SPDM_SUITE), "NVIDIA_OPAQUE": .object(op), "NVIDIA_RIM_BASE_URL": .string(N.NVIDIA_RIM_BASE_URL),
                                   "NVIDIA_GH100_CRL_URLS": strs(N.NVIDIA_GH100_CRL_URLS), "NVIDIA_GB100_CRL_URLS": strs(N.NVIDIA_GB100_CRL_URLS), "NVIDIA_OCSP_URL": .string(N.NVIDIA_OCSP_URL),
                                   "NVIDIA_OCSP_DEFAULT_MAX_AGE_MS": .int(Int64(N.NVIDIA_OCSP_DEFAULT_MAX_AGE_MS))]))
        case "parseReport": return Base.run { guard let raw = bytes(a0) else { throw JSError("bytes") }; return reportSummary(try N.parseReport(raw), raw) }
        case "formatVbiosVersion": return Base.run { guard let raw = bytes(a0) else { throw JSError("bytes") }; return .string(N.formatVbiosVersion(raw)) }
        case "spkiSha256Hex": return Base.run { .string(try N.spkiSha256Hex(a0?.asString ?? "")) }
        case "parsePemChain": return Base.run { .array(try N.parsePemChain(a0?.asString ?? "")) }
        case "verifyDeviceChain":
            return .value(N.verifyDeviceChain(a0?.asString ?? "", (a1?.asArray ?? []).compactMap { $0.asString }, Int64(IV.num(a2) ?? 0)))
        case "verifySpdmSignature": return Base.run { guard let raw = bytes(a0) else { throw JSError("bytes") }; return .bool(try N.verifySpdmSignature(raw, a1?.asString ?? "")) }
        case "spdmChallenge": return Base.run { b(try N.spdmChallenge(a0)) }
        case "rimIds":
            return Base.run {
                guard let raw = bytes(a0) else { throw JSError("bytes") }
                guard let ids = try N.rimIds(raw) else { return .null }
                return .object(["chip": .string(ids.chip), "driver": .string(ids.driver), "vbios": .string(ids.vbios), "driverVersion": .string(ids.driverVersion), "vbiosVersion": .string(ids.vbiosVersion)])
            }
        case "compareReport": return Base.run { guard let raw = bytes(a0) else { throw JSError("bytes") }; return try N.compareReport(raw, a1, a2) }
        default: return nil
        }
    }

    /// Loads a corpus whose long strings live in the `blobs` table.
    static func cases(_ file: String) throws -> [BaseCase] {
        let doc = K042.parse(String(decoding: try K042.bytes(file), as: UTF8.self))
        let blobs = doc.get("blobs")?.asObject ?? [:]
        return (doc.get("cases")?.asArray ?? []).map { raw in
            BaseCase(fn: raw.get("fn")?.asString ?? "", name: raw.get("name")?.asString ?? "?", args: (raw.get("args")?.asArray ?? []).map { AttestVectorTests.hydrate($0, blobs) },
                     out: AttestVectorTests.hydrate(raw.get("out") ?? .null, blobs), suspect: false, raw: raw)
        }
    }

    func testTheSpdmAndChainSurface() throws {
        let d = Base.Diffs()
        var seen: [String: Int] = [:]
        for c in try Self.cases("ref-attest-nvidia.json.gz") where Self.spdmFns.contains(c.fn) {
            seen[c.fn, default: 0] += 1
            guard var got = Self.call(c) else { XCTFail("unhandled fn \(c.fn)"); continue }
            if case let .value(v) = got { got = .value(Self.adopt(v, c.out)) }
            d.add(c, Base.diff(c, got))
        }
        XCTAssertEqual(seen, ["constants": 1, "parseReport": 66, "formatVbiosVersion": 9, "spkiSha256Hex": 3, "parsePemChain": 12, "verifyDeviceChain": 63, "verifySpdmSignature": 15, "spdmChallenge": 10, "rimIds": 26, "compareReport": 26])
        d.finish(231)
    }

    func testTheRimRevocationAndHookSurface() throws {
        let d = Base.Diffs()
        var seen: [String: Int] = [:]
        for file in ["ref-attest-nvidia.json.gz", "ref-attest-nvidia-rim.json.gz"] {
            for c in try Self.cases(file) where Self.rimFns.contains(c.fn) || Self.rimCorpusFns.contains(c.fn) {
                seen[c.fn, default: 0] += 1
                guard let got = Self.rimCall(c) else { XCTFail("unhandled fn \(c.fn)"); continue }
                d.add(c, Base.diff(c, got))
            }
        }
        XCTAssertEqual(seen, ["checkRevocation": 39, "fetchRim": 12, "fetchCrl": 4, "verifyRim": 108, "collateralHook": 55])
        d.finish(218)
    }

    /// Cases where this verifier is STRICTER than the reference, each pinned to the exact refusal it gives (never skipped): the reference emits a request with an empty
    /// hash OID for md5, and accepts or words differently a response whose time field a flipped byte put out of range.
    static let nativeStricterOcsp: [String: String] = [
        "ocspRequest/hash-md5": "unsupported CertID hash md5",
        "ocspVerify/real-byte80-flipped": "response carries a malformed (out-of-range) ASN.1 time",
        "ocspVerify/real-byte500-flipped": "response carries a malformed (out-of-range) ASN.1 time",
    ]

    func testTheOcspSurface() throws {
        let d = Base.Diffs()
        var seen: [String: Int] = [:]
        for c in try Self.cases("ref-attest-nvidia.json.gz") where Self.ocspFns.contains(c.fn) {
            seen[c.fn, default: 0] += 1
            guard var got = Self.ocspCall(c) else { XCTFail("unhandled fn \(c.fn)"); continue }
            if case let .value(v) = got {
                var adopted = Self.adopt(v, c.out)
                // fetch errors that carry a network library's text are informative
                if c.fn == "fetchOcsp", adopted.get("ok") == .bool(false), let w = c.out.get("error")?.asString, !w.hasPrefix("OCSP fetch failed"), !w.hasPrefix("fetchNvidiaOcsp") , case var .object(o) = adopted { o["error"] = .string(w); adopted = .object(o) }
                got = .value(adopted)
            }
            if let reason = Self.nativeStricterOcsp[c.name] {
                switch got {
                case .threw: XCTAssertEqual(Base.lastThrown, reason, "\(c.name): the native refusal")
                case let .value(v): XCTAssertEqual(v.get("ok"), .bool(false), c.name); XCTAssertEqual(v.get("reason")?.asString, reason, "\(c.name): the native refusal")
                }
                d.add(c, nil)
                continue
            }
            d.add(c, Base.diff(c, got))
        }
        XCTAssertEqual(seen, ["ocspRequest": 20, "ocspUrls": 8, "ocspVerify": 81, "ocspChain": 30, "fetchOcsp": 5, "asn1TimesWellFormed": 37])
        d.finish(181)
    }

    /// Every case of both corpora belongs to one of the groups above.
    func testNoCaseIsLeftOut() throws {
        let all = Self.spdmFns.union(Self.rimFns).union(Self.rimCorpusFns).union(Self.ocspFns)
        var n = 0
        for file in ["ref-attest-nvidia.json.gz", "ref-attest-nvidia-rim.json.gz"] {
            for c in try Self.cases(file) { n += 1; XCTAssertTrue(all.contains(c.fn), "a corpus fn no group replays: \(c.fn)") }
        }
        XCTAssertEqual(n, 630)
    }
}
