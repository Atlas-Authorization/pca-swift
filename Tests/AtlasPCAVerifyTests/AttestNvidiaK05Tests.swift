import XCTest
import Foundation
#if canImport(CryptoKit)
import CryptoKit
#else
import Crypto // Linux: swift-crypto
#endif
@testable import AtlasPCAVerify

/// The SPDM transcript reader, the device chain bounds, the constructor's index rules and the audit digest (packages/pca/src/attest-nvidia-spdm.ts).
final class AttestNvidiaK05Tests: XCTestCase {
    typealias F = StrictChainForge

    static func zeros(_ n: Int) -> [UInt8] { [UInt8](repeating: 0, count: n) }

    /// A request || response transcript with an all-zero nonce and signature unless given. `recLen` / `opaqueLen` override the declared lengths.
    static func transcript(record: [UInt8] = [], blocks: UInt8 = 0, opaque: [UInt8] = [], nonce: [UInt8] = zeros(32), recLen: Int? = nil, opaqueLen: Int? = nil) -> [UInt8] {
        let rl = recLen ?? record.count, ol = opaqueLen ?? opaque.count
        let request: [UInt8] = [0x11, 0xe0, 0x00, 0x00] + nonce + [0x00]
        let head: [UInt8] = [0x11, 0x60, 0x00, 0x00, blocks, UInt8(rl & 0xff), UInt8(rl >> 8 & 0xff), UInt8(rl >> 16 & 0xff)]
        let opaqueHead: [UInt8] = [UInt8(ol & 0xff), UInt8(ol >> 8 & 0xff)]
        let tail: [UInt8] = zeros(32) + opaqueHead + opaque + zeros(96)
        return request + head + record + tail
    }

    static func block(_ index: UInt8, _ digest: [UInt8]) -> [UInt8] {
        let size = digest.count + 3
        let head: [UInt8] = [index, 0x01, UInt8(size & 0xff), UInt8(size >> 8), 0x01, UInt8(digest.count & 0xff), UInt8(digest.count >> 8)]
        return head + digest
    }

    func why(_ b: [UInt8]) -> String {
        do {
            _ = try Nvidia.parseSpdm(b)
            return ""
        } catch {
            return Nvidia.msg(error)
        }
    }

    // ---- attest-nvidia-spdm.ts:120-176 ----

    func testMinimumLength() {
        let t = Self.transcript()
        XCTAssertEqual(t.count, 175)
        XCTAssertEqual(why(t), "")
        XCTAssertEqual(why(Array(t.dropLast())), "parseNvidiaSpdmEvidence: transcript too short (174)")
    }

    func testRecordLengthIsThreeBytes() throws {
        let digest = [UInt8](repeating: 0x5a, count: 65_529)
        let rep = try Nvidia.parseSpdm(Self.transcript(record: [0x01, 0x01, 0xfc, 0xff, 0x01, 0xf9, 0xff] + digest, blocks: 1))
        XCTAssertEqual(rep.measurements.count, 1)
        XCTAssertEqual(rep.measurements[0].index, 1)
        XCTAssertEqual(rep.measurements[0].digest, digest)
    }

    func testRecordBounds() throws {
        XCTAssertEqual(why(Self.transcript(recLen: 1)), "parseNvidiaSpdmEvidence: measurement record length overruns transcript")
        XCTAssertEqual(why(Self.transcript(record: [0x01, 0x01, 0x00], blocks: 0)), "parseNvidiaSpdmEvidence: truncated measurement block header")
        XCTAssertEqual(why(Self.transcript(record: [0x01, 0x01, 0x02, 0x00, 0x01, 0x00], blocks: 1)), "parseNvidiaSpdmEvidence: measurement block overruns record")
        XCTAssertEqual(why(Self.transcript(record: [0x01, 0x01, 0x03, 0x00, 0x01, 0x01, 0x00], blocks: 1)), "parseNvidiaSpdmEvidence: DMTF value overruns measurement block")
        let empty = try Nvidia.parseSpdm(Self.transcript(record: [0x07, 0x01, 0x03, 0x00, 0x01, 0x00, 0x00], blocks: 1))
        XCTAssertEqual(empty.measurements[0].index, 7)
        XCTAssertEqual(empty.measurements[0].digest, [])
        let one = try Nvidia.parseSpdm(Self.transcript(record: Self.block(9, [0xaa]), blocks: 1))
        XCTAssertEqual(one.measurements[0].digest, [0xaa])
    }

    func testOpaqueBounds() throws {
        XCTAssertEqual(why(Self.transcript(opaque: [0x03, 0x00, 0x00])), "parseNvidiaSpdmEvidence: truncated opaque TLV header")
        XCTAssertEqual(why(Self.transcript(opaque: [0x03, 0x00, 0x01, 0x00])), "parseNvidiaSpdmEvidence: opaque TLV overruns opaque data")
        let empty = try Nvidia.parseSpdm(Self.transcript(opaque: [0x03, 0x00, 0x00, 0x00]))
        XCTAssertEqual(empty.opaque[3], [])
        let full = try Nvidia.parseSpdm(Self.transcript(opaque: [0x03, 0x00, 0x01, 0x00, 0x41]))
        XCTAssertEqual(full.opaque[3], [0x41])
    }

    /// A report whose version was never read is refused (attest-nvidia-spdm.ts:342).
    func testAnUnreadVersionIsRefused() {
        XCTAssertEqual(Nvidia.versionProblem(SpdmReport()), "SPDM version 0x0/0x0 is not an accepted GET_MEASUREMENTS version")
    }

    // ---- attest-nvidia-spdm.ts:178-184 ----

    /// String.prototype.slice
    func testJsSlice() {
        let rows: [(Int, Int, String)] = [
            (0, 2, "ab"), (1, 3, "bc"), (0, 4, "abcd"), (0, 99, "abcd"), (-1, 4, "d"), (-2, -1, "c"), (-4, 1, "a"), (-9, 2, "ab"), (-9, -9, ""), (2, 2, ""), (3, 1, ""), (99, 99, ""),
        ]
        for (a, b, want) in rows { XCTAssertEqual(Nvidia.jsSlice("abcd", a, b), want, "\(a),\(b)") }
    }

    func testFormatVbiosVersion() {
        XCTAssertEqual(Nvidia.formatVbiosVersion([0x00, 0x9f, 0x00, 0x96, 0x04, 0x00, 0x00, 0x00]), "96.00.9f.00.04")
        XCTAssertEqual(Nvidia.formatVbiosVersion([0xaa]), "a")
        XCTAssertEqual(Nvidia.formatVbiosVersion([]), "")
    }

    // ---- the chain ----

    func testAnUnreadableCertificateIsNotACA() throws {
        XCTAssertFalse(Nvidia.certIsCA(AttCert()))
        XCTAssertTrue(Nvidia.certIsCA(try Cert.parseDER(F.selfSigned(F.rootKey, "Bare"))))
    }

    /// attest-nvidia-spdm.ts:196
    func testChainLengthBound() {
        let pem = F.pem(F.selfSigned(F.rootKey, "Bare")), pins = [F.pin(F.rootKey)]
        let five = Array(repeating: pem, count: 5).joined(separator: "\n"), six = five + "\n" + pem
        XCTAssertEqual(Nvidia.verifyDeviceChain(six, pins, F.NOW).1, "device chain unparseable: parsePemChain: chain longer than 5")
        XCTAssertFalse(Nvidia.verifyDeviceChain(five, pins, F.NOW).1.hasPrefix("device chain unparseable"))
    }

    /// attest-nvidia-spdm.ts:214: x509ValidAt with no skew. F.cert is valid 2025-01-01 .. 2035-01-01.
    func testChainValidityHasNoSkew() {
        let pem = F.pem(F.selfSigned(F.rootKey, "Bare")), pins = [F.pin(F.rootKey)]
        let from = DER.epochMs(2025, 1, 1, 0, 0, 0)!, to = DER.epochMs(2035, 1, 1, 0, 0, 0)!
        let outside = "device chain cert #0 is outside its validity window"
        XCTAssertEqual(Nvidia.verifyDeviceChain(pem, pins, from).1, "")
        XCTAssertEqual(Nvidia.verifyDeviceChain(pem, pins, to).1, "")
        XCTAssertEqual(Nvidia.verifyDeviceChain(pem, pins, from - 1).1, outside)
        XCTAssertEqual(Nvidia.verifyDeviceChain(pem, pins, to + 1).1, outside)
    }

    // ---- the constructor (attest-nvidia-spdm.ts:317-318) ----

    func config(_ meas: JObject) -> JObject { ["rootSpkiSha256": .array([.string("ab")]), "policy": .object(["measurements": .object(meas)])] }

    func testMeasurementIndexRange() throws {
        XCTAssertEqual(try NvidiaVerifier(config(["0": .string("AA")])).want.map { $0.index }, [0])
        XCTAssertEqual(try NvidiaVerifier(config(["255": .string("AA")])).want.map { $0.index }, [255])
        for bad in ["abc", "1.5", "-1", "256"] {
            XCTAssertThrowsError(try NvidiaVerifier(config([JKey(bad): .string("AA")])), bad) { e in
                XCTAssertEqual(Nvidia.msg(e), "createNvidiaSpdmVerifier: measurement index out of range", bad)
            }
        }
    }

    /// Numeric order, not the order of the key text; a tie of the index goes by the key.
    func testPinnedMeasurementOrder() throws {
        let v = try NvidiaVerifier(config(["10": .string("AA"), "9": .string("BB"), "2": .string("cc")]))
        XCTAssertEqual(v.want.map { $0.index }, [2, 9, 10])
        XCTAssertEqual(v.want.map { $0.digest }, ["cc", "bb", "aa"])
        let tie = try NvidiaVerifier(config(["1": .string("aa"), "1.0": .string("bb")]))
        XCTAssertEqual(tie.want.map { $0.digest }, ["aa", "bb"])
    }

    // ---- the audit digest (attest-nvidia-spdm.ts:297-301) ----

    func testMeasurementsDigestIsInIndexOrderAndStable() throws {
        let a: [UInt8] = [0xa1], b: [UInt8] = [0xb2], c: [UInt8] = [0xc3]
        let binding = AttestationBinding(holderPub: "holder", grantRef: "grant", epoch: 1, nonce: "nonce")
        let nonce = ACrypto.sha256(Attest.bindingBytes(binding).bytes!)
        let record: [UInt8] = Self.block(2, a) + Self.block(1, c) + Self.block(2, b)
        let body = Array(Self.transcript(record: record, blocks: 3, nonce: nonce).dropLast(96))
        let sig = try F.leafKey.signature(for: Data(body))
        let evidence: [UInt8] = body + Array(sig.rawRepresentation)
        let v = try NvidiaVerifier(["rootSpkiSha256": .array([.string(F.pin(F.rootKey))]), "policy": .object(["measurements": .object(["1": .string(ACrypto.hex(c))])])])
        let ev: JObject = ["evidence": .string(Attest.base64StdEncode(evidence)), "certChainPem": .string(F.chain().pem)]
        let r = v.verify(evidence: .object(ev), expected: binding, nowMs: F.NOW)
        XCTAssertEqual(r.reason, "")
        XCTAssertTrue(r.ok)
        let ordered: [UInt8] = c + a + b
        XCTAssertEqual(r.hostAsserted?["gpu_measurements_sha384"], ACrypto.hex(ACrypto.sha384(ordered)))
    }
}
