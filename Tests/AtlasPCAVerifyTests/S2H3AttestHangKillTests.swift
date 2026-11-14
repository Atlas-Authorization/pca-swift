import XCTest
import Foundation
@testable import AtlasPCAVerify

/// Round-2 hang sheet 3, attestation and registry parts: each call runs under S2Deadline.within (3 s); the unmutated code takes
/// milliseconds, a mutant that loses the loop's progress never returns.
final class A0H3AttestIntelCollateralHangTests: XCTestCase {
    private typealias C = IntelCollateral

    /// Line 144: the revoked-entry walk must move to the next entry.
    func testARevokedListIsWalkedToItsEnd() {
        let got: Set<String>?? = S2Deadline.within(3, "IntelCollateral.parseCRL with revoked entries") {
            let e1: [UInt8] = IntelForge.seq(DERB.tlv(0x02, [0x00, 0x8f]) + IntelForge.utc("250101000000Z"))
            let e2: [UInt8] = IntelForge.seq(DERB.tlv(0x02, [0x01, 0x02]) + IntelForge.utc("250101000000Z"))
            let tail: [UInt8] = IntelForge.utc("350101000000Z") + IntelForge.seq(e1 + e2)
            let der = IntelForge.crlWrap(IntelForge.crlTbs(tail), [0x03, 0x01, 0x00])
            return (try? C.parseCRL(der))?.revoked
        }
        XCTAssertEqual(got ?? nil, ["8f", "102"])
    }

    /// Line 181: ASCII white space is stepped over.
    func testAsciiWhiteSpaceIsSkipped() {
        let got: [Int]? = S2Deadline.within(3, "IntelCollateral.skipJSSpace") {
            [C.skipJSSpace(Array("  x".utf8), 0), C.skipJSSpace(Array("\t\n\u{0B}\u{0C}\r x".utf8), 0), C.skipJSSpace(Array("x".utf8), 0)]
        }
        XCTAssertEqual(got, [2, 6, 0])
    }

    /// Line 219: the object scan moves along the text, over a string with an escaped quote too.
    func testTheRawObjectIsScannedToItsClosingBrace() {
        let got: [[UInt8]?]? = S2Deadline.within(3, "IntelCollateral.rawJSONObject") {
            [C.rawJSONObject(Array(#"{"a":{"b":1}}"#.utf8), "a"), C.rawJSONObject(Array(#"{"a":{"s":"x\"}"}}"#.utf8), "a")]
        }
        XCTAssertEqual(got, [Array(#"{"b":1}"#.utf8), Array(#"{"s":"x\"}"}"#.utf8)])
    }

    /// Line 267: the fraction digits are consumed one at a time.
    func testFractionDigitsAreConsumed() {
        let t: Int64 = 1_767_225_600_000
        let got: [Int64?]? = S2Deadline.within(2, "IntelCollateral.jsDateParse") {
            [C.jsDateParse("2026-01-01T00:00:45.25Z"), C.jsDateParse("2026-01-01T00:00:45.1234Z")]
        }
        XCTAssertEqual(got, [t + 45_250, t + 45_123])
    }

    // ---- evaluateTcb, lines 394 and 399: the component walks move on ----
    private let mr = [UInt8](repeating: 0, count: 48)
    private let seam = [UInt8](repeating: 0, count: 8)
    private let sgx0 = [UInt8](repeating: 0, count: 16)

    private func comps() -> JSONValue {
        var out: [JSONValue] = []
        for _ in 0..<16 {
            let rec: JObject = ["svn": .int(0)]
            out.append(.object(rec))
        }
        return .array(out)
    }

    private func info() -> JObject {
        let tcb: JObject = ["sgxtcbcomponents": comps(), "tdxtcbcomponents": comps(), "pcesvn": .int(0)]
        let l: JObject = ["tcb": .object(tcb), "tcbStatus": .string("UpToDate"), "advisoryIDs": .array([])]
        let moduleFields: JObject = [
            "mrsigner": .string(String(repeating: "00", count: 48)),
            "attributes": .string("0000000000000000"),
            "attributesMask": .string("ffffffffffffffff"),
        ]
        return ["tcbLevels": .array([.object(l)]), "tdxModule": .object(moduleFields)]
    }

    func testAMatchingLevelEndsBothComponentWalks() {
        let got: String? = S2Deadline.within(3, "IntelCollateral.evaluateTcb") {
            let r = C.evaluateTcb(self.info(), self.sgx0, 0, [UInt8](repeating: 0, count: 16), self.mr, self.seam)
            return r.platform + "|" + r.err
        }
        XCTAssertEqual(got, "UpToDate|")
    }
}

final class A0H3AttestIntelChainHangTests: XCTestCase {
    /// AttestIntel.swift line 171: two certificates that issue each other; the walk stops at the first repeat.
    func testACyclicPckChainIsRefusedInTime() {
        typealias F = StrictChainForge
        func pem(_ der: [UInt8]) -> String {
            "-----BEGIN CERTIFICATE-----\n" + Data(der).base64EncodedString(options: [.lineLength64Characters, .endLineWithLineFeed]) + "\n-----END CERTIFICATE-----\n"
        }
        let a = F.cert(subject: "a", issuer: "b", subjectKey: F.rootKey, signer: F.midKey, serial: 1, exts: F.CA)
        let b = F.cert(subject: "b", issuer: "a", subjectKey: F.midKey, signer: F.rootKey, serial: 2, exts: F.CA)
        let chain = pem(a) + pem(b)
        let got: String? = S2Deadline.within(3, "DcapVerifier.verifyPckChain of a cycle") {
            let r = DcapVerifier.verifyPckChain(chain, "00", F.NOW)
            return (r.ok ? "ok:" : "refused:") + r.reason
        }
        XCTAssertEqual(got, "refused:PCK chain does not terminate in a self-signed root")
    }
}

final class A0H3ActionsRegistryHangTests: XCTestCase {
    private func s(_ x: String) -> JSONValue { .string(x) }
    private var d0: String { Base64URLStrict.encode([UInt8](repeating: 3, count: 32)) }
    private var d1: String { Base64URLStrict.encode([UInt8](repeating: 4, count: 32)) }
    private static let key = V2F.key("s2h3-registry")

    private func keys() -> JSONValue {
        .array([.object(["kid": s("k"), "alg": s("ed25519"), "pk": s(V2F.pub(Self.key))])])
    }

    private func signedWidenRecord() -> JSONValue {
        let body: JObject = ["v": .int(1), "kind": s(Actions.EVOLUTION_RECORD_KIND), "ns": s("ns"), "verb": s("a.b"), "from": .string(d0), "to": .string(d1),
                             "class": s("widen"), "reasons": .array([s("widened")])]
        var r = body
        r["sig"] = .object(["alg": s("ed25519"), "kid": s("k"), "value": s(V2F.sign(Self.key, IV.message(Actions.EVOLUTION_DOMAIN, .object(body))!))])
        return .object(r)
    }

    func testTheEvolutionSearchAndItsBacktrackBothEnd() {
        let rec = signedWidenRecord()
        let k = keys()
        let pin: JSONValue = .object(["pack": .object(["ns": s("ns"), "root": .string(d0)]), "on_new_action": s("deny"), "defs": .object(["a.b": .string(d0)])])
        let doc: JSONValue = .object(["verbs": .array([.object(["verb": s("a.b"), "def": .string(d1)])]), "pack": .object(["ns": s("ns"), "root": .string(d0)])])
        let want = Actions.evolutionDiffDigest(rec)
        XCTAssertNotNil(want)
        // no record leads to the presented definition (line 177: the search ends when the frontier is empty)
        let none: String? = S2Deadline.within(2, "Actions.decidePin without records") {
            let r = Actions.decidePin(pin: pin, doc: doc, verb: "a.b", records: [], keys: k, reapprovals: [], grantId: "g", issuer: "i")
            return (r.code ?? "-") + "|" + r.reason
        }
        XCTAssertEqual(none, "def_changed|the definition differs from the pinned digest and no signed evolution record chains to it")
        // a widening record: the path is walked back to the pin (line 200)
        let widened: PinDecision? = S2Deadline.within(2, "Actions.decidePin with a widening record") {
            Actions.decidePin(pin: pin, doc: doc, verb: "a.b", records: [rec], keys: k, reapprovals: [], grantId: "g", issuer: "i")
        }
        XCTAssertEqual(widened?.ok, false)
        XCTAssertEqual(widened?.code, "def_changed")
        XCTAssertEqual(widened?.needsReapproval, want)
    }
}

final class A0H3AttestNvidiaHangTests: XCTestCase {
    typealias T = AttestNvidiaK05Tests

    /// AttestNvidia.swift line 62: the next block starts after the previous one.
    func testMeasurementBlocksAreWalkedForward() {
        let rec: [UInt8] = T.block(9, [0xaa]) + T.block(10, [0xbb, 0xcc])
        let t: [UInt8] = T.transcript(record: rec, blocks: 2)
        let got: [Int]? = S2Deadline.within(2, "Nvidia.parseSpdm with two blocks") {
            guard let rep = try? Nvidia.parseSpdm(t) else { return [-1] }
            return [rep.measurements.count, rep.measurements[0].index, rep.measurements[0].digest.count, rep.measurements[1].index, rep.measurements[1].digest.count]
        }
        XCTAssertEqual(got, [2, 9, 1, 10, 2])
    }

}

final class A0H3AttestNvidiaOcspHangTests: XCTestCase {
    /// AttestNvidiaOcsp.swift line 48: the children of a node are read one after the other.
    func testChildrenAreWalkedForward() {
        let b: [UInt8] = [0x30, 0x06, 0x02, 0x01, 0x05, 0x02, 0x01, 0x06]
        let got: [Int]? = S2Deadline.within(2, "OCSP.kids") {
            guard let n = try? OCSP.readNode(b, 0, b.count), let ks = try? OCSP.kids(b, n) else { return [-1] }
            return ks.map { $0.end }
        }
        XCTAssertEqual(got, [5, 8])
    }
}

final class A0H3StoreConformanceHangTests: XCTestCase {
    /// StoreConformance.swift line 79: the lock is given back, so a second claim does not block.
    func testASecondClaimDoesNotBlock() {
        let got: [Bool]? = S2Deadline.within(3, "LossyStateStore.claim twice") {
            let l = LossyStateStore(MemoryStateStore())
            let first = (try? l.claim(key: "k", counter: 1)) == nil
            let second = (try? l.claim(key: "k", counter: 2))?.ok ?? false
            return [first, second]
        }
        XCTAssertEqual(got, [true, true])
    }
}
