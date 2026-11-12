import XCTest
@testable import AtlasPCAVerify

/// Status order and the TCB and QE evaluation (attest-intel-collateral.ts:271-276, 307-394).
final class AttestIntelCollateralK05EvalTests: XCTestCase {
    private typealias C = IntelCollateral

    private let below = "platform TCB is below every level in the TCB info"
    private let mr = [UInt8](repeating: 0, count: 48)
    private let seam = [UInt8](repeating: 0, count: 8)
    private let sgx0 = [UInt8](repeating: 0, count: 16)

    func testStatusHelpers() {
        XCTAssertEqual(C.statusRank("Revoked"), 6)
        XCTAssertEqual(C.statusRank("nope"), -1) // indexOf
        XCTAssertEqual(C.worstStatus("nope", "other"), "nope") // indexOf(a) >= indexOf(b) ? a : b
        XCTAssertEqual(C.worstStatus("UpToDate", "Revoked"), "Revoked")
    }

    private func comps(_ set: [Int: Int] = [:]) -> JSONValue {
        var out: [JSONValue] = []
        for i in 0..<16 {
            let rec: JObject = ["svn": .int(Int64(set[i] ?? 0))]
            out.append(.object(rec))
        }
        return .array(out)
    }

    private func level(sgx: [Int: Int] = [:], tdx: [Int: Int] = [:], advisories: [String] = []) -> JSONValue {
        let tcb: JObject = ["sgxtcbcomponents": comps(sgx), "tdxtcbcomponents": comps(tdx), "pcesvn": .int(0)]
        let l: JObject = ["tcb": .object(tcb), "tcbStatus": .string("UpToDate"), "advisoryIDs": .array(advisories.map { JSONValue.string($0) })]
        return .object(l)
    }

    private func info(_ lv: JSONValue) -> JObject {
        let moduleFields: JObject = [
            "mrsigner": .string(String(repeating: "00", count: 48)),
            "attributes": .string("0000000000000000"),
            "attributesMask": .string("ffffffffffffffff"),
        ]
        var identity = moduleFields
        identity["id"] = .string("TDX_01")
        let moduleLevel: JObject = ["tcb": .object(["isvsvn": .int(0)]), "tcbStatus": .string("UpToDate")]
        identity["tcbLevels"] = .array([.object(moduleLevel)])
        return ["tcbLevels": .array([lv]), "tdxModule": .object(moduleFields), "tdxModuleIdentities": .array([.object(identity)])]
    }

    private func tee(minor: UInt8, _ set: [Int: UInt8] = [:]) -> [UInt8] {
        var t = [UInt8](repeating: 0, count: 16)
        t[1] = minor
        for (i, v) in set { t[i] = v }
        return t
    }

    private func eval(_ lv: JSONValue, _ t: [UInt8], pckSgx: [UInt8]? = nil) -> C.TcbEval {
        C.evaluateTcb(info(lv), pckSgx ?? sgx0, 0, t, mr, seam)
    }

    func testBaseModuleComparesTheWholeTeeSvn() {
        XCTAssertEqual(eval(level(tdx: [0: 1]), tee(minor: 0)).err, below)
        XCTAssertEqual(eval(level(tdx: [0: 1]), tee(minor: 0, [0: 1])).platform, "UpToDate")
    }

    func testAModuleIdentityCoversTheFirstTwoComponents() {
        XCTAssertEqual(eval(level(tdx: [0: 5]), tee(minor: 1)).err, "")
        XCTAssertEqual(eval(level(tdx: [1: 5]), tee(minor: 1)).err, "")
        XCTAssertEqual(eval(level(tdx: [2: 1]), tee(minor: 1)).err, below)
    }

    func testEverySvnComponentIsCompared() {
        XCTAssertEqual(eval(level(sgx: [1: 1]), tee(minor: 0)).err, below)
        XCTAssertEqual(eval(level(sgx: [15: 1]), tee(minor: 0)).err, below)
        XCTAssertEqual(eval(level(tdx: [15: 1]), tee(minor: 0)).err, below)
    }

    func testAdvisoriesAreInSortOrder() {
        let ids = ["H", "C", "F", "A", "G", "B", "E", "D"]
        XCTAssertEqual(eval(level(advisories: ids), tee(minor: 0)).advisories, ["A", "B", "C", "D", "E", "F", "G", "H"])
    }

    /// Array.prototype.sort compares UTF-16 code units: an astral character (lead surrogate 0xD83D) sorts before U+FF5E.
    func testAdvisorySortIsUtf16() {
        XCTAssertEqual(eval(level(advisories: ["\u{FF5E}", "\u{1F600}"]), tee(minor: 0)).advisories, ["\u{1F600}", "\u{FF5E}"])
    }

    private func identity(prod: Int = 0, levels: [(Int, String)] = [(0, "UpToDate")]) -> JObject {
        var lv: [JSONValue] = []
        for (svn, status) in levels {
            let l: JObject = ["tcb": .object(["isvsvn": .int(Int64(svn))]), "tcbStatus": .string(status)]
            lv.append(.object(l))
        }
        return [
            "id": .string("TD_QE"), "version": .int(2),
            "miscselect": .string("00000000"), "miscselectMask": .string("ffffffff"),
            "attributes": .string(String(repeating: "00", count: 16)), "attributesMask": .string(String(repeating: "ff", count: 16)),
            "mrsigner": .string(String(repeating: "00", count: 32)), "isvprodid": .int(Int64(prod)), "tcbLevels": .array(lv),
        ]
    }

    private func qe(_ set: [Int: UInt8] = [:]) -> [UInt8] {
        var q = [UInt8](repeating: 0, count: 384)
        for (i, v) in set { q[i] = v }
        return q
    }

    func testQeMaskedFieldsCoverTheirLastByte() {
        XCTAssertEqual(C.evaluateQe(identity(), qe()).status, "UpToDate")
        XCTAssertEqual(C.evaluateQe(identity(), qe([19: 1])).err, "QE MISCSELECT does not match the QE identity")
        XCTAssertEqual(C.evaluateQe(identity(), qe([63: 1])).err, "QE ATTRIBUTES do not match the QE identity")
    }

    func testQeProdIdIsLittleEndian() {
        XCTAssertEqual(C.evaluateQe(identity(prod: 258), qe([256: 2, 257: 1])).err, "")
        XCTAssertEqual(C.evaluateQe(identity(prod: 2), qe([256: 2, 257: 1])).err, "QE ISVPRODID does not match the QE identity")
    }

    func testQeIsvSvnIsLittleEndian() {
        let levels: [(Int, String)] = [(300, "OutOfDate"), (256, "UpToDate"), (0, "Revoked")]
        XCTAssertEqual(C.evaluateQe(identity(levels: levels), qe([259: 1])).status, "UpToDate") // 256
        XCTAssertEqual(C.evaluateQe(identity(levels: levels), qe([258: 1])).status, "Revoked") // 1
    }
}
