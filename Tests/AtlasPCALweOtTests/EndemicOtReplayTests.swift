import CryptoKit
import Foundation
import XCTest
@testable import AtlasPCALweOt

/// Replays the TypeScript-reference corpus (test-data/ref-mpc-endemic.json.gz) through the native endemic OT over liblweot. Bytes are {"$bytes": b64url};
/// {"$throws": ...} means the native must refuse. Receiver key seeds are labels: sha256("atlas-pca-conformance/" + label). The workflow sets
/// ATLAS_PCA_LIBLWEOT_REQUIRED=1 so a missing library fails instead of skipping.
final class EndemicOtReplayTests: XCTestCase {
    typealias J = [String: Any]

    static func corpus(_ fn: String) throws -> [J] {
        let url = URL(fileURLWithPath: #filePath).deletingLastPathComponent().appendingPathComponent("../../test-data/ref-mpc-endemic.json.gz").standardized
        let p = Process()
        p.executableURL = URL(fileURLWithPath: "/usr/bin/env")
        p.arguments = ["gzip", "-dc", url.path]
        let pipe = Pipe()
        p.standardOutput = pipe
        try p.run()
        let data = pipe.fileHandleForReading.readDataToEndOfFile()
        p.waitUntilExit()
        var out: [J] = []
        let head = "{\"fn\":\"\(fn)\","
        for var line in String(decoding: data, as: UTF8.self).split(separator: "\n", omittingEmptySubsequences: true) where line.hasPrefix(head) {
            if line.hasSuffix(",") { line = line.dropLast() }
            out.append(try JSONSerialization.jsonObject(with: Data(line.utf8)) as! J)
        }
        XCTAssertFalse(out.isEmpty, "no oracle cases for \(fn)")
        return out
    }

    override func setUpWithError() throws {
        guard LweLattice.sizesMatch() else {
            if ProcessInfo.processInfo.environment["ATLAS_PCA_LIBLWEOT_REQUIRED"] == "1" { XCTFail("liblweot must load") }
            throw XCTSkip("liblweot not available")
        }
    }

    // ---- codecs ----
    static func b64(_ b: [UInt8]) -> J { ["$bytes": Data(b).base64EncodedString().replacingOccurrences(of: "+", with: "-").replacingOccurrences(of: "/", with: "_").replacingOccurrences(of: "=", with: "")] }

    static func by(_ v: Any?) -> [UInt8] {
        var s = ((v as! J)["$bytes"] as! String).replacingOccurrences(of: "-", with: "+").replacingOccurrences(of: "_", with: "/")
        while s.count % 4 != 0 { s += "=" }
        return [UInt8](Data(base64Encoded: s)!)
    }

    static func bl(_ a: [[UInt8]]) -> [J] { a.map(b64) }
    static func bp(_ a: [[[UInt8]]]) -> [[J]] { a.map { $0.map(b64) } }
    static func ints(_ v: Any?) -> [Int] { (v as! [NSNumber]).map { $0.intValue } }
    static func seed(_ label: Any?) -> [UInt8] { Array(SHA256.hash(data: Data(("atlas-pca-conformance/" + (label as! String)).utf8))) }
    static func rng(_ v: Any?) -> SplitMix64Stream { SplitMix64Stream(seed: UInt64(v as! String)!) }
    static func flip(_ b: [UInt8]) -> [UInt8] { b.map { $0 ^ 1 } }
    static func fill(_ n: Int, _ k: Int) -> [UInt8] { (0..<n).map { UInt8(truncatingIfNeeded: $0 * 31 + k * 7 + ($0 >> 3)) } }
    static func hex(_ b: [UInt8]) -> String { b.map { String(format: "%02x", $0) }.joined() }

    /// A reference throw needs a native error; otherwise the result must equal the reference value (deep Foundation equality).
    func replay(_ fn: String, _ f: ([Any]) throws -> Any) throws {
        var bad: [String] = []
        for c in try Self.corpus(fn) {
            let name = c["name"] as! String, want = c["out"]!, args = c["args"] as! [Any]
            let wantThrow = (want as? J)?["$throws"] != nil
            do {
                let got = try f(args)
                if wantThrow { bad.append("\(name): want a refusal, got a value") }
                else if !(got as AnyObject).isEqual(want) { bad.append("\(name): value differs from the reference") }
            } catch {
                if !wantThrow { bad.append("\(name): unexpected \(error)") }
            }
        }
        XCTAssert(bad.isEmpty, "\(bad.count) divergent case(s) of \(fn):\n" + bad.prefix(20).joined(separator: "\n"))
    }

    func testLweKeygenFips() throws {
        try replay("lweKeygenFips") { a in
            let k = try LweLattice.keygenFips203(Self.seed(a[0]))
            return ["pk": Self.b64(k.publicKey), "skSha256": Self.hex(Array(SHA256.hash(data: Data(k.secretKey))))] as J
        }
    }

    func testLweKeygen() throws {
        try replay("lweKeygen") { a in
            let k = try LweLattice.keygen(Self.seed(a[0]))
            return ["pk": Self.b64(k.publicKey), "skSha256": Self.hex(Array(SHA256.hash(data: Data(k.secretKey))))] as J
        }
    }

    func testLweEnc() throws { try replay("lweEnc") { a in Self.b64(try LweLattice.enc(try LweLattice.keygen(Self.seed(a[0])).publicKey, Self.by(a[1]), Self.by(a[2]))) } }

    func testLweDec() throws { try replay("lweDec") { a in Self.b64(try LweLattice.dec(try LweLattice.keygen(Self.seed(a[0])).secretKey, Self.by(a[1]))) } }

    func testLweRing() throws {
        try replay("lweRing") { a in Self.b64((a[0] as! String) == "add" ? try LweLattice.ringAdd(Self.by(a[1]), Self.by(a[2])) : try LweLattice.ringSub(Self.by(a[1]), Self.by(a[2]))) }
    }

    func testLweHash() throws { try replay("lweHash") { a in Self.b64(try LweLattice.hashToRing(Self.by(a[0]))) } }

    func testRandomOt() throws {
        try replay("randomOt") { a in
            let (m, st) = try EndemicOt.receive(Self.ints(a[0]), Self.rng(a[1]))
            let sm = try EndemicOt.sendRandom(m, Self.rng(a[2]))
            return ["rn": Self.b64(m.rn), "points": Self.bp(m.points), "rhos": Self.bl(m.rhos), "ciphertexts": Self.bp(sm.ciphertexts),
                    "senderPads": Self.bp(sm.senderPads), "recvPads": Self.bl(try EndemicOt.recoverRandom(st, sm))] as J
        }
    }

    func testRandomOtTamper() throws {
        try replay("randomOtTamper") { a in
            let (m, st) = try EndemicOt.receive(Self.ints(a[0]), Self.rng(a[1]))
            let sm = try EndemicOt.sendRandom(m, Self.rng(a[2])) { c in c[0][0] = Array(c[0][0].prefix(1087)) }
            return Self.bl(try EndemicOt.recoverRandom(st, sm))
        }
    }

    func testBaseOt() throws {
        try replay("baseOt") { a in
            let messages = (a[0] as! [[Any]]).map { [Self.by($0[0]), Self.by($0[1])] }
            let choices = Self.ints(a[1])
            let t = a[3] as! String
            let tamper: ((inout [[[UInt8]]]) -> Void)? = t == "enc" ? { e in e[0][0] = Self.flip(e[0][0]) }
                : t == "encChosen" ? { e in let c = choices[0] & 1; e[0][c] = Self.flip(e[0][c]) } : nil
            let r = try EndemicOt.baseOT(messages, choices, Self.rng(a[2]), tamperEncrypted: tamper)
            return ["received": Self.bl(r.received), "ciphertexts": Self.bp(r.transcript.ciphertexts), "encrypted": Self.bp(r.transcript.encrypted),
                    "commitments": Self.bp(r.transcript.commitments)] as J
        }
    }

    func testSendMalformed() throws {
        try replay("sendMalformed") { a in
            var m = try EndemicOt.receive([0, 1], Self.rng("77")).message
            switch a[0] as! String {
            case "nonce": m.rn = Self.fill(31, 1)
            case "count": m.rhos.removeFirst()
            case "point": m.points[1][0] = Self.fill(1151, 1)
            case "rho": m.rhos[0] = Self.fill(33, 1)
            default: break
            }
            return try EndemicOt.sendRandom(m, Self.rng("78")).ciphertexts.count
        }
    }
}
