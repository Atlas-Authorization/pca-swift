import AtlasPCAVerify
import Foundation
import XCTest
import AtlasPCAZk

/// The verification cases of the reference corpus (BN254 and BLS12-381) against the library. The corpus holds the reference's end-to-end
/// verdicts, which include checks made before the pairing (envelope shape, circuit and system tags, context pins); the cases those checks alone
/// decide are not replayed here. Every other case must agree: the default mode with the reference, strict mode with the reference except the
/// quirk cases, which the reference accepts and strict mode refuses.
final class ZkNativeCorpusTests: XCTestCase {
    /// Tag mismatches the default (snarkjs-compatible) mode does not read by design; the caller's canonical-envelope gate refuses them and strict mode must too.
    static let strictOnly = ["protocol-", "proof-curve-wrong"]
    static let gateOnly = ["expect-now-wrong", "expect-thunk-throws", "expectRiskHash", "circuit-", "system-", "extra-key", "proof-extra-key"]

    static func cases() throws -> [JSONValue] {
        let url = URL(fileURLWithPath: #filePath).deletingLastPathComponent().appendingPathComponent("../../test-data/ref-zk.json.gz").standardized
        let p = Process()
        p.executableURL = URL(fileURLWithPath: "/usr/bin/env")
        p.arguments = ["gzip", "-dc", url.path]
        let pipe = Pipe()
        p.standardOutput = pipe
        try p.run()
        let data = pipe.fileHandleForReading.readDataToEndOfFile()
        p.waitUntilExit()
        var out: [JSONValue] = []
        for var line in String(decoding: data, as: UTF8.self).split(separator: "\n", omittingEmptySubsequences: true) where line.hasPrefix("{\"fn\":\"verifyPolicyVmProof\",") {
            if line.hasSuffix(",") { line = line.dropLast() }
            out.append(try PCAWire.parseLenient(String(line)))
        }
        return out
    }

    private func member(_ v: JSONValue?, _ k: String) -> JSONValue? { v?.objectValue?[JKey(k)] }

    private func arg(_ c: JSONValue, _ i: Int) -> JSONValue? {
        guard let a = member(c, "args")?.arrayValue, i < a.count else { return nil }
        return a[i]
    }

    private func json(_ v: JSONValue?) -> [UInt8] { Array(PCAWire.canonical(v ?? .null).utf8) }

    func testTheVerifyCasesMatchTheReference() throws {
        XCTAssertFalse(PCAZkNative.version.isEmpty)
        let all = try Self.cases()
        XCTAssertEqual(all.count, 169)
        var checked = 0
        for (prefix, curve) in [("verifyPolicyVmProof/bn/", PCAZkNative.Curve.bn254), ("verifyPolicyVmProof/bls/", PCAZkNative.Curve.bls12381)] {
            let mine = all.filter { (member($0, "name")?.stringValue ?? "").hasPrefix(prefix) }
            guard let valid = mine.first(where: { member($0, "name")?.stringValue == prefix + "valid" }), let defaultKey = member(arg(valid, 1), "verificationKey") else {
                XCTFail("no \(prefix)valid case with a verification key"); continue
            }
            for c in mine {
                let name = member(c, "name")?.stringValue ?? ""
                let stem = String(name.dropFirst(prefix.count))
                let env = arg(c, 0)
                let vk = member(arg(c, 1), "verificationKey") ?? defaultKey
                // an envelope whose proof or signals are not there is refused by the caller's gate; the library sees JSON null and must refuse too
                func run(_ strict: Bool) -> Bool {
                    (try? PCAZkNative.verify(curve: curve, vkey: json(vk), proof: json(member(env, "proof")), signals: json(member(env, "publicSignals")), strict: strict).valid) ?? false
                }
                let compat = run(false), strict = run(true)
                if member(c, "out") == .bool(true) {
                    XCTAssertTrue(compat, "\(name): the default mode must accept")
                    XCTAssertEqual(strict, !stem.hasPrefix("quirk"), "\(name): strict mode verdict")
                } else if Self.strictOnly.contains(where: { stem.hasPrefix($0) }) {
                    XCTAssertFalse(strict, "\(name): strict mode must refuse")
                } else if !Self.gateOnly.contains(where: { stem.hasPrefix($0) }) {
                    XCTAssertFalse(compat || strict, "\(name): must be refused in both modes")
                } else {
                    continue
                }
                checked += 1
            }
        }
        XCTAssertGreaterThan(checked, 120)
    }

    func testUsageErrorsThrow() {
        XCTAssertThrowsError(try PCAZkNative.prove(curve: .bn254, wasm: [], zkey: [], input: [], seed: [1, 2, 3]))
        XCTAssertThrowsError(try PCAZkNative.prove(curve: .bn254, wasm: [0], zkey: [0], input: Array("{}".utf8)))
        XCTAssertEqual(try PCAZkNative.verify(curve: .bn254, vkey: Array("{}".utf8), proof: Array("{}".utf8), signals: Array("[]".utf8)).valid, false)
    }

}
