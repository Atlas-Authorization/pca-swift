import XCTest
import Foundation
@testable import AtlasPCAVerify

/// Differential replay of appending an action pack to a transparency log and verifying the entry (Ed25519 only: statements and receipts compare byte for byte).
final class RefActionsPackLogTests: XCTestCase {
    private static func key(_ v: JSONValue?) throws -> PCAEdKey {
        guard let s = v?.asString, let seed = Base64URLStrict.decode(s, length: 32) else { throw JSError("no seed") }
        return try Ed25519Deterministic.key(seed: seed)
    }

    func testPackLog() throws {
        try K042.requireCovers(["ActionTransparency"])
        let d = Base.Diffs()
        try Base.each("ref-actions-pack-log.json.gz", seeds: true) { c in
            let a0 = c.arg(0), a1 = c.arg(1)
            let got: BaseGot
            switch c.fn {
            case "appendPackToLog":
                got = RefActions.v {
                    let spec = RefActions.obj(a1)
                    let reg = try Self.key(spec[JKey("regSeed")]), ts = try Self.key(spec[JKey("tsSeed")])
                    let other = try Ed25519Deterministic.key(seed: Canonical.sha256(Array("atlas-pca-conformance/ref-actions-pack-log/other".utf8)))
                    let svc = PCAScittMemoryService(signer: .eddsa(ts), issuer: "ts")
                    for i in 0..<Int(IV.int(spec[JKey("preload")]) ?? 0) {
                        _ = try svc.register(try PCAScitt.signStatement(.object(["i": .int(Int64(i))]), signer: .eddsa(other), issuer: "other", subject: "s\(i)"))
                    }
                    let e = try ActionTransparency.appendPackToLog(RefActions.obj(a0), svc, .eddsa(reg), spec[JKey("issuer")]?.asString ?? "")
                    return .object(Jx.obj(["statement": Base.bytesValue(e.statement), "receipt": Base.bytesValue(e.receipt), "index": .int(e.index), "root": .string(e.root)]))
                }
            case "verifyPackLogEntry":
                let entry = RefActions.obj(a1), keys = RefActions.obj(c.arg(2))
                func pub(_ k: String) -> PCAScitt.CoseVerifier? { keys[JKey(k)]?.asString.flatMap { Base64URLStrict.decode($0, length: 32) }.map { .eddsa($0) } }
                guard let rk = pub("registry"), let lk = pub("log"), let st = Base.bytes(entry[JKey("statement")]), let rc = Base.bytes(entry[JKey("receipt")]) else { got = .value(.bool(false)); break }
                got = .value(.bool(ActionTransparency.verifyPackLogEntry(RefActions.obj(a0), st, rc, rk, lk, c.arg(3)?.asString)))
            default: d.skip("\(c.fn): not mapped"); return
            }
            d.add(c, Base.diff(c, got))
        }
        d.finish(100)
    }
}
