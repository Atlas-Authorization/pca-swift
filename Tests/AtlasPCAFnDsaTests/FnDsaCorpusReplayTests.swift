@testable import AtlasPCAVerify
import Foundation
import XCTest
@testable import AtlasPCAFnDsa

/// Replays the TypeScript-reference corpus (test-data/ref-fndsa.json.gz, 480 cases) through the native registry, framing, hybrid composition and backend seam.
/// Every case runs on the hash-derived TEST backend or an explicit stub backend; the Falcon primitive itself is covered by FnDsaNativeTests. Bytes are
/// {"$bytes": b64url}; {"$throws": ...} means the native must refuse. A JSON value of the wrong type (which Swift's types cannot express) must give the
/// refusal the reference gives: false for a verify, a throw for a sign.
final class FnDsaCorpusReplayTests: XCTestCase {
    typealias J = JSONValue
    static func k(_ s: String) -> JKey { JKey(s) }
    static func obj(_ p: [(String, J)]) -> J { .object(Dictionary(uniqueKeysWithValues: p.map { (JKey($0.0), $0.1) })) }
    static func B(_ b: [UInt8]) -> J { obj([("$bytes", .string(PCAWire.b64uEncode(b)))]) }

    static func bytes(_ v: J?) -> [UInt8]? {
        guard let o = v?.objectValue, o.count == 1, let inner = o[k("$bytes")] else { return nil }
        // a keyless corpus names its secret bytes by seed label: SHA-256("atlas-pca-conformance/" + label)
        if let so = inner.objectValue, so.count == 1, let label = so[k("$seed")]?.stringValue { return Canonical.sha256(Canonical.utf8("atlas-pca-conformance/" + label)) }
        guard let s = inner.stringValue else { return nil }
        return PCAWire.b64uDecode(s)
    }

    static func str(_ v: J?) -> String? { v?.stringValue }

    static func cases(_ fn: String) throws -> [[String: J]] {
        let url = URL(fileURLWithPath: #filePath).deletingLastPathComponent().appendingPathComponent("../../test-data/ref-fndsa.json.gz").standardized
        let p = Process()
        p.executableURL = URL(fileURLWithPath: "/usr/bin/env")
        p.arguments = ["gzip", "-dc", url.path]
        let pipe = Pipe()
        p.standardOutput = pipe
        try p.run()
        let data = pipe.fileHandleForReading.readDataToEndOfFile()
        p.waitUntilExit()
        var out: [[String: J]] = []
        let head = "{\"fn\":\"\(fn)\","
        for var line in String(decoding: data, as: UTF8.self).split(separator: "\n", omittingEmptySubsequences: true) where line.hasPrefix(head) {
            if line.hasSuffix(",") { line = line.dropLast() }
            let o = try PCAWire.parseLenient(String(line)).objectValue!
            out.append(Dictionary(uniqueKeysWithValues: o.map { ($0.key.s, $0.value) }))
        }
        XCTAssertFalse(out.isEmpty, "no oracle cases for \(fn)")
        return out
    }

    override func tearDown() { FnDsa.resetBackend() }

    func replay(_ fn: String, _ f: ([J]) throws -> J) throws {
        var bad: [String] = []
        for c in try Self.cases(fn) {
            let name = c["name"]?.stringValue ?? "?", want = c["out"]!, args = c["args"]!.arrayValue!
            let wantThrow = PCAWire.member(want, "$throws") != nil
            do {
                let got = try f(args)
                if wantThrow { bad.append("\(name): want a refusal, got a value") } else if got != want { bad.append("\(name): value differs from the reference") }
            } catch {
                if !wantThrow { bad.append("\(name): unexpected \(error)") }
            }
        }
        XCTAssert(bad.isEmpty, "\(bad.count) divergent case(s) of \(fn):\n" + bad.prefix(20).joined(separator: "\n"))
    }

    /// A refusal for input the reference could not even type-check.
    struct WrongType: Error {}
    static func need<T>(_ v: T?) throws -> T { guard let v = v else { throw WrongType() }; return v }

    static func install(_ kind: String) throws {
        FnDsa.resetBackend()
        let mock = FnDsa.registerTestBackend()
        switch kind {
        case "mock": break
        case "none": FnDsa.resetBackend()
        case "verify-only": FnDsa.setBackend(FalconBackend(verify: mock.verify))
        case "short-sig": FnDsa.setBackend(FalconBackend(verify: mock.verify, sign: { _, _ in [UInt8](repeating: 0, count: 10) }))
        case "all-true": FnDsa.setBackend(FalconBackend(verify: { _, _, _ in true }, sign: mock.sign))
        case "throws": FnDsa.setBackend(FalconBackend(verify: { _, _, _ in throw FnDsaError.invalid("backend exploded") }, sign: mock.sign))
        default: throw FnDsaError.invalid("unknown backend kind \(kind)")
        }
    }

    static func with<T>(_ kind: String, _ f: () throws -> T) throws -> T {
        defer { FnDsa.resetBackend() }
        try install(kind)
        return try f()
    }

    static func suiteJSON(_ s: FnDsaSuite?) -> J {
        guard let s = s else { return .null }
        return obj([("alg", .string(s.alg)), ("variant", .string(s.variant)), ("hasEd25519", .bool(s.hasEd25519)), ("sigBytes", .int(Int64(s.sigBytes))),
                    ("needsPqPk", .bool(s.needsPqPk)), ("pqPkBytes", .int(Int64(s.pqPkBytes))), ("needsPqSig", .bool(s.needsPqSig)),
                    ("pqSigBytes", .int(Int64(s.pqSigBytes))), ("fnSigBytes", .int(Int64(s.fnSigBytes)))])
    }

    static func signedJSON(_ s: FnDsa.Signed) -> J {
        var p: [(String, J)] = [("sig", .string(s.sig)), ("alg", .string(s.alg)), ("pq_pk", .string(s.pqPk))]
        if let q = s.pqSig { p.append(("pq_sig", .string(q))) }
        return obj(p)
    }

    func testRegistry() throws {
        try replay("resolveFnDsaAlg") { a in Self.suiteJSON(FnDsa.resolveAlg(Self.str(a[0]))) }
        try replay("isKnownFnDsaAlg") { a in .bool(FnDsa.isKnownAlg(Self.str(a[0]))) }
        try replay("isFnDsaVariant") { a in .bool(FnDsa.isVariant(Self.str(a[0]))) }
    }

    func testHashKatAndMockKeys() throws {
        try replay("hashKat") { a in
            guard case let .int(n) = a[1] else { throw WrongType() }
            return Self.B(try FnDsa.hashKat(try Self.need(Self.bytes(a[0])), Int(n)))
        }
        try replay("mockKeypair") { a in
            let v = try Self.need(Self.str(a[0]))
            let kp: (pk: [UInt8], sk: [UInt8])
            if a.count < 2 { kp = try FnDsa.mockKeypair(v) } else if let s = Self.str(a[1]) { kp = try FnDsa.mockKeypair(v, seed: s) } else { kp = try FnDsa.mockKeypair(v, seed: try Self.need(Self.bytes(a[1]))) }
            return Self.obj([("pk", Self.B(kp.pk)), ("sk", Self.B(kp.sk))])
        }
    }

    func testLeafMessage() throws {
        try replay("fndsaLeafMessage") { a in Self.B(try FnDsa.leafMessage(a[0], alg: try Self.need(Self.str(a[1])), pqPkB64u: try Self.need(Self.str(a[2])))) }
    }

    func testSignAndVerifyThroughEveryBackend() throws {
        try replay("fndsaSignWith") { a in
            let kind = try Self.need(Self.str(a[0])), v = try Self.need(Self.str(a[1]))
            let sk = try Self.need(Self.bytes(a[2])), m = try Self.need(Self.bytes(a[3]))
            return Self.B(try Self.with(kind) { try FnDsa.sign(v, sk: sk, msg: m) })
        }
        try replay("fndsaVerifyWith") { a in
            let kind = try Self.need(Self.str(a[0])), v = try Self.need(Self.str(a[1]))
            guard let pk = Self.bytes(a[2]), let m = Self.bytes(a[3]), let s = Self.bytes(a[4]) else { return .bool(false) } // a non-bytes argument: the reference's false
            return .bool(try Self.with(kind) { try FnDsa.verify(v, pk: pk, msg: m, sig: s) })
        }
    }

    func testKatTablePrecedence() throws {
        func vectors(_ v: J?) throws -> [(pk: [UInt8], msg: [UInt8], sig: [UInt8])] {
            try Self.need(v?.arrayValue).map { e in
                (try Self.need(Self.bytes(PCAWire.member(e, "pk"))), try Self.need(Self.bytes(PCAWire.member(e, "msg"))), try Self.need(Self.bytes(PCAWire.member(e, "sig"))))
            }
        }
        try replay("fndsaVerifyKat") { a in
            FnDsa.resetBackend()
            defer { FnDsa.resetBackend() }
            FnDsa.registerTestBackend(vectors: try vectors(a[4]))
            return .bool(try FnDsa.verify(try Self.need(Self.str(a[0])), pk: try Self.need(Self.bytes(a[1])), msg: try Self.need(Self.bytes(a[2])), sig: try Self.need(Self.bytes(a[3]))))
        }
        for c in try Self.cases("fndsaSignKat") {
            let v = (c["name"]!.stringValue!).split(separator: "/")[1].description
            FnDsa.resetBackend()
            defer { FnDsa.resetBackend() }
            FnDsa.registerTestBackend(vectors: try vectors(c["args"]!.arrayValue![0]))
            let got = Self.B(try FnDsa.sign(v, sk: try FnDsa.mockKeypair(v, seed: "ref").sk, msg: Array("m".utf8)))
            XCTAssertEqual(got, c["out"]!, c["name"]!.stringValue!)
        }
    }

    func testSignPcaWithFndsa() throws {
        try replay("signPcaWithFndsa") { a in
            let inp = try Self.need(a[0].objectValue)
            let fn = inp[Self.k("fnDsa")]?.objectValue
            FnDsa.edKeyFactory = { try Ed25519Deterministic.key(seed: $0) }
            defer { FnDsa.edKeyFactory = { try PCAEdKey(seed: $0) } }
            return try Self.with("mock") {
                Self.signedJSON(try FnDsa.signPca(alg: try Self.need(Self.str(inp[Self.k("alg")])), leaf: try Self.need(inp[Self.k("leaf")]),
                                                  pk: try Self.need(Self.bytes(try Self.need(fn)[Self.k("pk")])), sk: try Self.need(Self.bytes(try Self.need(fn)[Self.k("sk")])),
                                                  edSecret: Self.bytes(inp[Self.k("edSecret")])))
            }
        }
    }

    func testVerifyPcaFndsa() throws {
        func run(_ fn: String, _ kind: String) throws {
            try replay(fn) { a in
                let inp = try Self.need(a[0].objectValue)
                func s(_ k: String) -> String? { Self.str(inp[Self.k(k)]) }
                return .bool(try Self.with(kind) {
                    try FnDsa.verifyPca(alg: s("alg"), leaf: try Self.need(inp[Self.k("leaf")]), holder: s("holder"), pqPk: s("pq_pk"), sig: s("sig"), pqSig: s("pq_sig"))
                })
            }
        }
        try run("verifyPcaFndsa", "mock")
        try run("verifyPcaFndsaNone", "none")
    }

    func testNoBackendRefuses() {
        FnDsa.resetBackend()
        XCTAssertThrowsError(try FnDsa.verify("fn-dsa-512", pk: [UInt8](repeating: 0, count: FnDsa.pk512), msg: [0x6d], sig: [UInt8](repeating: 0, count: FnDsa.sig512))) { e in
            guard case FnDsaError.backendMissing = e else { return XCTFail("want backendMissing, got \(e)") }
        }
    }

    func testCorpusIsCovered() throws {
        var n = 0
        for fn in ["resolveFnDsaAlg", "isKnownFnDsaAlg", "isFnDsaVariant", "hashKat", "mockKeypair", "fndsaLeafMessage", "fndsaSignWith", "fndsaVerifyWith", "fndsaVerifyKat",
                   "fndsaSignKat", "signPcaWithFndsa", "verifyPcaFndsa", "verifyPcaFndsaNone"] { n += try Self.cases(fn).count }
        XCTAssertEqual(n, 480)
    }
}
