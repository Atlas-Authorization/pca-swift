import XCTest
import Foundation
import BigInt
@testable import AtlasPCAVerify
@testable import AtlasPCAVDF

/// Differential replay of the Wesolowski VDF and the PCA timelock against the reference (@atlasauth/pca-vdf): primality, the challenge prime, evaluation and
/// verification (plain and canonical), the modulus screen and the timelock. Big integers cross the corpus as decimal strings; step counts are JSON numbers.
final class VdfReplayTests: XCTestCase {
    static let file = "ref-vdf.json.gz"

    struct Case {
        let fn: String, name: String, args: [JSONValue], out: JSONValue
        func arg(_ i: Int) -> JSONValue? { i < args.count ? args[i] : nil }
        var threw: Bool { out.get("$throws")?.asString != nil }
    }

    struct Refusal: Error {}

    static func corpus(_ rel: String) throws -> [Case] {
        let url = URL(fileURLWithPath: #filePath).deletingLastPathComponent().appendingPathComponent("../../test-data/" + rel).standardized
        let p = Process()
        p.executableURL = URL(fileURLWithPath: "/usr/bin/env")
        p.arguments = ["gzip", "-dc", url.path]
        let out = Pipe()
        p.standardOutput = out
        try p.run()
        let data = out.fileHandleForReading.readDataToEndOfFile()
        p.waitUntilExit()
        var cases: [Case] = []
        for var line in String(decoding: data, as: UTF8.self).split(separator: "\n", omittingEmptySubsequences: true) where line.hasPrefix(#"{"fn":"#) {
            if line.hasSuffix(",") { line = line.dropLast() }
            guard let v = try? StrictJSON.parseLenient(String(line)) else { XCTFail("unparsable corpus line"); continue }
            cases.append(Case(fn: v.get("fn")?.asString ?? "", name: v.get("name")?.asString ?? "?", args: v.get("args")?.asArray ?? [], out: v.get("out") ?? .null))
        }
        return cases
    }

    /// The wrapper's `BigInt(s)`: anything but a decimal string throws.
    static func B(_ v: JSONValue?) throws -> BigInt {
        guard let s = v?.asString, let n = BigInt(s) else { throw Refusal() }
        return n
    }

    static func S(_ n: BigInt) -> JSONValue { .string(String(n)) }
    /// A JSON number as a JavaScript number; anything else is not a safe step count.
    static func N(_ v: JSONValue?) -> Double { IV.num(v) ?? .nan }
    static func bytes(_ v: JSONValue?) -> [UInt8]? { v?.asString.map { Array($0.utf8) } }

    static func proofValue(_ p: PCAVdf.Proof) -> JSONValue { .object(["y": S(p.y), "pi": S(p.pi)]) }
    static func verdictValue(_ v: PCAVdf.Verdict) -> JSONValue {
        var m: JObject = ["ok": .bool(v.ok)]
        if let r = v.reason { m["reason"] = .string(r) }
        return .object(m)
    }

    static func options(_ o: JSONValue?) throws -> PCATimelock.Options {
        PCATimelock.Options(steps: o?.get("steps").flatMap { IV.num($0) }, N: try B(o?.get("N")), beacon: bytes(o?.get("beacon")), allowInsecureDevModulus: o?.get("allowInsecureDevModulus") == .bool(true))
    }

    static func proofIn(_ p: JSONValue?) -> PCATimelock.Proof? {
        guard let o = p?.asObject else { return nil }
        let n: (String) -> BigInt? = { k in o[JKey(k)]?.asString.flatMap { BigInt($0) } }
        return PCATimelock.Proof(kind: o[JKey("kind")]?.asString, y: n("y"), pi: n("pi"), steps: o[JKey("steps")].flatMap { IV.num($0) })
    }

    func run(_ c: Case) throws -> JSONValue {
        let a0 = c.arg(0), a1 = c.arg(1), a2 = c.arg(2)
        switch c.fn {
        case "isProbablePrime": return .bool(PCAVdf.isProbablePrime(try Self.B(a0)))
        case "isMillerRabinProbablePrime": return .bool(PCAVdf.isMillerRabinProbablePrime(try Self.B(a0)))
        case "isStrongLucasProbablePrime": return .bool(PCAVdf.isStrongLucasProbablePrime(try Self.B(a0)))
        case "modpow": return Self.S(try PCAVdf.modpow(try Self.B(a0), try Self.B(a1), try Self.B(a2)))
        case "gcd": return Self.S(PCAVdf.gcd(try Self.B(a0), try Self.B(a1)))
        case "canonicalVdfOutput": return Self.S(PCAVdf.canonicalVdfOutput(try Self.B(a0), try Self.B(a1)))
        case "bigIntToBytes": return BaseLike.bytesValue(try PCAVdf.bigIntToBytes(try Self.B(a0)))
        case "bytesRoundTrip":
            guard let s = a0?.asString, let b = Base64URLStrict.decode(s) else { throw Refusal() }
            return BaseLike.bytesValue(try PCAVdf.bigIntToBytes(PCAVdf.bytesToBigInt(b)))
        case "hashToPrime":
            let bits = c.arg(4).map { Self.N($0) } ?? Double(PCAVdf.CHALLENGE_PRIME_BITS)
            return Self.S(try PCAVdf.hashToPrime(try Self.B(a0), try Self.B(a1), Self.N(a2), try Self.B(c.arg(3)), bits: bits))
        case "sequentialSquare": return Self.S(try PCAVdf.sequentialSquare(try Self.B(a0), Self.N(a1), try Self.B(a2)))
        case "vdfEval": return Self.proofValue(try PCAVdf.eval(try Self.B(a0), Self.N(a1), try Self.B(a2)))
        case "vdfEvalCanonical": return Self.proofValue(try PCAVdf.evalCanonical(try Self.B(a0), Self.N(a1), try Self.B(a2)))
        case "vdfVerifyDetailed", "vdfVerifyCanonicalDetailed":
            let x = try Self.B(a0), y = try Self.B(a1), pi = try Self.B(a2), n = try Self.B(c.arg(4))
            let t = Self.N(c.arg(3))
            return Self.verdictValue(c.fn == "vdfVerifyDetailed" ? PCAVdf.verifyDetailed(x, y, pi, t, n) : PCAVdf.verifyCanonicalDetailed(x, y, pi, t, n))
        case "checkProductionModulus": return Self.verdictValue(PCAVdf.checkProductionModulus(try Self.B(a0)))
        case "deriveTimelockInput": return Self.S(try PCATimelock.deriveTimelockInput(a0 ?? .null, try Self.B(a1), beacon: Self.bytes(a2)))
        case "requireTimelock":
            let r = try PCATimelock.requireTimelock(a0 ?? .null, try Self.options(a1))
            return .object(["kind": .string(r.kind), "x": Self.S(r.x), "steps": .int(Int64(r.steps)), "N": Self.S(r.N), "actionDigest": .string(r.actionDigest)])
        case "proveTimelockElapsed":
            let o = c.arg(3)
            let p = try PCATimelock.proveTimelockElapsed(a0 ?? .null, steps: a1.flatMap { IV.num($0) }, N: try Self.B(a2), beacon: Self.bytes(o?.get("beacon")), allowInsecureDevModulus: o?.get("allowInsecureDevModulus") == .bool(true))
            return .object(["kind": .string(p.kind ?? ""), "y": Self.S(p.y ?? 0), "pi": Self.S(p.pi ?? 0), "steps": .int(Int64(p.steps ?? 0))])
        case "verifyTimelock": return .bool(PCATimelock.verifyTimelock(a0 ?? .null, Self.proofIn(a1), try Self.options(a2)))
        default: throw Refusal()
        }
    }

    /// DEBUG builds run big-integer loops 50-100x slower: moduli over ~1300 bits are replayed in release builds (or with ATLAS_VDF_FULL=1).
    static func heavy(_ c: Case) -> Bool {
        #if DEBUG
        if ProcessInfo.processInfo.environment["ATLAS_VDF_FULL"] != nil { return false }
        let digits: (JSONValue) -> Int = { v in
            if let s = v.asString { return s.count }
            if let o = v.asObject { return o.values.map { $0.asString?.count ?? 0 }.max() ?? 0 }
            return 0
        }
        let heavyFns: Set<String> = ["vdfEval", "vdfEvalCanonical", "vdfVerifyDetailed", "vdfVerifyCanonicalDetailed", "sequentialSquare", "proveTimelockElapsed", "verifyTimelock", "checkProductionModulus", "requireTimelock"]
        return heavyFns.contains(c.fn) && (c.args.map(digits).max() ?? 0) > 400
        #else
        return false
        #endif
    }

    func testReplay() throws {
        let cases = try Self.corpus(Self.file)
        XCTAssertEqual(cases.count, 6673)
        var bad: [String] = []
        var run = 0, skipped = 0
        for c in cases {
            if Self.heavy(c) { skipped += 1; continue }
            run += 1
            let want = c.out
            do {
                let got = try self.run(c)
                if c.threw { bad.append("\(c.name): want throw got \(Canonical.canonicalize(got).prefix(120))") }
                else if Canonical.canonicalize(got) != Canonical.canonicalize(want) { bad.append("\(c.name): want \(Canonical.canonicalize(want).prefix(160)) got \(Canonical.canonicalize(got).prefix(160))") }
            } catch {
                if !c.threw { bad.append("\(c.name): want \(Canonical.canonicalize(want).prefix(160)) got throw \(error)") }
            }
        }
        print("vdf replay: \(run) compared, \(skipped) skipped (debug build, large modulus)")
        XCTAssertGreaterThan(run, 3500)
        XCTAssert(bad.isEmpty, "\(bad.count)/\(run) divergent:\n" + bad.prefix(30).joined(separator: "\n"))
    }

    func testDevModulusIsRefusedByTheProductionScreen() throws {
        let s = try PCAVdf.insecureDevSetup(bits: 64)
        XCTAssertFalse(PCAVdf.checkProductionModulus(s.N).ok)
    }

    func testTimelockRoundTrip() throws {
        let n = try PCAVdf.insecureDevSetup(bits: 64).N
        let beacon = Array("beacon-0123456789abcdef".utf8)
        let action: JSONValue = .string("dGVzdC1hY3Rpb24")
        let p = try PCATimelock.proveTimelockElapsed(action, steps: 50, N: n, beacon: beacon, allowInsecureDevModulus: true)
        let o = PCATimelock.Options(steps: 50, N: n, beacon: beacon, allowInsecureDevModulus: true)
        XCTAssertTrue(PCATimelock.verifyTimelock(action, p, o))
        XCTAssertFalse(PCATimelock.verifyTimelock(.string("other"), p, o))
        XCTAssertFalse(PCATimelock.verifyTimelock(action, p, PCATimelock.Options(steps: 51, N: n, beacon: beacon, allowInsecureDevModulus: true)))
        XCTAssertFalse(PCATimelock.verifyTimelock(action, p, PCATimelock.Options(steps: 50, N: n, beacon: beacon))) // a dev modulus is never production
    }
}

/// The corpus's bytes member: {"$bytes": base64url}.
enum BaseLike {
    static func bytesValue(_ b: [UInt8]) -> JSONValue { .object(["$bytes": .string(Base64URLStrict.encode(b))]) }
}
