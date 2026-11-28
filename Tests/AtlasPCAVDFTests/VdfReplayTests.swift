import XCTest
import Foundation
import BigInt
@testable import AtlasPCAVerify
@testable import AtlasPCAVDF

// AtlasPCAVerify (imported @testable) has its own internal BigUInt; this file means the VDF code's one.
private typealias BigUInt = PCAVdfBigUInt

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

    /// A local or IDE debug build skips the moduli over ~1300 bits (50-100x slower unoptimised); CI never does: its shards set ATLAS_VDF_FULL=1 and the test fails
    /// there if anything was skipped.
    static var full: Bool { ProcessInfo.processInfo.environment["ATLAS_VDF_FULL"] != nil }
    static var onCI: Bool { ProcessInfo.processInfo.environment["GITHUB_ACTIONS"] != nil }

    static func heavy(_ c: Case) -> Bool {
        #if DEBUG
        if full { return false }
        let digits: (JSONValue) -> Int = { v in
            if let s = v.asString { return s.count }
            if let o = v.asObject { return o.values.map { $0.asString?.count ?? 0 }.max() ?? 0 }
            return 0
        }
        let heavyFns: Set<String> = ["vdfEval", "vdfEvalCanonical", "vdfVerifyDetailed", "vdfVerifyCanonicalDetailed", "sequentialSquare", "proveTimelockElapsed", "verifyTimelock", "checkProductionModulus"]
        return heavyFns.contains(c.fn) && (c.args.map(digits).max() ?? 0) > 400
        #else
        return false
        #endif
    }

    /// Cases too slow to share a slice (the 8192-bit challenge prime: ~580 full-width Miller-Rabin rounds, 19-25 minutes at -O) replay on their own leg
    /// (`ATLAS_VDF_SOLO=1`); every `i/N` slice leaves them to it. An unsharded run replays them with the rest.
    static let soloCases: Set<String> = ["hashToPrime/bits8192"]
    static var solo: Bool { ProcessInfo.processInfo.environment["ATLAS_VDF_SOLO"] != nil }

    /// `ATLAS_VDF_SHARD=i/N`: this run replays the cases whose corpus index mod N is i (the heavy and the light cases spread evenly). Unset: every case. A malformed
    /// value is a failure, never a silent full or empty run.
    static func shard() -> (i: Int, n: Int)? {
        guard let raw = ProcessInfo.processInfo.environment["ATLAS_VDF_SHARD"] else { return nil }
        let parts = raw.split(separator: "/", omittingEmptySubsequences: false)
        guard parts.count == 2, let i = Int(parts[0]), let n = Int(parts[1]), n >= 1, i >= 0, i < n,
              String(i) == String(parts[0]), String(n) == String(parts[1]) else {
            XCTFail("ATLAS_VDF_SHARD must be i/N with 0 <= i < N (got \(raw))")
            return (-1, 1)
        }
        return (i, n)
    }

    func testReplay() throws {
        let cases = try Self.corpus(Self.file)
        XCTAssertEqual(cases.count, 6673)
        if Self.onCI { XCTAssertTrue(Self.full, "CI replays the full set: ATLAS_VDF_FULL=1 is required") }
        let sh = Self.shard()
        if sh?.i == -1 { return }
        if Self.solo && sh != nil { XCTFail("ATLAS_VDF_SOLO and ATLAS_VDF_SHARD are separate legs"); return }
        // every solo name is a corpus case exactly once: a renamed case can never drop out of both the slices and the solo leg
        for n in Self.soloCases { XCTAssertEqual(cases.filter { $0.name == n }.count, 1, "solo case \(n) in the corpus") }
        var bad: [String] = []
        var run = 0, skippedHeavy = 0, otherShard = 0, soloLeg = 0, expected = 0
        let prof = Profile()
        prof.start()
        defer { prof.stop() }
        for (index, c) in cases.enumerated() {
            if let s = sh, index % s.n != s.i { otherShard += 1; continue }
            let isSolo = Self.soloCases.contains(c.name)
            if Self.solo != isSolo && (Self.solo || sh != nil) { soloLeg += 1; continue }
            expected += 1
            if Self.heavy(c) { skippedHeavy += 1; continue }
            run += 1
            let want = c.out
            let began = DispatchTime.now().uptimeNanoseconds
            prof.begin(c)
            defer { prof.end(c, began) }
            do {
                let got = try self.run(c)
                if c.threw { bad.append("\(c.name): want throw got \(Canonical.canonicalize(got).prefix(120))") }
                else if Canonical.canonicalize(got) != Canonical.canonicalize(want) { bad.append("\(c.name): want \(Canonical.canonicalize(want).prefix(160)) got \(Canonical.canonicalize(got).prefix(160))") }
            } catch {
                if !c.threw { bad.append("\(c.name): want \(Canonical.canonicalize(want).prefix(160)) got throw \(error)") }
            }
        }
        print("vdf replay: shard \(Self.solo ? "solo" : sh.map { "\($0.i)/\($0.n)" } ?? "all"), \(run) compared, \(skippedHeavy) skipped as heavy (debug build without ATLAS_VDF_FULL), \(otherShard) left to other shards, \(soloLeg) left to the solo or slice legs, \(cases.count) in the corpus")
        if Self.full { XCTAssertEqual(skippedHeavy, 0, "the full replay skips nothing") }
        let inSlice = sh.map { (cases.count - $0.i + $0.n - 1) / $0.n } ?? cases.count
        XCTAssertEqual(expected + soloLeg, inSlice, "every case of this slice is accounted for")
        if Self.solo { XCTAssertEqual(expected, Self.soloCases.count, "the solo leg replays exactly the solo cases") }
        XCTAssertEqual(run + skippedHeavy, expected, "every case of this leg is replayed or skipped as heavy")
        if Self.full { XCTAssertEqual(run, expected) } else { XCTAssertGreaterThan(run, expected / 2) }
        XCTAssert(bad.isEmpty, "\(bad.count)/\(run) divergent:\n" + bad.prefix(30).joined(separator: "\n"))
    }

    /// The Montgomery modpow against BigInt's own `power(_:modulus:)`: random and edge moduli (3, 2^k +- 1, all-ones limbs), exponents 0 and 1, bases at and above the modulus.
    func testMontgomeryModpowMatchesBigInt() throws {
        var g = SystemRandomNumberGenerator()
        func rnd(_ limbs: Int) -> BigUInt { BigUInt(words: (0..<limbs).map { _ in UInt.random(in: 0...UInt.max, using: &g) }) }
        var mods: [BigUInt] = [3, 5, 7, (BigUInt(1) << 61) - 1, (BigUInt(1) << 64) - 1, (BigUInt(1) << 64) + 1, (BigUInt(1) << 127) - 1, (BigUInt(1) << 128) + 1,
                               (BigUInt(1) << 192) - 1, (BigUInt(1) << 256) - 189, (BigUInt(1) << 521) - 1, (BigUInt(1) << 2048) - 1, (BigUInt(1) << 2048) + 1]
        for limbs in [1, 2, 3, 4, 8, 17, 33] { for _ in 0..<3 { mods.append(rnd(limbs) | 1 | (BigUInt(1) << (64 * limbs - 1))) } }
        for m in mods {
            guard let mt = PCAMont(m) else { XCTFail("no context for \(m)"); continue }
            var bases: [BigUInt] = [0, 1, 2, m - 1, m, m + 1, m * 3 + 2, rnd(1), rnd(mt.k), rnd(mt.k + 2)]
            bases.append((m - 1) / 2)
            var exps: [BigUInt] = [0, 1, 2, 3, 15, 16, 17, 255, 65537, m - 1, m, rnd(1), rnd(3)]
            if mt.k <= 8 { exps.append(rnd(mt.k)) }
            for b in bases {
                for e in exps {
                    let want = (b % m).power(e, modulus: m)
                    let got = mt.fromMont(mt.pow(mt.toMont(b), e))
                    XCTAssertEqual(got, want, "\(b)^\(e) mod \(m)")
                }
            }
            // squarings and the one-step product
            let x = rnd(mt.k) % m
            XCTAssertEqual(mt.fromMont(mt.squarings(mt.toMont(x), 5)), x.power(32, modulus: m))
            XCTAssertEqual(mt.fromMont(mt.mul(mt.toMont(x), mt.toMont(m - 1))), (x * (m - 1)) % m)
            XCTAssertEqual(mt.fromMont(mt.add(mt.toMont(x), mt.toMont(m - 1))), (x + m - 1) % m)
            XCTAssertEqual(mt.fromMont(mt.sub(mt.toMont(x), mt.toMont(m - 1))), (x + 1) % m)
        }
        XCTAssertNil(PCAMont(4)); XCTAssertNil(PCAMont(1)); XCTAssertNil(PCAMont(0))
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

/// Cumulative time per function and the slowest cases, printed (and flushed) every 60 seconds from a background thread, so a killed run still shows the hotspot.
final class Profile: @unchecked Sendable {
    private let lock = NSLock()
    private var perFn: [String: (n: Int, sec: Double)] = [:]
    private var slow: [(sec: Double, name: String, fn: String, digits: Int)] = []
    private var current = ""
    private var running = true

    static func digits(_ c: VdfReplayTests.Case) -> Int {
        c.args.map { v -> Int in
            if let s = v.asString { return s.count }
            if let o = v.asObject { return o.values.map { $0.asString?.count ?? 0 }.max() ?? 0 }
            return 0
        }.max() ?? 0
    }

    func begin(_ c: VdfReplayTests.Case) { lock.lock(); current = "\(c.fn) \(c.name) (\(Profile.digits(c)) digits)"; lock.unlock() }

    func end(_ c: VdfReplayTests.Case, _ began: UInt64) {
        let sec = Double(DispatchTime.now().uptimeNanoseconds - began) / 1e9
        lock.lock()
        let old = perFn[c.fn] ?? (0, 0)
        perFn[c.fn] = (old.n + 1, old.sec + sec)
        slow.append((sec, c.name, c.fn, Profile.digits(c)))
        slow.sort { $0.sec > $1.sec }
        if slow.count > 5 { slow.removeLast() }
        current = ""
        lock.unlock()
    }

    func report(_ title: String) {
        lock.lock()
        var out = "vdf profile (\(title)); running now: \(current.isEmpty ? "-" : current)\n"
        for (fn, v) in perFn.sorted(by: { $0.value.sec > $1.value.sec }) { out += "  \(fn): \(v.n) cases, \(String(format: "%.2f", v.sec)) s\n" }
        for s in slow { out += "  slowest: \(String(format: "%.2f", s.sec)) s \(s.fn) \(s.name) (\(s.digits) decimal digits, about \(Int(Double(s.digits) * 3.3219)) bits)\n" }
        lock.unlock()
        print(out)
        fflush(stdout)
    }

    func start() {
        let t = Thread { [self] in
            var waited = 0
            while true {
                lock.lock(); let r = running; lock.unlock()
                if !r { return }
                Thread.sleep(forTimeInterval: 1)
                waited += 1
                if waited >= 60 { waited = 0; report("every 60 s") }
            }
        }
        t.start()
    }

    func stop() { lock.lock(); running = false; lock.unlock(); report("final") }
}

/// The corpus's bytes member: {"$bytes": base64url}.
enum BaseLike {
    static func bytesValue(_ b: [UInt8]) -> JSONValue { .object(["$bytes": .string(Base64URLStrict.encode(b))]) }
}
