import Foundation
import BigInt
import CryptoKit

/// Wesolowski Verifiable Delay Function over an RSA group (the reference is @atlasauth/pca-vdf): `y = x^(2^T) mod N` takes T SEQUENTIAL squarings,
/// and a proof `pi = x^floor(2^T / l)` (l = a Fiat-Shamir challenge prime) lets anyone check it with two modular exponentiations. Same domains,
/// transcript, check order and refusal reasons as the reference, so challenge primes and proofs are byte-identical.
///
/// A VDF in an RSA group needs a modulus of unknown factorisation (`RSA_2048_CHALLENGE_MODULUS`, or a ceremony modulus; see `checkProductionModulus`).
/// Step counts are JavaScript numbers (`Double`): anything that is not a non-negative safe integer is refused.
public enum PCAVdf {
    public static let CHALLENGE_PRIME_BITS = 256
    public static let INSECURE_DEV_SETUP_DEFAULT_BITS = 2048
    public static let MIN_PRODUCTION_MODULUS_BITS = 2048

    public static let RSA_2048_CHALLENGE_MODULUS = BigInt(
        "25195908475657893494027183240048398571429282126204032027777137836043662020707595556264018525880784406918290641249515082189298559149176184502808489120072"
        + "84499268739280728777673597141834727026189637501497182469116507761337985909570009733045974880842840179742910064245869181719511874612151517265463228221686"
        + "99875491824224336372590851418654620435767984233871847744479207399342365848238242811981638150106748104516603773060562016196762561338441436038339044149526"
        + "34432190114657544454178424020924616515723350778707749817125772467962926386356373289912154831438167899885040445364023527381951378636564391212010397122822120720357")!
    public static let DEFAULT_MODULUS = RSA_2048_CHALLENGE_MODULUS

    public struct VdfError: Error, CustomStringConvertible {
        public let description: String
        init(_ m: String) { description = m }
    }

    public struct Proof: Equatable { public var y: BigInt; public var pi: BigInt }
    public struct Verdict: Equatable { public var ok: Bool; public var reason: String? }

    // MARK: integer helpers

    private static let maxSafe = 9007199254740991.0

    /// `Number.isSafeInteger(v)` as an Int.
    static func safeInt(_ v: Double) -> Int? {
        guard v.isFinite, v.rounded(.towardZero) == v, abs(v) <= maxSafe else { return nil }
        return Int(v)
    }

    /// JS BigInt `%`: the sign follows the dividend; a zero divisor throws.
    static func rem(_ a: BigInt, _ n: BigInt) throws -> BigInt {
        guard n != 0 else { throw VdfError("Division by zero") }
        let r = BigInt(sign: .plus, magnitude: a.magnitude % n.magnitude)
        return a < 0 ? -r : r
    }

    static func umod(_ x: BigInt, _ n: BigInt) throws -> BigInt { try rem(try rem(x, n) + n, n) }

    static func big(_ u: BigUInt) -> BigInt { BigInt(sign: .plus, magnitude: u) }

    static func isOdd(_ n: BigUInt) -> Bool { n[bitAt: 0] }

    static func fromBytes(_ b: [UInt8]) -> BigUInt { b.reduce(BigUInt(0)) { ($0 << 8) | BigUInt($1) } }

    public static func bytesToBigInt(_ b: [UInt8]) -> BigInt { big(fromBytes(b)) }

    /// Big-endian magnitude; zero is one zero byte, a negative value throws.
    public static func bigIntToBytes(_ v: BigInt) throws -> [UInt8] {
        guard v >= 0 else { throw VdfError("bigIntToBytes: negative value") }
        if v == 0 { return [0] }
        return [UInt8](v.magnitude.serialize())
    }

    private static func u32be(_ n: UInt32) -> [UInt8] { [UInt8(n >> 24), UInt8((n >> 16) & 255), UInt8((n >> 8) & 255), UInt8(n & 255)] }
    private static func u64be(_ n: UInt64) -> [UInt8] { (0..<8).map { UInt8((n >> UInt64(56 - 8 * $0)) & 255) } }
    static func lenPrefixed(_ b: [UInt8]) -> [UInt8] { u32be(UInt32(truncatingIfNeeded: b.count)) + b }
    static func sha256(_ b: [UInt8]) -> [UInt8] { Array(SHA256.hash(data: Data(b))) }

    static func normalizeSteps(_ t: Double) throws -> Int {
        guard let s = safeInt(t), s >= 0 else { throw VdfError("VDF: steps T must be a non-negative safe integer, got \(t)") }
        return s
    }

    public static func gcd(_ a: BigInt, _ b: BigInt) -> BigInt {
        var x = a.magnitude, y = b.magnitude
        while !y.isZero { (x, y) = (y, x % y) }
        return big(x)
    }

    static func isUnit(_ v: BigInt, _ n: BigInt) -> Bool { v > 0 && v < n && gcd(v, n) == 1 }

    /// `base^exp mod m` for a positive modulus and a non-negative exponent (an inverse in a group of unknown order is refused).
    public static func modpow(_ base: BigInt, _ exp: BigInt, _ mod: BigInt) throws -> BigInt {
        guard mod > 0 else { throw VdfError("modpow: modulus must be positive") }
        if mod == 1 { return 0 }
        guard exp >= 0 else { throw VdfError("modpow: negative exponent (no inverse in a group of unknown order)") }
        let b = try umod(base, mod)
        return big(b.magnitude.power(exp.magnitude, modulus: mod.magnitude))
    }

    // MARK: primality (Baillie-PSW: strong Miller-Rabin on the first 25 primes + strong Lucas)

    private static let smallPrimes: [UInt64] = [2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37, 41, 43, 47, 53, 59, 61, 67, 71, 73, 79, 83, 89, 97]

    static func isPerfectSquare(_ n: BigInt) -> Bool {
        if n < 0 { return false }
        if n < 2 { return true }
        let r = n.magnitude.squareRoot()
        return r * r == n.magnitude
    }

    /// `a mod n` as a non-negative value for a small signed `a`.
    private static func floorMod(_ a: Int, _ n: BigUInt) -> BigUInt {
        if a >= 0 { return BigUInt(a) % n }
        let r = BigUInt(-a) % n
        return r.isZero ? r : n - r
    }

    /// `(c * x) mod n` for a small signed `c` and `x < n`.
    private static func mulSmallMod(_ c: Int, _ x: BigUInt, _ n: BigUInt) -> BigUInt {
        let m = (BigUInt(abs(c)) * x) % n
        return c < 0 ? (m.isZero ? m : n - m) : m
    }

    private static func jacobi(_ aIn: BigUInt, _ nIn: BigUInt) -> Int {
        var a = aIn, n = nIn, r = 1
        a %= n
        while !a.isZero {
            while !isOdd(a) {
                a >>= 1
                let m = Int(n % 8)
                if m == 3 || m == 5 { r = -r }
            }
            swap(&a, &n)
            if Int(a % 4) == 3 && Int(n % 4) == 3 { r = -r }
            a %= n
        }
        return n == 1 ? r : 0
    }

    public static func isStrongLucasProbablePrime(_ nSigned: BigInt) -> Bool {
        if nSigned < 3 || !isOdd(nSigned.magnitude) || isPerfectSquare(nSigned) { return false }
        let n = nSigned.magnitude
        var dd = 5
        while true {
            let j = jacobi(floorMod(dd, n), n)
            if j == -1 { break }
            if j == 0 && BigUInt(abs(dd)) != n { return false }
            dd = dd > 0 ? -(dd + 2) : -dd + 2
        }
        let p = 1
        let q = (1 - dd) / 4 // exact: D = 1 (mod 4)
        func mod(_ x: BigUInt) -> BigUInt { x % n }
        func half(_ x: BigUInt) -> BigUInt { (isOdd(x) ? x + n : x) >> 1 }
        var d = n + 1
        var s = 0
        while !isOdd(d) { d >>= 1; s += 1 }
        var u = BigUInt(1), v = BigUInt(p), qk = floorMod(q, n)
        var i = d.bitWidth - 2
        while i >= 0 {
            u = mod(u * v)
            v = (v * v + n * 2 - qk * 2) % n // v*v - 2*qk, kept non-negative (qk < n)
            qk = mod(qk * qk)
            if d[bitAt: i] {
                let u1 = half(mod(u + v)) // p == 1
                let v1 = half((mulSmallMod(dd, u, n) + v) % n)
                u = u1; v = v1
                qk = mulSmallMod(q, qk, n)
            }
            i -= 1
        }
        if u.isZero || v.isZero { return true }
        var k = 1
        while k < s {
            v = (v * v + n * 2 - qk * 2) % n
            if v.isZero { return true }
            qk = mod(qk * qk)
            k += 1
        }
        return false
    }

    public static func isMillerRabinProbablePrime(_ nSigned: BigInt) -> Bool {
        if nSigned < 3 || !isOdd(nSigned.magnitude) { return false }
        let n = nSigned.magnitude
        var d = n - 1
        var s = 0
        while !isOdd(d) { d >>= 1; s += 1 }
        for a in smallPrimes {
            let base = BigUInt(a) % n
            if base.isZero { continue }
            var x = base.power(d, modulus: n)
            if x == 1 || x == n - 1 { continue }
            var witness = true
            var k = 1
            while k < s {
                x = (x * x) % n
                if x == n - 1 { witness = false; break }
                k += 1
            }
            if witness { return false }
        }
        return true
    }

    public static func isProbablePrime(_ n: BigInt) -> Bool {
        if n < 2 { return false }
        for p in smallPrimes {
            if n == BigInt(p) { return true }
            if n.magnitude % BigUInt(p) == 0 { return false }
        }
        return isMillerRabinProbablePrime(n) && isStrongLucasProbablePrime(n)
    }

    // MARK: Fiat-Shamir challenge prime

    static let hashToPrimeDomain = Array("atlas-pca/vdf/wesolowski/hash-to-prime/v1".utf8) + [0]

    /// The challenge prime of (x, y, T, N): `bits` in [8, 8192] (default 256), the transcript length-prefixed, candidates expanded by counter / block sha256.
    public static func hashToPrime(_ x: BigInt, _ y: BigInt, _ t: Double, _ n: BigInt, bits: Double = Double(CHALLENGE_PRIME_BITS)) throws -> BigInt {
        guard let b = safeInt(bits), b >= 8, b <= 8192 else { throw VdfError("hashToPrime: bits must be an integer in [8, 8192]") }
        let steps = try normalizeSteps(t)
        let xr = try umod(x, n), yr = try umod(y, n)
        var transcript = hashToPrimeDomain
        transcript += lenPrefixed(try bigIntToBytes(xr))
        transcript += lenPrefixed(try bigIntToBytes(yr))
        transcript += lenPrefixed(try bigIntToBytes(BigInt(steps)))
        transcript += lenPrefixed(try bigIntToBytes(n))
        transcript += lenPrefixed(u32be(UInt32(b)))
        let seed = sha256(transcript)
        let bytesNeeded = (b + 7) / 8
        let topBit = BigUInt(1) << (b - 1)
        let mask = (BigUInt(1) << b) - 1
        var counter: UInt64 = 0
        while true {
            var chunks: [UInt8] = []
            var block: UInt32 = 0
            while chunks.count < bytesNeeded {
                chunks += sha256(seed + u64be(counter) + u32be(block))
                block += 1
            }
            let cand = (fromBytes(Array(chunks[0..<bytesNeeded])) & mask) | topBit | 1
            if isProbablePrime(big(cand)) { return big(cand) }
            counter += 1
        }
    }

    // MARK: the VDF

    /// `x^(2^T) mod N` by T sequential squarings.
    public static func sequentialSquare(_ x: BigInt, _ t: Double, _ n: BigInt) throws -> BigInt {
        guard n > 1 else { throw VdfError("VDF: modulus N must be > 1") }
        let steps = try normalizeSteps(t)
        let m = n.magnitude
        var y = try umod(x, n).magnitude
        for _ in 0..<steps { y = (y * y) % m }
        return big(y)
    }

    private static func wesolowskiProof(_ x: BigInt, _ t: Int, _ l: BigInt, _ n: BigInt) throws -> BigInt {
        let m = n.magnitude, lm = l.magnitude
        let xr = try umod(x, n).magnitude
        var pi = BigUInt(1) % m
        var r = BigUInt(1) % lm
        for _ in 0..<t {
            let twoR = r << 1
            let bit = twoR >= lm // r < l, so floor(2r / l) is 0 or 1
            r = bit ? twoR - lm : twoR
            pi = (pi * pi) % m
            if bit { pi = (pi * xr) % m }
        }
        return big(pi)
    }

    private static func checkEvalInput(_ x: BigInt, _ n: BigInt) throws {
        let xr = try umod(x, n)
        if !isUnit(xr, n) || xr == 1 || xr == n - 1 { throw VdfError("VDF: input x must be a non-trivial unit mod N (not 0, 1, -1, or sharing a factor with N)") }
    }

    private static func checkModulus(_ n: BigInt) throws {
        if n <= 3 || !isOdd(n.magnitude) { throw VdfError("VDF: modulus N must be odd and > 3") }
    }

    /// Evaluate: y = x^(2^T) mod N and the Wesolowski proof (the squarings ARE the delay: deliberately slow).
    public static func eval(_ x: BigInt, _ t: Double, _ n: BigInt) throws -> Proof {
        try checkModulus(n)
        let steps = try normalizeSteps(t)
        try checkEvalInput(x, n)
        let y = try sequentialSquare(x, t, n)
        let l = try hashToPrime(x, y, t, n)
        return Proof(y: y, pi: try wesolowskiProof(x, steps, l, n))
    }

    /// The representative of {y, N-y} that is at most N/2.
    public static func canonicalVdfOutput(_ y: BigInt, _ n: BigInt) -> BigInt { y > n - y ? n - y : y }

    /// `eval` with y and pi in canonical form (unique per input).
    public static func evalCanonical(_ x: BigInt, _ t: Double, _ n: BigInt) throws -> Proof {
        try checkModulus(n)
        let steps = try normalizeSteps(t)
        try checkEvalInput(x, n)
        let y = canonicalVdfOutput(try sequentialSquare(x, t, n), n)
        let l = try hashToPrime(x, y, t, n)
        return Proof(y: y, pi: canonicalVdfOutput(try wesolowskiProof(x, steps, l, n), n))
    }

    private static func verdict(_ ok: Bool, _ reason: String) -> Verdict { Verdict(ok: ok, reason: ok ? nil : reason) }

    private static func verify(_ x: BigInt, _ y: BigInt, _ pi: BigInt, _ t: Double, _ n: BigInt, canonical: Bool) -> Verdict {
        do {
            if n <= 3 || !isOdd(n.magnitude) { return verdict(false, "bad-modulus") }
            guard let steps = safeInt(t), steps >= 0 else { return verdict(false, "bad-steps") }
            if !isUnit(y, n) || (canonical && y > n - y) { return verdict(false, "non-canonical-y") }
            if !isUnit(pi, n) || (canonical && pi > n - pi) { return verdict(false, "non-canonical-pi") }
            let xr = try umod(x, n)
            if !isUnit(xr, n) || xr == 1 || xr == n - 1 { return verdict(false, "bad-input-x") }
            let l = try hashToPrime(x, y, Double(steps), n)
            let r = try modpow(2, BigInt(steps), l)
            let lhs = try (modpow(pi, l, n) * modpow(xr, r, n)).magnitude % n.magnitude
            let lhsB = big(lhs)
            let good = canonical ? (lhsB == y || lhsB == n - y) : lhsB == y
            return verdict(good, "equation-mismatch")
        } catch {
            return verdict(false, "malformed-input") // fail closed, like the reference catch
        }
    }

    /// {ok} or {ok: false, reason}; never throws.
    public static func verifyDetailed(_ x: BigInt, _ y: BigInt, _ pi: BigInt, _ t: Double, _ n: BigInt) -> Verdict { verify(x, y, pi, t, n, canonical: false) }
    public static func verifyCanonicalDetailed(_ x: BigInt, _ y: BigInt, _ pi: BigInt, _ t: Double, _ n: BigInt) -> Verdict { verify(x, y, pi, t, n, canonical: true) }
    public static func verifyProof(_ x: BigInt, _ y: BigInt, _ pi: BigInt, _ t: Double, _ n: BigInt) -> Bool { verifyDetailed(x, y, pi, t, n).ok }
    public static func verifyCanonical(_ x: BigInt, _ y: BigInt, _ pi: BigInt, _ t: Double, _ n: BigInt) -> Bool { verifyCanonicalDetailed(x, y, pi, t, n).ok }

    // MARK: modulus screening

    private final class Registry {
        let lock = NSLock()
        var dev = Set<BigInt>()
        var passed = Set<BigInt>()
    }
    private static let registry = Registry()

    private static let screenPrimes: [UInt64] = {
        let limit = 1 << 16
        var sieve = [Bool](repeating: false, count: limit)
        var out: [UInt64] = []
        for i in 2..<limit where !sieve[i] {
            out.append(UInt64(i))
            var j = i * i
            while j < limit { sieve[j] = true; j += i }
        }
        return out
    }()

    private static func randomPrime(_ bits: Int, _ rnd: (Int) -> [UInt8]) throws -> BigInt {
        guard bits >= 16 else { throw VdfError("randomPrime: bits too small") }
        let nbytes = (bits + 7) / 8
        let topBit = BigUInt(1) << (bits - 1)
        let mask = (BigUInt(1) << bits) - 1
        for _ in 0..<50000 {
            let cand = (fromBytes(rnd(nbytes)) & mask) | topBit | 1
            if isProbablePrime(big(cand)) { return big(cand) }
        }
        throw VdfError("insecureDevSetup: randomness source failed to yield a prime (stuck or constant RNG?)")
    }

    /// TEST ONLY: a modulus whose factors the caller knows (so it delays nobody). Registered, so the production screen refuses it.
    public static func insecureDevSetup(bits: Int = INSECURE_DEV_SETUP_DEFAULT_BITS, randomBytes: ((Int) -> [UInt8])? = nil) throws -> (N: BigInt, p: BigInt, q: BigInt, bits: Int) {
        guard bits >= 32 else { throw VdfError("insecureDevSetup: bits must be a safe integer >= 32") }
        let rnd = randomBytes ?? { n in (0..<n).map { _ in UInt8.random(in: 0...255) } }
        let half = bits / 2
        let p = try randomPrime(half, rnd)
        var q = try randomPrime(bits - half, rnd)
        var i = 0
        while p == q {
            if i >= 8 { throw VdfError("insecureDevSetup: randomness source returned the same prime repeatedly (constant RNG?)") }
            q = try randomPrime(bits - half, rnd)
            i += 1
        }
        let n = p * q
        registry.lock.lock(); registry.dev.insert(n); registry.lock.unlock()
        return (n, p, q, n.magnitude.bitWidth)
    }

    /// {ok} or {ok: false, reason}: is this modulus fit for a production VDF (large, odd, not a square, not prime, no small factor, not a dev modulus)?
    public static func checkProductionModulus(_ n: BigInt) -> Verdict {
        registry.lock.lock()
        let isDev = registry.dev.contains(n), passed = registry.passed.contains(n)
        registry.lock.unlock()
        if !isDev && passed { return Verdict(ok: true, reason: nil) }
        if isDev { return verdict(false, "modulus came from insecureDevSetup(): its factors are known, so it provides no delay") }
        if n <= 3 { return verdict(false, "modulus is too small") }
        if n.magnitude.bitWidth < MIN_PRODUCTION_MODULUS_BITS { return verdict(false, "modulus is below \(MIN_PRODUCTION_MODULUS_BITS) bits") }
        if !isOdd(n.magnitude) { return verdict(false, "modulus is even") }
        if isPerfectSquare(n) { return verdict(false, "modulus is a perfect square") }
        if isProbablePrime(n) { return verdict(false, "modulus is prime (group order N-1 is public)") }
        for p in screenPrimes where n.magnitude % BigUInt(p) == 0 { return verdict(false, "modulus has the small prime factor \(p)") }
        registry.lock.lock(); registry.passed.insert(n); registry.lock.unlock()
        return Verdict(ok: true, reason: nil)
    }
}
