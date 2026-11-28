import CLess
import Foundation
import XCTest
@testable import AtlasPCALess

/// Direct tests of the CLess C API (atlas_less.c) with arguments the Swift wrapper never passes: the C's own NULL, length and overflow
/// checks, the opened-length check, the allocation-failure path and the generator lock. They are the kill set of the C mutation job for
/// atlas_less.c. Calls that a mutant turns into a NULL dereference, an overrun or a deadlock run in a child process of this test bundle
/// (setUp runs the case named by PCA_C_CHILD_CASE and exits), so such a mutant fails a test here instead of ending the run.
fileprivate struct LessCFixture { let pk, sk, msg, sig, sigEmpty: [UInt8] }

/// State of the test-only seams of atlas_less.c: a C function pointer cannot capture, so the hooks below read and write these.
fileprivate enum LessSeam {
    static var calls = 0, failAt = 0, signLen = 0, skFreed = 0, skDirty = false
    static var skBuf: UnsafeMutableRawPointer?

    /// Routes the wrapper's allocations through malloc, failing the `failAt`-th (0: none), and checks on free that the temporary
    /// secret key (the one allocation of atlas_less_cat1_secret_key_bytes) was wiped.
    static func installAllocator(failAt: Int) {
        calls = 0
        self.failAt = failAt
        atlas_less_test_set_allocator({ n in
            LessSeam.calls += 1
            if LessSeam.calls == LessSeam.failAt { return nil }
            let p = malloc(n)
            if n == Int(atlas_less_cat1_secret_key_bytes()) { LessSeam.skBuf = p }
            return p
        }, { p in
            if let p = p, p == LessSeam.skBuf {
                let b = p.assumingMemoryBound(to: UInt8.self)
                for i in 0..<Int(atlas_less_cat1_secret_key_bytes()) where b[i] != 0 { LessSeam.skDirty = true }
                LessSeam.skFreed += 1
                LessSeam.skBuf = nil
            }
            free(p)
        })
    }

    /// Replaces the reference crypto_sign with one that reports success and a detached signature of `signLen` bytes (zeros):
    /// signLen == the minimum is exactly what crypto_sign returns when LESS_sign hits its pivot failure (zero published seeds).
    static func installSigner(signLen: Int) {
        self.signLen = signLen
        atlas_less_test_set_sign { _, smlen, _, mlen, _ in
            smlen?.pointee = mlen + UInt64(LessSeam.signLen)
            return 0
        }
    }
}

extension LessNativeTests {
    static let cChildVar = "PCA_C_CHILD_CASE"
    static var cLockChecked = false

    fileprivate static var pkN: Int { Int(atlas_less_cat1_public_key_bytes()) }
    fileprivate static var skN: Int { Int(atlas_less_cat1_secret_key_bytes()) }
    fileprivate static var sigMin: Int { Int(atlas_less_cat1_signature_min_bytes()) }
    fileprivate static var sigMax: Int { Int(atlas_less_cat1_signature_max_bytes()) }
    fileprivate static let step = 16

    fileprivate static func seed(_ label: String) -> [UInt8] {
        var b = [UInt8](repeating: 0, count: 32)
        for (i, c) in label.utf8.prefix(32).enumerated() { b[i] = c }
        return b
    }

    /// The shared known-answer key and signature (keygen seed "less-kg-main", signing seed "less-sign-main": the less-cat1-valid vector)
    /// and a signature over the empty message, which only a valid signature can tell from NULL with a length.
    fileprivate static func cFixture() throws -> LessCFixture {
        let key = try LessNative.keyFromSeed(seed("less-kg-main"))
        let msg = Array("atlas-pca/less-conformance/code-based-leaf-message".utf8)
        return LessCFixture(pk: key.vk, sk: key.sk, msg: msg, sig: try LessNative.sign(sk: key.sk, msg: msg, seed: seed("less-sign-main")),
                            sigEmpty: try LessNative.sign(sk: key.sk, msg: [], seed: seed("less-sign-empty")))
    }

    /// A C copy of `bytes` followed by `extra` zero bytes (never a zero-sized allocation); the caller deallocates it.
    fileprivate static func cCopy(_ bytes: [UInt8], extra: Int = 0) -> UnsafeMutablePointer<UInt8> {
        let n = max(bytes.count + extra, 1)
        let p = UnsafeMutablePointer<UInt8>.allocate(capacity: n)
        p.initialize(repeating: 0, count: n)
        for (i, b) in bytes.enumerated() { p[i] = b }
        return p
    }

    fileprivate static func sizeMax(minus k: Int) -> Int { Int(bitPattern: UInt.max - UInt(k)) }

    // MARK: verify

    func testCVerifyAuthenticatesExactlyTheMessage() throws {
        let f = try Self.cFixture()
        let pk = Self.cCopy(f.pk), msg = Self.cCopy(f.msg), sig = Self.cCopy(f.sig), se = Self.cCopy(f.sigEmpty)
        defer { pk.deallocate(); msg.deallocate(); sig.deallocate(); se.deallocate() }
        XCTAssertEqual(atlas_less_cat1_verify(pk, f.pk.count, msg, f.msg.count, sig, f.sig.count), 1)
        // the empty message given as NULL with length 0 is the empty message, not a NULL argument
        XCTAssertEqual(atlas_less_cat1_verify(pk, f.pk.count, nil, 0, se, f.sigEmpty.count), 1)
        XCTAssertEqual(atlas_less_cat1_verify(pk, f.pk.count, msg, 1, se, f.sigEmpty.count), 0)
        XCTAssertEqual(atlas_less_cat1_verify(pk, f.pk.count, nil, 0, sig, f.sig.count), 0)
        // msg||sig re-split 16 bytes either way still opens under the key (the reference reads the signature length from its trailing
        // seed count): only the comparison of the opened length with msg_len refuses a prefix or an extension of the signed message
        XCTAssertLessThanOrEqual(f.sig.count + Self.step, Self.sigMax, "the fixture leaves room for one more seed slot")
        let k = f.msg.count - Self.step
        let longer = Self.cCopy(Array(f.msg[k...]) + f.sig)
        let ext = Self.cCopy(f.msg + f.sig.prefix(Self.step))
        defer { longer.deallocate(); ext.deallocate() }
        XCTAssertEqual(atlas_less_cat1_verify(pk, f.pk.count, msg, k, longer, f.sig.count + Self.step), 0, "a strict prefix of the signed message")
        XCTAssertEqual(atlas_less_cat1_verify(pk, f.pk.count, ext, f.msg.count + Self.step, sig + Self.step, f.sig.count - Self.step), 0,
                       "the signed message extended by signature bytes")
    }

    /// Every buffer is real and at least as long as the length passed, so a mutant that skips a check reads only valid memory.
    func testCVerifyRefusesLengthsTheWrapperNeverPasses() throws {
        let f = try Self.cFixture()
        let pk = Self.cCopy(f.pk, extra: 1), msg = Self.cCopy(f.msg), big = Self.cCopy(f.sig, extra: 2 * Self.sigMax)
        defer { pk.deallocate(); msg.deallocate(); big.deallocate() }
        XCTAssertEqual(atlas_less_cat1_verify(pk, f.pk.count, msg, f.msg.count, big, f.sig.count), 1)
        XCTAssertEqual(atlas_less_cat1_verify(pk, f.pk.count - 1, msg, f.msg.count, big, f.sig.count), 0, "public key one byte short")
        XCTAssertEqual(atlas_less_cat1_verify(pk, f.pk.count + 1, msg, f.msg.count, big, f.sig.count), 0, "public key one byte long")
        for n in [f.sig.count - 1, f.sig.count + 1, Self.sigMin - 1, Self.sigMin - Self.step, Self.sigMax + 1, Self.sigMax + Self.step] {
            XCTAssertEqual(atlas_less_cat1_verify(pk, f.pk.count, msg, f.msg.count, big, n), 0, "signature length \(n)")
        }
    }

    /// The length checks are observable before any byte is read: with msg_len at the overflow boundary (SIZE_MAX - sig_len) a length
    /// that gets past them reaches malloc(SIZE_MAX), which fails with ENOMEM (and the answer stays 0), while a refused length returns
    /// before any allocation and leaves errno 0.
    func testCVerifyLengthChecksComeBeforeTheAllocation() throws {
        let f = try Self.cFixture()
        let pk = Self.cCopy(f.pk), msg = Self.cCopy(f.msg), buf = Self.cCopy([], extra: 2 * Self.sigMax)
        defer { pk.deallocate(); msg.deallocate(); buf.deallocate() }
        func attempt(_ sigLen: Int) -> Int32 {
            errno = 0
            let r = atlas_less_cat1_verify(pk, f.pk.count, msg, Self.sizeMax(minus: sigLen), buf, sigLen)
            let e = errno
            XCTAssertEqual(r, 0, "sig_len \(sigLen) at the overflow boundary (the allocation fails) accepted")
            return e
        }
        for n in [Self.sigMin, Self.sigMax] { XCTAssertEqual(attempt(n), ENOMEM, "legal sig_len \(n): the boundary itself is admitted") }
        for n in [Self.sigMin - Self.step, Self.sigMax + Self.step, Self.sigMin + 1, Self.sigMax - 1] {
            XCTAssertEqual(attempt(n), 0, "illegal sig_len \(n) got past the length checks")
        }
    }

    // MARK: keygen and sign

    func testCKeygenRefusesCapacitiesAndSeedsTheWrapperNeverPasses() {
        let pkN = Self.pkN, skN = Self.skN
        let pk = Self.cCopy([], extra: pkN + 8), sk = Self.cCopy([], extra: skN + 8), seed = Self.cCopy(Self.seed("c-keygen") + Self.seed("c-keygen-2"))
        defer { pk.deallocate(); sk.deallocate(); seed.deallocate() }
        XCTAssertEqual(atlas_less_cat1_keygen(pk, pkN, sk, skN, seed, 32), 1)
        XCTAssertEqual(atlas_less_cat1_keygen(pk, pkN, sk, skN, seed, 64), 1)
        for (pc, sc, sl) in [(pkN - 1, skN, 32), (pkN + 1, skN, 32), (pkN, skN - 1, 32), (pkN, skN + 1, 32), (0, skN, 32), (pkN, 0, 32),
                             (pkN, skN, 31), (pkN, skN, 1), (pkN, skN, 0)] {
            XCTAssertEqual(atlas_less_cat1_keygen(pk, pc, sk, sc, seed, sl), 0, "pk_cap \(pc) sk_cap \(sc) seed_len \(sl)")
        }
    }

    func testCSignRefusesLengthsTheWrapperNeverPasses() throws {
        let f = try Self.cFixture()
        let skN = Self.skN, sigMax = Self.sigMax
        let sk = Self.cCopy(f.sk, extra: 32), seed = Self.cCopy(Self.seed("c-sign") + Self.seed("c-sign-2")), msg = Self.cCopy(f.msg)
        let sig = Self.cCopy([], extra: 2 * sigMax), pk = Self.cCopy(f.pk)
        defer { sk.deallocate(); seed.deallocate(); msg.deallocate(); sig.deallocate(); pk.deallocate() }
        var n = 0
        for (sl, cap) in [(32, sigMax), (64, sigMax), (32, 2 * sigMax)] {
            n = 0
            XCTAssertEqual(atlas_less_cat1_sign(sk, skN, msg, 3, seed, sl, sig, cap, &n), 1, "seed_len \(sl) sig_cap \(cap)")
            XCTAssertTrue(n >= Self.sigMin && n <= sigMax, "signature length \(n)")
        }
        n = 0
        XCTAssertEqual(atlas_less_cat1_sign(sk, skN, nil, 0, seed, 32, sig, sigMax, &n), 1, "the empty message given as NULL")
        XCTAssertEqual(atlas_less_cat1_verify(pk, f.pk.count, nil, 0, sig, n), 1, "and it signs the empty message")
        for (what, skLen, sl, cap) in [("sk_len-1", skN - 1, 32, sigMax), ("sk_len+1", skN + 1, 32, sigMax), ("sk_len 0", 0, 32, sigMax),
                                       ("seed_len 31", skN, 31, sigMax), ("seed_len 1", skN, 1, sigMax), ("seed_len 0", skN, 0, sigMax),
                                       ("sig_cap max-1", skN, 32, sigMax - 1), ("sig_cap 0", skN, 32, 0)] {
            XCTAssertEqual(atlas_less_cat1_sign(sk, skLen, msg, 3, seed, sl, sig, cap, &n), 0, what)
        }
    }

    // MARK: child-process cases

    /// NULL pointers and overflowing lengths: the unmutated C refuses each before reading anything (every answer 0).
    fileprivate static let rawCases = ["verify-nil-pk", "verify-nil-sig", "verify-nil-msg-with-length", "verify-msg-len-max", "verify-msg-len-wraps-to-zero",
                                       "sign-nil-sk", "sign-nil-seed", "sign-nil-sig", "sign-nil-sig-len", "sign-nil-msg-with-length",
                                       "sign-len-bound-plus-1", "sign-len-max", "keygen-nil-pk", "keygen-nil-sk", "keygen-nil-seed"]

    func testCNullAndOverflowArgumentsAreRefused() throws {
        let r = try runCChild("testSizesAreTheReferences", "raw", seconds: 300)
        XCTAssertTrue(r.ok && r.out.contains("c-done"), "the child did not finish cleanly:\n\(r.out)")
        for c in Self.rawCases { XCTAssertTrue(r.out.contains("c-case \(c) 0\n"), "\(c): want a clean refusal (0):\n\(r.out)") }
    }

    fileprivate static func runRawCases() throws {
        let f = try cFixture()
        let pk = cCopy(f.pk), msg = cCopy(f.msg), sig = cCopy(f.sig), sk = cCopy(f.sk), seed = cCopy(Self.seed("c-raw"))
        let out = cCopy([], extra: 2 * sigMax), kpk = cCopy([], extra: pkN), ksk = cCopy([], extra: skN)
        var n = 0
        let say = { (c: String, r: Int32) in FileHandle.standardError.write(Data("c-case \(c) \(r)\n".utf8)) }
        let pl = f.pk.count, ml = f.msg.count, sl = f.sig.count
        for c in rawCases {
            let r: Int32
            switch c {
            case "verify-nil-pk": r = atlas_less_cat1_verify(nil, pl, msg, ml, sig, sl)
            case "verify-nil-sig": r = atlas_less_cat1_verify(pk, pl, msg, ml, nil, sl)
            case "verify-nil-msg-with-length": r = atlas_less_cat1_verify(pk, pl, nil, ml, sig, sl)
            case "verify-msg-len-max": r = atlas_less_cat1_verify(pk, pl, msg, sizeMax(minus: 0), sig, sl)
            case "verify-msg-len-wraps-to-zero": r = atlas_less_cat1_verify(pk, pl, msg, sizeMax(minus: sl - 1), sig, sl) // msg_len + sig_len wraps to 0
            case "sign-nil-sk": r = atlas_less_cat1_sign(nil, skN, msg, 3, seed, 32, out, sigMax, &n)
            case "sign-nil-seed": r = atlas_less_cat1_sign(sk, skN, msg, 3, nil, 32, out, sigMax, &n)
            case "sign-nil-sig": r = atlas_less_cat1_sign(sk, skN, msg, 3, seed, 32, nil, sigMax, &n)
            case "sign-nil-sig-len": r = atlas_less_cat1_sign(sk, skN, msg, 3, seed, 32, out, sigMax, nil)
            case "sign-nil-msg-with-length": r = atlas_less_cat1_sign(sk, skN, nil, 3, seed, 32, out, sigMax, &n)
            // sizeof(sign_t) is LESS_SIGNATURE_SIZE(MAX_PUBLISHED_SEEDS), the signature maximum: one past the guard, cap would wrap
            case "sign-len-bound-plus-1": r = atlas_less_cat1_sign(sk, skN, msg, sizeMax(minus: sigMax + 16 - 1), seed, 32, out, sigMax, &n)
            case "sign-len-max": r = atlas_less_cat1_sign(sk, skN, msg, sizeMax(minus: 0), seed, 32, out, sigMax, &n)
            case "keygen-nil-pk": r = atlas_less_cat1_keygen(nil, pkN, ksk, skN, seed, 32)
            case "keygen-nil-sk": r = atlas_less_cat1_keygen(kpk, pkN, nil, skN, seed, 32)
            case "keygen-nil-seed": r = atlas_less_cat1_keygen(kpk, pkN, ksk, skN, nil, 32)
            default: r = -1
            }
            say(c, r)
        }
        FileHandle.standardError.write(Data("c-done\n".utf8))
    }

    /// The test-only seams. Allocation failure: keygen answers 0 and writes nothing whichever temporary fails (a mutant that goes on
    /// dereferences NULL, hence the child). Wipe: the temporary secret key is all zero when freed (seeds chosen so some key's last
    /// byte is non-zero). Signer: the wrapper refuses the reference's zero-seed failure output and any length it cannot produce,
    /// and accepts the shortest real one (one published seed); NULL restores the reference.
    fileprivate static let seamCases = ["keygen-alloc-fail-1", "keygen-alloc-fail-2", "keygen-wipe", "sign-zero-seeds", "sign-one-seed",
                                        "sign-max", "sign-past-max", "sign-off-step", "sign-restored"]

    func testCSeamsAllocationFailureWipeAndSignerFailure() throws {
        let r = try runCChild("testSizesAreTheReferences", "seams", seconds: 300)
        XCTAssertTrue(r.ok && r.out.contains("c-done"), "the child did not finish cleanly:\n\(r.out)")
        for c in Self.seamCases { XCTAssertTrue(r.out.contains("c-seam \(c) ok\n"), "\(c):\n\(r.out)") }
    }

    fileprivate static func runSeamCases() throws {
        let f = try cFixture() // signs for real: before any seam is installed
        let say = { (c: String, good: Bool) in FileHandle.standardError.write(Data("c-seam \(c) \(good ? "ok" : "bad")\n".utf8)) }
        let pk = cCopy([], extra: pkN), sk = cCopy([], extra: skN), seed = cCopy(Self.seed("c-seam"))
        let ssk = cCopy(f.sk), msg = cCopy(f.msg), spk = cCopy(f.pk), sig = cCopy([], extra: 2 * sigMax)
        defer { pk.deallocate(); sk.deallocate(); seed.deallocate(); ssk.deallocate(); msg.deallocate(); spk.deallocate(); sig.deallocate() }
        for at in [1, 2] { // the temporary public key, then the temporary secret key
            for i in 0..<pkN { pk[i] = 0xA5 }
            for i in 0..<skN { sk[i] = 0xA5 }
            LessSeam.installAllocator(failAt: at)
            let r = atlas_less_cat1_keygen(pk, pkN, sk, skN, seed, 32)
            atlas_less_test_set_allocator(nil, nil)
            say("keygen-alloc-fail-\(at)", r == 0 && (0..<pkN).allSatisfy { pk[$0] == 0xA5 } && (0..<skN).allSatisfy { sk[$0] == 0xA5 })
        }
        var lastByteSet = false, allOk = true
        LessSeam.skFreed = 0
        LessSeam.skDirty = false
        LessSeam.installAllocator(failAt: 0)
        for i in 0..<4 {
            let s = cCopy(Self.seed("c-seam-wipe-\(i)"))
            allOk = allOk && atlas_less_cat1_keygen(pk, pkN, sk, skN, s, 32) == 1
            lastByteSet = lastByteSet || sk[skN - 1] != 0
            s.deallocate()
        }
        atlas_less_test_set_allocator(nil, nil)
        say("keygen-wipe", allOk && lastByteSet && LessSeam.skFreed == 4 && !LessSeam.skDirty)
        let cases: [(String, Int, Int32)] = [("sign-zero-seeds", sigMin, 0), ("sign-one-seed", sigMin + step, 1),
                                             ("sign-max", sigMax, 1), ("sign-past-max", sigMax + step, 0), ("sign-off-step", sigMin + step + 1, 0)]
        for (what, n, want) in cases {
            for i in 0..<(2 * sigMax) { sig[i] = 0xEE }
            var len = 7
            LessSeam.installSigner(signLen: n)
            let r = atlas_less_cat1_sign(ssk, skN, msg, f.msg.count, seed, 32, sig, sigMax, &len)
            atlas_less_test_set_sign(nil)
            say(what, r == want && (want == 1 ? len == n : len == 7 && sig[0] == 0xEE))
        }
        var len = 0
        let r = atlas_less_cat1_sign(ssk, skN, msg, f.msg.count, seed, 32, sig, sigMax, &len)
        say("sign-restored", r == 1 && atlas_less_cat1_verify(spk, f.pk.count, msg, f.msg.count, sig, len) == 1)
        FileHandle.standardError.write(Data("c-done\n".utf8))
    }

    /// Generator lock: each call takes it and gives it back (sequential calls; one that kept it makes the next one wait forever), and
    /// concurrent seeded calls give the same keys and signatures as sequential ones (without the lock they reseed and draw from the one
    /// process-global generator under each other).
    fileprivate static func runLockCase() throws {
        let seeds = (0..<8).map { i in (0..<32).map { UInt8(truncatingIfNeeded: $0 * 7 + i * 31 + 1) } }
        let msg = Array("generator lock".utf8)
        let want = try seeds.map { try LessNative.keygen(seed: $0) }
        let again = try LessNative.keygen(seed: seeds[0])
        let wantSig = try seeds.map { try LessNative.sign(sk: want[0].sk, msg: msg, seed: $0) }
        var bad = again.vk == want[0].vk && again.sk == want[0].sk ? 0 : 1
        let lock = NSLock()
        for _ in 0..<16 {
            DispatchQueue.concurrentPerform(iterations: seeds.count) { i in
                let k = try? LessNative.keygen(seed: seeds[i])
                let s = try? LessNative.sign(sk: want[0].sk, msg: msg, seed: seeds[i])
                if k?.vk != want[i].vk || k?.sk != want[i].sk || s != wantSig[i] { lock.lock(); bad += 1; lock.unlock() }
            }
        }
        FileHandle.standardError.write(Data((bad == 0 ? "c-lock ok\n" : "c-lock mismatches \(bad)\n").utf8))
    }

    /// Called from setUp: in a child, runs the named case and exits; in the parent, checks the generator lock once in a child first.
    func cChildHook() throws {
        if let c = ProcessInfo.processInfo.environment[Self.cChildVar] {
            if c == "raw" { try Self.runRawCases() } else if c == "lock" { try Self.runLockCase() } else if c == "seams" { try Self.runSeamCases() }
            exit(0)
        }
        guard !Self.cLockChecked else { return }
        Self.cLockChecked = true
        let r = try runCChild("testSizesAreTheReferences", "lock", seconds: 600)
        if !(r.ok && r.out.contains("c-lock ok")) {
            XCTFail("the LESS generator lock is not taken and released around every call:\n\(r.out)")
            exit(1) // with the lock never released, every later keygen or sign of this process would wait forever
        }
    }

    /// Runs `test` again in a child process of this test bundle with PCA_C_CHILD_CASE=`name`. Answers whether it exited 0 within
    /// `seconds` (killed otherwise), and its output.
    func runCChild(_ test: String, _ name: String, seconds: Double) throws -> (ok: Bool, out: String) {
        let filter = String(reflecting: type(of: self)) + "/" + test
        let p = Process()
        #if os(macOS)
        p.executableURL = URL(fileURLWithPath: "/usr/bin/xcrun")
        p.arguments = ["xctest", "-XCTest", filter, Bundle(for: type(of: self)).bundlePath]
        #else
        p.executableURL = Bundle.main.executableURL ?? URL(fileURLWithPath: CommandLine.arguments[0])
        p.arguments = [filter]
        #endif
        let log = FileManager.default.temporaryDirectory.appendingPathComponent("pca-c-child-\(UUID().uuidString).log")
        try Data().write(to: log)
        defer { try? FileManager.default.removeItem(at: log) }
        let h = try FileHandle(forWritingTo: log)
        p.standardOutput = h
        p.standardError = h
        var env = ProcessInfo.processInfo.environment
        env[Self.cChildVar] = name
        p.environment = env
        try p.run()
        try? h.close()
        let end = Date().addingTimeInterval(seconds)
        while p.isRunning && Date() < end { usleep(20_000) }
        let hung = p.isRunning
        if hung { kill(p.processIdentifier, SIGKILL) }
        p.waitUntilExit()
        let out = ((try? String(contentsOf: log, encoding: .utf8)) ?? "") + (hung ? "\n(killed after \(Int(seconds)) s)\n" : "")
        return (!hung && p.terminationReason == .exit && p.terminationStatus == 0, out)
    }
}
