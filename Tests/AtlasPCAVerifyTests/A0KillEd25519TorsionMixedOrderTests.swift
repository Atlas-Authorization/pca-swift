import XCTest
import Foundation
@testable import AtlasPCAVerify

/// Mixed-order public key A = aB + T (T of order 8), R = rB, message ground so k = SHA-512(R || A || M) mod L is a multiple of 8 and
/// S = r + k*a: [S]B = R + [k]A holds (kT = O), so a cofactorless check accepts it. Ported from the Rust lane's k05d_ed25519_mixed_order
/// (vectors generated with a pure-Python edwards25519; the assertions below re-check the premise that A is strict-clean). The guard
/// Ed25519Torsion.isPrimeOrder is what refuses it (TS keys.ts:38).
final class A0KillEd25519TorsionMixedOrderTests: XCTestCase {
    override func setUp() { super.setUp(); continueAfterFailure = false }

    private func hex(_ s: String) -> [UInt8] { stride(from: 0, to: s.count, by: 2).map { UInt8(s[s.index(s.startIndex, offsetBy: $0)..<s.index(s.startIndex, offsetBy: $0 + 2)], radix: 16)! } }

    private let cases: [(a: String, msg: String, sig: String)] = [
        ("01803011a601f354905c774e752f5b4714407e693c098050cc08ea9f8375396a", "k05d mixed-order 23",
         "5fff4d81550e016b012fb30b8a76954efc0db28ea3c159a75f5930542985634585f281e885be86ce059f85062a4c0fdc7112644b7ef587a20489fb2b5c5e0d06"),
        ("5bb32c320ba5555d6331685f5d1624b9cc3d5a1585833604d5899fa5c1fd2e99", "k05d mixed-order 2",
         "6a6529c4681ac6b776677a4a7835f6aa96c0601fc019108f19704c888e0877a194cf372020ac15f5deeab516829f9320f705bb8ab58a07f35f5c51fb55aeb808"),
    ]

    func testMixedOrderKeyIsRefusedByTheTorsionGuard() {
        for (i, c) in cases.enumerated() {
            let pk = hex(c.a), sig = hex(c.sig), msg = Array(c.msg.utf8)
            XCTAssertTrue(Ed25519Strict.isCanonicalS(sig), "premise: S canonical (case \(i))")
            XCTAssertTrue(Ed25519Strict.isStrictPoint(pk), "premise: A is not small order and canonical (case \(i))")
            XCTAssertTrue(Ed25519Strict.isStrictPoint(Array(sig[0..<32])), "premise: R is strict-clean (case \(i))")
            // every call that reaches the field arithmetic runs under a deadline: a mutant that loops there must FAIL here (killed), not hang the run
            let prime: Bool? = S2Deadline.within(30, "isPrimeOrder case \(i)") { Ed25519Torsion.isPrimeOrder(pk) }
            XCTAssertEqual(prime, false, "A = aB + T is not in the prime-order subgroup (case \(i))")
            let ok: Bool? = S2Deadline.within(30, "verify case \(i)") { Ed25519Strict.verify(publicKey: pk, message: msg, signature: sig) }
            XCTAssertEqual(ok, false, "mixed-order key refused (case \(i))")
        }
    }
}
