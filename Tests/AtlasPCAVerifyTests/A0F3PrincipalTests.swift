import XCTest
import Foundation
@testable import AtlasPCAVerify

/// F3 requireVerifiedPrincipal + resolvePrincipal (server/require-pca.ts:884-893).
final class A0F3PrincipalTests: XCTestCase {
    override func setUp() { super.setUp(); continueAfterFailure = false }

    private func run(_ edit: (inout PCA.AuthorizeInput) -> Void) -> PCA.AuthorizeResult { AZ.run(AZ.signed(), edit) }

    func testUnverifiedPrincipalDeniesOnlyWhenRequired() {
        let verified = PCA.PrincipalInfo(pub: "p", subjectType: "user", subjectId: "u1", verified: true)
        let ok = run { $0.resolvePrincipal = { _, _ in verified }; $0.requireVerifiedPrincipal = true }
        XCTAssertTrue(ok.allow, "\(ok.reasons)")
        XCTAssertEqual(ok.checks["principal"], .pass)
        let unknown = run { $0.resolvePrincipal = { _, _ in nil } }
        XCTAssertTrue(unknown.allow, "\(unknown.reasons)")
        XCTAssertEqual(unknown.checks["principal"], .notEnforced)
        let denied = run { $0.resolvePrincipal = { _, _ in nil }; $0.requireVerifiedPrincipal = true }
        XCTAssertFalse(denied.allow)
        XCTAssertTrue(denied.reasons.contains("principal: the grant issuer is not an enrolled, verified principal"), "\(denied.reasons)")
        let unverified = run { $0.resolvePrincipal = { p, _ in PCA.PrincipalInfo(pub: p, subjectType: "unverified", subjectId: nil, verified: false) }; $0.requireVerifiedPrincipal = true }
        XCTAssertFalse(unverified.allow)
    }

    func testRequiringWithoutAResolverDeniesAndAThrowFailsClosed() {
        let noResolver = run { $0.requireVerifiedPrincipal = true }
        XCTAssertFalse(noResolver.allow)
        XCTAssertTrue(noResolver.reasons.contains("principal: requireVerifiedPrincipal needs a resolvePrincipal resolver"), "\(noResolver.reasons)")
        struct Boom: Error {}
        let broke = run { $0.resolvePrincipal = { _, _ in throw Boom() } }
        XCTAssertFalse(broke.allow)
        XCTAssertEqual(broke.checks["principal"], .fail)
        let absent = run { _ in }
        XCTAssertNil(absent.checks["principal"], "no resolver, not required: the check is not reported")
    }

    func testTheResolverSeesTheGrantIssuer() {
        let s = AZ.signed()
        let want = s.grant.get("issuer")?.asString
        let seen = A0F3SeenBox()
        _ = AZ.run(s) { $0.resolvePrincipal = { p, _ in seen.set(p); return nil } }
        XCTAssertEqual(seen.value, want)
    }
}

final class A0F3SeenBox: @unchecked Sendable {
    private let l = NSLock()
    private var v: String?
    func set(_ x: String) { l.lock(); v = x; l.unlock() }
    var value: String? { l.lock(); defer { l.unlock() }; return v }
}
