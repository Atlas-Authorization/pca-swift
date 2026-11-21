import XCTest
import Foundation
import CryptoKit
@testable import AtlasPCAVerify

/// The signer transports of networked FROST: a signer in the same process, and signers behind loopback HTTP servers, driven by one coordinator.
final class FrostNetTransportTests: XCTestCase {
    private func fixture() throws -> (services: [PCAFrostNet.GuardianSignerService], keygen: PCAFrost.KeygenResult, policy: PCAEdKey) {
        let policy = try PCAEdKey(seed: Canonical.sha256(Array("frost-net-transport-policy".utf8)))
        let kg = try PCAFrost.trustedDealerKeygen(t: 2, n: 3)
        let services = try kg.participantShares.map { p in
            try PCAFrostNet.GuardianSignerService(identifier: .int(p.identifier), share: p.share, groupPublicKey: kg.groupPublicKey, threshold: .int(2), policyAuthorityPublicKey: policy.pub)
        }
        return (services, kg, policy)
    }

    func testAMixedSetOfSignersSignsOverInProcessAndHttpTransports() throws {
        let f = try fixture()
        let s2 = try PCAFrostNet.startSignerHttpServer(f.services[1])
        let s3 = try PCAFrostNet.startSignerHttpServer(f.services[2])
        defer { s2.close(); s3.close() }
        XCTAssertGreaterThan(s2.port, 0)
        XCTAssertEqual(s2.url, "http://127.0.0.1:\(s2.port)")
        let transports: [PCAFrostSignerTransport] = [PCAFrostNet.inProcessTransport(f.services[0]), PCAFrostNet.httpSignerTransport(baseUrl: s2.url, identifier: 2),
                                                     PCAFrostNet.httpSignerTransport(baseUrl: s3.url, identifier: 3)]
        let vs = f.keygen.participantShares.map { PCAFrost.VerificationShare(identifier: $0.identifier, publicKey: $0.publicKey) }
        let coord = try PCAFrostNet.NetworkCoordinator(groupPublicKey: f.keygen.groupPublicKey, threshold: .int(2), signers: transports, verificationShares: vs)
        let message = Array("approve payout 80 USD".utf8)
        let allow = try PCAFrostNet.issueAllowToken(policySecret: f.policy.seed, message: message, frostActionDigest: nil, groupPublicKey: f.keygen.groupPublicKey, nonce: nil,
                                                    notBefore: nil, expiresAt: nil)
        // only the signers behind HTTP: the shares never leave their services
        let r = try coord.sign(message, allow: allow, signerIds: [2, 3])
        XCTAssertEqual(r.signers.sorted(), [2, 3])
        let pk = try Curve25519.Signing.PublicKey(rawRepresentation: Data(f.keygen.groupPublicKey))
        XCTAssertTrue(pk.isValidSignature(Data(r.signature), for: Data(message)), "the aggregate is an ordinary Ed25519 signature under the group key")
        // a message the allow token does not cover is refused by every signer
        XCTAssertThrowsError(try coord.sign(Array("approve payout 8000 USD".utf8), allow: allow))
    }

    func testAnUnreachableSignerIsAFailedSigner() throws {
        let f = try fixture()
        let live = try PCAFrostNet.startSignerHttpServer(f.services[1])
        defer { live.close() }
        let dead = try PCAFrostNet.startSignerHttpServer(f.services[2])
        let deadUrl = dead.url
        dead.close()
        let transports: [PCAFrostSignerTransport] = [PCAFrostNet.httpSignerTransport(baseUrl: live.url, identifier: 2), PCAFrostNet.httpSignerTransport(baseUrl: deadUrl, identifier: 3, timeoutMs: 500)]
        let vs = f.keygen.participantShares.map { PCAFrost.VerificationShare(identifier: $0.identifier, publicKey: $0.publicKey) }
        let coord = try PCAFrostNet.NetworkCoordinator(groupPublicKey: f.keygen.groupPublicKey, threshold: .int(2), signers: transports, verificationShares: vs)
        let message = Array("m".utf8)
        let allow = try PCAFrostNet.issueAllowToken(policySecret: f.policy.seed, message: message, frostActionDigest: nil, groupPublicKey: f.keygen.groupPublicKey, nonce: nil,
                                                    notBefore: nil, expiresAt: nil)
        XCTAssertThrowsError(try coord.sign(message, allow: allow)) { e in
            XCTAssertFalse((e as? PCAFrostNet.CoordinatorError)?.isTimeout ?? true)
        }
    }
}
