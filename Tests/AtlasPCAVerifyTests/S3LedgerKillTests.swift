import XCTest
import Foundation
@testable import AtlasPCAVerify

/// Ledger.swift guards on missing members / policy, and the chain verdict of a valid chain.
final class S3LedgerKillTests: XCTestCase {
    typealias J = JSONValue

    private func head(_ key: PCAEdKey) throws -> JObject {
        let base: JObject = ["instance_id": J.string("i"), "principal": J.string("p"), "size": J.int(1), "root": J.string("r"), "prev_root": J.null, "timestamp": J.int(5)]
        let msg = try XCTUnwrap(IV.message(Ledger.STH_DOMAIN, J.object(base)))
        var m = base
        m["guardian"] = J.string(key.id)
        m["sig"] = J.string(Base64URLStrict.encode(try key.sign(msg)))
        return m
    }

    func testWitnessedHeadWithAMissingMemberIsRefused() {
        let wh: J = .object(["witness": J.string("w"), "principal": J.string("p"), "root": J.string("r"), "sig": J.string("x")])
        XCTAssertFalse(Ledger.verifyWitnessedHead(wh, "w"), "line 105: size is absent")
    }

    func testWitnessCosignatureWithAMissingMemberIsRefused() {
        let sth: J = .object(["instance_id": J.string("i"), "principal": J.string("p"), "size": J.int(1), "root": J.string("r")])
        let cosig: J = .object(["key": J.string("w"), "sig": J.string("x")])
        XCTAssertFalse(Ledger.verifyWitnessCosignature(sth, cosig, "w"), "line 122: prev_root is absent")
    }

    func testWitnessCosignaturesNeedAnObjectHeadAndAPolicy() {
        let sth: J = .object(["witnesses": J.array([])])
        let pol: JObject = ["threshold": J.int(1), "witnessKeys": J.array([J.string("w")])]
        XCTAssertFalse(Ledger.verifyWitnessCosignatures(J.string("x"), pol), "line 140: the head is not an object")
        XCTAssertFalse(Ledger.verifyWitnessCosignatures(nil, pol), "line 140: no head")
        XCTAssertFalse(Ledger.verifyWitnessCosignatures(sth, nil), "line 140: no policy")
    }

    func testValidSingleCheckpointChainVerdict() throws {
        let key = try PCAEdKey.generate()
        let sth = try head(key)
        XCTAssertTrue(Ledger.verifyTreeHead(J.object(sth), key.id, nil), "the head itself is genuine")
        let v = Ledger.verifyCheckpointChain(J.array([J.object(["sth": J.object(sth)])]), key.id, nil)
        XCTAssertEqual(v, Ledger.CheckpointVerdict(ok: true, at: 0), "line 202: a valid chain reports at 0")
        let bad = Ledger.verifyCheckpointChain(J.array([J.object(["sth": J.object(sth)]), J.object(["sth": J.object(sth)])]), key.id, nil)
        XCTAssertEqual(bad, Ledger.CheckpointVerdict(ok: false, at: 1), "a second checkpoint without a proof fails at 1")
    }
}
