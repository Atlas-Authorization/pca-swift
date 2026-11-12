import XCTest
import Foundation
@testable import AtlasPCAVerify

/// ArgProvenance.swift pinned to the reference packages/pca/src/arg-provenance.ts (:231 isReadOnlyAction, :240 isWord).
final class ArgProvenanceK05KillTests: XCTestCase {
    func testReadOnlyTraitsMustAllBeKnownStrings() {
        func action(_ traits: JSONValue) -> JSONValue { .object(["effects": .array([.string("read")]), "traits": traits]) }
        XCTAssertTrue(PCA.isReadOnlyAction(action(.array([.string("pca.pii_access")]))))
        XCTAssertFalse(PCA.isReadOnlyAction(action(.array([.string("pca.bulk")]))))
        XCTAssertFalse(PCA.isReadOnlyAction(action(.array([.int(1)]))))
        XCTAssertFalse(PCA.isReadOnlyAction(action(.string("pca.pii_access"))))
    }

    func testWordUnitBoundaries() {
        for c: UInt16 in [48, 57, 65, 90, 95, 97, 121, 122, 0x80, 0xFFFF] { XCTAssertTrue(PCA.isWordUnit(c), "\(c)") }
        for c: UInt16 in [47, 58, 64, 91, 94, 96, 123, 0x7F] { XCTAssertFalse(PCA.isWordUnit(c), "\(c)") }
    }
}
