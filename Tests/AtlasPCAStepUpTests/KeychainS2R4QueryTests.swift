#if canImport(Security)
import XCTest
import Security
@testable import AtlasPCAStepUp

/// The attributes the Keychain store hands to SecItemAdd / SecItemCopyMatching, checked on the query dictionaries themselves (a Keychain that
/// does not report kSecAttrAccessible cannot show them).
final class S2R4KeychainQueryTests: XCTestCase {
    private var store: KeychainSecretStore { KeychainSecretStore(service: "svc.s2r4", account: "acct.s2r4") }

    func testTheAddQueryIsDeviceBoundUnlockedOnlyAndNotSynchronizable() {
        let q = store.addQuery(Data([1, 2, 3]))
        XCTAssertEqual(q[kSecAttrAccessible as String] as? String, kSecAttrAccessibleWhenUnlockedThisDeviceOnly as String)
        XCTAssertEqual(q[kSecAttrSynchronizable as String] as? Bool, false)
        XCTAssertEqual(q[kSecValueData as String] as? Data, Data([1, 2, 3]))
        XCTAssertEqual(q[kSecAttrService as String] as? String, "svc.s2r4")
        XCTAssertEqual(q[kSecAttrAccount as String] as? String, "acct.s2r4")
        XCTAssertEqual(q[kSecClass as String] as? String, kSecClassGenericPassword as String)
    }

    func testTheLoadQueryReturnsTheDataOfExactlyOneItem() {
        let q = store.loadQuery()
        XCTAssertEqual(q[kSecReturnData as String] as? Bool, true)
        XCTAssertEqual(q[kSecMatchLimit as String] as? String, kSecMatchLimitOne as String)
        XCTAssertEqual(q[kSecAttrService as String] as? String, "svc.s2r4")
        XCTAssertEqual(q[kSecAttrAccount as String] as? String, "acct.s2r4")
    }
}
#endif
