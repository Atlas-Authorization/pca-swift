#if canImport(Security)
import XCTest
import Security
@testable import AtlasPCAStepUp

/// The Keychain store on a real Keychain (CI unlocks a throwaway default keychain first): round trip, absent item, overwrite, delete
/// of a present and of an absent item, and the item is stored non-synchronizable (never iCloud).
final class KeychainSecretStoreTests: XCTestCase {
    var store = KeychainSecretStore()
    override func setUp() {
        super.setUp()
        store = KeychainSecretStore(service: "net.atlasauth.pca.stepup.test.\(UUID().uuidString)", account: "principal-ed25519")
    }
    override func tearDown() { try? store.delete(); super.tearDown() }

    func testRoundTripOverwriteAndDelete() throws {
        XCTAssertNil(try store.load())
        try store.delete() // deleting an absent item is fine
        let a = Data((0..<32).map { UInt8($0) }), b = Data((0..<32).map { UInt8(255 - $0) })
        try store.save(a)
        XCTAssertEqual(try store.load(), a)
        try store.save(b)
        XCTAssertEqual(try store.load(), b)
        try store.delete()
        XCTAssertNil(try store.load())
        try store.delete()
    }

    func testTheItemIsNotSynchronizable() throws {
        try store.save(Data([1, 2, 3]))
        let q: [String: Any] = [kSecClass as String: kSecClassGenericPassword, kSecAttrService as String: store.service,
                                kSecAttrAccount as String: store.account, kSecAttrSynchronizable as String: kCFBooleanTrue as Any,
                                kSecReturnData as String: true, kSecMatchLimit as String: kSecMatchLimitOne]
        var out: CFTypeRef?
        XCTAssertEqual(SecItemCopyMatching(q as CFDictionary, &out), errSecItemNotFound)
    }

    func testPrincipalDeviceKeyOverTheKeychain() throws {
        let key = PrincipalDeviceKey(store: store)
        XCTAssertFalse(key.exists)
        let pub = try key.generate()
        XCTAssertTrue(key.exists)
        XCTAssertEqual(try key.publicKey(), pub)
    }
}
#endif
