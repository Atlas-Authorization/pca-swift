#if canImport(Security)
import XCTest
import Security
@testable import AtlasPCAStepUp

/// The Keychain item is device-bound: readable only while unlocked, never migrated to another device. Skipped where the keychain does
/// not report the accessibility attribute (the macOS file-based keychain does not store it).
final class S2G7KeychainKillTests: XCTestCase {
    func testTheItemIsAccessibleOnlyWhileUnlockedOnThisDevice() throws {
        let store = KeychainSecretStore(service: "net.atlasauth.pca.stepup.test.\(UUID().uuidString)", account: "principal-ed25519")
        defer { try? store.delete() }
        try store.save(Data([1, 2, 3]))
        let q: [String: Any] = [kSecClass as String: kSecClassGenericPassword, kSecAttrService as String: store.service, kSecAttrAccount as String: store.account,
                                kSecReturnAttributes as String: true, kSecMatchLimit as String: kSecMatchLimitOne]
        var out: CFTypeRef?
        XCTAssertEqual(SecItemCopyMatching(q as CFDictionary, &out), errSecSuccess)
        let attrs = try XCTUnwrap(out as? [String: Any])
        guard let acc = attrs[kSecAttrAccessible as String] as? String else { throw XCTSkip("this keychain does not report kSecAttrAccessible") }
        XCTAssertEqual(acc, kSecAttrAccessibleWhenUnlockedThisDeviceOnly as String)
    }
}
#endif
