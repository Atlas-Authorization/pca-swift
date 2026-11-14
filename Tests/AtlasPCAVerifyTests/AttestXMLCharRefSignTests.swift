import XCTest
@testable import AtlasPCAVerify

/// A character reference is digits only (XML 1.0 [66] CharRef): a sign is refused, as xmldom does not decode it either.
final class AttestXMLCharRefSignTests: XCTestCase {
    func decode(_ s: String) -> String {
        do { return try XML.decode(ArraySlice(Array(s.utf8))) } catch { return "ERR " + ((error as? AttestError)?.message ?? "?") }
    }

    func testASignedReferenceIsRefused() {
        for r in ["#+65", "#-0", "#x+41", "#x-0", "#", "#x", "#٣"] { XCTAssertEqual(decode("&\(r);"), "ERR invalid character reference &\(r);", r) }
    }

    func testPlainReferencesStillDecode() {
        XCTAssertEqual(decode("&#65;&#x41;&#x0041;"), "AAA")
        // leading zeros are legal (XML 1.0 [66]) and accepted
        XCTAssertEqual(decode("&#000065;&#x000041;&#0;x"), "ERR invalid character reference &#0;")
        XCTAssertEqual(decode("&#000065;&#x000041;"), "AA")
    }
}
