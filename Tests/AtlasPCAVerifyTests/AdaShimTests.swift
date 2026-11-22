import CAda
import XCTest

/// The C shim over Ada (`atlas_ada_domain_to_ascii`) called directly: its argument checks, buffer bound and host parsing, so each of its branches is decided here and not
/// only through the verifier's Swift wrapper.
final class AdaShimTests: XCTestCase {
    private func convert(_ host: String, cap: Int = 256) -> (rc: Int32, out: String, n: Int) {
        let input = Array(host.utf8)
        var out = [UInt8](repeating: 0, count: max(cap, 1))
        var n = 0
        let rc = input.withUnsafeBufferPointer { ib in
            atlas_ada_domain_to_ascii(ib.baseAddress, ib.count, &out, cap, &n)
        }
        return (rc, String(decoding: out.prefix(rc == 1 ? n : 0), as: UTF8.self), n)
    }

    func testPlainAndInternationalHosts() {
        XCTAssertEqual(convert("EXAMPLE.com").out, "example.com")
        let r = convert("bücher.de")
        XCTAssertEqual(r.rc, 1)
        XCTAssertEqual(r.out, "xn--bcher-kva.de")
        XCTAssertEqual(r.n, 16)
        XCTAssertEqual(convert("0x7f.1").out, "127.0.0.1")
    }

    func testRefusedHosts() {
        XCTAssertEqual(convert("a b").rc, 0)
        XCTAssertEqual(convert("").rc, 0)
        XCTAssertEqual(convert("a<b").rc, 0)
    }

    func testOneByteHost() {
        let r = convert("a")
        XCTAssertEqual(r.rc, 1)
        XCTAssertEqual(r.out, "a")
    }

    func testBufferBound() {
        XCTAssertEqual(convert("example.com", cap: 11).rc, 1)
        XCTAssertEqual(convert("example.com", cap: 10).rc, 0)
        XCTAssertEqual(convert("example.com", cap: 11).out, "example.com")
    }

    func testNullArguments() {
        var out = [UInt8](repeating: 0, count: 16)
        var n = 0
        let host = Array("example.com".utf8)
        host.withUnsafeBufferPointer { ib in
            XCTAssertEqual(atlas_ada_domain_to_ascii(nil, 11, &out, 16, &n), 0)
            XCTAssertEqual(atlas_ada_domain_to_ascii(ib.baseAddress, 11, nil, 16, &n), 0)
            XCTAssertEqual(atlas_ada_domain_to_ascii(ib.baseAddress, 11, &out, 16, nil), 0)
            XCTAssertEqual(atlas_ada_domain_to_ascii(ib.baseAddress, 0, &out, 16, &n), 0)
            XCTAssertEqual(atlas_ada_domain_to_ascii(ib.baseAddress, 11, &out, 16, &n), 1)
            XCTAssertEqual(n, 11)
        }
    }
}
