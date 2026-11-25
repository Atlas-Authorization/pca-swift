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

    // MARK: atlas_ada_url_part / atlas_ada_url_set_param

    /// The buffer is far larger than `cap`, so a shim that ignores the bound is seen as a wrong verdict, not as a stack overwrite.
    private func part(_ url: String, _ which: Int32, cap: Int = 256) -> (rc: Int32, out: String, n: Int) {
        let input = Array(url.utf8)
        var out = [UInt8](repeating: 0, count: 512)
        var n = 99_999
        let rc = input.withUnsafeBufferPointer { ib in atlas_ada_url_part(ib.baseAddress, ib.count, which, &out, cap, &n) }
        return (rc, rc == 1 ? String(decoding: out.prefix(n), as: UTF8.self) : "", n)
    }

    private func setParam(_ url: String, _ key: String, _ value: String, cap: Int = 256) -> (rc: Int32, out: String) {
        let input = Array(url.utf8), k = Array(key.utf8), v = Array(value.utf8)
        var out = [UInt8](repeating: 0, count: 512)
        var n = 0
        let rc = input.withUnsafeBufferPointer { ib in k.withUnsafeBufferPointer { kb in v.withUnsafeBufferPointer { vb in
            atlas_ada_url_set_param(ib.baseAddress, ib.count, kb.baseAddress, kb.count, vb.baseAddress, vb.count, &out, cap, &n) } } }
        return (rc, rc == 1 ? String(decoding: out.prefix(n), as: UTF8.self) : "")
    }

    func testUrlPartsEachSelectorReturnsItsOwnPart() {
        let u = "HTTPS://Example.COM:8443/p?q=1#f"
        XCTAssertEqual(part(u, 0).out, "https:")
        XCTAssertEqual(part(u, 1).out, "example.com")
        XCTAssertEqual(part(u, 2).out, "example.com:8443")
        XCTAssertEqual(part(u, 3).out, "https://example.com:8443/p?q=1#f")
        XCTAssertEqual(part(u, 3).n, 32)
        XCTAssertEqual(part("https://example.com:443/x", 2).out, "example.com", "the default port is not part of the host")
        XCTAssertEqual(part(u, 4).rc, 0, "an unknown selector is refused")
        XCTAssertEqual(part(u, -1).rc, 0)
        let empty = part("file:///x", 1)
        XCTAssertEqual(empty.rc, 1, "an empty hostname is an answer")
        XCTAssertEqual(empty.n, 0)
    }

    func testUrlPartRefusals() {
        XCTAssertEqual(part("not a url", 3).rc, 0)
        XCTAssertEqual(part("", 3).rc, 0)
        XCTAssertEqual(part("a", 3).rc, 0)
        XCTAssertEqual(part("https://example.com/", 3, cap: 20).rc, 1, "exactly fits")
        XCTAssertEqual(part("https://example.com/", 3, cap: 19).rc, 0, "one byte over")
        XCTAssertEqual(part("https://example.com/", 3, cap: 20).out, "https://example.com/")
        // the last input byte counts: the URL with and without its final label differ
        XCTAssertEqual(part("https://example.co", 1).out, "example.co")
        var out = [UInt8](repeating: 0, count: 16)
        var n = 0
        let u = Array("https://example.com/".utf8)
        u.withUnsafeBufferPointer { ib in
            XCTAssertEqual(atlas_ada_url_part(ib.baseAddress, ib.count, 1, nil, 16, &n), 0)
            XCTAssertEqual(atlas_ada_url_part(ib.baseAddress, ib.count, 1, &out, 16, nil), 0)
            XCTAssertEqual(atlas_ada_url_part(ib.baseAddress, ib.count, 1, &out, 16, &n), 1)
            XCTAssertEqual(n, 11)
        }
    }

    func testSetParamReplacesTheFirstAndDropsTheRest() {
        XCTAssertEqual(setParam("https://x.test/p?a=1&b=2&a=3", "a", "9").out, "https://x.test/p?a=9&b=2")
        XCTAssertEqual(setParam("https://x.test/p?a=1", "k", "v").out, "https://x.test/p?a=1&k=v", "one-byte key and value")
        XCTAssertEqual(setParam("https://x.test/", "key", "va lue").out, "https://x.test/?key=va+lue")
        XCTAssertEqual(setParam("https://x.test/?x=1", "ab", "cd").out, "https://x.test/?x=1&ab=cd", "the key and the value are not swapped or cut")
        XCTAssertEqual(setParam("https://x.test/?x=1", "k", "").out, "https://x.test/?x=1&k=", "an empty value")
    }

    func testSetParamRefusals() {
        XCTAssertEqual(setParam("not a url", "k", "v").rc, 0)
        XCTAssertEqual(setParam("", "k", "v").rc, 0)
        XCTAssertEqual(setParam("https://x.test/", "k", "v", cap: 19).rc, 1, "exactly fits")
        XCTAssertEqual(setParam("https://x.test/", "k", "v", cap: 18).rc, 0, "one byte over")
        XCTAssertEqual(setParam("https://x.test/?a=1", "a", "2").out, "https://x.test/?a=2")
        var out = [UInt8](repeating: 0, count: 64)
        var n = 0
        let u = Array("https://x.test/".utf8), k = Array("k".utf8)
        u.withUnsafeBufferPointer { ub in k.withUnsafeBufferPointer { kb in
            XCTAssertEqual(atlas_ada_url_set_param(ub.baseAddress, ub.count, kb.baseAddress, 1, kb.baseAddress, 1, nil, 64, &n), 0)
            XCTAssertEqual(atlas_ada_url_set_param(ub.baseAddress, ub.count, kb.baseAddress, 1, kb.baseAddress, 1, &out, 64, nil), 0)
            XCTAssertEqual(atlas_ada_url_set_param(ub.baseAddress, ub.count, kb.baseAddress, 1, kb.baseAddress, 1, &out, 64, &n), 1)
        } }
    }
}
