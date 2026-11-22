import XCTest
import Foundation
@testable import AtlasPCAVerify

/// Kills the PolicyClasses.swift, AttestXML.swift and AttestIntel.swift survivors of group 9.
final class S2G9MiscKillTests: XCTestCase {
    private func rep(_ n: Int) -> String { String(repeating: "a", count: n) }

    func testPolicyClassDigestBound() {
        func list(_ digest: String) -> JSONValue {
            .array([.object(["class": .string("org"), "revision": .int(1), "digest": .string(digest), "decision": .string("allow")])])
        }
        XCTAssertNil(PolicyClasses.classVerdictsError(list(rep(128))), "line 36")
        XCTAssertEqual(PolicyClasses.classVerdictsError(list(rep(129))), "policy_classes[0].digest invalid", "line 36")
        XCTAssertEqual(PolicyClasses.classVerdictsError(list("")), "policy_classes[0].digest invalid")
    }

    func testAdjacentTextIsOneNode() throws {
        let d = try XML.parse("<a>0123456789<![CDATA[abc]]>d</a>")
        XCTAssertEqual(d.root?.children.count, 1, "line 43: text, CDATA and text merge")
        XCTAssertEqual(d.root?.textContent(), "0123456789abcd")
        let n = XmlNode(elem: true)
        n.appendText("x")
        n.appendText("y")
        XCTAssertEqual(n.children.count, 1)
        XCTAssertEqual(n.children[0].text, "xy")
        XCTAssertTrue(n.children[0].parent === n, "line 48: a text node knows its element")
    }

    func testAnUnprefixedNameClearsAStalePrefix() throws {
        let n = XmlNode(elem: true)
        n.name = "e"
        n.prefix = "stale"
        try n.resolveNames()
        XCTAssertEqual(n.prefix, "", "line 58")
        XCTAssertEqual(n.local, "e")
    }

    func testARepeatedAttributeIsRefused() {
        func err(_ s: String) -> String? {
            do {
                _ = try XML.parse(s)
                return nil
            } catch { return (error as? AttestError)?.message }
        }
        XCTAssertEqual(err(#"<a b="1" b="2"/>"#), "attribute b is repeated", "line 281")
        XCTAssertNil(err(#"<a b="1" c="2"/>"#))
    }

    /// Two certificates that issue each other never end in a self-signed root; the walk must stop at the first repeat (line 171: without
    /// the `seen` set it never ends).
    func testACyclicPckChainIsRefused() {
        typealias F = StrictChainForge
        func pem(_ der: [UInt8]) -> String {
            "-----BEGIN CERTIFICATE-----\n" + Data(der).base64EncodedString(options: [.lineLength64Characters, .endLineWithLineFeed]) + "\n-----END CERTIFICATE-----\n"
        }
        let a = F.cert(subject: "a", issuer: "b", subjectKey: F.rootKey, signer: F.midKey, serial: 1, exts: F.CA)
        let b = F.cert(subject: "b", issuer: "a", subjectKey: F.midKey, signer: F.rootKey, serial: 2, exts: F.CA)
        let r = DcapVerifier.verifyPckChain(pem(a) + pem(b), "00", F.NOW)
        XCTAssertFalse(r.ok)
        XCTAssertEqual(r.reason, "PCK chain does not terminate in a self-signed root")
    }
}
