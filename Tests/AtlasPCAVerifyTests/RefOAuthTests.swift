import XCTest
import Foundation
@testable import AtlasPCAVerify

/// Shared helpers of the protocol-bridge replay tests (test-data/ref-<package>.json.gz, produced by the TypeScript reference).
enum Ref {
    static func obj(_ v: JSONValue?) -> JObject { v?.asObject ?? [:] }
    static func strings(_ v: JSONValue?) -> [String]? {
        guard let a = v?.asArray else { return nil }
        let s = a.compactMap { $0.asString }
        return s.count == a.count ? s : nil
    }
    /// A refusal's code: JSError.code (the reference's stable code where it carries one).
    static func code(_ e: Error) -> String? { (e as? JSError)?.code }
    static func s(_ f: () throws -> String) -> BaseGot { Base.run(code) { .string(try f()) } }
    static func v(_ f: () throws -> JSONValue) -> BaseGot { Base.run(code) { try f() } }
}

/// Differential replay of PCAOAuth against the reference (@atlasauth/pca-oauth): RFC 9728 metadata, the 401 challenge, RFC 8707
/// resource indicators, token audience, the pca_grant builder / token gate and the action-derived scopes.
final class RefOAuthTests: XCTestCase {
    static let file = "ref-oauth.json.gz"

    func testOAuthBridge() throws {
        try K042.requireCovers(["OAuth", "WhatwgURL", "JSInterop", "PcaGrant", "A2a"])
        let d = Base.Diffs()
        try Base.each(Self.file) { c in
            let a0 = c.arg(0), a1 = c.arg(1)
            let got: BaseGot
            switch c.fn {
            case "resourceIdentifierProblem":
                got = .value(Base.opt(PCAOAuth.resourceIdentifierProblem(a0)))
            case "prmPathForResource":
                got = Ref.s { try PCAOAuth.prmPathForResource(a0?.asString ?? "") }
            case "prmUrlForResource":
                got = Ref.s { try PCAOAuth.prmUrlForResource(a0?.asString ?? "") }
            case "protectedResourceMetadata":
                got = Ref.v { try PCAOAuth.protectedResourceMetadata(Ref.obj(a0)) }
            case "parseProtectedResourceMetadata":
                got = Ref.v { try PCAOAuth.parseProtectedResourceMetadata(a0, Ref.obj(a1)) }
            case "wwwAuthenticate":
                got = Ref.s { try PCAOAuth.wwwAuthenticate(a0, Ref.obj(a1)) }
            case "mcpUnauthorized":
                got = Ref.v { try PCAOAuth.mcpUnauthorized(a0, Ref.obj(a1)) }
            case "upgradeUnauthorizedChallenge":
                got = Ref.v { try PCAOAuth.upgradeUnauthorizedChallenge(a0, a1, Ref.obj(c.arg(2))) }
            case "checkResourceIndicator":
                got = Ref.v { try PCAOAuth.checkResourceIndicator(a0, a1) }
            case "checkTokenAudience":
                got = Ref.v { try PCAOAuth.checkTokenAudience(a0, a1) }
            case "oauthDiscoveryHandler":
                got = Ref.v { try PCAOAuth.oauthDiscoveryHandler(Ref.obj(a0)) }
            case "buildPcaGrantDetail":
                let o = Ref.obj(a0)
                guard let ids = Ref.strings(o["chainIds"]) else { d.skip("buildPcaGrantDetail: non-string chain ids"); return }
                got = Ref.v { try PCAOAuth.buildPcaGrantDetail(chainIds: ids, chainRef: o["chainRef"], bundleRevision: o["bundleRevision"], locations: o["locations"]) }
            case "pcaGrantRequestParam":
                got = .value(.string(PCAOAuth.pcaGrantRequestParam(a0?.asArray ?? [])))
            case "authorizePcaGrantToken":
                let o = Ref.obj(a0)
                guard let ids = Ref.strings(o["chainIds"]), let res = o["resource"]?.asString else { d.skip("authorizePcaGrantToken: untyped input"); return }
                got = .value(PCAOAuth.authorizePcaGrantToken(authorizationDetails: o["authorizationDetails"], resource: res, chainIds: ids,
                                                             proofVerified: o["proofVerified"] == .bool(true)))
            case "oauthScopeForAction":
                let o = Ref.obj(a1)
                got = .value(PCAOAuth.oauthScopeForAction(a0, provider: o["provider"], granted: o["granted"], resource: o["resource"]))
            default:
                d.skip("\(c.fn): not mapped"); return
            }
            d.add(c, Base.diff(c, got))
        }
        d.finish(800)
    }

    func testWhatwgURLBasics() {
        XCTAssertEqual(WhatwgURL.parse("https://RS.Example.com:443/a/../Mcp?x=1#f")?.htu, "https://rs.example.com/Mcp")
        XCTAssertEqual(WhatwgURL.parse("https://[0:0::1]:8443/x")?.host, "[::1]:8443")
        XCTAssertEqual(WhatwgURL.parse("http://0x7f.1/")?.host, "127.0.0.1")
        XCTAssertNil(WhatwgURL.parse("https://"))
        XCTAssertNil(WhatwgURL.parse("https://a b/"))
        XCTAssertNil(WhatwgURL.parse("rs.example.com/mcp"))
    }
}
