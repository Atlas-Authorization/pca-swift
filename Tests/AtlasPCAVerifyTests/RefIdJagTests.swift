import XCTest
import Foundation
@testable import AtlasPCAVerify

/// Differential replay of PCAIdJag against the reference (@atlasauth/pca-idjag): ID-JAG verification (strict draft and loose),
/// the principal / capability projection, the caveat readers and the token-exchange / jwt-bearer request shapes.
final class RefIdJagTests: XCTestCase {
    static let file = "ref-idjag.json.gz"

    /// More than one new string-keyed `extra` member: their order in the body is the producer's insertion order, which a parsed
    /// vector no longer has.
    static func extraOrderLost(_ opts: JSONValue?, base: Set<String>) -> Bool {
        guard let e = opts?.get("extra")?.asObject else { return false }
        return e.filter { JS.indexKey($0.key.s) == nil && !base.contains($0.key.s) && JS.nonEmptyString($0.value) != nil }.count > 1
    }

    func testIdJag() throws {
        try K042.requireCovers(["Idjag", "Oidc", "Jose", "JSInterop"])
        let d = Base.Diffs()
        try Base.each(Self.file) { c in
            let a0 = c.arg(0), a1 = c.arg(1)
            let got: BaseGot
            switch c.fn {
            case "constants":
                got = .value(.object([
                    "MAX_ID_JAG_CHARS": .int(Int64(PCAIdJag.MAX_ID_JAG_CHARS)), "IDJAG_AUTHORITY_CAVEAT": .string(PCAIdJag.IDJAG_AUTHORITY_CAVEAT),
                    "IDJAG_PROVENANCE_CAVEAT": .string(PCAIdJag.IDJAG_PROVENANCE_CAVEAT), "GRANT_TYPE_TOKEN_EXCHANGE": .string(PCAIdJag.GRANT_TYPE_TOKEN_EXCHANGE),
                    "GRANT_TYPE_JWT_BEARER": .string(PCAIdJag.GRANT_TYPE_JWT_BEARER), "TOKEN_TYPE_ID_JAG": .string(PCAIdJag.TOKEN_TYPE_ID_JAG),
                    "TOKEN_TYPE_ID_TOKEN": .string(PCAIdJag.TOKEN_TYPE_ID_TOKEN), "TOKEN_TYPE_ACCESS_TOKEN": .string(PCAIdJag.TOKEN_TYPE_ACCESS_TOKEN),
                    "TOKEN_TYPE_JWT": .string(PCAIdJag.TOKEN_TYPE_JWT), "CLIENT_ASSERTION_TYPE_JWT_BEARER": .string(PCAIdJag.CLIENT_ASSERTION_TYPE_JWT_BEARER),
                ]))
            case "verifyIdJag":
                let o = a1?.asObject
                var consume: ((String, JSONValue) throws -> Bool)? = nil
                if let mode = o?["consumeJti"]?.get("mode")?.asString {
                    if mode == "truthy" { d.skip("consumeJti returning a truthy non-boolean: not expressible with a Bool store"); return }
                    consume = { _, _ in
                        if mode == "throw" { throw JSError("store down") }
                        return mode == "fresh"
                    }
                }
                got = Ref.v {
                    var key: OidcKey? = nil
                    if let k = o?["key"] { if let j = k.get("jwks") { key = .set(try OidcLocalJwks(j)) } else { key = .jwk(k) } }
                    return try PCAIdJag.verifyIdJag(a0, a1, key: key, fetch: o?["fetch"].map { RefOidcTests.fetch($0) }, consumeJti: consume)
                }
            case "idJagToPcaPrincipal":
                got = Ref.v { try PCAIdJag.idJagToPcaPrincipal(a0, c.args.count > 1 ? (a1 ?? .null) : nil) }
            case "idJagToCapability":
                got = Ref.v { try PCAIdJag.idJagToCapability(a0, a1, principalSecret: Base.bytes(a1?.get("principalSecret"))) }
            case "isIdJagAuthorityCaveat":
                got = .value(.bool(PCAIdJag.isIdJagAuthorityCaveat(a0)))
            case "isIdJagProvenanceCaveat":
                got = .value(.bool(PCAIdJag.isIdJagProvenanceCaveat(a0)))
            case "readIdJagAuthority":
                got = Ref.v { try PCAIdJag.readIdJagAuthority(a0) }
            case "readIdJagProvenance":
                got = Ref.v { try PCAIdJag.readIdJagProvenance(a0) }
            case "tokenExchangeRequest":
                if Self.extraOrderLost(a0, base: ["grant_type", "subject_token", "subject_token_type", "requested_token_type", "audience", "resource",
                                                  "scope", "actor_token", "actor_token_type", "client_id"]) { d.skip("extra member order lost in the vector"); return }
                got = Ref.v { try PCAIdJag.tokenExchangeRequest(a0) }
            case "jwtBearerAssertion":
                if Self.extraOrderLost(a0, base: ["grant_type", "assertion", "scope", "client_id", "client_assertion_type", "client_assertion"]) {
                    d.skip("extra member order lost in the vector"); return
                }
                got = Ref.v { try PCAIdJag.jwtBearerAssertion(a0) }
            default:
                d.skip("\(c.fn): not mapped"); return
            }
            d.add(c, Base.diff(c, got))
        }
        d.finish(330)
    }
}
