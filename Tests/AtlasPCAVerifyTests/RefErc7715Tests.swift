import XCTest
import Foundation
@testable import AtlasPCAVerify

/// Differential replay of Erc7715 against the reference (@atlasauth/pca-erc7715). The verify options carry `owners` (context -> grant
/// digest) for the context-owner hook. Native stricter (counted, not failed): a grant without `expiresAtSec` refuses `expiry_extended`
/// where the reference compares against undefined and passes.
final class RefErc7715Tests: XCTestCase {
    func testErc7715() throws {
        try K042.requireCovers(["Erc7715", "JSInterop"])
        let d = Base.Diffs()
        try Base.each("ref-erc7715.json.gz") { c in
            let got: BaseGot
            switch c.fn {
            case "grantToPermissionRequest":
                got = Ref.v { try Erc7715.grantToPermissionRequest(c.arg(0), Ref.obj(c.arg(1))) }
            case "supportsRequest":
                got = .value(.bool(Erc7715.supportsRequest(c.arg(0), c.arg(1))))
            case "revokeParams":
                got = .value(Erc7715.revokeParams(c.arg(0)))
            case "verifyGrantedPermission":
                let o = c.arg(3)
                let owners = o?.get("owners")?.asObject
                let owner: ((String) -> JSONValue?)? = owners.map { m in { (k: String) -> JSONValue? in m[JKey(k)] } }
                let r = Erc7715.verifyGrantedPermission(c.arg(0), c.arg(1), c.arg(2), allowedManagers: o?.get("allowedManagers"),
                                                        contextOwner: owner)
                if r == "expiry_extended", c.out == .null, c.arg(0)?.get("expiresAtSec") == nil { d.skip("native stricter: grant without expiresAtSec"); return }
                got = .value(Base.opt(r))
            case "grantDigestOf":
                got = Erc7715.grantDigestOf(c.arg(0) ?? .null).map { .value(.string($0)) } ?? .threw(nil)
            default:
                d.skip("\(c.fn): not mapped"); return
            }
            d.add(c, Base.diff(c, got))
        }
        d.finish(4000)
    }
}
