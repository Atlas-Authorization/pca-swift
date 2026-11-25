import XCTest
import Foundation
@testable import AtlasPCAVerify

/// Differential replay of the build step (artifacts, generated types, tool map, pack signing and verification) and of pack building,
/// sharding and upgrade verification, plus the transparency statement payload.
final class RefActionsBuildTests: XCTestCase {
    func testBuild() throws {
        try K042.requireCovers(["ActionBuild", "ActionDerive", "ActionLint"])
        let d = Base.Diffs()
        try Base.each("ref-actions-build.json.gz", seeds: true) { c in
            let a0 = c.arg(0), a1 = c.arg(1)
            let got: BaseGot
            switch c.fn {
            case "buildArtifacts": got = RefActions.v { try ActionBuild.buildArtifacts(RefActions.list(a0), RefActions.obj(a1)) }
            case "generateTypes": got = RefActions.v { .string(try ActionBuild.generateTypes(RefActions.list(a0))) }
            case "toolAction": got = RefActions.v { try ActionBuild.toolActionMapOf(RefActions.list(a0))(a1?.asString ?? "", RefActions.obj(c.arg(2))) ?? .null }
            case "packConsistencyError": got = .value(Base.opt(ActionBuild.packConsistencyError(a0)))
            case "signPack":
                got = RefActions.v {
                    guard let seed = Base.bytes(c.arg(2)) else { throw ActionKitError(code: "bad_seed", message: "seed") }
                    return try ActionBuild.signPack(RefActions.obj(a0), kid: a1?.asString ?? "", key: try Ed25519Deterministic.key(seed: seed))
                }
            case "packKeyOf":
                got = RefActions.v {
                    guard let seed = Base.bytes(a1) else { throw ActionKitError(code: "bad_seed", message: "seed") }
                    return ActionBuild.packKeyOf(a0?.asString ?? "", try Ed25519Deterministic.key(seed: seed))
                }
            case "verifyPack": got = .value(ActionBuild.verifyPack(a0, a1))
            default: d.skip("\(c.fn): not mapped"); return
            }
            d.add(c, Base.diff(c, got))
        }
        d.finish(45)
    }

    func testPacks() throws {
        try K042.requireCovers(["ActionBuild", "ActionEvolve", "ActionsRegistry"])
        let d = Base.Diffs()
        try Base.each("ref-actions-pack.json.gz", seeds: true) { c in
            let a0 = c.arg(0), a1 = c.arg(1)
            let got: BaseGot
            switch c.fn {
            case "buildPack":
                got = RefActions.v {
                    guard let seed = Base.bytes(a1) else { throw ActionKitError(code: "bad_seed", message: "seed") }
                    return try ActionPacks.buildPack(RefActions.obj(a0), key: PCASuiteKey.ed25519(try Ed25519Deterministic.key(seed: seed)), { _ in false })
                }
            case "shardDefs": got = RefActions.v { .array(try ActionPacks.shardDefs(RefActions.list(a0), a1)) }
            case "verifyUpgrade":
                got = .value(ActionPacks.verifyUpgrade(RefActions.obj(a0), RefActions.obj(a1), c.arg(2), c.arg(3)?.asObject, c.arg(4)?.asObject, { _ in false }))
            case "packStatementPayload": got = .value(ActionTransparency.packStatementPayload(RefActions.obj(a0)))
            default: d.skip("\(c.fn): not mapped"); return
            }
            d.add(c, Base.diff(c, got))
        }
        d.finish(80)
    }
}
