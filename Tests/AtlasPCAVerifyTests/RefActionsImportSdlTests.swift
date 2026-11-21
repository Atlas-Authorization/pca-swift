import XCTest
import Foundation
@testable import AtlasPCAVerify

/// Differential replay of the GraphQL and gRPC importers (SDL / proto parsing, introspection, descriptor sets).
final class RefActionsImportSdlTests: XCTestCase {
    func testImportSdl() throws {
        try K042.requireCovers(["ImportersSdl", "ImportersGrpc", "ImportCommon"])
        let d = Base.Diffs()
        try Base.each("ref-actions-import-sdl.json.gz") { c in
            let a0 = c.arg(0), a1 = c.arg(1)
            // a {"$bytes": b64url} argument is the byte string itself
            let raw: [UInt8]? = a0?.get("$bytes") != nil ? (Base.bytes(a0) ?? []) : nil
            let got: BaseGot
            switch c.fn {
            case "parseGraphqlSdl": got = RefActions.v { try GraphqlImporter.parseGraphqlSdl(a0?.asString ?? "").toJson() }
            case "fromIntrospection": got = RefActions.v { try GraphqlImporter.fromIntrospection(a0).toJson() }
            case "importGraphql": got = RefActions.v { .object(try GraphqlImporter.importGraphql(a0, RefActions.obj(a1))) }
            case "parseProto": got = RefActions.v { try GrpcImporter.parseProto(a0?.asString ?? "").toJson() }
            case "parseDescriptorSet": got = RefActions.v { try GrpcImporter.parseDescriptorSet(raw ?? []).toJson() }
            case "importGrpc": got = RefActions.v { .object(try GrpcImporter.importGrpc(raw == nil ? a0 : nil, RefActions.obj(a1), bytes: raw)) }
            default: d.skip("\(c.fn): not mapped"); return
            }
            d.add(c, Base.diff(c, got))
        }
        d.finish(250)
    }
}
