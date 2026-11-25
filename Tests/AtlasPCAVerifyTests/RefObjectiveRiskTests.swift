import XCTest
import Foundation
@testable import AtlasPCAVerify

/// Differential replay of the objective risk functional (canonical action, inverse registry, resource graph and blast radius, native and BYO embedders,
/// goal commitment and distance, calibration, harm currency, `objectiveRisk` and its dispute-game oracle) against the reference: every case of the corpus.
final class RefObjectiveRiskTests: XCTestCase {
    typealias OR = PCAObjectiveRisk

    private func num(_ d: Double) -> JSONValue { d.isFinite ? PCAFacade.jsNum(d) : .double(d) }
    private func doubles(_ v: JSONValue?) -> [Double] { (v?.asArray ?? []).map { JS.toNumber($0) } }
    private func strings(_ v: JSONValue?) -> [String] { (v?.asArray ?? []).compactMap { $0.asString } }

    private func registry(_ s: JSONValue?) -> OR.InverseRegistry {
        let r = OR.InverseRegistry(trustedVerifiers: strings(s?.get("trusted")))
        for e in s?.get("entries")?.asArray ?? [] { if let p = e.asArray, p.count == 2, let verb = p[0].asString { r.register(verb, p[1]) } }
        return r
    }

    private func graph(_ s: JSONValue?) throws -> OR.ResourceGraph {
        let g = OR.ResourceGraph()
        for n in s?.get("nodes")?.asArray ?? [] { try g.addNode(n) }
        for e in s?.get("edges")?.asArray ?? [] { try g.addEdge(e) }
        return g
    }

    private func infer(_ spec: JSONValue?, dims: Int64?) -> (String) throws -> JSONValue {
        { json in
            if spec?.get("throws") == .bool(true) { throw JSError("infer boom") }
            if spec?.get("notArray") == .bool(true) { return .string("x") }
            if spec?.get("byLen") == .bool(true) {
                return .array((0..<Int(dims ?? 4)).map { .int(Int64(json.utf16.count + $0)) })
            }
            return spec?.get("vector") ?? .null
        }
    }

    private func embedder(_ s: JSONValue?) throws -> OR.Embedder {
        switch s?.get("scheme")?.asString {
        case "native"?: return try OR.nativeHashEmbedder(s?.get("config") ?? .null)
        case "fixed"?:
            let v = s?.get("vector") ?? .null
            return OR.Embedder(modelId: s?.get("modelId") ?? .null, config: s?.get("config") ?? .null, dims: JS.toNumber(s?.get("dims"))) { _ in v }
        default:
            let d = s?.get("descriptor") ?? .null
            let claimed = JS.present(s?.get("claimedModelId"))?.asString
            return try OR.byoEmbedder(d, claimedModelId: claimed, infer: infer(s?.get("infer"), dims: d.get("dims")?.safeInt))
        }
    }

    private func context(_ c: JSONValue?) throws -> OR.Context {
        OR.Context(
            registry: registry(c?.get("registry")), authorizedKinds: strings(c?.get("authorizedKinds")), graph: try graph(c?.get("graph")),
            scope: JS.truthy(c?.get("scope")) ? c?.get("scope") : nil, embedder: try embedder(c?.get("embedder")), goal: c?.get("goal") ?? .null,
            commitments: c?.get("commitments") ?? .null, denominations: c?.get("denominations")?.asArray ?? [], weights: c?.get("weights") ?? .null,
            taint: ToolSchema.fin(c?.get("taint")) ?? .nan, age: ToolSchema.fin(c?.get("age")) ?? .nan,
            attestedUncertainty: JS.present(c?.get("attestedUncertainty")).map { JS.toNumber($0) },
            calibration: JS.truthy(c?.get("calibration")) ? doubles(c?.get("calibration")) : nil)
    }

    private func run(_ c: BaseCase) throws -> JSONValue {
        let a = c.args.map { RefAnalyzer.revive($0) }
        func arg(_ i: Int) -> JSONValue? { i < a.count ? a[i] : nil }
        func opt(_ i: Int) -> JSONValue? { JS.present(arg(i)) }
        switch c.fn {
        case "constants":
            return .object(["METRIC": .string(OR.METRIC), "DEFAULT_EPSILON": num(OR.DEFAULT_EPSILON), "NATIVE_SCHEME": .string(OR.NATIVE_SCHEME),
                            "DEFAULT_MAX_PARAM_LEAVES": .int(Int64(OR.DEFAULT_MAX_PARAM_LEAVES)), "DEFAULT_NATIVE_CONFIG": OR.DEFAULT_NATIVE_CONFIG])
        case "canonicalAction": return try OR.canonicalAction(arg(0))
        case "canonicalActionJson": return .string(try OR.canonicalActionJson(arg(0) ?? .null))
        case "canonicalActionDigest": return .string(try OR.canonicalActionDigest(arg(0) ?? .null))
        case "registryOps":
            let r = OR.InverseRegistry(trustedVerifiers: strings(arg(0)))
            var out: [JSONValue] = []
            for op in arg(1)?.asArray ?? [] {
                let p = op.asArray ?? []
                switch p.first?.asString {
                case "register": r.register(p[1].asString ?? "", p[2]); out.append(.null)
                case "lookup": out.append(r.lookup(p[1].asString ?? "") ?? .null)
                case "trustedVerifiers": out.append(.array(r.trustedVerifiers().map { .string($0) }))
                default: out.append(.string(try r.digest()))
                }
            }
            return .array(out)
        case "registryDigest": return .string(try registry(arg(0)).digest())
        case "reversibility": return OR.reversibility(verb: arg(0)?.get("verb"), registry: registry(arg(1)), authorizedKinds: strings(arg(2)))
        case "graphBuild":
            let g = try graph(arg(0))
            return .object(["size": .int(Int64(g.size)), "digest": .string(try g.digest())])
        case "graphReachable": return .array(try graph(arg(0)).reachable(arg(1), opt(2)).map { .string($0) })
        case "graphNode": return try graph(arg(0)).node(arg(1)) ?? .null
        case "blastRadius": return OR.blastRadius(resource: arg(0)?.get("resource"), graph: try graph(arg(1)), scope: opt(2))
        case "nativeEmbed":
            let e = try OR.nativeHashEmbedder(arg(0))
            return .object(["modelId": e.modelId, "dims": num(e.dims), "config": e.config, "vector": try e.embed(arg(1) ?? .null)])
        case "byoModelId": return .string(try OR.byoModelId(arg(0) ?? .null))
        case "byoEmbed":
            let d = arg(0) ?? .null
            let e = try OR.byoEmbedder(d, claimedModelId: opt(1)?.asString, infer: infer(arg(2), dims: d.get("dims")?.safeInt))
            return .object(["modelId": e.modelId, "dims": num(e.dims), "vector": try e.embed(arg(3) ?? .null)])
        case "validateVector": return .array(try OR.validateVector(arg(0), JS.toNumber(arg(1))))
        case "conformanceCheck": return .bool(OR.conformanceCheck(try embedder(arg(0)), arg(1)?.asArray ?? []))
        case "commitGoal": return try OR.commitGoal(try embedder(arg(0)), arg(1), epsilon: opt(2))
        case "verifyGoalCommitment": return OR.verifyGoalCommitment(arg(0), try embedder(arg(1))).map { .string($0) } ?? .null
        case "vectorDistance":
            return num(OR.vectorDistance(doubles(arg(0)), doubles(arg(1)), epsilon: opt(2).map { JS.toNumber($0) } ?? OR.DEFAULT_EPSILON))
        case "committedDistanceChecked": return OR.committedDistanceChecked(arg(0) ?? .null, arg(1), try embedder(arg(2)))
        case "committedDistance": return num(OR.committedDistance(arg(0), arg(1), try embedder(arg(2))))
        case "calibrate": return num(OR.calibrate(JS.toNumber(arg(0)), doubles(arg(1))))
        case "conformalThreshold": return OR.conformalThreshold(doubles(arg(0)), JS.toNumber(arg(1))).map { num($0) } ?? .null
        case "calibrationDigest": return .string(try OR.calibrationDigest(doubles(arg(0))))
        case "harmReport": return OR.harmReport(arg(0), arg(1)?.asArray ?? [])
        case "objectiveRisk": return try OR.objectiveRisk(arg(0), try context(arg(1)))
        case "objectiveRiskOracle": return OR.objectiveRiskOracle(try context(arg(0)), input: arg(1) ?? .null, snapshot: arg(2))
        default: XCTFail("unhandled fn \(c.fn)"); return .null
        }
    }

    func testReplay() throws {
        let d = Base.Diffs()
        var seen: [String: Int] = [:]
        let n = try Base.each("ref-objective-risk.json.gz") { c in
            seen[c.fn, default: 0] += 1
            let got = Base.run({ ($0 as? JSError)?.code }) { RefAnalyzer.out(try self.run(c)) }
            // the reference's own engine message for a property read of null: only "a refusal reason" is compared
            if c.fn == "verifyGoalCommitment", let want = c.out.asString, want.hasPrefix("Cannot read properties"), case let .value(v) = got {
                d.add(c, v.asString?.isEmpty == false ? nil : "\(c.name): want a refusal reason")
            } else {
                d.add(c, Base.diff(c, got))
            }
        }
        XCTAssertEqual(n, 4052)
        XCTAssertEqual(seen["graphReachable"], 1190)
        XCTAssertEqual(seen["objectiveRisk"], 178)
        XCTAssertEqual(seen.values.reduce(0, +), 4052)
        d.finish(4052)
    }
}
