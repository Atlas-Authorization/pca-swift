import XCTest
import Foundation
@testable import AtlasPCAVerify

/// Differential replay of the policy-safety CI gate against the reference (@atlasauth/pca-policy-ci): input normalisation, the lint
/// rules over the analyzer, the summary and exit codes, the pinned lint-rule digest, the authoring gates and the command line (files
/// are written into a fresh directory and the names resolve there). A second corpus runs the parts that need the analyzer's schema
/// validator and test / coverage runners.
final class RefPolicyCiTests: XCTestCase {
    typealias CI = PCAPolicyCi

    static func strings(_ v: JSONValue?) throws -> [String] {
        guard let a = v?.asArray else { throw JSError("not an array") }
        return try a.map { guard let s = $0.asString else { throw JSError("not a string") }; return s }
    }

    static func replay(_ file: String, min: Int) throws {
        try K042.requireCovers(["PolicyCi", "Analyzer", "Predicates"])
        let d = Base.Diffs()
        try Base.each(file) { c in
            let a0 = c.arg(0), a1 = c.arg(1), a2 = c.arg(2)
            let got: BaseGot
            switch c.fn {
            case "normalizePolicyInput": got = RefAnalyzer.run { CI.normalizePolicyInput(a0) }
            case "normalizeChain": got = RefAnalyzer.run { guard let a = a0?.asArray else { throw JSError("chain.every is not a function") }; return CI.normalizeChain(a).json }
            case "isCapability": got = .value(.bool(CI.isCapability(a0)))
            case "isEnvelope": got = .value(.bool(CI.isEnvelope(a0)))
            case "lintPolicy": got = RefAnalyzer.run { .array(try CI.lintPolicy(a0, a1)) }
            case "lintChain": got = RefAnalyzer.run { guard let a = a0?.asArray else { throw JSError("chain.length") }; return .array(try CI.lintChain(a, a1)) }
            case "lint": got = RefAnalyzer.run { .array(try CI.lint(a0, a1)) }
            case "lintPolicies": got = RefAnalyzer.run { try CI.lintPolicies(a0, a1) }
            case "summarize": got = RefAnalyzer.run { try CI.summarize(a0, a1) }
            case "checkLintRulesPin":
                guard let pin = a0?.asString else { got = .threw(nil); break }
                if c.args.count > 1 && a1?.asString == nil { d.skip("checkLintRulesPin: a non-string actual digest"); return }
                got = RefAnalyzer.run { try CI.checkLintRulesPin(pin, actual: a1?.asString) }
            case "toAnalyzerPolicy": got = RefAnalyzer.run { CI.toAnalyzerPolicy(a0) }
            case "diffCommand": got = RefAnalyzer.run { try CI.diffCommand(a0, a1, a2) }
            case "testCommand": got = RefAnalyzer.run { try CI.testCommand(a0, a1, a2) }
            case "coverageCommand": got = RefAnalyzer.run { try CI.coverageCommand(a0, a1, a2) }
            case "parseArgs": got = RefAnalyzer.run { CI.parseArgs(try Self.strings(a0)).json }
            case "run":
                got = RefAnalyzer.run {
                    let spec = c.raw.get("args")
                    let dir = NSTemporaryDirectory() + "pca-policy-ci-" + UUID().uuidString
                    defer { try? FileManager.default.removeItem(atPath: dir) }
                    try FileManager.default.createDirectory(atPath: dir, withIntermediateDirectories: true)
                    for (name, body) in spec?.get("files")?.asObject ?? [:] {
                        let path = dir + "/" + name.s
                        try FileManager.default.createDirectory(atPath: (path as NSString).deletingLastPathComponent, withIntermediateDirectories: true)
                        try Data((body.asString ?? "").utf8).write(to: URL(fileURLWithPath: path))
                    }
                    var lines: [JSONValue] = []
                    let code = try CI.run(try Self.strings(spec?.get("argv")), dir: dir) { lines.append(.string($0)) }
                    return .object(["code": .int(Int64(code)), "lines": .array(lines)])
                }
            default: d.skip("\(c.fn): not mapped"); return
            }
            d.add(c, Base.diff(c, got))
        }
        d.finish(min)
    }

    func testPolicyCi() throws { try Self.replay("ref-policy-ci.json.gz", min: 1900) }

    /// The parts that run on the analyzer's schema validator and test / coverage runners.
    func testPolicyCiAnalyzerExtras() throws { try Self.replay("ref-policy-ci-java-extra.json.gz", min: 150) }
}
