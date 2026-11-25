import XCTest
import Foundation
@testable import AtlasPCAVerify

/// The seeded provider catalog by name (the 15 exported manifests, their digests and validity, the structural invariants, the display order of
/// BUILTIN_MANIFESTS, ids outside the catalog) against the reference corpus: every case, every fn.
final class RefConnectorsProvidersTests: XCTestCase {
    typealias K = PCAConnectors
    typealias P = PCAConnectors.Providers

    private static let named: [String: K.ProviderManifest] = [
        "google": P.google, "github": P.github, "slack": P.slack, "notion": P.notion, "hubspot": P.hubspot, "atlassian": P.atlassian, "salesforce": P.salesforce,
        "microsoft": P.microsoft, "shopify": P.shopify, "snowflake": P.snowflake, "linear": P.linear, "zoom": P.zoom, "stripe": P.stripe, "dropbox": P.dropbox,
        "airtable": P.airtable,
    ]

    private static func strings(_ v: JSONValue?) -> [String] { (v?.asArray ?? []).compactMap { $0.asString } }

    static func call(_ c: BaseCase) -> BaseGot? {
        let a0 = c.arg(0)
        switch c.fn {
        case "provider":
            return RefAnalyzer.run {
                guard let m = named[a0?.asString ?? ""] else { throw PCAProducerError("provider") }
                return .object(["manifest": m.json, "digest": .string(K.manifestDigest(m)), "valid": .bool({ if case .valid = K.validateManifest(m.json) { return true } else { return false } }())])
            }
        case "invariants":
            return RefAnalyzer.run {
                guard let name = a0?.asString, let m = named[name] else { throw PCAProducerError("provider") }
                let j = m.json
                let available = strings(j.get("scopesAvailable"))
                return .object(["defaultScopesSubset": .bool(strings(j.get("defaultScopes")).allSatisfy { available.contains($0) }),
                                "scopesUnique": .bool(Set(available).count == available.count), "idMatchesKey": .bool(m.id == name),
                                "httpsEndpoints": .bool([m.authorizeUrl, m.tokenUrl].allSatisfy { $0.hasPrefix("https://") })])
            }
        case "builtinManifests":
            return .value(.object(["ids": .array(P.BUILTIN_MANIFESTS.map { .string($0.id) }), "digests": .array(P.BUILTIN_MANIFESTS.map { .string(K.manifestDigest($0)) }),
                                   "catalogDigest": .string(K.catalogDigest())]))
        case "unknownProvider": return .value(.object(["found": .bool(K.defaultRegistry.get(a0?.asString ?? "") != nil)]))
        default: return nil
        }
    }

    func testEveryCaseOfTheReferenceCorpus() throws {
        let d = Base.Diffs()
        var seen: [String: Int] = [:]
        let n = try Base.each("ref-connectors-providers.json.gz") { c in
            seen[c.fn, default: 0] += 1
            guard let got = Self.call(c) else { XCTFail("unhandled fn \(c.fn)"); return }
            d.add(c, Base.diff(c, got))
        }
        XCTAssertEqual(n, 40)
        XCTAssertEqual(seen, ["provider": 15, "invariants": 15, "unknownProvider": 9, "builtinManifests": 1])
        d.finish(40)
    }
}
