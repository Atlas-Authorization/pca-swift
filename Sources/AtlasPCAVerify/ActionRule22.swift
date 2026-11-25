import Foundation

/// The trait engine the verifier's rule 22 (`traits`) calls: the integrity of a document's traits and materialized floors against the registry it
/// carries, and the decision of a verb's floors against what the grant provides and the call context. Anything malformed denies.
public struct Rule22Engine: Sendable {
    public init() {}

    /// nil when the document's traits and materialized floors are what the registry derives; else the refusal reason.
    public func schemaError(_ doc: JSONValue, _ reviewers: JSONValue? = nil) -> String? {
        guard case let .object(d) = doc else { return "schema_floor_forged: the schema document must be an object" }
        return Actions.schemaFloorError(d, reviewers)
    }

    /// `allow`, `escalate` or `deny` of the verb's floors against `grant` (`{caveats, max_esc, preauth_esc}`) and the call `context` keys.
    public func decide(doc: JSONValue, verb: String, grant: JSONValue, context: [String]) -> String {
        let caveats = AK.arr(grant.get("caveats")).compactMap { $0.asString }
        return Actions.rule22Decide(doc: doc, verb: verb, grantCaveats: caveats, maxEsc: IV.int(grant.get("max_esc")).map { Int($0) } ?? 3,
                                    preauthEsc: IV.int(grant.get("preauth_esc")).map { Int($0) } ?? 0, context: context)
    }
}

public let RULE22_ENGINE = Rule22Engine()
