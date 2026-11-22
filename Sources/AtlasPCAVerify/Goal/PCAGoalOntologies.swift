import Foundation

/// The shipped intent ontologies and the selector catalog of each domain (reference data in GoalOntologiesData.swift).
public enum PCAGoalOntologies {
    /// Names of the shipped ontologies.
    public static let NAMES: [String] = GoalOntologiesData.names

    private static func parse(_ s: String) throws -> JSONValue {
        return IV.normalized(try StrictJSON.parseLenient(s))
    }

    /// The intent ontology of a shipped domain (a fresh parsed copy), or nil for an unknown name.
    public static func ontology(_ name: String) throws -> JSONValue? {
        guard let s = GoalOntologiesData.ontologies[name] else { return nil }
        return try parse(s)
    }

    /// The selector catalog of a shipped domain ({known, verbs}), or nil for an unknown name.
    public static func selCatalog(_ name: String) throws -> JSONValue? {
        guard let s = GoalOntologiesData.catalogs[name] else { return nil }
        return try parse(s)
    }

    /// Every shipped ontology by name.
    public static func all() throws -> [String: JSONValue] {
        var m: [String: JSONValue] = [:]
        for n in NAMES {
            guard let o = try ontology(n) else { throw IrError("shipped ontology \(n) is missing") }
            m[n] = o
        }
        return m
    }

    /// The reference's `ALL_ONTOLOGIES`: payments, email, calendar_travel, code_repos, data_access.
    public static var ALL_ONTOLOGIES: [String: JSONValue] { get throws { try all() } }

    /// The reference's five named exports, each a fresh parsed copy.
    public static func payments() throws -> JSONValue { try named("payments") }
    public static func email() throws -> JSONValue { try named("email") }
    public static func travel() throws -> JSONValue { try named("calendar_travel") }
    public static func code() throws -> JSONValue { try named("code_repos") }
    public static func data() throws -> JSONValue { try named("data_access") }
    private static func named(_ n: String) throws -> JSONValue {
        guard let o = try ontology(n) else { throw IrError("shipped ontology \(n) is missing") }
        return o
    }
}
