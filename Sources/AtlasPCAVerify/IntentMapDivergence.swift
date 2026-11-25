import Foundation

extension PCAIntentMap {
    /// A runtime divergence is one more labelled observation; a negative one also vetoes the cell. Returns {before, after, grant}.
    public static func applyDivergence(_ l: PCAIntentLearner, _ outcome: JSONValue, _ y: Int) throws -> JSONValue {
        var before: Int64 = 0
        for c in l.cells() where c.inGrant { before += 1 }
        _ = try l.observe(outcome, y: y, source: "runtime", region: nil)
        var after: Int64 = 0
        for c in l.cells() where c.inGrant { after += 1 }
        let s: JSONValue = l.synthesize()
        let grant: JSONValue = JSONValue.object([JKey("predicates"): s.get("predicates") ?? JSONValue.array([]), JKey("caveats"): s.get("caveats") ?? JSONValue.array([])])
        return JSONValue.object([JKey("before"): JSONValue.int(before), JKey("after"): JSONValue.int(after), JKey("grant"): grant])
    }
}
