import Foundation

/// Keep a platform's action definitions in step with the sources they were imported from. Pure: the caller fetches the source and stores the lock. The
/// lock records, per source, the digest of each operation AS IMPORTED (before any review). On the next sync an operation is `added` (lands as imported,
/// unreviewed, so strict), `changed` (the NEW imported form replaces the reviewed def and is unreviewed until a reviewer confirms it again; the semantic
/// diff is reported), `unchanged` (the current, possibly reviewed, def is kept) or `removed` (deprecated). A def the lock does not attribute to this
/// source is never touched.
public enum ActionSync {
    /// Strip the review to the imported state: a changed operation is never carried over as confirmed.
    private static func asImported(_ d: JObject) throws -> JObject {
        guard case let .object(rv)? = d["review"] else { throw JSError("the def has no review") }
        if rv["state"] != .string("confirmed") { return d }
        var c = d
        c["review"] = AK.obj(["state": .string("unreviewed")])
        return c
    }

    /// Merge a fresh import of one source into the current defs: `{defs, entries, deprecated, lock, needsReview}`. `lock` may be nil;
    /// `now`: seconds since the epoch of this sync. `reg` nil is the core registry; `attestationVerified` may be nil.
    public static func syncSource(_ current: [JSONValue], _ imported: [JSONValue], _ specDigest: String?, _ lock: JObject?, _ now: JSONValue?,
                                  _ reg: TraitRegistry? = nil, _ attestationVerified: ((JObject) -> Bool)? = nil) throws -> JObject {
        let r = reg ?? Actions.coreRegistry
        var cur: [JKey: JObject] = [:]
        for d in current { cur[JKey(JS.toString(d.get("verb")))] = AK.o(d) }
        var imp: [JKey: JObject] = [:]
        for d in imported { imp[JKey(JS.toString(d.get("verb")))] = try asImported(AK.o(d)) }
        let lockOps: JObject = lock?["ops"]?.asObject ?? [:]
        var ops: JObject = [:]
        var entries: [JSONValue] = [], defs: [JSONValue] = []
        for k in imp.keys.sorted(by: { ActionBusinessRules.u16less($0.s, $1.s) }) {
            let verb = k.s, d = imp[k]!
            let dg = try Actions.defDigest(d)
            ops[k] = .string(dg)
            let locked = lockOps[k]
            if let old = cur[k] {
                // `locked === dg || (locked === undefined && defDigest(old) === dg)`: the old def is only digested when there is no lock entry
                let unchanged: Bool
                if .string(dg) == locked { unchanged = true } else if locked == nil { unchanged = try Actions.defDigest(old) == dg } else { unchanged = false }
                if unchanged {
                    entries.append(AK.obj(["verb": .string(verb), "change": .string("unchanged")]))
                    defs.append(.object(old))
                } else {
                    let diff: JSONValue
                    do { diff = try ActionDiff.diffDefs(old, d, r, attestationVerified) }
                    catch { diff = AK.obj(["class": .string("incomparable"), "reasons": AK.strs([(error as? ActionKitError)?.message ?? (error as? JSError)?.message ?? "\(error)"])]) }
                    entries.append(AK.obj(["verb": .string(verb), "change": .string("changed"), "diff": diff]))
                    defs.append(.object(d))
                }
            } else {
                entries.append(AK.obj(["verb": .string(verb), "change": .string("added")]))
                defs.append(.object(d))
            }
        }
        let deprecated = lockOps.keys.filter { imp[$0] == nil }.map { $0.s }.sorted(by: ActionBusinessRules.u16less)
        for v in deprecated { entries.append(AK.obj(["verb": .string(v), "change": .string("removed")])) }
        let needs = entries.contains { $0.get("change") == .string("added") || $0.get("change") == .string("changed") }
        return [JKey("defs"): .array(defs), JKey("entries"): .array(entries), JKey("deprecated"): AK.strs(deprecated),
                JKey("lock"): AK.obj(["spec_digest": specDigest.map { .string($0) } ?? .null, "ops": .object(ops), "synced_at": now ?? .null]), JKey("needsReview"): .bool(needs)]
    }

    /// One line per entry, then a summary.
    public static func syncText(_ r: JObject) -> String {
        var lines: [String] = []
        var added = 0, changed = 0, removed = 0, unchanged = 0
        for e0 in AK.arr(r["entries"]) {
            let change = JS.toString(e0.get("change"))
            switch change { case "added": added += 1; case "changed": changed += 1; case "removed": removed += 1; default: unchanged += 1 }
            if change == "unchanged" { continue }
            let pad = change + String(repeating: " ", count: max(0, 9 - change.utf16.count))
            var suffix = ""
            if let diff = e0.get("diff"), diff != .null {
                let rss = AK.arr(diff.get("reasons")).map { JS.toString($0) }
                suffix = "  (" + JS.toString(diff.get("class")) + (rss.isEmpty ? "" : ": " + rss.joined(separator: ", ")) + ")"
            }
            lines.append("\(pad) \(JS.toString(e0.get("verb")))\(suffix)")
        }
        lines.append("\(added) added, \(changed) changed, \(removed) removed (deprecated), \(unchanged) unchanged"
            + (r["needsReview"] == .bool(true) ? "; added and changed actions are unreviewed (strict) until a reviewer confirms them" : ""))
        return lines.joined(separator: "\n")
    }
}
