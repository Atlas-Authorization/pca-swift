import XCTest
import Foundation
@testable import AtlasPCAVerify

/// Differential test of ActionsRegistry.swift (evolution records, registry signatures, re-approvals, the grant pin, signed packs +
/// shards, the rollback tracker, rule 22, pack proofs) against the TS reference (pca-actions registry): test-data/k05-actionregistry.json.gz.
/// Mappings onto the typed Swift API:
/// - the registry signature checks return a Bool in Swift: the reference's null is true, any reason is false; inside a pack verdict a
///   reference "pack signature: <detail>" is Swift's "pack signature: invalid" (and likewise for an evolution record's signature);
/// - `textPrefix` cases carry an engine-specific message tail (a JS exception text): the decision must match, the tail is not compared;
/// - an argument the typed API cannot hold (a non-string verb, a non-array record list) must be one the reference refuses.
final class K05ActionRegistryOracleTests: XCTestCase {
    static let file = "k05-actionregistry.json.gz"
    static let covers = ["ActionsRegistry", "Actions", "ActionSchema", "Merkle", "IntentValues", "StrictJSON", "Canonical", "Base64URLStrict", "Ed25519Strict",
                         "PQ", "JSONValue", "Keys"]

    static func code(_ e: Error) -> String? { (e as? ActionKitError)?.code }

    /// A Swift pack reason against the reference's (see the class comment).
    static func sameReason(_ want: String, _ got: String, _ prefix: String?) -> Bool {
        if want == got { return true }
        if let p = prefix { return want.hasPrefix(p) && !got.isEmpty }
        for (ts, sw) in [("pack signature: ", "pack signature: invalid"), ("evolution record: signature", "evolution record: invalid")] where want.hasPrefix(ts) { return got == sw }
        if want.hasPrefix("evolution record for '"), want.hasSuffix("names a definition that is not in the pack") { return got == "evolution record names a definition that is not in the pack" }
        return false
    }

    static func verdict(_ v: PackVerdict) -> JSONValue {
        v.ok ? .object(["ok": .bool(true), "digest": .string(v.digest), "verbs": .array(v.defs.map { $0.get("verb") ?? .null })])
            : .object(["ok": .bool(false), "reason": .string(v.reason)])
    }

    /// Compares an {ok, reason?, ...} object with the reason under `sameReason` and every other member exactly.
    static func reasonDiff(_ c: K05Case, _ got: JSONValue) -> String? {
        guard case let .object(w) = c.out, case let .object(g) = got else { return K05.diff(c, .value(got)) }
        var w2 = w, g2 = g
        let wr = w2.removeValue(forKey: "reason")?.asString, gr = g2.removeValue(forKey: "reason")?.asString
        let ok = K05.canon(.object(w2)) == K05.canon(.object(g2)) && (wr == nil) == (gr == nil) && (wr.map { sameReason($0, gr ?? "", c.meta("textPrefix")) } ?? true)
        return ok ? nil : "\(c.name): want \(K05.canon(c.out).prefix(300)) got \(K05.canon(got).prefix(300))"
    }

    /// Known, reasoned divergences that are not Swift bugs (nil = none): ML-DSA where the platform has none (refused fail-closed),
    /// a -0 the reference takes as an integer, and which unknown member a refusal names (a parsed Swift object keeps no member order).
    static func excused(_ c: K05Case, _ d: String) -> String? {
        if !MLDSA.available, K05.canon(c.raw).contains("ml-dsa") { return "ML-DSA is not available on this platform: refused fail-closed" }
        if c.args.contains(where: K05.negZero) { return "-0 accepted by the reference (Number.isInteger), refused by the strict Swift profile" }
        if let w = c.out.asString, w.contains("unknown member '"), d.contains("got \"\(w.prefix(upTo: w.range(of: "unknown member '")!.upperBound))") {
            return "both refuse an unknown member; which one is named depends on member order (a parsed Swift object keeps none)"
        }
        return nil
    }

    static func add(_ dd: K05.Diffs, _ c: K05Case, _ d: String?) {
        if let d = d, let why = excused(c, d) { dd.skip(why); return }
        dd.add(c, d)
    }

    /// A Bool verdict against the reference's `null | reason`.
    static func boolDiff(_ c: K05Case, _ ok: Bool) -> String? {
        let want = c.out == .null
        return want == ok ? nil : "\(c.name): want \(K05.canon(c.out).prefix(200)) got \(ok)"
    }

    func testRecordsSignaturesPins() throws {
        try K042.requireCovers(Self.covers)
        let d = K05.Diffs()
        try K05.each(Self.file, ["evolutionRecordError", "evolutionDiffDigest", "verifyRegistrySig", "verifyEvolutionRecord", "reapprovalValid", "actionPinError",
                                 "decidePin", "compareVersions"]) { c in
            let a = c.arg(0)
            switch c.fn {
            case "evolutionRecordError":
                let r = Actions.evolutionRecordError(a, signed: c.arg(1) != .bool(false))
                if let p = c.meta("textPrefix"), let w = c.out.asString, let g = r { Self.add(d, c, w.hasPrefix(p) && !g.isEmpty ? nil : "\(c.name): want \(w) got \(g)"); return }
                Self.add(d, c, K05.diff(c, .value(K05.opt(r))))
            case "evolutionDiffDigest":
                Self.add(d, c, K05.diff(c, Actions.evolutionDiffDigest(a).map { .value(.string($0)) } ?? .threw(nil)))
            case "verifyRegistrySig":
                guard let dom = a?.asString, let body = c.arg(1)?.asObject, let sig = c.arg(2)?.asObject else {
                    Self.add(d, c, c.out.asString != nil ? nil : "\(c.name): untyped args the reference accepts"); return
                }
                Self.add(d, c, Self.boolDiff(c, Actions.verifyRegistrySig(dom, body, sig, c.arg(3))))
            case "verifyEvolutionRecord":
                Self.add(d, c, Self.boolDiff(c, Actions.verifyEvolutionRecord(a, c.arg(1))))
            case "reapprovalValid":
                guard let g = c.arg(1)?.asString, let i = c.arg(2)?.asString, let v = c.arg(3)?.asString, let df = c.arg(4)?.asString else {
                    Self.add(d, c, c.out == .bool(false) ? nil : "\(c.name): untyped args the reference accepts"); return
                }
                Self.add(d, c, K05.diff(c, .value(.bool(Actions.reapprovalValid(a, grantId: g, issuer: i, verb: v, diff: df)))))
            case "actionPinError":
                Self.add(d, c, K05.diff(c, .value(K05.opt(Actions.actionPinError(a)))))
            case "compareVersions":
                guard let x = a?.asString, let y = c.arg(1)?.asString else { d.skip("compareVersions: non-string args"); return }
                Self.add(d, c, K05.diff(c, Actions.compareVersions(x, y).map { .value(.int(Int64($0.signum()))) } ?? .threw("bad_version")))
            default: // decidePin
                let i = a?.asObject ?? [:]
                let prefixed = c.meta("textPrefix") != nil
                guard let verb = i["verb"]?.asString, let recs = (i["records"] ?? .array([])).asArray, let reaps = (i["reapprovals"] ?? .array([])).asArray,
                      let grant = i["grant"]?.asObject, let gid = grant["id"]?.asString, let iss = grant["issuer"]?.asString else {
                    // the typed API cannot take it: the reference must refuse (its refusal text is a JS exception, prefix-only)
                    Self.add(d, c, c.out.get("ok") == .bool(false) ? nil : "\(c.name): untyped input the reference accepts"); return
                }
                let r = Actions.decidePin(pin: i["pin"], doc: i["doc"], verb: verb, records: recs, keys: i["keys"], reapprovals: reaps, grantId: gid, issuer: iss)
                var o: JObject = ["ok": .bool(r.ok)]
                if r.ok { o["via"] = K05.opt(r.via) } else {
                    o["code"] = K05.opt(r.code); o["escalate"] = .bool(r.escalate); o["reason"] = .string(r.reason)
                    if let n = r.needsReapproval { o["needs_reapproval"] = .string(n) }
                }
                if prefixed { Self.add(d, c, r.ok ? "\(c.name): the reference failed closed, Swift allowed" : nil); return }
                Self.add(d, c, K05.diff(c, .value(.object(o))))
            }
        }
        d.finish(5200) // 5806 cases, 280 carry a lone surrogate (skipped); macOS < 26 also excuses its ML-DSA cases
    }

    func testPacks() throws {
        try K042.requireCovers(Self.covers)
        let d = K05.Diffs()
        try K05.each(Self.file, ["packShapeError", "packDefs", "verifyPack", "verifyPackProof", "rule22Decide"]) { c in
            let a = c.arg(0)
            switch c.fn {
            case "packShapeError":
                guard c.arg(1) != .bool(false) else { d.skip("packShapeError: the unsigned (pre-signing) shape is not part of the Swift verifier"); return }
                let r = Actions.packShapeError(a)
                if let p = c.meta("textPrefix"), let w = c.out.asString, let g = r { Self.add(d, c, w.hasPrefix(p) && !g.isEmpty ? nil : "\(c.name): want \(w) got \(g)"); return }
                Self.add(d, c, K05.diff(c, .value(K05.opt(r))))
            case "packDefs":
                guard let p = a?.asObject else { d.skip("packDefs: a non-object pack"); return }
                let got = K05.run(Self.code) { .array(try Actions.packDefs(p, c.arg(1)?.asObject ?? [:]).map { $0.get("verb") ?? .null }) }
                // a reference canonicalizer throw (textPrefix, no code): Swift's strict hash is undefined there and refuses with its own code
                if c.meta("textPrefix") != nil, c.threw, case .threw = got { Self.add(d, c, nil); return }
                Self.add(d, c, K05.diff(c, got))
            case "verifyPack":
                Self.add(d, c, Self.reasonDiff(c, Self.verdict(Actions.verifyPack(a, keys: c.arg(1), shards: c.arg(2)?.asObject ?? [:]))))
            case "verifyPackProof":
                guard let root = a?.asString, let dg = c.arg(2)?.asString else { Self.add(d, c, K05.diff(c, .value(.bool(false)))); return }
                Self.add(d, c, K05.diff(c, .value(.bool(Actions.verifyPackProof(root: root, proof: c.arg(1) ?? .null, digest: dg)))))
            default: // rule22Decide
                let g = c.arg(2)
                let ctx = Actions.strings(c.arg(3))
                guard let verb = c.arg(1)?.asString, let cav = Actions.strings(g?.get("caveats")), let cx = ctx else {
                    if c.out == .string("deny") { Self.add(d, c, nil) } else { d.skip("rule22Decide: a grant/context the typed Swift API cannot hold, which the reference does not deny") }
                    return
                }
                // a tier the typed API cannot hold (missing, non-integer, -0, unsafe) is denied, as by the reference
                guard let me = IV.int(g?.get("max_esc")), let pe = IV.int(g?.get("preauth_esc")) else { Self.add(d, c, K05.diff(c, .value(.string("deny")))); return }
                Self.add(d, c, K05.diff(c, .value(.string(Actions.rule22Decide(doc: a ?? .null, verb: verb, grantCaveats: cav, maxEsc: Int(me), preauthEsc: Int(pe), context: cx)))))
            }
        }
        d.finish(14_000)
    }

    func testTracker() throws {
        try K042.requireCovers(Self.covers)
        var keys: JSONValue?
        try K05.each(Self.file, ["verifyPack"]) { c in if c.name == "verifyPack/p1" { keys = c.arg(1) } }
        XCTAssertNotNil(keys, "verifyPack/p1 (the tracker's pinned keys) is missing")
        let d = K05.Diffs()
        try K05.each(Self.file, ["packTracker"]) { c in
            let t = Actions.PackTracker(keys: keys)
            var outs: [JSONValue] = []
            for st in c.arg(0)?.asArray ?? [] {
                let s = st.asArray ?? []
                let pack = s.first ?? .null, shards = (s.count > 1 ? s[1].asObject : nil) ?? [:]
                let r = t.accept(pack, shards: shards)
                outs.append(r.ok ? .object(["ok": .bool(true), "status": .string(r.value)]) : .object(["ok": .bool(false), "code": .string(r.value)]))
            }
            // reasons compare only for bad_pack (the verify reason); other refusal texts are each port's wording
            let want: [JSONValue] = (c.out.asArray ?? []).map { w in
                guard var o = w.asObject else { return w }
                if o["code"] != .string("bad_pack") { o["reason"] = nil }
                return .object(o)
            }
            var bad: String?
            for (i, g) in outs.enumerated() {
                guard i < want.count else { bad = "\(c.name): extra step"; break }
                var w = want[i].asObject ?? [:]
                if let wr = w.removeValue(forKey: "reason")?.asString {
                    let s = c.arg(0)?.asArray?[i].asArray ?? []
                    let vr = Actions.verifyPack(s.first ?? .null, keys: keys, shards: (s.count > 1 ? s[1].asObject : nil) ?? [:]).reason
                    if !Self.sameReason(wr, vr, nil) { bad = "\(c.name) step \(i): want reason \(wr) got \(vr)"; break }
                }
                if K05.canon(.object(w)) != K05.canon(g) { bad = "\(c.name) step \(i): want \(K05.canon(want[i])) got \(K05.canon(g))"; break }
            }
            if bad == nil, outs.count != want.count { bad = "\(c.name): \(outs.count) steps, want \(want.count)" }
            Self.add(d, c, bad)
        }
        d.finish(14) // macOS < 26 has no ML-DSA: the ML-DSA tracker case is excused there
    }
}
