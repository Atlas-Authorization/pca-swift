import XCTest
import Foundation
#if canImport(CryptoKit)
import CryptoKit
#else
import Crypto
#endif
@testable import AtlasPCAVerify

/// Action-kit conformance: every vector of the shared action corpus (monorepo: packages/pca-conformance/vectors/actions; mirrors vendor it at
/// <conformance>/actions) must reproduce its `expect` exactly through `Actions` and the v2 `conformAction`. No skips, no vector left unread.
final class ActionsVectorTests: XCTestCase {
    static let dir: URL = {
        let vendored = ConformanceTests.conformanceDir.appendingPathComponent("actions", isDirectory: true)
        if FileManager.default.fileExists(atPath: vendored.path) { return vendored }
        return ConformanceTests.conformanceDir.deletingLastPathComponent().deletingLastPathComponent().deletingLastPathComponent()
            .appendingPathComponent("packages/pca-conformance/vectors/actions", isDirectory: true)
    }()

    static func cases() throws -> [JSONValue] {
        let names = try FileManager.default.contentsOfDirectory(atPath: dir.path).filter { $0.hasSuffix(".json") }.sorted()
        return try names.map { try ConformanceTests.loadText(ConformanceTests.readText(dir.appendingPathComponent($0))) }
    }

    static func codeOf(_ e: String?) -> JSONValue {
        guard let e = e else { return .object(["ok": .bool(true)]) }
        let code = e.split(separator: ":", maxSplits: 1, omittingEmptySubsequences: false)[0].split(separator: " ", maxSplits: 1, omittingEmptySubsequences: false)[0]
        return .object(["ok": .bool(false), "code": .string(String(code))])
    }

    static func profile(_ p: Profile) -> JSONValue { p.json }

    static func registry(_ i: JSONValue) throws -> TraitRegistry {
        if case let .array(c)? = i.get("custom_traits"), !c.isEmpty { return try Actions.extendRegistry(Actions.coreRegistry, c) }
        return Actions.coreRegistry
    }

    static func replay(_ c: JSONValue) throws -> JSONValue {
        let i = c.get("input")!
        switch c.get("kind")!.asString! {
        case "parse": return .object(["ok": .bool(Actions.validateDef(i.get("def")!) == nil)])
        case "digest":
            let d = i.get("def")!.asObject!
            return .object(["digest": .string(Actions.defDigest(d)), "normalized": .object(Actions.normalize(d))])
        case "effective":
            let e = try Actions.effective(i.get("def")!.asObject!, Actions.coreRegistry, i.get("pins"))
            return .object(["confirmed": .bool(e.confirmed), "traits": .array(e.traits.map { .string($0) }), "closure": .array(e.closure.map { .string($0) }), "eff": e.eff.json])
        case "expand":
            do {
                let reg = try registry(i)
                let ids = Actions.strings(i.get("traits"))!
                return .object(["closure": .array(try Actions.closure(reg, ids).map { .string($0) }), "floor": try Actions.floorOf(reg, ids).json])
            } catch is ActionKitError { return .object(["error": .bool(true)]) }
        case "schema_verb":
            do { return codeOf(Actions.schemaVerbFloorError(i.get("verb")!.asObject!, try registry(i), i.get("pins"))) } catch is ActionKitError { return .object(["error": .bool(true)]) }
        case "floor":
            let g = i.get("grant")!
            return .object(["decision": .string(Actions.floorDecision(
                grantCaveats: Actions.strings(g.get("caveats"))!, maxEsc: Int(IV.int(g.get("max_esc"))!), preauthEsc: Int(IV.int(g.get("preauth_esc"))!),
                callContext: Actions.strings(i.get("call")!.get("context"))!, rho: Profile(json: i.get("profile"))!))])
        case "conform":
            let r = ActionSchema.conform(i.get("schema")!, verb: i.get("verb")!.asString!, params: i.get("params")!)
            return r.ok ? .object(["ok": .bool(true)]) : .object(["ok": .bool(false), "code": .string(r.code)])
        case "pack":
            let ds = Actions.strings(i.get("digests"))!
            let idx = Int(IV.int(i.get("index"))!)
            return .object(["root": .string(try Actions.packRoot(ds)), "proof": try Actions.packProof(ds, ds[idx])])
        case "rule22_schema": return codeOf(Actions.rule22Code(Actions.schemaFloorError(i.get("doc")!.asObject!, i.get("pins"))))
        case "rule22":
            if let code = Actions.rule22Code(Actions.schemaFloorError(i.get("doc")!.asObject!, i.get("pins"))) { return .object(["integrity": .string(code), "decision": .string("deny")]) }
            let g = i.get("grant")!
            return .object(["integrity": .string("ok"), "decision": .string(Actions.rule22Decide(
                doc: i.get("doc")!, verb: i.get("verb")!.asString!, grantCaveats: Actions.strings(g.get("caveats"))!,
                maxEsc: Int(IV.int(g.get("max_esc"))!), preauthEsc: Int(IV.int(g.get("preauth_esc"))!), context: Actions.strings(i.get("context"))!))])
        case "schema_shape": return .object(["ok": .bool(ActionSchema.shapeError(i.get("doc")!, signed: false) == nil)])
        case "pack_verify":
            let v = Actions.verifyPack(i.get("pack"), keys: i.get("keys"), shards: i.get("shards")?.asObject ?? [:])
            return v.ok ? .object(["ok": .bool(true), "digest": .string(v.digest), "defs": .int(Int64(v.defs.count))]) : .object(["ok": .bool(false)])
        case "evolution_verify":
            let r = i.get("record")
            return .object(["ok": .bool(Actions.verifyEvolutionRecord(r, i.get("keys"))), "diff": Actions.evolutionDiffDigest(r).map { .string($0) } ?? .null])
        case "reapproval_verify":
            let g = i.get("grant")!
            return .object(["ok": .bool(Actions.reapprovalValid(i.get("reapproval"), grantId: g.get("id")!.asString!, issuer: g.get("issuer")!.asString!,
                                                                verb: i.get("verb")!.asString!, diff: i.get("diff")!.asString!))])
        case "pin":
            let g = i.get("grant")!
            let d = Actions.decidePin(pin: i.get("pin"), doc: i.get("doc"), verb: i.get("verb")!.asString!, records: i.get("records")?.asArray ?? [], keys: i.get("keys"),
                                      reapprovals: i.get("reapprovals")?.asArray ?? [], grantId: g.get("id")!.asString!, issuer: g.get("issuer")!.asString!)
            if d.ok { return .object(["ok": .bool(true), "via": .string(d.via!)]) }
            var o: JObject = ["ok": .bool(false), "code": .string(d.code!), "escalate": .bool(d.escalate)]
            if let n = d.needsReapproval { o["needs_reapproval"] = .string(n) }
            return .object(o)
        case "pack_proof_verify":
            return .object(["ok": .bool(Actions.verifyPackProof(root: i.get("root")!.asString!, proof: i.get("proof")!, digest: i.get("digest")!.asString!))])
        case "tracker":
            let t = Actions.PackTracker(keys: i.get("keys"))
            return .array(i.get("steps")!.asArray!.map { st in
                let r = t.accept(st.get("pack")!, shards: st.get("shards")?.asObject ?? [:])
                return r.ok ? .object(["ok": .bool(true), "status": .string(r.value)]) : .object(["ok": .bool(false), "code": .string(r.value)])
            })
        case "approval_render":
            do {
                let r = try Approval.render(def: i.get("def")!.asObject!, params: i.get("params")!, confirmed: i.get("confirmed") == .bool(true))
                let d = Approval.renderDigest(r)!
                return .object(["ok": .bool(true), "render": r, "digest": .string(d), "words": .string(Approval.bindingWords(d)!)])
            } catch let e as ActionKitError { return .object(["ok": .bool(false), "code": .string(e.code)]) }
        case "approval_digest":
            if Approval.renderShapeError(i.get("render")) != nil { return .object(["ok": .bool(false)]) }
            return .object(["ok": .bool(true), "digest": .string(Approval.renderDigest(i.get("render")!)!)])
        case "approval_challenge":
            guard let a = i.get("action_digest")?.asString, let r = i.get("render_digest")?.asString, let c = Approval.challenge(actionDigest: a, renderDigest: r) else { return .object(["ok": .bool(false)]) }
            return .object(["ok": .bool(true), "challenge": .string(c)])
        case "approval_escalation":
            let b = i.get("bind")!
            let bind = EscalationBinding(policyDigest: b.get("policy_digest")!.asString!, actionDigest: b.get("action_digest")!.asString!, historyHead: b.get("history_head")!.asString!, renderDigest: b.get("render_digest")?.asString)
            let pins = i.get("principals")!.asArray!.map { PinnedSigner($0.asString!) }
            let v = PCA.verifyEscalationAnswer(i.get("answer"), principals: pins, bind: bind, now: IV.int(i.get("now"))!)
            return v.ok ? .object(["ok": .bool(true), "decision": .string(v.decision)]) : .object(["ok": .bool(false), "reason": .string(v.reason)])
        default:
            XCTFail("unknown vector kind"); return .null
        }
    }

    static func replayProfile(_ c: JSONValue) -> JSONValue {
        let i = c.get("input")!
        do {
            switch c.get("kind")!.asString! {
            case "approval_psd2": return .object(["ok": .bool(true), "linking": try Approval.psd2Linking(i.get("render")!)])
            case "approval_batch":
                let b = try Approval.batch(i.get("items")!.asArray!)
                return .object(["ok": .bool(true), "batch": b.get("batch")!, "action_digest": b.get("action_digest")!, "render_digest": b.get("render_digest")!, "challenge": b.get("challenge")!, "words": b.get("words")!])
            default:
                XCTFail("unknown approval profile vector kind"); return .null
            }
        } catch let e as ActionKitError { return .object(["ok": .bool(false), "code": .string(e.code)]) }
        catch { return .null }
    }

    func testApprovalProfileVectorsReplay() throws {
        var dir = ConformanceTests.conformanceDir.appendingPathComponent("approval-profiles", isDirectory: true)
        if !FileManager.default.fileExists(atPath: dir.path) {
            dir = ConformanceTests.conformanceDir.deletingLastPathComponent().deletingLastPathComponent().deletingLastPathComponent()
                .appendingPathComponent("packages/pca-conformance/vectors/approval-profiles", isDirectory: true)
        }
        let names = try FileManager.default.contentsOfDirectory(atPath: dir.path).filter { $0.hasSuffix(".json") }.sorted()
        XCTAssertGreaterThanOrEqual(names.count, 12)
        for n in names {
            let c = try ConformanceTests.loadText(ConformanceTests.readText(dir.appendingPathComponent(n)))
            XCTAssertEqual(Self.replayProfile(c), c.get("expect"), c.get("id")?.asString ?? n)
        }
    }

    func testEveryVectorReplays() throws {
        let cs = try Self.cases()
        XCTAssertGreaterThanOrEqual(cs.count, 781)
        var kinds: [String: Int] = [:]
        for c in cs {
            let kind = c.get("kind")!.asString!
            kinds[kind, default: 0] += 1
            XCTAssertEqual(try Self.replay(c), c.get("expect"), c.get("id")?.asString ?? "?")
        }
        for k in ["parse", "digest", "effective", "expand", "floor", "conform", "pack", "schema_verb", "rule22", "rule22_schema", "pack_verify", "evolution_verify", "reapproval_verify", "pin", "pack_proof_verify", "tracker", "schema_shape", "approval_render", "approval_digest", "approval_challenge", "approval_escalation"] { XCTAssertGreaterThanOrEqual(kinds[k] ?? 0, 8, k) }
    }

    func testPinnedDigests() {
        XCTAssertEqual(Actions.traitsDigest(Actions.coreRegistry), "W2xe4TXZKavAeEpzGVYC8pp-ZhOxDv-_3TF76MveweM")
        XCTAssertEqual(Actions.tablesDigest(), "I7nxRoiVhU18WNY_EaUqegG7KeBYtfP8gMmibsfXJtU")
        XCTAssertEqual(Actions.coreRegistry.traits.count, 22)
    }

    func testPackProofVerifiesAndTamperFails() throws {
        let c = try Self.cases().first { $0.get("id")?.asString == "pack-builtin" }!
        let ds = Actions.strings(c.get("input")!.get("digests"))!
        let root = c.get("expect")!.get("root")!.asString!
        for d in ds { XCTAssertTrue(Actions.verifyPackProof(root: root, proof: try Actions.packProof(ds, d), digest: d)) }
        XCTAssertFalse(Actions.verifyPackProof(root: root, proof: try Actions.packProof(ds, ds[0]), digest: ds[1]))
        XCTAssertThrowsError(try Actions.packRoot([ds[0], ds[0]]))
        XCTAssertThrowsError(try Actions.packRoot([]))
    }

    func testWholeDocumentRule22() throws {
        let c = try Self.cases().first { $0.get("id")?.asString == "schema-verb-adv-honest" }!
        var doc: JObject = ["verbs": .array([c.get("input")!.get("verb")!])]
        XCTAssertNil(Actions.schemaFloorError(doc))
        doc["traits_digest"] = .string(String(repeating: "A", count: 43))
        XCTAssertTrue(Actions.schemaFloorError(doc)!.hasPrefix("traits_digest_mismatch"))
    }

    /// Differential oracle (kill-test style): closure by naive fixed-point iteration agrees with the DFS closure for the 22 core traits,
    /// and FloorDecision is antitone in the profile (a larger profile never decides more permissively).
    func testClosureOracleAndFloorAntitone() throws {
        let reg = Actions.coreRegistry
        let ids = reg.traits.keys.map { $0.s }.sorted()
        for a in ids {
            var s: Set<String> = [a]
            while true {
                let n = s.union(s.flatMap { reg.traits[JKey($0)]!.implies })
                if n == s { break }
                s = n
            }
            XCTAssertEqual(try Actions.closure(reg, [a]), s.sorted(), a)
        }
        let rank = ["deny": 0, "escalate": 1, "allow": 2]
        for a in ids { for b in ids {
            let pa = reg.traits[JKey(a)]!.floor, pb = Actions.join(pa, reg.traits[JKey(b)]!.floor)
            let da = Actions.floorDecision(grantCaveats: ["amount_cap"], maxEsc: 2, preauthEsc: 1, callContext: ["idempotency"], rho: pa)
            let db = Actions.floorDecision(grantCaveats: ["amount_cap"], maxEsc: 2, preauthEsc: 1, callContext: ["idempotency"], rho: pb)
            XCTAssertLessThanOrEqual(rank[db]!, rank[da]!, "\(a) \(b)")
        } }
    }

    /// Verb-level confirmation end to end: a pinned reviewer's signature counts; a wrong role, a tampered digest, a missing pin or a forged signature do not.
    func testVerbConfirmation() throws {
        let k = Curve25519.Signing.PrivateKey()
        let pk = Base64URLStrict.encode(Array(k.publicKey.rawRepresentation))
        func pins(_ roles: [String]) -> JSONValue {
            .object(["keys": .array([.object(["kid": .string("rev"), "pk": .string(pk), "roles": .array(roles.map { .string($0) })])])])
        }
        let reg = Actions.coreRegistry
        let def = Base64URLStrict.encode([UInt8](repeating: 3, count: 32))
        let base: JObject = ["verb": .string("v"), "def": .string(def), "traits": .array([.string("pca.bulk")])]
        var att: JObject = ["def_digest": .string(def), "traits_digest": .string(Actions.traitsDigest(reg)), "facts_digest": .string(Actions.factsDigest(base)), "final_traits": .array([.string("pca.bulk")]),
                            "dismissed": .array([]), "reviewer_kid": .string("rev"), "ts": .int(5)]
        att["sig"] = .string(Base64URLStrict.encode(Array(try k.signature(for: Data(Actions.reviewMessage(att)!)))))
        let verb = base.merging(["confirmation": .object(att)]) { $1 }
        XCTAssertTrue(Actions.verbConfirmed(verb, reg, pins(["reviewer"])))
        XCTAssertFalse(Actions.verbConfirmed(verb, reg, nil))
        XCTAssertFalse(Actions.verbConfirmed(verb, reg, pins(["publisher"])))
        XCTAssertFalse(Actions.verbConfirmed(verb, reg, pins(["reviewer", "importer"])))
        XCTAssertFalse(Actions.verbConfirmed(verb.merging(["def": .string(String(def.dropLast()) + "A")]) { $1 }, reg, pins(["reviewer"])))
        XCTAssertFalse(Actions.verbConfirmed(verb.merging(["traits": .array([])]) { $1 }, reg, pins(["reviewer"])))
        XCTAssertFalse(Actions.verbConfirmed(verb.merging(["verb": .string("w")]) { $1 }, reg, pins(["reviewer"]))) // another fact
        var forged = att
        forged["ts"] = .int(6)
        XCTAssertFalse(Actions.verbConfirmed(verb.merging(["confirmation": .object(forged)]) { $1 }, reg, pins(["reviewer"])))
        XCTAssertNotNil(Actions.reviewerPinsError(.object(["keys": .array([.object(["kid": .string(""), "pk": .string(pk), "roles": .array([.string("reviewer")])])])])))
    }
}
