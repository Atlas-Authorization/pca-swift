import XCTest
import Foundation
@testable import AtlasPCAVerify

/// Replay of the second half of the small public surface of core pca against the TypeScript reference (ref-core-small-surface): the cheap
/// pre-authentication checks, discharge requests, threshold assembly, decision meet, detector policy and fold, the replay guard, obligation collection,
/// discovery documents and the policy templates, builder and links.
final class RefCoreSmallSurface2Tests: XCTestCase {
    static let file = "ref-core-small-surface.json.gz"

    func tplKey(_ label: String) throws -> PCASuiteKey {
        .ed25519(try PCAEdKey(seed: Canonical.sha256(Array("atlas-pca-conformance/small/tpl/\(label)".utf8))))
    }

    func perms(_ v: JSONValue?) -> [(String, [String])]? {
        guard let o = v?.asObject else { return nil }
        return JS.keyOrder(o).map { ($0.s, o[$0]?.asArray?.compactMap { $0.asString } ?? []) }
    }

    func strMap(_ v: JSONValue?) -> [String: String]? {
        guard let o = v?.asObject else { return nil }
        return o.reduce(into: [:]) { $0[$1.key.s] = $1.value.asString }
    }

    func permsJSON(_ p: [(String, [String])]) -> JSONValue {
        PCAApprovalChannels.obj(p.map { ($0.0, .array($0.1.map { .string($0) })) })
    }

    func okOr(_ f: () throws -> JSONValue) -> JSONValue {
        do { return try f() } catch { return .object(["ok": .bool(false)]) }
    }

    func testSmallSurfaceSecondHalfAgainstTheReference() throws {
        let d = Base.Diffs()
        let fns: Set<String> = ["pcactnCheapClaims", "dischargeRequests", "assembleThreshold", "isBudgetAllocCaveat", "meetAll", "escalateThreshold",
                                "detectorReceiptShapeError", "detectorReceiptRef", "detectorPolicyError", "detectorSignal", "guardSeq", "collectObligations",
                                "verifyChainCheap", "holderPqKey", "parseDiscoveryDocument", "parseDiscoveryIntent", "acceptsSuite", "buildDiscoveryDocument",
                                "fetchDiscovery", "listTemplates", "fromTemplate", "policyBuilder", "createLink", "slotsDigest", "linkDigest", "limits",
                                "isCanonicalCompactJwsMax", "resolveReversibilityClass", "agentCaveatContext", "namedUnmetLimitReason", "catalogReversibilityScore",
                                "catalogRisk", "undoLifecycle", "undoStore"]
        let n = try Base.each(Self.file, fns) { c in
            let got: BaseGot = Base.run {
                switch c.fn {
                case "pcactnCheapClaims": return Base.optJSON(PCA.pcactnCheapClaims(c.arg(0), audience: c.arg(1)?.asString ?? "", now: JS.toNumber(c.arg(2))))
                case "dischargeRequests": return .array(PCA.dischargeRequests(grant: c.arg(0) ?? .null, chain: c.arg(1), actionDigest: c.arg(2)?.asString))
                case "assembleThreshold": return PCA.assembleThreshold(c.arg(0))
                case "isBudgetAllocCaveat": return .bool(PCA.isBudgetAllocCaveat(c.arg(0)))
                case "meetAll": return .string(PCA.meetAll((c.arg(0)?.asArray ?? []).map { $0.asString ?? "" }))
                case "escalateThreshold":
                    guard let t = c.arg(0)?.get("t")?.safeInt, let proof = c.arg(0)?.get("proof")?.asString, let min = c.arg(1)?.safeInt else { throw JSError("args") }
                    let r = Risk.escalate(Risk.Required(t: Int(t), proof: proof, optimisticAllowed: c.arg(0)?.get("optimisticAllowed") == .bool(true)), minT: Int(min))
                    return .object(["t": .int(Int64(r.t)), "proof": .string(r.proof), "optimisticAllowed": .bool(r.optimisticAllowed)])
                case "detectorReceiptShapeError": return Base.opt(PCADetectorReceipt.shapeError(c.arg(0)))
                case "detectorReceiptRef": return .string(try PCADetectorReceipt.ref(c.arg(0) ?? .null))
                case "detectorPolicyError": return Base.opt(PCADetectorReceipt.detectorPolicyError(c.arg(0)))
                case "detectorSignal": return PCADetectorReceipt.detectorSignal(c.arg(0))
                case "guardSeq":
                    let o = c.arg(0) ?? .null
                    let opts = PCAReplayGuard.Options(clockSkewMs: o.get("clockSkewMs").flatMap { IV.num($0) }, requireNonce: o.get("requireNonce") != .bool(false), counters: o.get("counters") == .bool(true))
                    let store = MemoryStateStore()
                    var out: [JSONValue] = []
                    for st in c.arg(1)?.asArray ?? [] {
                        let v = PCAReplayGuard.guardReplay(store: store, pcactn: st.get("p"), aud: o.get("aud")?.asString, now: st.get("now")?.safeInt ?? 0, options: opts)
                        out.append(v.ok ? .object(["ok": .bool(true)]) : .object(["ok": .bool(false), "code": .string(v.code ?? ""), "reason": .string(v.reason ?? "")]))
                    }
                    return .array(out)
                case "collectObligations":
                    let r = Obligations.collectObligations(c.arg(0), ctx: c.arg(1) ?? .object([:]))
                    return r.ok ? .object(["ok": .bool(true), "obligations": .array(r.obligations)]) : .object(["ok": .bool(false), "reason": .string(r.reason ?? "")])
                case "verifyChainCheap":
                    let r = PCA.verifyChainCheap(c.arg(0)?.asArray ?? [], expectedRootIssuer: c.arg(1)?.asString, allowedSuites: c.arg(2)?.asArray?.compactMap { $0.asString })
                    return r.ok ? .object(["ok": .bool(true), "pqHops": .int(Int64(r.pqHops))]) : .object(["ok": .bool(false), "reason": .string(r.reason ?? "")])
                case "holderPqKey": return Base.opt(PCA.holderPqKey(alg: c.arg(0), holder: c.arg(1)?.asString ?? "", artifactPqPk: c.arg(2)?.asString, holderPq: c.arg(3)?.asString))
                case "parseDiscoveryDocument": return try PCADiscovery.parseDiscoveryDocument(c.arg(0))
                case "parseDiscoveryIntent": return try PCADiscovery.parseDiscoveryIntent(c.arg(0))
                case "acceptsSuite": return .bool(PCADiscovery.acceptsSuite(c.arg(0), c.arg(1)?.asString ?? ""))
                case "buildDiscoveryDocument": return try PCADiscovery.buildDiscoveryDocument(c.arg(0) ?? .null)
                case "fetchDiscovery":
                    let mode = c.arg(1)?.asString ?? ""
                    var urls: [JSONValue] = []
                    let fetch: PCADiscovery.Fetch = { url, headers in
                        urls.append(.string(url + "|" + (headers["accept"] ?? "")))
                        if mode == "throw" { throw JSError("boom") }
                        let body = mode == "bad" ? JSONValue.parse("{\"nope\":1}") : JSONValue.parse("{\"audience\":\"https://rs.example\",\"pca_versions\":[2],\"signature_suites\":[\"ed25519\",\"ml-dsa-65\"],\"action_header\":\"PCA-Action\"}")
                        return PCADiscovery.Reply(ok: mode != "500", status: mode == "500" ? 500 : 200, json: body)
                    }
                    var out: [(String, JSONValue)] = []
                    do { out.append(("doc", try PCADiscovery.fetchDiscovery(c.arg(0)?.asString ?? "", fetch: fetch))) } catch { out.append(("error", .bool(true))) }
                    out.append(("urls", .array(urls)))
                    return PCAApprovalChannels.obj(out)
                case "listTemplates":
                    return .array(PCAPolicyTemplates.listTemplates().map { t in
                        var p: [(String, JSONValue)] = [("name", .string(t.name)), ("description", .string(t.description)), ("permissions", permsJSON(t.permissions))]
                        if let l = t.limits { p.append(("limits", PCAApprovalChannels.obj(l.sorted { $0.key < $1.key }.map { ($0.key, .string($0.value)) }))) }
                        if let r = t.riskPolicy { p.append(("riskPolicy", .object(r))) }
                        return PCAApprovalChannels.obj(p)
                    })
                case "fromTemplate":
                    return okOr {
                        var o = PCAPolicyTemplates.FromTemplateOptions(principal: try tplKey("p"), goal: "g", holder: try tplKey("h"), now: 1_700_000_000_000)
                        if let ov = c.arg(1), ov.isObject {
                            o.permissions = perms(ov.get("permissions")); o.limits = strMap(ov.get("limits")); o.riskPolicy = ov.get("riskPolicy")?.asObject
                            o.budgetModel = ov.get("budgetModel")?.asString
                        }
                        let h = try PCAPolicyTemplates.fromTemplate(c.arg(0)?.asString ?? "", o)
                        return PCAApprovalChannels.obj([("ok", .bool(true)), ("predicates", .array(h.policy.predicates)), ("caveats", .array(h.policy.caveats)),
                                                        ("riskPolicy", .object(h.policy.riskPolicy)), ("budgetModel", .string(h.policy.budgetModel))])
                    }
                case "policyBuilder":
                    return okOr {
                        var b = PCAPolicyTemplates.policy()
                        for op in c.arg(0)?.asArray ?? [] {
                            guard let a = op.asArray, let name = a.first?.asString else { throw JSError("op") }
                            switch name {
                            case "from": b = try PCAPolicyTemplates.PolicyBuilder.from(a[1].asString ?? "")
                            case "allow": b = b.allow(a[1].asString ?? "", (a[2].asArray ?? []).compactMap { $0.asString })
                            case "limit": b = b.limit(a[1].asString ?? "", a[2].asString ?? "")
                            default: b = b.risk(a[1].asObject ?? [:])
                            }
                        }
                        let p = try b.build()
                        var built: [(String, JSONValue)] = [("permissions", permsJSON(p.permissions)), ("limits", PCAApprovalChannels.obj(p.limits.sorted { $0.key < $1.key }.map { ($0.key, .string($0.value)) }))]
                        if let r = p.riskPolicy { built.append(("riskPolicy", .object(r))) }
                        return .object(["ok": .bool(true), "built": PCAApprovalChannels.obj(built)])
                    }
                case "createLink":
                    return okOr { .object(["ok": .bool(true), "ref": try PCA.createLink(c.arg(0) ?? .null, c.arg(1) ?? .null, bindParams: c.arg(2) == .bool(true))]) }
                case "slotsDigest": return .string(try PCA.slotsDigest(c.arg(0) ?? .null))
                case "linkDigest": return .string(try PCA.linkDigest(c.arg(0) ?? .null))
                case "limits":
                    return .object(["MAX_SLOTS": .int(Int64(PCA.MAX_SLOTS)), "MAX_SLOT_STRING": .int(Int64(PCA.MAX_SLOT_STRING)), "MAX_SLOT_SET": .int(Int64(PCA.MAX_SLOT_SET)),
                                    "TEMPLATE_KIND": .string(PCA.TEMPLATE_KIND), "TIGHTEN_KIND": .string(PCA.TIGHTEN_KIND)])
                case "isCanonicalCompactJwsMax": return .bool(Jose.isCanonicalCompactJws(c.arg(0), parts: 3, maxBytes: 40))
                case "resolveReversibilityClass":
                    return Base.opt(PCA.resolveReversibilityClass(c.arg(0), plan: c.arg(1)?.asArray, nodeId: c.arg(2)?.asString))
                case "agentCaveatContext": return PCA.agentCaveatContext(c.arg(0), c.arg(1))
                case "namedUnmetLimitReason": return Base.opt(PCA.namedUnmetLimitReason(c.arg(0), c.arg(1)))
                case "catalogReversibilityScore":
                    return .object(PCA.CATALOG_REVERSIBILITY_SCORE.reduce(into: JObject()) { $0[JKey($1.key)] = PCARiskBudgets.num($1.value) })
                case "catalogRisk":
                    return PCA.catalogRisk(verb: c.arg(0)?.asString ?? "", params: c.arg(1), grant: c.arg(2) ?? .null, taint: IV.num(c.arg(3)))
                case "undoLifecycle":
                    let key = try PCAEdKey(seed: Canonical.sha256(Array("atlas-pca-conformance/small/undo/service".utf8)))
                    guard let rec = c.arg(0) else { throw JSError("record") }
                    var cur = try Undo.withReceipt(rec, event: "opened", note: "", at: rec.get("opened_at")?.safeInt ?? 0, key: key)
                    var out: [JSONValue] = [cur]
                    for st in c.arg(1)?.asArray ?? [] {
                        guard let a = st.asArray, a.count == 2 else { throw JSError("step") }
                        let t = Undo.transition(cur, a[0], now: JS.toNumber(a[1]))
                        if t.outcome == "applied", let next = t.record {
                            cur = try Undo.withReceipt(next, event: t.event ?? "", note: t.note ?? "", at: a[1].safeInt ?? 0, key: key)
                            out.append(.object(["applied": a[0].get("kind") ?? .null, "record": cur]))
                        } else { out.append(.object([JKey(t.outcome): t.code.map { .string($0) } ?? .null])) }
                    }
                    out.append(.object(["chain": Base.opt(Undo.receiptChainError(cur, expectedSigner: key.id))]))
                    return .array(out)
                case "undoStore":
                    let store: UndoStore = c.arg(0)?.asString == "memory" ? MemoryUndoStore() : KvUndoStore(MemoryAtomicKV(), durable: true)
                    var out: [JSONValue] = []
                    for op in c.arg(1)?.asArray ?? [] {
                        guard let a = op.asArray, let name = a.first?.asString else { throw JSError("op") }
                        do {
                            switch name {
                            case "create":
                                let r = try store.create(a[1])
                                out.append(r.created ? .object(["created": .bool(true)]) : .object(["created": .bool(false), "record": r.record ?? .null]))
                            case "get": out.append(try store.get(a[1].asString ?? "") ?? .null)
                            case "replace": out.append(.bool(try store.replace(a[1].asString ?? "", expectedVer: a[2].safeInt ?? 0, next: a[3])))
                            default:
                                let q = a[1]
                                out.append(.array(try store.list(UndoQuery(state: q.get("state")?.asString ?? "", windowEndedBy: q.get("windowEndedBy")?.safeInt, grantRef: q.get("grantRef")?.asString,
                                                                           bondRef: q.get("bondRef")?.asString, limit: q.get("limit")?.safeInt.map { Int($0) }))))
                            }
                        } catch let e as UndoError { out.append(.object(["error": .string(e.code)])) }
                    }
                    return .array(out)
                default: throw JSError("unhandled \(c.fn)")
                }
            }
            d.add(c, Base.diff(c, got))
        }
        XCTAssertGreaterThan(n, 400)
        d.finish(400)
    }
}

extension Base {
    /// A nullable JSON value as the reference writes it (nil is null).
    static func optJSON(_ v: JSONValue?) -> JSONValue { v ?? .null }
}
