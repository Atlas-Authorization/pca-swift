import XCTest
import Foundation
@testable import AtlasPCAVerify

/// Differential replay of the pca-grants scenarios (decision log and batches, replay audit, shadow rollout, list-authorized, the grant service and its
/// HTTP binding, leases and their routes, blueprint group kill and admissions) against the TypeScript reference. A thrown step is `{$err: code}`.
final class RefGrantsScenarioTests: XCTestCase {
    static let file = "ref-grants.json.gz"
    static let T0: Int64 = 1_800_000_000_000

    static func key(_ label: String) throws -> PCAEdKey { try RefGrantsTests.key(.string(label)) }
    static func pub(_ label: String) throws -> String { try key(label).id }
    static func obj(_ v: JSONValue?) throws -> JObject { try RefGrantsTests.obj(v) }
    static func int(_ v: JSONValue?) -> Int64 { IV.safe(v).map { Int64($0) } ?? 0 }
    static func err(_ e: Error) -> JSONValue {
        if let g = e as? GrantResource.GrantError { return .object(["$err": .string(g.code)]) }
        if let l = e as? ListAuthorized.ListError { return .object(["$err": .string(l.code)]) }
        return .object(["$err": .string("x")])
    }

    /// "$key:LABEL" strings and {"$sign": {kind, label, fields}} objects, recursively.
    static func resolve(_ v: JSONValue) throws -> JSONValue {
        switch v {
        case let .string(s): return s.hasPrefix("$key:") ? .string(try pub(String(s.dropFirst(5)))) : v
        case let .array(a): return .array(try a.map(resolve))
        case let .object(o):
            if let sg = o["$sign"]?.asObject {
                let k = try key(sg["label"]?.asString ?? ""), f = try obj(try resolve(sg["fields"] ?? .null))
                switch sg["kind"]?.asString ?? "" {
                case "lease": return try PCAGrants.signLease(k, f)
                case "leaseOver": return try PCAGrants.signLeaseUnsafeOverCap(k, f)
                case "revocation": return try PCAGrants.signLeaseRevocation(k, f)
                case "blueprint": return try PCAGrants.signBlueprint(k, f)
                case "breakglass": return try PCAGrants.signBreakGlass(k, f)
                case "review": return try PCAGrants.signBreakGlassReview(k, f)
                default: throw JSError("bad kind")
                }
            }
            var out: JObject = [:]
            for (k, x) in o { out[k] = try resolve(x) }
            return .object(out)
        default: return v
        }
    }

    func replay(_ fn: String, min: Int, _ body: @escaping (BaseCase) throws -> JSONValue) throws {
        let d = Base.Diffs()
        let n = try Base.each(Self.file, [fn]) { c in d.add(c, Base.diff(c, Base.run { try body(c) })) }
        XCTAssertGreaterThanOrEqual(n, min, fn)
        d.finish(min)
    }

    // ---- decision log, batches, replay audit ----

    func testLogScenario() throws {
        try replay("logScenario", min: 7) { c in
            let spec = try Self.obj(c.arg(0))
            let k = try Self.key(spec["label"]?.asString ?? "")
            let log = PCAGrants.DecisionLog(k, maskClasses: (spec["mask"]?.asArray ?? []).compactMap { $0.asString })
            let recs = try (spec["records"]?.asArray ?? []).map { try log.append(try Self.obj($0)) }
            let now = Self.int(spec["now"])
            let head = try log.head(now)
            var out: JObject = ["recs": .array(recs), "head": head, "size": .int(Int64(log.size))]
            var proofs: [JSONValue] = [], incl: [JSONValue] = [], batches: [JSONValue] = []
            let pi = spec["proofs"]?.asArray ?? []
            for i in pi { proofs.append((try? log.proof(Int(Self.int(i)))) ?? .object(["$err": .bool(true)])) }
            for (j, i) in pi.enumerated() {
                if proofs[j].get("$err") != nil { incl.append(.object(["$err": .bool(true)])); continue }
                incl.append(.bool(K3.verifyRecordInclusion(recs[Int(Self.int(i))], proof: proofs[j], head: head, signer: k.id)))
            }
            func verdict(_ v: K3.BatchVerdict) -> JSONValue {
                v.ok ? .object(["ok": .bool(true), "next": .int(v.next), "lastCommit": .string(v.lastCommit)]) : .object(["ok": .bool(false), "reason": .string(v.reason)])
            }
            for bo in spec["batches"]?.asArray ?? [] {
                let b = try Self.obj(bo)
                do {
                    let bt = try PCAGrants.nextBatch(log, from: b["from"], max: b["max"], now: spec["now"])
                    let from = Self.int(b["from"])
                    let last = try from == 0 ? "" : PCAGrants.recordCommit(recs[Int(from) - 1])
                    var tampered = bt
                    if var recsB = bt.get("records")?.asArray, !recsB.isEmpty, var first = recsB[0].asObject {
                        first["at"] = .int(1)
                        recsB[0] = .object(first)
                        var t = try Self.obj(bt)
                        t["records"] = .array(recsB)
                        tampered = .object(t)
                    }
                    let st: JSONValue = .object(["next": .int(from), "lastCommit": .string(last)])
                    batches.append(.object(["bt": bt, "verdict": verdict(K3.verifyBatch(bt, state: st, signer: k.id)),
                                            "tampered": verdict(K3.verifyBatch(tampered, state: st, signer: k.id)),
                                            "wrong": verdict(K3.verifyBatch(bt, state: st, signer: try Self.pub("zz")))]))
                } catch { batches.append(.object(["$err": .bool(true)])) }
            }
            out["proofs"] = .array(proofs)
            out["incl"] = .array(incl)
            out["batches"] = .array(batches)
            return .object(out)
        }
    }

    func testReplayScenario() throws {
        try replay("replayScenario", min: 5) { c in
            let spec = try Self.obj(c.arg(0))
            func table(_ t: JSONValue?) -> (JSONValue) -> String? { { i in i.asString.flatMap { t?.get($0)?.asString } } }
            let revT = spec["revT"]
            let diff = PCAGrants.semanticDiff(spec["cases"]?.asArray ?? [], old: table(spec["oldT"]), new: table(spec["newT"]))
            let audit = PCAGrants.auditReplay(spec["records"]?.asArray ?? [], spec["cases"]?.asArray ?? []) { input, rev in
                revT?.get(JS.toString(input) + "@" + JS.toString(rev))?.asString
            }
            return .object(["diff": .array(diff), "audit": .array(audit)])
        }
    }

    // ---- shadow ----

    func testShadowScenario() throws {
        try replay("shadowScenario", min: 51) { c in
            let spec = try Self.obj(c.arg(0))
            let log = Shadow.ShadowLog(try Self.key(spec["label"]?.asString ?? ""))
            func fn(_ t: JSONValue?) -> (JSONValue) throws -> String? {
                { i in
                    let d = i.asString.flatMap { t?.get($0)?.asString }
                    if d == "throw" { throw JSError("boom") }
                    return d == "junk" ? "weird" : d
                }
            }
            let cands = (spec["cands"]?.asArray ?? []).map { Shadow.Candidate(digest: $0.get("digest")?.asString ?? "", decide: fn($0.get("T"))) }
            var runs: [JSONValue] = []
            for ob in spec["obs"]?.asArray ?? [] {
                let run = try Shadow.runShadow(ob.get("input") ?? .null, enforced: fn(spec["enforcedT"]), candidates: cands)
                var r: JObject = ["shadow": .array(run.shadow.map { $0.json })]
                if let d = run.decision { r["decision"] = .string(d) }
                runs.append(.object(r))
                for oc in run.shadow {
                    try log.observe(enforcedDigest: spec["enforcedDigest"]?.asString ?? "", actionDigest: ob.get("action_digest")?.asString ?? "", enforced: run.decision, outcome: oc, at: Self.int(ob.get("at")))
                }
            }
            var stats: JObject = [:], diffsOut: JObject = [:]
            var flat: [JObject] = []
            for co in spec["cands"]?.asArray ?? [] {
                let d = co.get("digest")?.asString ?? ""
                stats[JKey(d)] = log.stats(d).json
                let ds = log.diffs(d)
                diffsOut[JKey(d)] = .array(ds.map { .object($0) })
                flat.append(contentsOf: ds)
            }
            let zz = try Self.pub("zz")
            let verify: [JSONValue] = flat.map { d in
                var badSig = d, badAt = d
                badSig["sig"] = .string(String((d["sig"]?.asString ?? "").dropFirst()) + "A")
                badAt["at"] = .int((d["at"]?.safeInt ?? 0) + 1)
                return .array([Shadow.verifyShadowDiff(.object(d), signer: log.signer), Shadow.verifyShadowDiff(.object(d)), Shadow.verifyShadowDiff(.object(d), signer: zz),
                               Shadow.verifyShadowDiff(.object(badSig), signer: log.signer), Shadow.verifyShadowDiff(.object(badAt))].map { .bool($0) })
            }
            var out: JObject = ["runs": .array(runs), "diffs": .object(diffsOut), "stats": .object(stats), "verify": .array(verify), "signer": .string(log.signer)]
            if let g = spec["gate"]?.asObject {
                let principals: [JSONValue] = try (g["principals"]?.asArray ?? []).map { .string(try Self.pub($0.asString ?? "")) }
                let explanations: [JSONValue] = try (g["explain"]?.asArray ?? []).map { e in
                    try Shadow.signWideningExplanation(try Self.key(e.get("label")?.asString ?? ""), ["shadow_digest": e.get("shadow_digest") ?? .null, "action_digest": e.get("action_digest") ?? .null,
                                                                                                          "reason_digest": e.get("reason_digest") ?? .null])
                }
                var approval: JSONValue?
                if let ap = g["approval"], !ap.isNull {
                    approval = try Shadow.signPromotionApproval(try Self.key(ap.get("label")?.asString ?? ""), ["shadow_digest": ap.get("shadow_digest") ?? .null,
                                                                                                                "enforced_digest": ap.get("enforced_digest") ?? .null, "at": ap.get("at") ?? .null])
                }
                out["explanations"] = .array(explanations)
                out["approval"] = approval ?? .null
                var opts = g["options"]?.asObject ?? [:]
                if opts["principals"] == nil || opts["principals"] == .null { opts["principals"] = .array(principals) }
                if opts["explanations"] == nil || opts["explanations"] == .null { opts["explanations"] = .array(explanations) }
                if let a = approval { opts["approval"] = a }
                let gate = Shadow.promotionGate(log, opts)
                out["gate"] = .object(gate)
                if let pr = spec["promote"]?.asObject {
                    do {
                        let used: JObject = pr["useGate"] == .bool(false) ? ["ok": .bool(false), "code": .string("bad_input"), "reason": .string("x")] : gate
                        out["promoted"] = .object(try Shadow.promoteShadow(try Self.obj(pr["enforced"]), try Self.obj(pr["candidate"]), used, now: pr["now"]))
                    } catch { out["promoted"] = .object(["$err": .bool(true)]) }
                }
            }
            return .object(out)
        }
    }

    // ---- list-authorized ----

    func testWindowAccumulator() throws {
        try replay("windowAcc", min: 2) { c in
            let acc = ListAuthorized.WindowReadAccumulator(cap: Self.int(c.arg(0)), windowMs: Self.int(c.arg(1)))
            return .array((c.arg(2)?.asArray ?? []).map { o in .bool(acc.charge(o.get("key")?.asString ?? "", Self.int(o.get("units")), Self.int(o.get("now")))) })
        }
    }

    final class Rel: ListAuthorized.RelationSource {
        let allowed: Set<String>
        let useList: Bool
        let page: (String?, Int) -> ListAuthorized.CandidatePage
        init(allowed: Set<String>, useList: Bool, page: @escaping (String?, Int) -> ListAuthorized.CandidatePage) { self.allowed = allowed; self.useList = useList; self.page = page }
        func check(_ subject: String, _ relation: String, _ obj: String) -> Bool { allowed.contains(obj) }
        var supportsListObjects: Bool { useList }
        func listObjects(_ subject: String, _ relation: String, _ type: String, _ cursor: String?, _ limit: Int) -> ListAuthorized.CandidatePage { page(cursor, limit) }
    }

    func testListScenario() throws {
        try replay("listScenario", min: 28) { c in
            let spec = try Self.obj(c.arg(0))
            let acc = ListAuthorized.WindowReadAccumulator(cap: Self.int(spec["cap"]), windowMs: Self.int(spec["windowMs"]))
            let universe = (spec["universe"]?.asArray ?? []).compactMap { $0.asString }
            func pageOf(_ list: [String], _ cursor: String?, _ limit: Int) -> ListAuthorized.CandidatePage {
                let idx = cursor.flatMap { Int(IV.jsNumber($0).isFinite ? IV.jsNumber($0) : 0) } ?? 0
                let end = Swift.min(idx + limit + (spec["overfetch"] == .bool(true) ? 3 : 0), list.count)
                let objects = idx >= list.count ? [] : Array(list[idx..<end])
                let next: String? = idx + limit < list.count ? String(idx + limit) : spec["emptyNext"] == .bool(true) ? "" : nil
                return ListAuthorized.CandidatePage(objects: objects, next: next)
            }
            let relSpec = spec["relation"]?.asObject
            let listed = relSpec?["listed"]?.asArray.map { $0.compactMap { $0.asString } } ?? universe
            let rel = Rel(allowed: Set((relSpec?["allowed"]?.asArray ?? []).compactMap { $0.asString }), useList: relSpec?["useList"] == .bool(true)) { cur, lim in pageOf(listed, cur, lim) }
            let permitted: Set<String>? = spec["permitted"]?.asArray.map { Set($0.compactMap { $0.asString }) }
            let tamper = spec["tamper"]?.asObject
            var out: [JSONValue] = []
            var cursor: String?
            var p: Int64 = 0
            while p < Self.int(spec["pages"]) {
                let t: JObject? = (tamper != nil && p == Self.int(tamper?["page"])) ? tamper : nil
                do {
                    let cands: ListAuthorized.CandidateSource
                    if relSpec?["asCandidates"] == .bool(true) {
                        cands = try ListAuthorized.candidatesFromRelation(rel, subject: spec["subject"]?.asString ?? "", relation: relSpec?["name"]?.asString ?? "")
                    } else {
                        cands = { _, cur, lim in pageOf(universe, cur, lim) }
                    }
                    let useCursor = t?["dropCursor"] != .bool(true) && cursor != nil
                    var cur: String?
                    if useCursor { cur = t?["cursor"] != nil ? t?["cursor"]?.asString : cursor }
                    let args = ListAuthorized.Args(
                        subject: t?["subject"]?.asString ?? spec["subject"]?.asString ?? "", resourceType: spec["type"]?.asString ?? "",
                        permits: { x in permitted == nil || permitted!.contains(x) }, candidates: cands,
                        filterId: t?["filterId"]?.asString ?? spec["filterId"]?.asString ?? "", policyDigest: spec["policyDigest"]?.asString ?? "",
                        freshAtDigest: spec["freshAt"]?.asString ?? "", limit: t?["limit"] != nil ? Self.int(t?["limit"]) : Self.int(spec["limit"]), reads: acc,
                        now: Self.T0 + p * (spec["nowStep"] != nil ? Self.int(spec["nowStep"]) : 1),
                        signingSecret: try Self.key(t?["label"]?.asString ?? spec["label"]?.asString ?? ""),
                        relationSource: relSpec != nil ? rel : nil,
                        relation: relSpec != nil ? (t?["relation"]?.asString ?? relSpec?["name"]?.asString) : nil,
                        cursor: cur, maxScan: spec["maxScan"] != nil ? Self.int(spec["maxScan"]) : nil)
                    let r = try ListAuthorized.listAuthorized(args)
                    out.append(r.json)
                    cursor = r.nextCursor
                } catch {
                    out.append(Self.err(error))
                    if t == nil { break }
                }
                p += 1
            }
            return .array(out)
        }
    }

    // ---- grant management ----

    func testGrantScenario() throws {
        try replay("grantScenario", min: 14) { c in
            let spec = try Self.obj(c.arg(0))
            let store = GrantResource.MemoryGrantStore()
            var events: [JSONValue] = []
            var gc = 0, nc = 0
            var o = GrantResource.Options(store: store, now: { Self.T0 }, newId: { k in
                if k == "grant" { gc += 1; return "g_\(gc)" }
                nc += 1
                return "n_\(nc)"
            })
            if spec["providers"] == .bool(true) {
                o.usage = { g in .object(["rev": g["rev"] ?? .null]) }
                o.remainingBudget = { _ in .object(["left": .int(5)]) }
                o.residual = { g in .object(["id": g["id"] ?? .null]) }
            }
            if spec["stepUp"] == .bool(true) { o.verifyStepUp = { ref, _ in ref == "ok-step" } }
            o.onRevoke = { ids, scope, root in events.append(.object(["revoked": .array(ids.map { .string($0) }), "scope": .string(scope), "root": root["id"] ?? .null])) }
            o.onChange = { kind, g in events.append(.object(["change": .string(kind), "id": g["id"] ?? .null, "rev": g["rev"] ?? .null])) }
            if spec["validateNeed"] == .bool(true) { o.validateNeed = { nd in nd["verb"]?.asString == "forbidden" ? "verb not allowed" : nil } }
            let svc = GrantResource.GrantService(o)
            var caller: GrantHttp.Caller?
            let handler = GrantHttp.grantResourceHandler(svc) { _ in caller }
            func sec(_ by: String) throws -> PCAEdKey { try Self.key(by == "principal" ? "$P" : by == "holder" ? "$A" : "$X") }
            var out: [JSONValue] = []
            for raw in spec["steps"]?.asArray ?? [] {
                do {
                    let s = try Self.obj(try Self.resolve(raw))
                    let r: JSONValue
                    switch s["op"]?.asString ?? "" {
                    case "register": r = .object(try svc.register(try Self.obj(s["grant"])))
                    case "list":
                        let f = s["filter"]?.asObject ?? [:]
                        r = .object(try svc.list(GrantResource.ListFilter(principal: f["principal"]?.asString, agent: f["agent"]?.asString, status: f["status"]?.asString,
                                                                          limit: f["limit"] != nil ? Self.int(f["limit"]) : nil, cursor: f["cursor"]?.asString)))
                    case "inspect": r = .object(try svc.inspect(s["id"]?.asString ?? ""))
                    case "amend":
                        let id = s["id"]?.asString ?? "", action = s["action"]?.asString ?? ""
                        let g = try svc.inspect(id)
                        var req: JObject = ["action": s["action"] ?? .null, "authority": s["authority"] ?? .null]
                        if s["by"]?.asString != "none" {
                            let by = s["by"]?.asString ?? ""
                            req["signed_by"] = s["signed_by"] ?? .string(by == "holder" ? "holder" : "principal")
                            req["sig"] = .string(try PCAGrants.signBody(GrantResource.GRANT_AMEND_DOMAIN, try GrantResource.amendMessage(g, action: action, authority: s["authority"]), try sec(by)))
                        }
                        if let su = s["stepUp"] { req["step_up_ref"] = su }
                        r = .object(try svc.amend(id, req))
                    case "revoke":
                        let id = s["id"]?.asString ?? "", scope = s["scope"]?.asString ?? "", by = s["by"]?.asString ?? ""
                        let g = try svc.inspect(id)
                        if by == "admin" { r = .object(try svc.revoke(id, scope: scope, sig: nil, admin: true)) }
                        else if by == "noauth" { r = .object(try svc.revoke(id, scope: scope, sig: nil, admin: false)) }
                        else {
                            let sig = try PCAGrants.signBody(GrantResource.GRANT_REVOKE_DOMAIN, GrantResource.grantRevokeMessage(g["id"]?.asString ?? "", scope: scope), try sec(by))
                            r = .object(try svc.revoke(id, scope: scope, sig: sig, admin: false))
                        }
                    case "needs": r = .object(try svc.requestNeeds(s["id"]?.asString ?? "", s["needs"]))
                    case "approve":
                        let needId = s["needId"]?.asString ?? ""
                        let nid = try svc.needGrantId(needId)
                        let g = try svc.inspect(nid)
                        let msg = GrantResource.needApproveMessage(["id": .string(needId), "grant_id": .string(nid)], rev: g["rev"], approved: s["approved"])
                        let sig = try PCAGrants.signBody(GrantResource.NEED_APPROVE_DOMAIN, msg, try sec(s["by"]?.asString ?? ""))
                        r = .object(try svc.approveNeeds(needId, approved: s["approved"], sig: sig, stepUpRef: s["stepUp"]?.asString))
                    case "deny": try svc.denyNeeds(s["needId"]?.asString ?? ""); r = .null
                    case "http":
                        if let w = s["who"]?.asObject { caller = GrantHttp.Caller(principal: w["principal"]?.asString, admin: w["admin"] == .bool(true)) } else { caller = nil }
                        var q: [String: String] = [:]
                        for (k, v) in s["query"]?.asObject ?? [:] { q[k.s] = v.asString ?? "" }
                        let res = handler(GrantHttp.Request(method: s["method"]?.asString ?? "", path: s["path"]?.asString ?? "", query: q, body: s["body"]))
                        r = .object(["status": .int(Int64(res.status)), "body": res.body])
                    default: throw JSError("bad op")
                    }
                    out.append(r)
                } catch { out.append(Self.err(error)) }
            }
            let grants = try store.list().sorted { ($0["id"]?.asString ?? "").utf16.lexicographicallyPrecedes(($1["id"]?.asString ?? "").utf16) }
            return .object(["steps": .array(out), "events": .array(events), "grants": .array(grants.map { .object($0) })])
        }
    }

    // ---- leases ----

    func testLeaseScenario() throws {
        try replay("leaseScenario", min: 8) { c in
            let spec = try Self.obj(c.arg(0))
            let pm = spec["policy"]?.asObject
            let policy = Lease.Policy(authorities: [try Self.pub("auth")], minApprovals: pm?["minApprovals"] != nil ? Self.int(pm?["minApprovals"]) : 1,
                                      eligibleApprovers: pm?["eligibleApprovers"]?.asArray.map { $0.compactMap { $0.asString } },
                                      maxTtlCeiling: pm?["maxTtlCeiling"] != nil ? Self.int(pm?["maxTtlCeiling"]) : nil)
            let reg = try Lease.Registry(policy: policy, kv: MemoryAtomicKV(), shards: spec["shards"] != nil ? Int(Self.int(spec["shards"])) : 4, clock: { Self.T0 })
            var lw: LeaseHttp.Caller?
            let handler = LeaseHttp.leaseResourceHandler(reg, authenticate: { _ in lw }, now: { Self.T0 })
            var out: [JSONValue] = []
            for raw in spec["steps"]?.asArray ?? [] {
                do {
                    let s = try Self.obj(try Self.resolve(raw))
                    let r: JSONValue
                    switch s["op"]?.asString ?? "" {
                    case "accept":
                        let a = reg.accept(s["lease"], chain: (s["chain"]?.asArray ?? []).compactMap { $0.asString })
                        var m: JObject = ["ok": .bool(a.code == nil)]
                        if let code = a.code { m["code"] = .string(code); if let why = a.reason, !why.isEmpty { m["reason"] = .string(why) } } else { m["replaced"] = .bool(a.replaced); m["seq"] = .int(a.seq) }
                        r = .object(m)
                    case "revoke":
                        let rv = reg.revoke(s["rev"])
                        var m: JObject = ["ok": .bool(rv.code == nil)]
                        if let code = rv.code { m["code"] = .string(code) } else { m["revoked"] = .int(Int64(rv.revoked)) }
                        r = .object(m)
                    case "get": r = reg.get(s["id"]?.asString ?? "").map { .object($0) } ?? .null
                    case "history":
                        r = .array(reg.history(s["id"]?.asString ?? "").map { h in
                            .object(["seq": .int(h.seq), "renewed_at": .int(h.renewedAt), "expires_at": .int(h.expiresAt), "justification_digest": .string(h.justificationDigest)])
                        })
                    case "shardRevs": r = .array(try reg.shardRevocations(Int(Self.int(s["i"]))).map { .object($0) })
                    case "renew":
                        var ro = Leases.RenewOptions(now: s["now"], increment: s["increment"], justificationDigest: s["just"]?.asString, approvers: s["approvers"])
                        if let vs = s["vetoSeq"] { let v = Self.int(vs); ro.veto = { cur in (cur["seq"]?.safeInt ?? 0) >= v } }
                        if let ch = s["chain"]?.asArray { ro.chain = ch.compactMap { $0.asString } }
                        let rr = Leases.renewLease(try Self.key(s["label"]?.asString ?? "auth"), reg, s["id"]?.asString ?? "", ro)
                        r = rr.get("ok") == .bool(true) ? rr : .object(["ok": .bool(false), "code": rr.get("code") ?? .null])
                    case "check":
                        let d = Lease.checkLease(s["lease"], registry: reg, now: s["now"])
                        var m: JObject = ["decision": .string(d.decision)]
                        if let code = d.code { m["code"] = .string(code) }
                        if let l = d.leaseId { m["lease_id"] = .string(l) }
                        if let e = d.expiresAt { m["expires_at"] = .int(e) }
                        r = .object(m)
                    case "http":
                        if let w = s["who"]?.asObject { lw = LeaseHttp.Caller(admin: w["admin"] == .bool(true), principal: w["principal"]?.asString) } else { lw = nil }
                        let res = handler(GrantHttp.Request(method: s["method"]?.asString ?? "", path: s["path"]?.asString ?? "", body: s["body"]))
                        r = .object(["status": .int(Int64(res.status)), "body": res.body])
                    default: throw JSError("bad op")
                    }
                    out.append(r)
                } catch { out.append(Self.err(error)) }
            }
            return .array(out)
        }
    }

    // ---- blueprints ----

    func testBlueprintScenario() throws {
        try replay("blueprintScenario", min: 3) { c in
            let spec = try Self.obj(c.arg(0))
            let reg = Blueprint.Registry(operators: [try Self.pub("op")], store: Blueprint.MemoryStore())
            let adm = PCAGrants.AdmissionRegistry()
            var revoked: [JSONValue] = []
            let fresh = PCAGrants.FreshAtIssuer(try Self.key("iss"), scope: "scope", initial: ["revocation_epoch": .int(0), "ledger_tree_size": .int(0), "budget_version": .int(0),
                                                                                                    "policy_revision": .int(0), "policy_digest": .string("pd")])
            var out: [JSONValue] = []
            for raw in spec["steps"]?.asArray ?? [] {
                do {
                    let s = try Self.obj(try Self.resolve(raw))
                    let r: JSONValue
                    switch s["op"]?.asString ?? "" {
                    case "accept":
                        let a = reg.accept(s["bp"])
                        var m: JObject = ["ok": .bool(a.code == nil)]
                        if let code = a.code { m["code"] = .string(code) } else { m["replaced"] = .bool(a.replaced) }
                        r = .object(m)
                    case "epoch": r = .int(reg.epoch)
                    case "kill":
                        let rv: ((String, String, Int64) throws -> Void)? = s["revoker"] == .bool(true) ? { value, reason, at in
                            revoked.append(.object(["kind": .string("issuer"), "value": .string(value), "reason": .string(reason), "revokedAt": .int(at)]))
                        } : nil
                        let adv: ((Int64, Int64) throws -> JSONValue)? = s["fresh"] == .bool(true) ? { epoch, now in try fresh.advance(["revocation_epoch": .int(epoch)], now: now) } : nil
                        r = try PCAGrants.groupKill(try Self.key(s["label"]?.asString ?? "op"), reg, key: s["key"]?.asString ?? "", now: Self.int(s["now"]), reason: s["reason"]?.asString,
                                                    revokeIssuer: rv, advanceFreshAt: adv)
                    case "revoked": r = .array(revoked)
                    case "admit":
                        guard let bp = try reg.get(s["key"]?.asString ?? "") else { throw JSError("no blueprint") }
                        adm.admit(s["instance"]?.asString ?? "", bp, until: Self.int(s["until"]))
                        r = .bool(true)
                    case "admitRevoke": r = .bool(adm.revoke(s["instance"]?.asString ?? "", s["key"]?.asString ?? ""))
                    case "admitCheck":
                        guard let bp = try reg.get(s["key"]?.asString ?? "") else { throw JSError("no blueprint") }
                        r = .bool(try adm.checker(Self.int(s["now"]))(s["instance"]?.asString ?? "", bp))
                    default: throw JSError("bad op")
                    }
                    out.append(r)
                } catch { out.append(Self.err(error)) }
            }
            return .array(out)
        }
    }
}
