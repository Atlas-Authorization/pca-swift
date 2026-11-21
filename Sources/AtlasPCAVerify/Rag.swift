import Foundation

/// FGA for RAG: retrieval-time, per-principal document filtering driven by the PCA policy evaluator (the pure core of `@atlasauth/pca-rag`).
///
/// FAIL CLOSED: a document is admitted only when a permit predicate cleanly matches one of its ACL entries (verb = relation, resource = object)
/// and no deny predicate matches. Anything unknown (no ACL, a malformed document, an incomplete policy translation, an evaluator error) drops the
/// document. Every decision is recorded (`Result.decision`), with a content digest of the whole decision set that can be bound into a receipt.
///
/// Values are JSON (`JSONValue`). A principal is a string id or `{id, attributes?, env?}`. A policy is a list of predicates, `{openfga: {model,
/// tuples}}`, `{predicates, denies?, report?}` or an already-compiled policy (`compilePolicy`). `order` is the member order of an OpenFGA model's
/// `relations` objects (a parsed object has none); it fixes the order of the translation report lines.
public enum PCARag {
    public struct Result<D> {
        /// The admitted documents, in candidate order.
        public let documents: [D]
        /// The decision record: the proof trace.
        public let decision: JSONValue
    }

    // MARK: documents and ACLs

    private static func nonEmpty(_ v: JSONValue?) -> Bool { if case let .string(s)? = v { return !s.isEmpty } else { return false } }

    private static func isDocAcl(_ v: JSONValue?) -> Bool {
        guard case let .object(o)? = v else { return false }
        return nonEmpty(o["relation"]) && nonEmpty(o["object"])
    }

    private static func aclArray(_ acl: JSONValue?) -> [JSONValue] {
        if case let .array(a)? = acl { return a.filter { isDocAcl($0) } }
        if let a = acl, isDocAcl(a) { return [a] }
        return []
    }

    /// A `relation:object` tag as an ACL entry; the split is at the FIRST colon, so an object id may contain colons.
    private static func tagToAcl(_ tag: JSONValue?) -> JSONValue? {
        guard case let .string(t)? = tag else { return nil }
        let u = Array(t.utf16)
        guard let i = u.firstIndex(of: 0x3a), i > 0, i < u.count - 1 else { return nil }
        return .object(["relation": .string(String(decoding: u[..<i], as: UTF16.self)), "object": .string(String(decoding: u[(i + 1)...], as: UTF16.self))])
    }

    /// ACL entries from freeform `acl` (one entry or a list) and `tags` (`relation:object` strings) metadata.
    public static func aclsFromMetadata(_ acl: JSONValue?, _ tags: JSONValue?) -> [JSONValue] {
        var out = aclArray(acl)
        if case let .array(ts)? = tags { for t in ts { if let a = tagToAcl(t) { out.append(a) } } }
        return out
    }

    // MARK: principal

    /// The acting identity of a verified PCActn: its LEAF capability holder (map the key to your policy's identity with `opts.id`). Throws on a
    /// PCActn with no capability chain, rather than producing an empty principal. `opts`: `{id?, attributes?, env?}`.
    public static func principalFromPCActn(_ pcactn: JSONValue?, _ opts: JSONValue? = nil) throws -> JSONValue {
        var holder: JSONValue?
        if case let .array(chain)? = pcactn?.get("cap_chain"), let last = chain.last { holder = last.get("holder") }
        guard nonEmpty(holder), let h = holder else { throw JSError("principalFromPCActn: PCActn has no leaf capability holder") }
        var out: JObject = [:]
        if let id = opts?.get("id"), !id.isNull { out["id"] = id } else { out["id"] = h }
        if let a = opts?.asObject?["attributes"] { out["attributes"] = a }
        if let e = opts?.asObject?["env"] { out["env"] = e }
        return .object(out)
    }

    private static func toPrincipal(_ p: JSONValue?) -> JObject? {
        switch p {
        case let .string(s)?: return ["id": .string(s)]
        case let .object(o)?: return o
        case .array?: return [:] // a JavaScript array is an object with no id
        default: return nil
        }
    }

    // MARK: policy compilation

    private static func incomplete(_ reason: String) -> JSONValue {
        .object(["predicates": .array([]), "denies": .array([]), "incomplete": .bool(true), "incompleteReason": .string(reason)])
    }

    /// JavaScript `x.length > 0` for a JSON value that is not null.
    private static func lengthPositive(_ x: JSONValue?) -> Bool {
        switch x {
        case let .array(a)?: return !a.isEmpty
        case let .string(s)?: return !s.isEmpty
        case let .object(o)?: if let n = IV.num(o["length"]) { return n > 0 } else { return false }
        default: return false
        }
    }

    private static func hasErrors(_ report: JSONValue?) -> Bool { if case let .array(e)? = report?.get("errors") { return !e.isEmpty } else { return false } }

    /// Compile any policy into `{predicates, denies, incomplete, incompleteReason?, report?}` (an already-compiled policy passes through). A value
    /// that is not a policy, or a translation with errors, is INCOMPLETE: nothing is admitted.
    public static func compilePolicy(_ policy: JSONValue?, order: PCAPolicyBridge.KeyOrder? = nil) throws -> JSONValue {
        switch policy {
        case .array?, .object?: break
        default: return incomplete("no usable policy was supplied (fail closed)")
        }
        guard case let .object(p)? = policy else {
            return .object(["predicates": policy ?? .null, "denies": .array([]), "incomplete": .bool(false)])
        }
        if case .bool? = p["incomplete"] { return .object(p) }
        if p["openfga"] == nil, p["predicates"]?.asArray == nil { return incomplete("the policy has no predicates and is not an OpenFGA policy (fail closed)") }
        if let fga = p["openfga"] {
            let f: JObject
            switch fga {
            case let .object(o): f = o
            case .array: f = [:] // an array has no model or tuples
            default: return incomplete("the OpenFGA policy has no model (fail closed)")
            }
            let br = PCAPolicyBridge.openfgaToPca(f["model"], f["tuples"], order: order)
            let report = br.get("report")
            var o: JObject = ["predicates": br.get("predicates") ?? .null, "denies": br.get("denies") ?? .null, "incomplete": .bool(hasErrors(report))]
            o["report"] = report ?? .null
            return .object(o)
        }
        var out: JObject = ["predicates": p["predicates"] ?? .null, "denies": p["denies"]?.asArray != nil ? p["denies"]! : .array([])]
        if let r = p["report"] {
            guard case let .object(ro) = r, let errors = ro["errors"], !errors.isNull else { throw JSError("compilePolicy: report.errors is required") } // the reference reads report.errors.length
            out["report"] = r
            out["incomplete"] = .bool(lengthPositive(errors))
        } else {
            out["incomplete"] = .bool(false)
        }
        return .object(out)
    }

    // MARK: the filter

    /// The evaluation context for ONE ACL entry: the subject is the principal's attributes plus its id.
    private static func context(_ principal: JObject, _ acl: JObject) -> JSONValue {
        var subject = PCAMcp.spreadObj(principal["attributes"])
        subject["id"] = principal["id"] ?? .null
        var ctx: JObject = ["action": .object(["verb": acl["relation"] ?? .null, "resource": acl["object"] ?? .null]), "subject": .object(subject)]
        if let e = principal["env"] { ctx["env"] = e }
        return .object(ctx)
    }

    private static func decideDocument(_ id: String, _ acls: [JSONValue], _ principal: JObject, _ compiled: JObject) -> JSONValue {
        func no(_ reason: String) -> JSONValue { .object(["id": .string(id), "allowed": .bool(false), "reason": .string(reason)]) }
        if compiled["incomplete"] == .bool(true) {
            if case let .string(why)? = compiled["incompleteReason"] { return no(why) }
            return no("policy translation incomplete (fail closed)")
        }
        guard nonEmpty(principal["id"]), case let .string(pid)? = principal["id"] else { return no("no principal identity (fail closed)") }
        if acls.isEmpty { return no("no decidable ACL metadata (fail closed)") }
        var last = "no relation grants access (fail closed)"
        let pol: JSONValue = .object(["predicates": compiled["predicates"] ?? .null, "denies": compiled["denies"] ?? .null])
        for a in acls {
            guard case let .object(acl) = a else { continue }
            let res: JSONValue
            do { res = try PCAPolicyBridge.decide(pol, context(principal, acl)) } catch {
                last = "evaluator error (fail closed)"
                continue
            }
            if res.get("allowed") == .bool(true) {
                var d: JObject = ["id": .string(id), "allowed": .bool(true), "via": a,
                                  "reason": .string("granted: \(pid) has \(JS.toString(acl["relation"])) on \(JS.toString(acl["object"]))")]
                if let m = res.get("matched"), !m.isNull { d["matched"] = m }
                return .object(d)
            }
            if case let .string(r)? = res.get("reason") { last = r }
        }
        return no(last)
    }

    /// The generic filter. `id` and `acls` read a candidate's id (nil or empty: positional `doc#i`) and its ACL entries (anything that is not a list or
    /// entry yields none); either throwing marks the document unreadable and drops it.
    public static func filter<D>(principal input: JSONValue?, candidates: [D]?, policy: JSONValue?, order: PCAPolicyBridge.KeyOrder? = nil,
                                 id: (D, Int) throws -> JSONValue?, acls: (D) throws -> JSONValue?) throws -> Result<D> {
        let principal = toPrincipal(input) ?? ["id": .string("")]
        let compiledValue = try compilePolicy(policy, order: order)
        let compiled = compiledValue.asObject ?? [:]
        let list = candidates ?? []
        var documents: [D] = []
        var decisions: [JSONValue] = [], allowedIds: [JSONValue] = [], droppedIds: [JSONValue] = [], allowedIndexes: [JSONValue] = []
        var seen = Set<String>()
        for (i, doc) in list.enumerated() {
            let rawId: JSONValue?, docAcls: [JSONValue]
            do {
                rawId = try id(doc, i)
                docAcls = aclArray(try acls(doc))
            } catch {
                let fid = "doc#\(i)" // metadata that cannot even be read is unknown: fail closed
                decisions.append(.object(["id": .string(fid), "allowed": .bool(false), "reason": .string("unreadable document metadata (fail closed)")]))
                droppedIds.append(.string(fid))
                continue
            }
            var docId: String
            if case let .string(s)? = rawId, !s.isEmpty { docId = s } else { docId = "doc#\(i)" }
            if seen.contains(docId) { docId += "#dup\(i)" } // two candidates with one id must stay distinguishable
            seen.insert(docId)
            let d = decideDocument(docId, docAcls, principal, compiled)
            decisions.append(d)
            if d.get("allowed") == .bool(true) {
                documents.append(doc)
                allowedIds.append(.string(docId))
                allowedIndexes.append(.int(Int64(i)))
            } else {
                droppedIds.append(.string(docId))
            }
        }
        var pid = ""
        if case let .string(s)? = principal["id"] { pid = s }
        var base: JObject = ["principal": .string(pid), "considered": .int(Int64(list.count)), "allowedIds": .array(allowedIds), "allowedIndexes": .array(allowedIndexes),
                             "droppedIds": .array(droppedIds), "policyIncomplete": .bool(compiled["incomplete"] == .bool(true))]
        var hashed = base
        hashed["v"] = .int(1)
        hashed["kind"] = .string("pca-rag/filter")
        base["decisions"] = .array(decisions)
        base["digest"] = .string(Canonical.hashCanonical(.object(hashed)))
        if let r = compiled["report"], !r.isNull { base["report"] = r }
        return Result(documents: documents, decision: .object(base))
    }

    /// Filter JSON documents (`{id, acl?, tags?}` objects) with the default readers. A null document is unreadable (dropped); another value that is
    /// not an object has no id and no ACL.
    public static func filterDocuments(principal: JSONValue?, candidates: [JSONValue]?, policy: JSONValue?, order: PCAPolicyBridge.KeyOrder? = nil) throws -> Result<JSONValue> {
        func fields(_ d: JSONValue) throws -> JObject {
            if d.isNull { throw JSError("null document") }
            return d.asObject ?? [:]
        }
        return try filter(principal: principal, candidates: candidates, policy: policy, order: order,
                          id: { d, _ in try fields(d)["id"] }, acls: { d in .array(aclsFromMetadata(try fields(d)["acl"], try fields(d)["tags"])) })
    }
}
