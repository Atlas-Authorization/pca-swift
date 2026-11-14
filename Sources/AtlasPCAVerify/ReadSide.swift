import Foundation

public struct ReadResult: Equatable {
    public let decision: String
    public let code: String?
    public let view: JObject
    public let fields: JObject
    public let labels: [String]
    public let counts: [String: Int64]

    /// The shape the shared vectors expect: {decision, code, view, fields, labels, counts}.
    public var json: JSONValue {
        var c: JObject = [:]
        for (k, v) in counts { c[JKey(k)] = .int(v) }
        return .object([
            "decision": .string(decision), "code": code.map { JSONValue.string($0) } ?? .null, "view": .object(view), "fields": .object(fields),
            "labels": .array(labels.map { .string($0) }), "counts": .object(c),
        ])
    }
}

public struct SinkResult: Equatable {
    public let decision: String
    public let code: String?
    public let labels: [String]
    public var json: JSONValue {
        .object(["decision": .string(decision), "code": code.map { JSONValue.string($0) } ?? .null, "labels": .array(labels.map { .string($0) })])
    }
}

public enum ChainLabels: Equatable {
    case labels([String])
    case failed(code: String, at: Int)
}

struct ReadEntry {
    let verb: String, prefix: String
    let purposes: [String]
    let modes: [String: String]
    let defaultMode: String
}

struct ReadGrant {
    let raw: JSONValue
    let principal: String
    let issuedAt: Int64, expiresAt: Int64
    let reads: [ReadEntry]
    let caps: [String: Int64]
    let sinks: [String: (allow: [String], escalate: [String])]
}

/// K5 read-side authorization: a principal-signed READ GRANT masks what an agent may see per data class (tighten-only) and rules where
/// labelled data may flow next. Total; replays packages/pca/conformance/readside-vectors.json. Port of packages/pca/src/readside.ts.
public enum ReadSide {
    public static let READ_GRANT_DOMAIN = "atlas-pca/read-grant/v1\u{0}"
    public static let READ_RECEIPT_DOMAIN = "atlas-pca/read-receipt/v1\u{0}"
    static let RG_REF = "atlas-pca/read-grant-ref/v1"
    static let RR_REF = "atlas-pca/read-receipt-ref/v1"
    static let RH = "atlas-pca/read-hash/v1"
    static let RT = "atlas-pca/read-token/v1"
    static let RV = "atlas-pca/read-value/v1"
    static let SALT_MIN = 16

    /// `^(show|last4|hash|token|drop|bucket:[1-9][0-9]{0,8})$`
    static func isMode(_ s: String) -> Bool {
        if ["show", "last4", "hash", "token", "drop"].contains(s) { return true }
        let u = Array(s.utf8)
        let p = Array("bucket:".utf8)
        guard u.count > p.count, u.count <= p.count + 9, Array(u[0..<p.count]) == p else { return false }
        let d = u[p.count...]
        return d.first.map { $0 >= 0x31 && $0 <= 0x39 } == true && d.allSatisfy { $0 >= 0x30 && $0 <= 0x39 }
    }
    static func modeV(_ v: JSONValue?) -> String? { if let s = v?.asString, isMode(s) { return s }; return nil }
    static func rank(_ m: String) -> Int {
        if m.hasPrefix("bucket:") { return 2 }
        switch m { case "show": return 0; case "last4": return 1; case "token": return 3; case "hash": return 4; default: return 5 }
    }
    static func labelV(_ v: JSONValue?) -> String? { if let s = v?.asString, K5.isLabel(s) { return s }; return nil }

    static func parseEntry(_ x: JSONValue) -> ReadEntry? {
        guard let e = x.asObject, K5.onlyKeys(e, ["verb", "resource_prefix", "purposes", "modes", "default_mode"]),
              let verb = K3Sig.str(e["verb"], 128), let prefix = K3Sig.str(e["resource_prefix"], 512),
              let purposes = K5.sortedUnique(e["purposes"], 16, K5.isId), !purposes.isEmpty,
              let mo = e["modes"]?.asObject, mo.count <= 32, let dm = modeV(e["default_mode"]) else { return nil }
        var modes: [String: String] = [:]
        for (k, v) in mo {
            guard K5.isLabel(k.s), let m = modeV(v) else { return nil }
            modes[k.s] = m
        }
        return ReadEntry(verb: verb, prefix: prefix, purposes: purposes, modes: modes, defaultMode: dm)
    }

    /// `validReadGrantBody`: nil when malformed.
    static func parseGrant(_ v: JSONValue?) -> ReadGrant? {
        guard let raw = v, let b = raw.asObject, K5.onlyKeys(b, ["v", "id", "principal", "issued_at", "expires_at", "reads", "caps", "sinks"]),
              K5.uint(b["v"]) == 1, K5.idV(b["id"]) != nil, let principal = K5.b32(b["principal"]),
              let iat = K5.uint(b["issued_at"]), let exp = K5.uint(b["expires_at"]),
              let ra = b["reads"]?.asArray, !ra.isEmpty, ra.count <= 32,
              let co = b["caps"]?.asObject, co.count <= 32,
              let so = b["sinks"]?.asObject, so.count <= 16 else { return nil }
        var reads: [ReadEntry] = []
        for x in ra { guard let e = parseEntry(x) else { return nil }; reads.append(e) }
        var caps: [String: Int64] = [:]
        for (k, x) in co { guard K5.isLabel(k.s), let n = K5.uint(x) else { return nil }; caps[k.s] = n }
        var sinks: [String: (allow: [String], escalate: [String])] = [:]
        for (k, x) in so {
            guard K5.isId(k.s), let o = x.asObject, K5.onlyKeys(o, ["allow", "escalate"]),
                  let a = K5.sortedUnique(o["allow"], 16, K5.isLabel), let e = K5.sortedUnique(o["escalate"], 16, K5.isLabel),
                  !a.contains(where: { e.contains($0) }) else { return nil }
            sinks[k.s] = (a, e)
        }
        return ReadGrant(raw: raw, principal: principal, issuedAt: iat, expiresAt: exp, reads: reads, caps: caps, sinks: sinks)
    }

    public static func readGrantDigest(_ body: JSONValue) -> String? { K3Sig.digest(RG_REF, "g", body) }
    public static func readReceiptRef(_ r: JSONValue) -> String? { K3Sig.digest(RR_REF, "r", r) }

    /// A bad_request / bad_grant / bad_signature / not_yet / expired code, or the verified grant. `principal` and `now` must be a canonical key / unsigned safe integer.
    static func gradeGrant(_ g: JSONValue?, _ principal: JSONValue?, _ now: JSONValue?) -> (grant: ReadGrant?, code: String?, principal: String, now: Int64) {
        guard let p = K5.b32(principal), let n = K5.uint(now) else { return (nil, "bad_request", "", 0) }
        guard let sg = g?.asObject, K5.onlyKeys(sg, ["body", "sig"]), let body = parseGrant(sg["body"]) else { return (nil, "bad_grant", p, n) }
        if body.principal != p || !K3Sig.verifyBody(READ_GRANT_DOMAIN, body.raw, signer: p, sig: sg["sig"]) { return (nil, "bad_signature", p, n) }
        if n < body.issuedAt { return (nil, "not_yet", p, n) }
        if n >= body.expiresAt { return (nil, "expired", p, n) }
        return (body, nil, p, n)
    }

    static func out(_ code: String, _ counts: [String: Int64] = [:]) -> ReadResult {
        ReadResult(decision: "deny", code: code, view: [:], fields: [:], labels: [], counts: counts)
    }
    static func sorted<S: Sequence>(_ xs: S) -> [String] where S.Element == String { xs.sorted { IV.utf8Less($0, $1) } }

    /// Apply a read grant to one response. `input` is {principal, now, verb, resource, purpose, schema, record, tighten, salt, counts}.
    public static func redactRead(grant: JSONValue?, input: JSONValue?) -> ReadResult {
        do { return try redact(grant, input) } catch { return out("bad_request") }
    }

    static func redact(_ grant: JSONValue?, _ input: JSONValue?) throws -> ReadResult {
        let inp = input?.asObject ?? [:]
        let gr = gradeGrant(grant, inp["principal"], inp["now"])
        guard let g = gr.grant else { return out(gr.code ?? "bad_request") }
        guard input?.asObject != nil, let verb = K3Sig.str(inp["verb"], 128), let resource = K3Sig.str(inp["resource"], 512),
              let purpose = inp["purpose"]?.asString, K5.isId(purpose), let salt = inp["salt"]?.asString, IV.u16(salt) >= SALT_MIN else { return out("bad_request") }
        guard let sc = inp["schema"]?.asObject, let sf = sc["fields"]?.asObject, let req = sc["required"]?.asArray else { return out("bad_request") }
        var classes: [String: String] = [:]
        for (k, v) in sf { guard K5.isName(k.s), let c = v.asString, K5.isLabel(c) else { return out("bad_request") }; classes[k.s] = c }
        var required: [String] = []
        for p in req { guard let s = p.asString, classes[s] != nil else { return out("bad_request") }; required.append(s) }
        guard let record = K5.scalarMap(inp["record"]), let tg = inp["tighten"]?.asObject, let co = inp["counts"]?.asObject else { return out("bad_request") }
        var tighten: [String: String] = [:]
        for (k, v) in tg { guard K5.isLabel(k.s), let m = modeV(v) else { return out("bad_request") }; tighten[k.s] = m }
        var counts0: [String: Int64] = [:]
        for (k, v) in co { guard K5.isLabel(k.s), let n = K5.uint(v) else { return out("bad_request") }; counts0[k.s] = n }

        let rb = Array(resource.utf8)
        guard let entry = g.reads.first(where: { IV.same($0.verb, verb) && rb.starts(with: $0.prefix.utf8) && $0.purposes.contains(purpose) }) else { return out("no_read_scope", counts0) }
        var fields: JObject = [:]
        var view: JObject = [:]
        var used: [String: Int64] = [:]
        func field(_ cls: String, _ action: String, _ kind: String?, _ vd: String) -> JSONValue {
            .object(["class": .string(cls), "action": .string(action), "kind": kind.map { JSONValue.string($0) } ?? .null, "vd": .string(vd)])
        }
        for path in sorted(record.keys.map { $0.s }) {
            guard let v = record[JKey(path)] else { continue }
            // a field the schema does not classify is never shown
            let vd = try K5.hash(RV, "v", .object(["salt": .string(salt), "p": .string(path), "v": v]), full: true)
            guard let cls = classes[path] else { fields[JKey(path)] = field("unclassified", "dropped", nil, vd); continue }
            var mode = entry.modes[cls] ?? entry.defaultMode
            if let t = tighten[cls], rank(t) > rank(mode) { mode = t }
            var shown: JSONValue? = nil
            var action = "masked"
            var kind: String? = mode.hasPrefix("bucket:") ? "bucket" : mode
            if mode == "show" {
                shown = v; action = "shown"; kind = nil
            } else if mode == "last4" {
                if let s = v.asString {
                    let u = Array(s.unicodeScalars)
                    if u.allSatisfy({ $0.value < 0x10000 }) && u.count > 4 { shown = .string("****" + IV.text(u.suffix(4))) }
                }
            } else if mode.hasPrefix("bucket:") {
                if case let .int(n) = v, n >= 0, let d = Int64(mode.dropFirst(7)), d > 0 { shown = .int(n - (n % d)) }
            } else if mode == "hash" {
                shown = .string(try K5.hash(RH, "v", .object(["salt": .string(salt), "c": .string(cls), "v": v]), full: true))
            } else if mode == "token" {
                let h = try K5.hash(RT, "v", .object(["salt": .string(salt), "c": .string(cls), "v": v]), full: true)
                shown = .string("tok_" + String(h.prefix(22)))
            }
            guard let sv = shown else { fields[JKey(path)] = field(cls, "dropped", nil, vd); continue }
            fields[JKey(path)] = field(cls, action, kind, vd)
            view[JKey(path)] = sv
            used[cls, default: 0] += 1
        }
        var counts = counts0
        for (c, n) in used {
            counts[c, default: 0] += n
            if let cap = g.caps[c], counts[c, default: 0] > cap { return out("read_cap", counts0) }
        }
        if required.contains(where: { view[JKey($0)] == nil }) {
            return ReadResult(decision: "escalate", code: "required_dropped", view: [:], fields: [:], labels: [], counts: counts0)
        }
        var labels = Set<String>()
        for (_, f) in fields { if f.get("action")?.asString != "dropped", let c = f.get("class")?.asString { labels.insert(c) } }
        return ReadResult(decision: "allow", code: nil, view: view, fields: fields, labels: sorted(labels), counts: counts)
    }

    /// A read receipt's raw object when well-formed (`validReadReceipt`), with its parsed pieces.
    static func parseReceipt(_ x: JSONValue) -> (raw: JObject, grant: String, seq: Int64, prev: String?, labels: [String], issuedAt: Int64, signer: String, sig: String, classes: [String])? {
        guard let r = x.asObject, K5.onlyKeys(r, ["v", "grant", "verb", "resource", "purpose", "seq", "prev", "fields", "labels", "issued_at", "signer", "sig"]),
              K5.uint(r["v"]) == 1, let grant = K5.b32(r["grant"]), K3Sig.str(r["verb"], 128) != nil, K3Sig.str(r["resource"], 512) != nil,
              let pu = r["purpose"]?.asString, K5.isId(pu), let seq = K5.uint(r["seq"]),
              let prev = K5.nullable(r["prev"], K5.b32), (seq == 0) == (prev == nil),
              let iat = K5.uint(r["issued_at"]), let signer = K5.b32(r["signer"]), let sig = r["sig"]?.asString,
              let labels = K5.sortedUnique(r["labels"], 32, K5.isLabel),
              let fo = r["fields"]?.asObject, fo.count <= 64 else { return nil }
        var classes: [String] = []
        for (k, f) in fo {
            guard K5.isName(k.s), let o = f.asObject, K5.onlyKeys(o, ["class", "action", "kind", "vd"]),
                  let c = o["class"]?.asString, c == "unclassified" || K5.isLabel(c),
                  let a = o["action"]?.asString, a == "shown" || a == "masked" || a == "dropped",
                  K5.nullable(o["kind"], { $0?.asString }) != nil, K5.b32(o["vd"]) != nil else { return nil }
            if a != "dropped" { classes.append(c) }
        }
        return (r, grant, seq, prev, labels, iat, signer, sig, classes)
    }

    /// The labels carried by a verified, unbroken chain of read receipts, or an error code. Hashing failures surface as bad_receipt.
    public static func readChainLabels(receipts: JSONValue?, rsSigner: String, grantDigest: String, now: Int64) -> ChainLabels {
        guard let list = receipts?.asArray else { return .failed(code: "bad_receipt", at: 0) }
        var all = Set<String>()
        var prev: JObject? = nil
        for (i, x) in list.enumerated() {
            guard let r = parseReceipt(x), r.signer == rsSigner, r.grant == grantDigest, r.seq == Int64(i), r.issuedAt <= now else { return .failed(code: "bad_receipt", at: i) }
            let linked: Bool
            if let p = prev {
                guard let ref = readReceiptRef(.object(p)) else { return .failed(code: "bad_request", at: i) }
                linked = r.prev == ref
            } else { linked = r.prev == nil }
            if !linked || !K3Sig.verifyBody(READ_RECEIPT_DOMAIN, .object(K3Sig.without(r.raw, "sig")), signer: rsSigner, sig: .string(r.sig)) { return .failed(code: "bad_receipt", at: i) }
            // the receipt's labels must be exactly the classes of its non-dropped fields: an understated label list would launder data
            if sorted(Set(r.classes)) != r.labels { return .failed(code: "bad_receipt", at: i) }
            all.formUnion(r.labels)
            prev = r.raw
        }
        return .labels(sorted(all))
    }

    /// May data read under these receipts reach `sink`? Deny on any label the grant does not allow; escalate on an "ask" label.
    public static func checkSink(grant: JSONValue?, principal: JSONValue?, rsSigner: JSONValue?, now: JSONValue?, sink: JSONValue?, receipts: JSONValue?) -> SinkResult {
        func no(_ code: String) -> SinkResult { SinkResult(decision: "deny", code: code, labels: []) }
        let gr = gradeGrant(grant, principal, now)
        guard let g = gr.grant else { return no(gr.code ?? "bad_request") }
        guard let rs = K5.b32(rsSigner), let sinkName = sink?.asString else { return no("bad_request") }
        guard let rule = g.sinks[sinkName] else { return no("unknown_sink") }
        guard let gd = readGrantDigest(g.raw) else { return no("bad_request") }
        switch readChainLabels(receipts: receipts, rsSigner: rs, grantDigest: gd, now: gr.now) {
        case let .failed(code, _): return no(code)
        case let .labels(ls):
            if ls.contains(where: { !rule.allow.contains($0) && !rule.escalate.contains($0) }) { return SinkResult(decision: "deny", code: "label_flow", labels: ls) }
            if ls.contains(where: { rule.escalate.contains($0) }) { return SinkResult(decision: "escalate", code: "label_escalate", labels: ls) }
            return SinkResult(decision: "allow", code: nil, labels: ls)
        }
    }
}
