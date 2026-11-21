import XCTest
import Foundation
@testable import AtlasPCAVerify

/// A replay store that refuses every consume (`refuses`) or is down (`throws`).
final class ScriptedConsumeStore: PCAStateStore {
    let down: Bool
    init(down: Bool) { self.down = down }
    func claim(key: String, counter: Int64) throws -> ClaimResult { throw PCAStoreArgumentError() }
    func consumeOnce(key: String, retainUntil: Int64, now: Int64) throws -> Bool {
        if down { throw PCAStoreArgumentError() }
        return false
    }
}

/// Differential replay of PCAEvents against the reference (@atlasauth/pca-events): event build / serialize / parse, signed
/// webhooks and the replay-consuming delivery check. A secret is a string or {"$bytes": b64url}. serializeEvent cases whose object
/// carries members outside the event's own (their insertion order is not recoverable from a parsed tree) are not compared; a
/// payload with a duplicate member is refused natively (the reference keeps the last one): counted as native stricter.
final class RefEventsTests: XCTestCase {
    static func secret(_ v: JSONValue?) -> PCAEvents.Secret? {
        if let s = v?.asString { return .text(s) }
        if let o = v?.asObject, o["$bytes"]?.asString == "" { return .bytes([]) }
        if let o = v?.asObject, o.count == 1, o["$bytes"] != nil { return Base.bytes(v).map { .bytes($0) } }
        return nil
    }

    static func onlyEventKeys(_ v: JSONValue) -> Bool {
        guard let o = v.asObject else { return true }
        return o.keys.allSatisfy { PCAEvents.ORDER.contains($0.s) } && o.values.allSatisfy(onlyEventKeys)
    }

    static func normalize(_ v: JSONValue) -> JSONValue {
        guard var o = v.asObject, o["ok"] == .bool(false), let r = o["reason"]?.asString else { return v }
        if r.hasPrefix("canonicalize:") { o["reason"] = .string("<canonicalize>") }
        else if !["a replay store", "bad signature", "replayed", "replay store", "parseEvent: "].contains(where: { r.hasPrefix($0) }) { o["reason"] = .string("<json>") }
        return .object(o)
    }

    func testEvents() throws {
        try K042.requireCovers(["Events", "JSInterop"])
        let d = Base.Diffs()
        try Base.each("ref-events.json.gz") { c in
            let got: BaseGot
            let opts = c.arg(2)
            switch c.fn {
            case "minSecretBytes":
                got = .value(.int(Int64(PCAEvents.MIN_SECRET_BYTES)))
            case "buildStepUpEvent":
                got = Ref.v { try PCAEvents.buildStepUpEvent(c.arg(0) ?? .null, c.arg(1)) }
            case "serializeEvent":
                guard let e = c.arg(0), Self.onlyEventKeys(e) else { d.skip("serializeEvent: members outside the event (insertion order)"); return }
                got = Ref.v { .string(try PCAEvents.serializeEvent(e)) }
            case "parseEvent":
                if let t = c.arg(0)?.asString, t.contains("{\"id\":\"dup\","), !c.threw { d.skip("native stricter: duplicate member refused"); return }
                got = Ref.v { try PCAEvents.parseEvent(c.arg(0)) }
            case "signWebhook", "webhookHeaders":
                guard let s = Self.secret(c.arg(0)) else { got = .threw(nil); break }
                let p = c.arg(1)?.asString ?? ""
                got = c.fn == "signWebhook" ? Ref.s { try PCAEvents.signWebhook(s, p, timestamp: opts?.get("timestamp")) }
                                             : Ref.v { try PCAEvents.webhookHeaders(s, p, timestamp: opts?.get("timestamp")) }
            case "verifyWebhook":
                let o = c.arg(3)
                got = .value(.bool(PCAEvents.verifyWebhook(Self.secret(c.arg(0)), c.arg(1)?.asString ?? "", opts, toleranceSec: o?.get("toleranceSec"), now: o?.get("now"))))
            case "deliveryScenario":
                let spec = c.arg(0)
                let mode = spec?.get("store")?.asString
                let store: PCAStateStore = mode == "throws" ? (ScriptedConsumeStore(down: true) as PCAStateStore) : mode == "refuses" ? (ScriptedConsumeStore(down: false) as PCAStateStore) : (MemoryStateStore() as PCAStateStore)
                var out: [JSONValue] = []
                for del in spec?.get("deliveries")?.asArray ?? [] {
                    let o = del.get("opts")
                    let noStore = spec?.get("noReplay") == .bool(true) || spec?.get("noOpts") == .bool(true) || o?.get("replay") == .null
                    let sec = Self.secret(JS.present(del.get("secret")) ?? .string("whsec_0123456789abcdef0123456789"))
                    let v = PCAEvents.verifyDelivery(sec, del.get("payload")?.asString ?? "", del.get("header"), replay: noStore ? nil : store,
                                                     toleranceSec: o?.get("toleranceSec"), now: o?.get("now"))
                    out.append(Self.normalize(v))
                }
                got = .value(.array(out))
            default:
                d.skip("\(c.fn): not mapped"); return
            }
            d.add(c, Base.diff(c, got))
        }
        d.finish(900)
    }
}
