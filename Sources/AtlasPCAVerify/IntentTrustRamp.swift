import Foundation

/// Trust ramp: start narrow, widen only through confirmed behaviour, and every negative runtime signal vetoes its cell for good. A
/// one-sided Bernoulli CUSUM on divergences (negative signals about actions the grant admitted) freezes widening on alarm: positive
/// signals are queued until a rebase on a new signed statement; negative signals are always applied.
public final class PCAIntentTrustRamp {
    var l: PCAIntentLearner
    public let drift: PCAIntentRamp.DriftDetector
    private var queued: [(o: JSONValue, signal: String?)] = []
    public private(set) var log: [RampRecord] = []

    /// One recorded signal.
    public struct RampRecord {
        public let signal: String?
        public let y: Int
        public let wasInGrant: Bool
        public let before: Int
        public let after: Int
        public let applied: Bool
        public let drift: PCAIntentRamp.DriftState

        public func toJson() -> JSONValue {
            .object(["signal": signal.map { JSONValue.string($0) } ?? .null, "y": .int(Int64(y)), "wasInGrant": .bool(wasInGrant), "before": .int(Int64(before)),
                     "after": .int(Int64(after)), "applied": .bool(applied), "drift": drift.toJson()])
        }
    }

    public init(_ l: PCAIntentLearner, _ rho0: Double?, _ rho1: Double?, _ h: Double?) throws {
        self.l = l
        self.drift = try PCAIntentRamp.DriftDetector(rho0, rho1, h)
    }

    public func learner() -> PCAIntentLearner { l }

    /// Widening is frozen while a drift alarm stands.
    public func frozen() -> Bool { drift.state().alarm }

    /// Positive signals held back by a freeze (released only by a rebase, which discards them).
    public func pending() -> [JSONValue] {
        queued.map { q in
            .object(["o": .object(["verb": q.o.get("verb") ?? .null, "values": q.o.get("values") ?? .null]), "signal": q.signal.map { JSONValue.string($0) } ?? .null])
        }
    }

    private func grantSize() -> Int {
        var n = 0
        for c in l.cells() where c.inGrant { n += 1 }
        return n
    }

    @discardableResult
    public func record(_ o: JSONValue, _ signal: String?) throws -> RampRecord {
        let y = PCAIntentRamp.signalLabel(signal)
        let wasInGrant = l.admitsOutcome(o)
        let before = grantSize()
        var d = drift.state()
        if wasInGrant { d = drift.update(y == 0) }
        var applied = true
        if y == 1 && frozen() {
            queued.append((o: o, signal: signal))
            applied = false
        } else {
            try l.observe(o, y: y, source: "runtime", region: nil)
        }
        let rec = RampRecord(signal: signal, y: y, wasInGrant: wasInGrant, before: before, after: grantSize(), applied: applied, drift: d)
        log.append(rec)
        return rec
    }

    /// Record a SIGNED runtime observation: the signature must verify, the signer must be trusted, and the observation must be about
    /// this map and a runtime one. Returns `{ok: true, record}` or `{ok: false, reason}`.
    public func recordObservation(_ obs: JSONValue?, _ mapDigest: String, _ trustedSigners: [String], _ expectedSigner: String?, _ pqPins: JSONValue?) throws -> JSONValue {
        func no(_ reason: JSONValue) -> JSONValue { .object(["ok": .bool(false), "reason": reason]) }
        let v: JSONValue = PCAIntentObservation.verifyIntentObservation(obs, expectedSigner, pqPins?.asObject)
        if v.get("ok") != .bool(true) { return no(v.get("reason") ?? .null) }
        guard let o = obs?.asObject else { return no(.string("observation is not an object")) }
        guard let signer = o["signer"]?.asString, trustedSigners.contains(where: { IV.same($0, signer) }) else { return no(.string("untrusted observation signer")) }
        guard IV.same(o["map_digest"]?.asString, mapDigest) else { return no(.string("observation is about a different map")) }
        guard IV.same(o["source"]?.asString, "runtime") else { return no(.string("only runtime observations feed the ramp")) }
        guard let verb = o["verb"]?.asString else { return no(.string("observation has no verb")) }
        let values: JSONValue = .object(o["values"]?.asObject ?? [:])
        let yes: Bool = IV.num(o["y"]) == 1.0
        let rec = try record(.object(["verb": .string(verb), "values": values]), yes ? "principal-confirm" : "postcondition-violation")
        return .object(["ok": .bool(true), "record": rec.toJson()])
    }

    /// Re-base on a new learner (the only way to clear an alarm): the old vetoes are not carried over and queued positives are discarded.
    public func rebase(_ next: PCAIntentLearner) {
        l = next
        queued.removeAll()
        drift.reset()
    }
}
