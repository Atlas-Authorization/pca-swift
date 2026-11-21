import Foundation

/// The trust ramp's pure parts: runtime signal labels, the narrow starting configuration, and the drift detector, a one-sided
/// Bernoulli CUSUM on divergences (negative signals about actions the grant admitted). S_t = max(0, S_{t-1} + log LR_t); an
/// alarm at S_t >= h is sticky until reset.
public enum PCAIntentRamp {
    /// y = 1 for jit-approve and principal-confirm; every other signal is y = 0 (a veto).
    public static func signalLabel(_ signal: String?) -> Int {
        guard let s = signal else { return 0 }
        return IV.same(s, "jit-approve") || IV.same(s, "principal-confirm") ? 1 : 0
    }

    /// The narrow start: tau 1, eta 0, a high empty-set prior for every verb (very high for verbs the slots do not name).
    public static func narrowStart(_ omega: WalletOmega, _ slots: JSONValue?, _ slotNullMass: Double?, _ otherNullMass: Double?) -> JSONValue {
        var nullMass: JObject = [:]
        let named: [JSONValue] = slots?.get("verbs")?.asArray ?? []
        for vs in omega.verbs {
            let isNamed: Bool = named.contains { IV.same($0.asString, vs.verb) }
            nullMass[JKey(vs.verb)] = .double(isNamed ? (slotNullMass ?? 0.5) : (otherNullMass ?? 0.95))
        }
        return .object(["eta": .double(0.0), "tau": .double(1.0), "nullMass": .object(nullMass)])
    }

    /// The detector's state.
    public struct DriftState {
        public let statistic: Double
        public let alarm: Bool
        public let informative: Double
        public let divergences: Double

        public func toJson() -> JSONValue {
            .object(["statistic": .double(statistic), "alarm": .bool(alarm), "informative": .double(informative), "divergences": .double(divergences)])
        }
    }

    /// Defaults: rho0 0.02, rho1 0.25, h ln(100); a nil member takes its default.
    public final class DriftDetector {
        public let rho0: Double
        public let rho1: Double
        public let h: Double
        private var s = DriftState(statistic: 0.0, alarm: false, informative: 0.0, divergences: 0.0)

        public init(_ rho0: Double?, _ rho1: Double?, _ h: Double?) throws {
            self.rho0 = rho0 ?? 0.02
            self.rho1 = rho1 ?? 0.25
            self.h = h ?? FdLibm.log(100.0)
            guard self.rho0 > 0 && self.rho0 < self.rho1 && self.rho1 < 1 else { throw JSError("DriftDetector: need 0 < rho0 < rho1 < 1") }
            guard self.h > 0 else { throw JSError("DriftDetector: h must be positive") }
        }

        /// Feed one signal about an action inside the grant: `diverged` = a negative signal.
        @discardableResult
        public func update(_ diverged: Bool) -> DriftState {
            let inc: Double = diverged ? FdLibm.log(rho1 / rho0) : FdLibm.log((1 - rho1) / (1 - rho0))
            let sum: Double = s.statistic + inc
            let statistic: Double = sum > 0.0 ? sum : 0.0
            s = DriftState(statistic: statistic, alarm: s.alarm || statistic >= h, informative: s.informative + 1, divergences: s.divergences + (diverged ? 1 : 0))
            return s
        }

        public func state() -> DriftState { s }

        public func reset() {
            s = DriftState(statistic: 0.0, alarm: false, informative: 0.0, divergences: 0.0)
        }
    }
}
