import Foundation

/// Proof of progress, the prover side: state sources (an in-memory one and one that signs what it observes), the tracker that records hash-chained steps
/// with the mode and charge rule, and the anchor of a trajectory head in the transparency ledger.
extension PCAProgress {
    /// An observer of the real state. `observe` returns `{state, state_digest, source, evidence?}` for a request `{action_digest, goal_commitment,
    /// prior_digest}`, or nil (no observation).
    public protocol StateSource: AnyObject {
        var id: String { get }
        func observe(_ req: JSONValue) throws -> JSONValue?
    }

    /// A state held in memory (every state is a detached copy), with a counter in the evidence.
    public final class InMemoryStateSource: StateSource {
        private var cur: JSONValue
        private var count: Int64 = 0
        public let id: String
        public private(set) var requests: [JSONValue] = []
        public init(initial: JSONValue, id: String = "in-memory") throws { cur = try PCAProgress.snapshot(initial); self.id = id }
        public func apply(_ next: JSONValue) throws { cur = try PCAProgress.snapshot(next) }
        public func observe(_ req: JSONValue) throws -> JSONValue? {
            requests.append(req)
            let state = try PCAProgress.snapshot(cur)
            let n = count
            count += 1
            return .object(["state": state, "state_digest": .string(try PCAProgress.stateDigest(state)), "source": .string(id),
                            "evidence": .object(["kind": .string("in-memory"), "n": .int(n), "prior": req.get("prior_digest") ?? .null, "action": req.get("action_digest") ?? .null])])
        }
    }

    /// A state source that signs each observation (Ed25519, deterministic): the evidence is the attestation `{source, goal_commitment, action_digest,
    /// prior_digest, state_digest, sig}` an `attestedStateVerifier` checks. The post-quantum suites sign through the opt-in OpenSSL product and are not
    /// built here.
    public final class AttestedStateSource: StateSource {
        public let id: String
        public let publicKey: String
        private let key: PCAEdKey
        private let observeState: (JSONValue) throws -> JSONValue
        public private(set) var attestations: [JSONValue] = []
        public init(id: String, key: PCAEdKey, observeState: @escaping (JSONValue) throws -> JSONValue) throws {
            if id.isEmpty { throw JSError("AttestedStateSource: id is required") }
            self.id = id; self.key = key; self.publicKey = key.id; self.observeState = observeState
        }
        public func observe(_ req: JSONValue) throws -> JSONValue? {
            let state = try PCAProgress.snapshot(try observeState(req))
            let digest = try PCAProgress.stateDigest(state)
            var stmt: JObject = ["source": .string(id), "state_digest": .string(digest)]
            for k in ["goal_commitment", "action_digest", "prior_digest"] { if let v = req.get(k) { stmt[JKey(k)] = v } }
            let msg = try PCAProgress.stateAttestationMessage(.object(stmt), alg: nil, algPresent: false, pqPk: nil, pqPresent: false)
            stmt["sig"] = .string(Base64URLStrict.encode(try key.sign(msg)))
            attestations.append(.object(stmt))
            return .object(["state": state, "state_digest": .string(digest), "source": .string(id), "evidence": .object(stmt)])
        }
    }

    /// The tracker of one goal: it holds the current state, the hash chain, the exploration spent and the recorded steps. Every step is classified by the
    /// shared mode and charge rule; the guard may prohibit it; the exploration budget is strict (spent may EQUAL it). Results are the reference's
    /// `{ok: true, step, spent, remaining}` / `{ok: false, reason, stepUp}`.
    public final class ProgressTracker {
        public let goal: JSONValue
        public let commitment: JSONValue
        private let reg: PotentialRegistry
        private let guardFn: StepGuard?
        private var seq: Int64 = 0
        private var head = PCAProgress.GENESIS
        private var spentTotal: Int64 = 0
        private var cur: JSONValue
        private var curDigest: String
        private var log: [JSONValue] = []

        /// Refuses a goal that does not match the commitment and an initial state its potential rejects.
        public init(goal: JSONValue, commitment: JSONValue, initial: JSONValue, registry: (() throws -> PotentialRegistry)? = nil, guardFn: StepGuard? = nil) throws {
            if !PCAProgress.verifyGoalCommitment(goal, commitment) { throw JSError("goal does not match commitment") }
            self.goal = try PCAProgress.snapshot(goal)
            self.commitment = commitment
            self.reg = try registry?() ?? PCAProgress.DEFAULT_POTENTIALS
            self.guardFn = guardFn
            cur = try PCAProgress.snapshot(initial)
            curDigest = try PCAProgress.stateDigest(cur)
            _ = try PCAProgress.potentialOf(self.goal, reg, cur)
        }

        public var spent: Int64 { spentTotal }
        public var remaining: Int64 { goal.get("explorationBudget")!.safeInt! - spentTotal }
        public var state: JSONValue { cur }
        public var currentStateDigest: String { curDigest }
        public var steps: [JSONValue] { log }
        /// Whether the potential of the current state is 0.
        public func reached() throws -> Bool { try PCAProgress.potentialOf(goal, reg, cur) == 0 }

        private static func denied(_ reason: String, stepUp: Bool = false) -> JSONValue { .object(["ok": .bool(false), "reason": .string(reason), "stepUp": .bool(stepUp)]) }

        /// Record a transition to `after` by the action `actionDigest`.
        public func step(_ after: JSONValue?, _ actionDigest: JSONValue?) -> JSONValue { advance(after, actionDigest, "", "") }

        /// Observe the state through a source (bound to this transition) and record it; any fault, an empty observation, or a source id or state digest
        /// that does not match is `state-source-mismatch`.
        public func stepObserved(_ source: StateSource, _ actionDigest: JSONValue?) -> JSONValue {
            do {
                let req: JSONValue = .object(["action_digest": actionDigest ?? .null, "goal_commitment": commitment, "prior_digest": .string(curDigest)])
                guard let obs = try source.observe(req), obs != .null, obs.get("source")?.asString.map({ $0.utf16.elementsEqual(source.id.utf16) }) == true,
                      let sd = obs.get("state_digest")?.asString, sd.utf16.elementsEqual(try PCAProgress.stateDigest(obs.get("state")).utf16) else {
                    return Self.denied("state-source-mismatch")
                }
                let evidence = try PCAProgress.hashStrict(.object(["t": .string("pca-evidence"), "e": JS.present(obs.get("evidence")) ?? .null]))
                return advance(obs.get("state"), actionDigest, source.id, evidence)
            } catch { return Self.denied("state-source-mismatch") }
        }

        private func advance(_ afterIn: JSONValue?, _ actionDigest: JSONValue?, _ stateSource: String, _ evidenceDigest: String) -> JSONValue {
            guard let ad = actionDigest?.asString, !ad.isEmpty else { return Self.denied("malformed") }
            let after: JSONValue, afterDigest: String, pb: Int64, pa: Int64, cls: (mode: String, charge: Int64)
            do {
                after = try PCAProgress.snapshot(afterIn)
                afterDigest = try PCAProgress.stateDigest(after)
                pb = try PCAProgress.potentialOf(goal, reg, cur)
                pa = try PCAProgress.potentialOf(goal, reg, after)
                cls = try PCAProgress.classify(pb, pa, goal.get("epsilon")!.safeInt!)
            } catch { return Self.denied(PCAProgress.denialOf(error)) }
            if let g = guardFn, !PCAProgress.runGuard(g, .object(["seq": .int(seq), "before": cur, "after": after, "action_digest": .string(ad)])) { return Self.denied("prohibited") }
            let (next, overflow) = spentTotal.addingReportingOverflow(cls.charge)
            if overflow || abs(next) > Canonical.MAX_SAFE || next > goal.get("explorationBudget")!.safeInt! { return Self.denied("exploration-exhausted", stepUp: true) }
            var body: JObject = ["goal_commitment": commitment, "seq": .int(seq), "before": cur, "after": after, "before_digest": .string(curDigest),
                                 "after_digest": .string(afterDigest), "action_digest": .string(ad), "mode": .string(cls.mode), "potential_before": .int(pb),
                                 "potential_after": .int(pa), "charge": .int(cls.charge), "state_source": .string(stateSource), "evidence_digest": .string(evidenceDigest),
                                 "prev": .string(head)]
            guard let digest = try? PCAProgress.stepBodyDigest(body) else { return Self.denied("malformed") }
            body["digest"] = .string(digest)
            let step: JSONValue = .object(body)
            log.append(step)
            seq += 1
            head = digest
            spentTotal = next
            cur = after
            curDigest = afterDigest
            return .object(["ok": .bool(true), "step": step, "spent": .int(spentTotal), "remaining": .int(remaining)])
        }
    }

    /// Anchor the trajectory head in the transparency ledger: `{head, salt, commit, index, ledgerHead}`. The salt (default: 16 random bytes, base64url)
    /// keeps the head out of the public ledger; `commit` is `{t, salt, head}` hashed.
    public static func anchorTrajectoryHead(_ ledger: PCATransparencyLedger, _ steps: JSONValue?, salt: String? = nil) throws -> JSONValue {
        let head = try trajectoryHead(steps)
        let s = salt ?? Base64URLStrict.encode((0..<16).map { _ in UInt8.random(in: 0...255) })
        let commit = try trajectoryAnchorCommit(.string(s), head)
        let appended = try ledger.appendCommitment(commit)
        return .object(["head": head, "salt": .string(s), "commit": .string(commit), "index": .int(Int64(appended.index)), "ledgerHead": ledger.head()])
    }
}
