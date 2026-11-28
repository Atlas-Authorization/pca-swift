import Foundation

/// The k-of-n semantic judge threshold: signed judge verdicts bound to one action and goal, one key one vote, an optional split-conformal
/// cutoff on the aggregate score. Verdicts are JSON {judge, actionDigest, goalCommitment, faithful, score, judgeMeasurement, sig, alg?,
/// pq_pk?, pq_sig?}. The attested-judge gate (a hardware-attested enclave appraisal) is injected as a predicate over a verdict: when
/// given, a verdict it rejects does not vote.
public enum PCAIntentSemantic {
    public static let SEMANTIC_JUDGE_DOMAIN = "atlas-pca/semantic-judge/v1\u{0}"
    public static let SCORE_SCALE = 1000000.0

    private static func fin(_ x: Double) -> Bool { !x.isNaN && !x.isInfinite }

    /// A score on the integer grid [0, 1e6]; non-finite is 0.
    public static func quantizeScore(_ score: Double) -> Int64 {
        if !fin(score) { return 0 }
        let q = WJ.jsRound(score * SCORE_SCALE) + 0
        let c = q < 0 ? 0.0 : (q > SCORE_SCALE ? SCORE_SCALE : q)
        return Int64(c)
    }

    /// The signed statement of a verdict (suite fields bound in for a non-ed25519 suite).
    public static func statementOf(_ v: JSONValue) throws -> JSONValue {
        let o = try IntentTree.obj(v)
        var base = JObject()
        base["v"] = .int(1)
        base["actionDigest"] = o["actionDigest"] ?? .null
        base["goalCommitment"] = o["goalCommitment"] ?? .null
        base["faithful"] = .bool(o["faithful"] == .bool(true))
        base["score_ppm"] = .int(quantizeScore(IV.num(o["score"]) ?? Double.nan))
        let jm = IntentTree.present(o["judgeMeasurement"])
        if let m = jm { base["judgeMeasurement"] = .string(m.asString ?? JS.toString(m)) } else { base["judgeMeasurement"] = .string("") }
        // an unresolvable or ed25519 suite binds nothing; any other binds its name and (when present) the PQ key
        if let alg = o["alg"]?.asString, alg != "ed25519", PQ.resolve(alg) != nil {
            base["alg"] = .string(alg)
            if let pk = o["pq_pk"] { base["pq_pk"] = pk }
        }
        return .object(base)
    }

    /// Verify ONE verdict against an expected action / goal binding. Total: never throws. `pqPins` maps a judge key to the verifier's
    /// pinned post-quantum key.
    public static func verifyJudgeVerdict(_ vo: JSONValue?, _ expectedAction: String?, _ expectedGoal: String?, _ pqPins: JSONValue?) -> Bool {
        guard let v = vo?.asObject else { return false }
        guard let judge = v["judge"]?.asString, IV.digest(.string(judge)) != nil else { return false }
        guard let ad = v["actionDigest"]?.asString, let gc = v["goalCommitment"]?.asString else { return false }
        guard let ea = expectedAction, let eg = expectedGoal, IV.same(ad, ea), IV.same(gc, eg) else { return false }
        guard case .bool? = v["faithful"] else { return false }
        guard let score = IV.num(v["score"]), fin(score), score >= 0, score <= 1 else { return false }
        guard v["judgeMeasurement"]?.asString != nil, v["sig"]?.asString != nil else { return false }
        if IV.sigAlg(v["alg"]) == nil { return false }
        guard let stmt = try? statementOf(.object(v)), let msg = IV.message(SEMANTIC_JUDGE_DOMAIN, stmt) else { return false }
        let pin = pqPins?.asObject?[JKey(judge)]?.asString
        return IV.verifyPinned(alg: v["alg"], identity: judge, artifactPqPk: v["pq_pk"], msg: msg, sig: v["sig"], pqSig: v["pq_sig"], pin: pin) == .valid
    }

    private static func clampAlpha(_ alpha: JSONValue?) -> Double {
        guard let a = IV.num(alpha), fin(a) else { return 1.0 }
        if a <= 0 { return Double.leastNonzeroMagnitude }
        return a > 1 ? 1.0 : a
    }

    private static func unfaithful(_ samples: JSONValue?) -> [Double] {
        var out: [Double] = []
        guard let list = samples?.asArray else { return out }
        for so in list {
            guard let o = so.asObject else { continue }
            if o["faithful"] == .bool(false), let sc = IV.num(o["score"]), fin(sc) { out.append(sc) }
        }
        return out
    }

    /// The split-conformal upper quantile of the unfaithful scores (+Infinity when too few to certify alpha).
    public static func conformalThreshold(_ calibration: JSONValue?) -> Double {
        let c = calibration?.asObject
        let alpha = clampAlpha(c?[JKey("alpha")])
        var u = unfaithful(c?[JKey("samples")])
        let m = u.count
        if m == 0 { return Double.infinity }
        let rank = (Double(m + 1) * (1 - alpha)).rounded(.up)
        if rank > Double(m) { return Double.infinity }
        u.sort()
        return u[Int(max(rank, 1.0)) - 1]
    }

    /// Fraction of the unfaithful samples whose score exceeds the cutoff (0 with none).
    public static func empiricalFalseAllowRate(_ samples: JSONValue?, _ cutoff: Double) -> Double {
        var m = 0
        var allowed = 0
        for sc in unfaithful(samples) {
            m += 1
            if sc > cutoff { allowed += 1 }
        }
        return m == 0 ? 0.0 : Double(allowed) / Double(m)
    }

    /// {ok, agreeCount, aggregateScore, cutoff?, reason?}; the cutoff may be +Infinity (too few calibration samples to certify alpha).
    private static func result(_ ok: Bool, _ agree: Int, _ score: Double, _ cutoff: Double?, _ reason: String?) -> JSONValue {
        var r: JObject = ["ok": .bool(ok), "agreeCount": .int(Int64(agree)), "aggregateScore": .double(score)]
        if let c = cutoff { r["cutoff"] = .double(c) }
        if let m = reason { r["reason"] = .string(m) }
        return .object(r)
    }

    /// Verify a k-of-n ensemble. `opts`: judgeKeys, k, goalCommitment, actionDigest, calibration?, pqPins?. `attestationGate`
    /// (optional) must accept a verdict for it to vote.
    public static func verifySemanticThreshold(_ verdicts: JSONValue?, _ opts: JSONValue, _ attestationGate: ((JSONValue) -> Bool)? = nil) -> JSONValue {
        let o = opts.asObject ?? JObject()
        let k = o["k"]
        var allow = Set<JKey>()
        if let jk = o["judgeKeys"]?.asArray {
            for key in jk { if let s = key.asString, IV.digest(key) != nil { allow.insert(JKey(s)) } }
        }
        guard let ad = o["actionDigest"]?.asString, let gc = o["goalCommitment"]?.asString else {
            return result(false, 0, 0.0, nil, "missing action/goal binding")
        }
        guard let kd = IV.num(k), fin(kd), kd == kd.rounded(.down), kd >= 1 else {
            return result(false, 0, 0.0, nil, "invalid quorum k=" + JS.toString(k))
        }
        let pins = o["pqPins"]
        var order: [JKey] = []
        var byJudge: [JKey: (faithful: [Bool], scores: [Int64])] = [:]
        if let list = verdicts?.asArray {
            for vo in list {
                guard let v = vo.asObject, let judge = v["judge"]?.asString, allow.contains(JKey(judge)) else { continue }
                if !verifyJudgeVerdict(vo, ad, gc, pins) { continue }
                if let gate = attestationGate, !gate(vo) { continue }
                var g = byJudge[JKey(judge)] ?? (faithful: [], scores: [])
                if byJudge[JKey(judge)] == nil { order.append(JKey(judge)) }
                let f = v["faithful"] == .bool(true)
                if !g.faithful.contains(f) { g.faithful.append(f) }
                let q = quantizeScore(IV.num(v["score"]) ?? 0)
                if !g.scores.contains(q) { g.scores.append(q) }
                byJudge[JKey(judge)] = g
            }
        }
        var agreeing: [(judge: String, score: Int64)] = []
        for j in order {
            guard let g = byJudge[j] else { continue }
            if g.faithful.count == 1 && g.faithful[0] && g.scores.count == 1 { agreeing.append((j.s, g.scores[0])) }
        }
        agreeing.sort { Canonical.compareUtf8($0.judge, $1.judge) < 0 }
        let agree = agreeing.count
        var acc = 0.0
        for a in agreeing { acc += Double(a.score) / SCORE_SCALE }
        let aggregate = agree == 0 ? 0.0 : acc / Double(agree)
        if Double(agree) < kd {
            return result(false, agree, aggregate, nil, "only \(agree) distinct trusted judge(s) agree, need " + JS.toString(k))
        }
        if let cal = IntentTree.present(o["calibration"]) {
            let cutoff = conformalThreshold(cal)
            if !(aggregate > cutoff) {
                return result(false, agree, aggregate, cutoff,
                              "aggregateScore " + JS.toString(.double(aggregate)) + " does not exceed calibrated cutoff " + JS.toString(.double(cutoff)))
            }
            return result(true, agree, aggregate, cutoff, nil)
        }
        return result(true, agree, aggregate, nil, nil)
    }
}
