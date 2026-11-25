import XCTest
import Foundation
@testable import AtlasPCAVerify
#if canImport(AtlasPCAOpenSSL)
import AtlasPCAOpenSSL
#endif

/// The leftovers of five intent modules against ref-intent-misc2: the shared strict-artifact helpers (this group), the signed question and problem,
/// the classifier verdicts, the accumulator receipts and sequencer key sets and the session-store half of the history. Each group is replayed with its fn set
/// and its case total asserted. Signing under ML-DSA is compared byte for byte when the opt-in OpenSSL product is linked.
final class RefIntentMisc2Tests: XCTestCase {
    typealias A = RefAnalyzer
    typealias R = PCAIntentArtifacts

    static func mlDsa(_ seed: [UInt8]) throws -> PCAPQKey {
        #if canImport(AtlasPCAOpenSSL)
        if PCAOpenSSL.mlDsaAvailable() { return try PCAOpenSSL.mlDsaKey(.mlDsa65, seed: seed) }
        #endif
        return try PCAPQKey.fromSeed(.mlDsa65, seed: seed)
    }
    static var exactMlDsa: Bool {
        #if canImport(AtlasPCAOpenSSL)
        return PCAOpenSSL.mlDsaAvailable()
        #else
        return false
        #endif
    }

    /// A signing key of `(secret, suite)` arguments (`suite` is `{alg, pqSeed}` or null).
    static func key(_ secret: JSONValue?, _ suite: JSONValue?) throws -> PCASuiteKey {
        guard let s = Base.bytes(secret) else { throw PCAProducerError("secret") }
        let ed = try Ed25519Deterministic.key(seed: s)
        var key = PCASuiteKey.ed25519(ed)
        if let su = JS.present(suite) {
            guard let alg = IV.sigAlg(su.get("alg")) else { throw PCAProducerError("alg") }
            key = try PCASuiteKey(alg: alg, ed: ed, pq: try Base.bytes(su.get("pqSeed")).map { try mlDsa($0) })
        }
        return key
    }

    private static func strings(_ v: JSONValue?) -> [String]? { v?.asArray.map { $0.compactMap { $0.asString } } }

    static let artifactFns: Set<String> = ["isPathSegment", "isPlainObject", "isSafeInt", "utf8Len", "isBoundedString", "isDigest", "isScalar", "scalarEq", "closedMembers", "pinPqOk",
                                           "artifactSuiteError", "artifactMessage", "signArtifact", "verifyArtifactSig", "artifactRef", "publicKeyB64u", "resolveParamPath", "isParamPath",
                                           "setNested", "isClock", "ownGet", "nullRecord"]

    static func artifactCall(_ c: BaseCase) -> BaseGot? {
        let a0 = A.arg(c, 0), a1 = A.arg(c, 1), a2 = A.arg(c, 2), a3 = A.arg(c, 3)
        switch c.fn {
        case "isPathSegment": return .value(.bool(R.isPathSegment(a0)))
        case "isPlainObject": return .value(.bool(R.isPlainObject(a0)))
        case "isSafeInt": return .value(.bool(R.isSafeInt(a0)))
        case "isClock": return .value(.bool(R.isClock(a0)))
        case "utf8Len": return A.run { .int(Int64(R.utf8Len(a0?.asString ?? ""))) }
        case "isBoundedString": return .value(.bool(R.isBoundedString(a0, IV.num(a1) ?? .nan)))
        case "isDigest": return .value(.bool(R.isDigest(a0)))
        case "isScalar": return .value(.bool(R.isScalar(a0)))
        case "scalarEq": return .value(.bool(R.scalarEq(a0, a1)))
        case "closedMembers":
            guard let o = a0?.asObject else { return .threw(nil) }
            return .value(R.closedMembers(o, required: strings(a1) ?? [], optional: strings(a2), where: a3?.asString).map { .string($0) } ?? .null)
        case "pinPqOk": return .value(.bool(R.pinPqOk(a0 ?? nil)))
        case "artifactSuiteError": return .value(R.artifactSuiteError(a0).map { .string($0) } ?? .null)
        case "artifactMessage": return A.run { Base.bytesValue(try R.artifactMessage(a0?.asString ?? "", a1 ?? .null)) }
        case "signArtifact": return A.run { try R.signArtifact(a0?.asString ?? "", a1 ?? .null, key: try key(a2, a3)) }
        case "verifyArtifactSig": return .value(.bool(R.verifyArtifactSig(a0?.asString ?? "", a1 ?? .null, pin: a2 ?? .null)))
        case "artifactRef": return A.run { .string(try R.artifactRef(a0?.asString ?? "", a1?.asString ?? "", a2 ?? .null)) }
        case "publicKeyB64u": return A.run { guard let s = Base.bytes(a0) else { throw JSError("secret") }; return .string(R.publicKeyB64u(s)) }
        case "resolveParamPath":
            let r = R.resolveParamPath(a0, a1)
            return .value(.object(r.found ? ["found": .bool(true), "value": r.value ?? .null] : ["found": .bool(false)]))
        case "isParamPath": return .value(.bool(R.isParamPath(a0)))
        case "setNested":
            guard let root = a0?.get("root")?.asObject, let path = a0?.get("path")?.asString else { return .threw(nil) }
            let r = R.setNested(root, path, a0?.get("value") ?? .null)
            return .value(.object(["ok": .bool(r.ok), "root": .object(r.root)]))
        case "ownGet": return .value(R.ownGet(a0, a1?.asString ?? "") ?? .null)
        case "nullRecord": return .value(.object([:]))
        default: return nil
        }
    }

    /// A message or key made by the platform's hedged ML-DSA differs from the reference in the ML-DSA signature only.
    static func signed(_ c: BaseCase, _ got: BaseGot) -> BaseGot {
        if !exactMlDsa, !c.threw, c.fn == "signIntentRequired", case let .value(v) = got, case var .object(mine) = v, case var .object(want) = c.out,
           case var .object(ms)? = mine["sig"], case var .object(ws)? = want["sig"], let alg = ws["alg"]?.asString, alg != "ed25519" {
            let f = JKey(alg.hasPrefix("hybrid") ? "pq_value" : "value")
            ms[f] = nil; ws[f] = nil; mine["sig"] = .object(ms); want["sig"] = .object(ws)
            return Base.canon(.object(mine)) == Base.canon(.object(want)) ? .value(c.out) : got
        }
        guard !exactMlDsa, !c.threw, case let .value(v) = got, case var .object(mine) = v, case var .object(want) = c.out, let alg = want["alg"]?.asString, alg != "ed25519" else { return got }
        let field = JKey(alg.hasPrefix("hybrid") ? "pq_sig" : "sig")
        guard mine[field] != nil else { return got }
        mine[field] = nil
        want[field] = nil
        return Base.canon(.object(mine)) == Base.canon(.object(want)) ? .value(c.out) : got
    }

    /// Replays the cases of `fns` and asserts their number and per-fn counts.
    func replay(_ fns: Set<String>, call: (BaseCase) -> BaseGot?, total: Int, counts: [String: Int]) throws {
        let d = Base.Diffs()
        var seen: [String: Int] = [:]
        let n = try Base.each("ref-intent-misc2.json.gz", fns, seeds: true) { c in
            seen[c.fn, default: 0] += 1
            guard let got = call(c) else { XCTFail("unhandled fn \(c.fn)"); return }
            let diff = Base.diff(c, Self.signed(c, got))
            if diff != nil, !MLDSA.available, Base.canon(.array(c.args)).contains("ml-dsa") { d.skip("ML-DSA is not available on this OS"); return }
            d.add(c, diff)
        }
        XCTAssertEqual(n, total)
        XCTAssertEqual(seen, counts)
        d.finish(total - d.skipped.values.reduce(0, +))
    }

    func testTheArtifactHelpers() throws {
        try replay(Self.artifactFns, call: Self.artifactCall, total: 254,
                   counts: ["isPathSegment": 16, "isPlainObject": 8, "isSafeInt": 12, "utf8Len": 7, "isBoundedString": 12, "isDigest": 12, "isScalar": 16, "scalarEq": 11, "closedMembers": 8,
                            "pinPqOk": 6, "artifactSuiteError": 12, "artifactMessage": 10, "signArtifact": 8, "verifyArtifactSig": 18, "artifactRef": 8, "publicKeyB64u": 2,
                            "resolveParamPath": 25, "isParamPath": 25, "setNested": 14, "isClock": 12, "ownGet": 11, "nullRecord": 1])
    }

    static let requiredFns: Set<String> = ["intentActionDigest", "cellCoordsError", "intentRequiredShapeError", "signIntentRequired", "verifyIntentRequired", "verifyIntentRequiredAt", "intentProblem"]

    static func requiredCall(_ c: BaseCase) -> BaseGot? {
        typealias Q = PCAIntentRequired
        let a0 = A.arg(c, 0), a1 = A.arg(c, 1), a2 = A.arg(c, 2), a3 = A.arg(c, 3)
        switch c.fn {
        case "intentActionDigest": return A.run { .string(try Q.intentActionDigest(a0)) }
        case "cellCoordsError": return .value(Q.cellCoordsError(a0).map { .string($0) } ?? .null)
        case "intentRequiredShapeError":
            let signed = a1?.get("signed") != .bool(false)
            return .value(Q.intentRequiredShapeError(a0, signed: signed).map { .string($0) } ?? .null)
        case "signIntentRequired": return A.run { try PCASigners.signIntentRequired(a0 ?? .null, kid: a1?.asString ?? "", site: try key(a2, a3)) }
        case "verifyIntentRequired", "verifyIntentRequiredAt": return .value(Q.verifyIntentRequiredAt(a0, a1, a2))
        case "intentProblem": return A.run { try Q.intentProblem(a0, detail: a1?.get("detail"), body: a1?.get("body")) }
        default: return nil
        }
    }

    func testTheQuestionAndItsProblem() throws {
        try replay(Self.requiredFns, call: Self.requiredCall, total: 224,
                   counts: ["intentActionDigest": 6, "cellCoordsError": 26, "intentRequiredShapeError": 90, "signIntentRequired": 8, "verifyIntentRequired": 26, "verifyIntentRequiredAt": 26, "intentProblem": 42])
    }

    static let classifierFns: Set<String> = ["validateClassifierVerdictWire", "classifierContentDigest", "signClassifierVerdict", "classifierVerdictRef", "validateClassifierPolicy",
                                             "classifierCheckActive", "decideClassifierDimensions", "verifyClassifierAttestation"]

    static func classifierCall(_ c: BaseCase) -> BaseGot? {
        typealias K = PCAIntentClassifier
        let a0 = A.arg(c, 0), a1 = A.arg(c, 1), a2 = A.arg(c, 2)
        switch c.fn {
        case "validateClassifierVerdictWire": return .value(K.validateClassifierVerdictWire(a0).map { .string($0) } ?? .null)
        case "classifierContentDigest": return A.run { .string(try K.classifierContentDigest(a0 ?? .null)) }
        case "signClassifierVerdict": return A.run { guard let sec = Base.bytes(a1) else { throw JSError("secret") }; return try K.signClassifierVerdict(a0 ?? .null, key: try key(a1, a2), secret: sec) }
        case "classifierVerdictRef": return A.run { .string(try K.classifierVerdictRef(a0 ?? .null)) }
        case "validateClassifierPolicy": return .value(K.validateClassifierPolicy(a0).map { .string($0) } ?? .null)
        case "classifierCheckActive": return .value(.bool(K.classifierCheckActive(a0)))
        case "decideClassifierDimensions": return .value(K.decideClassifierDimensions(a0))
        case "verifyClassifierAttestation": return .value(K.verifyClassifierAttestation(a0, a1, a2))
        default: return nil
        }
    }

    func testTheClassifierVerdicts() throws {
        try replay(Self.classifierFns, call: Self.classifierCall, total: 158,
                   counts: ["validateClassifierVerdictWire": 26, "classifierContentDigest": 12, "signClassifierVerdict": 7, "classifierVerdictRef": 5, "validateClassifierPolicy": 42,
                            "classifierCheckActive": 11, "decideClassifierDimensions": 44, "verifyClassifierAttestation": 11])
    }

    final class MemTx: PCAIntentSessionTx {
        var log: [JSONValue]
        init(_ l: [JSONValue]) { log = l }
        func events() throws -> [JSONValue] { log }
        func append(_ e: JSONValue) throws { log.append(e) }
        func setStatus(_ id: String, _ status: String) throws -> Bool {
            guard let i = log.firstIndex(where: { $0.get("id")?.asString == id }), case var .object(o) = log[i] else { return false }
            o["status"] = .string(status)
            log[i] = .object(o)
            return true
        }
    }
    final class MemStore: PCAIntentSessionStore {
        var durable: Bool? = true
        var logs: [String: [JSONValue]] = [:]
        func withSession<T>(_ session: String, _ fn: (PCAIntentSessionTx) throws -> T) throws -> T {
            let tx = MemTx(logs[session] ?? [])
            defer { logs[session] = tx.log }
            return try fn(tx)
        }
    }

    struct VerifyThrew: Error {}

    /// Replays a script of store operations and flattens what each one returned, as the reference does.
    static func admitCall(_ c: BaseCase) -> BaseGot? {
        guard let ops = A.arg(c, 0)?.asArray else { return .threw(nil) }
        let store = MemStore()
        var out: [JSONValue] = []
        let err: JSONValue = .object(["$err": .bool(true)])
        for op in ops {
            guard let parts = op.asArray, let name = parts.first?.asString else { return .threw(nil) }
            switch name {
            case "store":
                let d = parts[1].get("durable")
                store.durable = d == nil ? true : (d == .string("absent") ? nil : d == .bool(true))
                out.append(.null)
            case "admit":
                let a = parts[1]
                let verifyAs = a.get("verifyAs")
                do {
                    let v: JSONValue = try PCAIntentHistory.admitIntentAction(
                        store: store, session: a.get("session")?.asString ?? "", root: a.get("root"), event: a.get("event") ?? .null,
                        requireDurable: a.get("requireDurable") != .bool(false),
                        verify: { acc in
                            if verifyAs == .string("throws") { throw VerifyThrew() }
                            out.append(.object(["acc": acc]))
                            return verifyAs ?? .null
                        }, allow: { $0.get("allow") == .bool(true) })
                    out.append(v)
                } catch { out.append(err) }
            case "settle":
                if let r = try? PCAIntentHistory.settleIntentEvent(store: store, session: parts[1].asString ?? "", id: parts[2].asString ?? "", status: parts[3].asString ?? "") { out.append(.bool(r)) } else { out.append(err) }
            case "events": out.append(.array(store.logs[parts[1].asString ?? ""] ?? []))
            default: return .threw(nil)
            }
        }
        return .value(.array(out))
    }

    static func constantsValue() -> JSONValue {
        func re(_ s: String) -> JSONValue { .object(["$regex": .string(s)]) }
        func strs(_ a: [String]) -> JSONValue { .array(a.map { .string($0) }) }
        typealias Ar = PCAIntentArtifacts
        typealias Rq = PCAIntentRequired
        typealias Cl = PCAIntentClassifier
        typealias Ac = PCAIntentAcc
        return .object([
            "DATA_CLASS_RE": re(Ar.DATA_CLASS_RE), "INTENT_NAME_RE": re(Ar.INTENT_NAME_RE), "PARAM_SEGMENT_RE": re(Ar.PARAM_SEGMENT_RE), "SUITE_MEMBERS": strs(Ar.SUITE_MEMBERS),
            "FRICTIONS": strs(Rq.FRICTIONS), "INTENT_ACTION_DOMAIN": .string(Rq.INTENT_ACTION_DOMAIN), "INTENT_PROBLEM_KINDS": strs(Rq.INTENT_PROBLEM_KINDS),
            "INTENT_REQUIRED_DOMAIN": .string(Rq.INTENT_REQUIRED_DOMAIN), "PROBLEM_BASE": .string(Rq.PROBLEM_BASE),
            "INTENT_CLASSIFIER_DOMAIN": .string(Cl.INTENT_CLASSIFIER_DOMAIN), "INTENT_CLASSIFIER_REF_DOMAIN": .string(Cl.INTENT_CLASSIFIER_REF_DOMAIN),
            "MAX_CLASSIFIER_LABELS": .int(Int64(Cl.MAX_CLASSIFIER_LABELS)), "MAX_COMMITTED_CLASSES": .int(Int64(Cl.MAX_COMMITTED_CLASSES)),
            "ACC_AGGS": strs(Ac.ACC_AGGS), "ACC_ID_RE": re(Ac.ACC_ID_RE), "ACC_RECEIPT_CORE_DOMAIN": .string(Ac.ACC_RECEIPT_CORE_DOMAIN), "ACC_RECEIPT_DOMAIN": .string(Ac.ACC_RECEIPT_DOMAIN),
            "ACC_RECEIPT_REF_DOMAIN": .string(Ac.ACC_RECEIPT_REF_DOMAIN), "ACC_RESERVE_DOMAIN": .string(Ac.ACC_RESERVE_DOMAIN), "ACC_SCOPES": strs(Ac.ACC_SCOPES),
            "DEFAULT_MAX_KEYSET_AGE_MS": .int(Int64(Ac.DEFAULT_MAX_KEYSET_AGE_MS)), "DEFAULT_MAX_RECEIPT_AGE_MS": .int(Int64(Ac.DEFAULT_MAX_RECEIPT_AGE_MS)), "KID_RE": re(Ac.KID_RE),
            "MAX_MONITOR_WITHIN": .int(Int64(Ac.MAX_MONITOR_WITHIN)), "MAX_RECEIPT_LIFETIME_MS": .int(Int64(Ac.MAX_RECEIPT_LIFETIME_MS)),
            "MAX_SESSION_ACCUMULATORS": .int(Int64(Ac.MAX_SESSION_ACCUMULATORS)), "MAX_SESSION_MONITORS": .int(Int64(Ac.MAX_SESSION_MONITORS)), "MONITOR_KINDS": strs(Ac.MONITOR_KINDS),
            "RECEIPT_SKEW_MS": .int(Int64(Ac.RECEIPT_SKEW_MS)), "SEQUENCER_KEYS_DOMAIN": .string(Ac.SEQUENCER_KEYS_DOMAIN), "SEQUENCER_KEYS_REF_DOMAIN": .string(Ac.SEQUENCER_KEYS_REF_DOMAIN),
            "COUNTED_STATUSES": strs(Ac.COUNTED_STATUSES), "EVENT_STATUSES": strs(Ac.EVENT_STATUSES),
        ])
    }

    static let accFns: Set<String> = ["constants", "monitorStates", "monitorInitialState", "distinctKey", "sortedDistinct", "signAccReceipt", "accReceiptDigest", "accReceiptCoreDigest",
                                      "verifyReceiptSignature", "signSequencerKeySet", "sequencerKeySetDigest", "verifyKeySet", "accContextFor", "admit"]
    /// The one reference case that supplies `allowUnboundPq` (accepting a post-quantum half with no pinned key): refused here, by decision.
    static var unboundRefused = 0

    static func accCall(_ c: BaseCase) -> BaseGot? {
        typealias K = PCAIntentAcc
        let a0 = A.arg(c, 0), a1 = A.arg(c, 1), a2 = A.arg(c, 2), a3 = A.arg(c, 3)
        switch c.fn {
        case "constants": return .value(constantsValue())
        case "monitorStates": return .value(K.monitorStates(a0).map { .array($0.map { .string($0) }) } ?? .null)
        case "monitorInitialState": return .value(.string(K.monitorInitialState(a0)))
        case "distinctKey": return .value(K.distinctKey(a0).map { .string($0) } ?? .null)
        case "sortedDistinct": return .value(.array(K.sortedDistinct((a0?.asArray ?? []).compactMap { $0.asString }).map { .string($0) }))
        case "signAccReceipt": return A.run { guard let sec = Base.bytes(a1) else { throw JSError("secret") }; return try K.signAccReceipt(a0 ?? .null, key: try key(a1, a2), secret: sec) }
        case "accReceiptDigest": return A.run { .string(try K.accReceiptDigest(a0 ?? .null)) }
        case "accReceiptCoreDigest": return A.run { .string(try K.accReceiptCoreDigest(a0 ?? .null)) }
        case "verifyReceiptSignature":
            let ok = K.verifyAccReceiptSignature(a0, expectedSigner: a1?.asString ?? "", pin: a2)
            if a2?.get("allowUnboundPq") == .bool(true) {
                XCTAssertFalse(ok, "allowUnboundPq is never ported: an unbound post-quantum half is refused")
                unboundRefused += 1
                return .value(c.out)
            }
            return .value(.bool(ok))
        case "signSequencerKeySet": return A.run { guard let sec = Base.bytes(a1) else { throw JSError("secret") }; return try K.signSequencerKeySet(a0 ?? .null, key: try key(a1, a2), rootSecret: sec) }
        case "sequencerKeySetDigest": return A.run { .string(try K.sequencerKeySetDigest(a0 ?? .null)) }
        case "verifyKeySet": return .value(.bool(K.verifySequencerKeySet(a0, root: a1?.asString ?? "", rootPqPk: a2)))
        case "accContextFor": return A.run { try PCAIntentHistory.accContextFor(a0, a1?.asArray ?? [], a2, a3) }
        case "admit": return admitCall(c)
        default: return nil
        }
    }

    func testTheAccumulatorReceiptsAndSessionStore() throws {
        Self.unboundRefused = 0
        try replay(Self.accFns, call: Self.accCall, total: 134,
                   counts: ["constants": 1, "monitorStates": 13, "monitorInitialState": 13, "distinctKey": 18, "sortedDistinct": 7, "signAccReceipt": 16, "accReceiptDigest": 4,
                            "accReceiptCoreDigest": 4, "verifyReceiptSignature": 8, "signSequencerKeySet": 15, "sequencerKeySetDigest": 3, "verifyKeySet": 8, "accContextFor": 13, "admit": 11])
        XCTAssertEqual(Self.unboundRefused, 1)
    }

    /// The whole corpus, no fn filter: every case of the file belongs to one of the groups above.
    func testNoCaseOfTheCorpusIsLeftOut() throws {
        let all = Self.artifactFns.union(Self.requiredFns).union(Self.classifierFns).union(Self.accFns)
        var n = 0
        let total = try Base.each("ref-intent-misc2.json.gz", seeds: true) { c in
            n += 1
            XCTAssertTrue(all.contains(c.fn), "a corpus fn no group replays: \(c.fn)")
        }
        XCTAssertEqual(total, 770)
        XCTAssertEqual(n, 770)
    }
}
