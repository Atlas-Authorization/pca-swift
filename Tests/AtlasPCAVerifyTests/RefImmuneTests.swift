import XCTest
import Foundation
@testable import AtlasPCAVerify

/// Differential replay of the immune system's adaptation, no-widen check, digests, signed tightening proposals and durable store against the
/// reference. The guardian key is rebuilt from the seed label the corpus names (sha256 of "atlas-pca-conformance/immune/<label>"); Ed25519
/// signatures are deterministic, so proposals compare byte for byte.
final class RefImmuneTests: XCTestCase {
    static let file = "ref-immune-java.json.gz"
    typealias I = PCAImmune

    static func key(_ label: String) throws -> PCAEdKey {
        try Ed25519Deterministic.key(seed: Canonical.sha256(Array("atlas-pca-conformance/immune/\(label)".utf8)))
    }

    /// The pinned guardian "@g" is the public key of the seed labelled g.
    static func pin(_ opts: JSONValue?) throws -> JSONValue? {
        guard var o = opts?.asObject, o["guardian"] == .string("@g") else { return opts }
        o["guardian"] = .string(try key("g").id)
        return .object(o)
    }

    static func assessment(_ v: JSONValue?) -> I.Assessment? {
        guard let level = v?.get("level")?.asString, let score = IV.num(v?.get("score")), let sig = v?.get("signals")?.asArray, sig.allSatisfy({ $0.asString != nil }),
              let c = v?.get("components"), let d = IV.num(c.get("drift")), let vo = IV.num(c.get("volatility")), let vi = IV.num(c.get("violation")) else { return nil }
        return I.Assessment(level: level, score: score, signals: sig.compactMap { $0.asString }, drift: d, volatility: vo, violation: vi)
    }

    static func hasWeights(_ v: JSONValue?) -> Bool { v?.get("weights")?.asObject != nil }

    func testImmune() throws {
        let d = Base.Diffs()
        try Base.each(Self.file) { c in
            let a0 = c.arg(0), a1 = c.arg(1)
            let got: BaseGot
            switch c.fn {
            case "adapt":
                guard let base = a0?.asObject, let a = Self.assessment(a1) else { d.skip("adapt: untyped input (a Swift type error)"); return }
                if c.threw { d.skip("adapt: the reference throws on this input"); return }
                let r = I.adapt(base, a)
                got = .value(.object(["policy": .object(r.policy), "changed": .bool(r.changed), "rationale": .string(r.rationale)]))
            case "noWidenViolation":
                guard let b = a0?.asObject, let n = a1?.asObject, Self.hasWeights(a0), Self.hasWeights(a1) else { d.skip("noWidenViolation: untyped input"); return }
                got = .value(I.noWidenViolation(b, n).map { .string($0) } ?? .null)
            case "policyDigest": got = .value(.string(I.policyDigest(a0 ?? .null)))
            case "immuneStateDigest": got = .value(.string(I.immuneStateDigest(a0 ?? .null)))
            case "issueTighteningProposal":
                guard let label = c.arg(4)?.asString else { d.skip("issueTighteningProposal: untyped"); return }
                got = Ref.v { try I.issueTighteningProposal(base: a0 ?? .null, state: a1 ?? .null, epoch: c.arg(2) ?? .null, now: c.arg(3) ?? .null, guardian: try Self.key(label)) }
            case "applyTightening":
                got = .value(I.applyTightening(base: a0 ?? .null, proposal: a1, options: try Self.pin(c.arg(2))))
            case "store":
                guard let subject = a0?.asString, let ops = a1?.asArray else { d.skip("store: untyped"); return }
                let kv = MemoryAtomicKV()
                let st = I.ImmuneStore(kv: kv, subject: subject)
                var out: [JSONValue] = []
                for o in ops {
                    let op = o.asArray ?? []
                    func at(_ i: Int) -> JSONValue? { i < op.count ? op[i] : nil }
                    do {
                        switch op.first?.asString {
                        case "seed": kv.update("immune/state/\(subject)") { _ in at(1) ?? .null }; out.append(.null)
                        case "get": out.append(try st.get())
                        case "observe": out.append(try st.observe(at(1) ?? .null))
                        case "lastEpoch": out.append(.int(try st.lastEpoch()))
                        case "apply": out.append(try st.apply(base: at(1) ?? .null, proposal: at(2), options: try Self.pin(at(3))))
                        default: throw JSError("op")
                        }
                    } catch { out.append(.object(["$err": .string("Error")])) }
                }
                got = .value(.array(out))
            default: d.skip("\(c.fn): not mapped"); return
            }
            d.add(c, Base.diff(c, got))
        }
        d.finish(300)
    }
}
