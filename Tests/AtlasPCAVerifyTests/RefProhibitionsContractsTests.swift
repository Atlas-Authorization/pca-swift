import XCTest
import Foundation
@testable import AtlasPCAVerify

/// A signed document of the reference: byte-exact where Ed25519 signing is deterministic. Apple's CryptoKit signs Ed25519 with a random nonce, so there
/// everything but `sig` is compared exactly and the signature is verified by the module's own verifier.
func refSignedDocument(_ c: BaseCase, _ got: BaseGot, _ verify: (JSONValue) -> Bool) -> BaseGot {
    #if os(Linux)
    return got
    #else
    guard case let .value(g) = got, !c.threw, case var .object(a) = c.out, case var .object(b) = g, b[JKey("sig")]?.asString != nil else { return got }
    a[JKey("sig")] = nil
    b[JKey("sig")] = nil
    guard Base.canon(.object(a)) == Base.canon(.object(b)), verify(g) else { return got }
    return .value(c.out)
    #endif
}

/// The prohibition names neither the shared vectors nor the base corpus reach: the constants, validateWhen, whenMatches, signConstitution, composeAuthority,
/// the non-strict advanceState and evidenceDigest. Every case of the reference corpus is replayed.
final class RefProhibitionsTests: XCTestCase {
    typealias B = BaseProhibitionsOracleTests
    typealias P = Prohibitions

    static func call(_ c: BaseCase) -> BaseGot? {
        let a0 = c.arg(0), a1 = c.arg(1), a2 = c.arg(2), a3 = c.arg(3)
        switch c.fn {
        case "constants":
            return .value(.object([
                "CONSTITUTION_VERSION": .int(Int64(P.CONSTITUTION_VERSION)), "CONSTITUTION_SIG_DOMAIN": .string(P.CONSTITUTION_SIG_DOMAIN),
                "EVIDENCE_VERSION": .int(Int64(P.EVIDENCE_VERSION)), "SAFETY_EVIDENCE_SIG_DOMAIN": .string(P.SAFETY_EVIDENCE_SIG_DOMAIN),
                "STATE_DIGEST_DOMAIN": .string(P.STATE_DIGEST_DOMAIN), "STATE_CHAIN_DOMAIN": .string(P.STATE_CHAIN_DOMAIN), "MAX_LEDGER": .int(Int64(P.MAX_LEDGER)),
                "MAX_INVARIANTS": .int(Int64(P.MAX_INVARIANTS)), "MAX_DEADLINE": .int(Int64(P.MAX_DEADLINE)),
            ]))
        // the label is interpolated into the message, so a label that is not a string reads as its JavaScript text
        case "validateWhen": return .value(B.opt(P.validateWhen(a0, JS.toString(a1))))
        case "whenMatches": return .value(.bool(P.whenMatches(a0, a1)))
        case "signConstitution":
            return refSignedDocument(c, Base.run({ _ in nil }) { try P.signConstitution(a0 ?? .null, principal: try B.key(a1)) }) { P.verifyConstitution($0).ok }
        case "composeAuthority":
            // permitted counts only when it is exactly true
            let r = P.composeAuthority(permitted: a0 == .bool(true), a1, a2, a3)
            return .value(.object(["allow": .bool(r.allow), "decidedBy": .string(r.decidedBy), "permitted": .bool(r.permitted), "prohibition": r.prohibition.json]))
        case "advanceState": return .value(P.advanceState(a0, a1, a2 ?? .null, now: B.optNum(a3)))
        case "evidenceDigest": return Base.run({ _ in nil }) { .string(try P.evidenceDigest(a0 ?? .null)) }
        default: return nil
        }
    }

    func testEveryCaseOfTheReferenceCorpus() throws {
        let d = Base.Diffs()
        let n = try Base.each("ref-prohibitions.json.gz", seeds: true) { c in
            guard let got = Self.call(c) else { XCTFail("unhandled fn \(c.fn)"); return }
            d.add(c, Base.diff(c, got))
        }
        XCTAssertEqual(n, 1637)
        d.finish(1634) // three cases carry a lone surrogate, which a Swift String cannot hold
    }

    func testTheSpreadOfANonObjectBody() throws {
        // `{id, sig, ...rest} = c`: an array or a string spreads into its indexed members, a number has none, null has nothing to take
        XCTAssertEqual(try P.constitutionId(.string("x")), try P.constitutionId(.object(["0": .string("x")])))
        XCTAssertEqual(try P.constitutionId(.array([.int(7)])), try P.constitutionId(.object(["0": .int(7)])))
        XCTAssertEqual(try P.constitutionId(.int(5)), try P.constitutionId(.object([:])))
        XCTAssertThrowsError(try P.constitutionId(.null))
        XCTAssertThrowsError(try P.constitutionId(.string("\u{1F600}")))
    }
}

/// The contracts surface (clauses, contract id and signature, the embedded constitution, check, advance, check-and-advance with their options), every case
/// of the reference corpus.
final class RefContractsTests: XCTestCase {
    typealias B = BaseProhibitionsOracleTests

    static func advanced(_ r: AdvanceContractResult, composed: Bool) -> JSONValue {
        var o: JObject = ["ok": .bool(r.ok), "violated": B.strs(r.violated), "reasons": B.strs(r.reasons), "evaluated": .array(r.evaluated), "next": r.next,
                          "decidedBy": .string(r.decidedBy)]
        if composed {
            o[JKey("allow")] = .bool(r.allow)
            o[JKey("permitted")] = .bool(r.permitted)
        }
        return .object(o)
    }

    static func call(_ c: BaseCase) -> BaseGot? {
        let a0 = c.arg(0), a1 = c.arg(1), a2 = c.arg(2), a3 = c.arg(3)
        switch c.fn {
        case "constants":
            return .value(.object(["CONTRACT_VERSION": .int(Int64(Contracts.CONTRACT_VERSION)), "CONTRACT_SIG_DOMAIN": .string(Contracts.CONTRACT_SIG_DOMAIN),
                                   "MAX_CLAUSES": .int(Int64(Contracts.MAX_CLAUSES)), "MAX_CLAUSE_DEPTH": .int(Int64(Contracts.MAX_CLAUSE_DEPTH))]))
        case "validateClause":
            var seen = Set((a1?.asArray ?? []).compactMap { $0.asString.map { JKey($0) } })
            return .value(B.strs(Contracts.validateClause(a0, &seen, Int(IV.num(a2) ?? 1))))
        case "contractId": return Base.run({ _ in nil }) { .string(try Contracts.contractId(a0 ?? .null)) }
        case "signContract":
            return refSignedDocument(c, Base.run({ _ in nil }) { try Contracts.signContract(a0 ?? .null, principal: try B.key(a1)) }) { Contracts.verifyContract($0).ok }
        case "embeddedConstitution": return Base.run({ _ in nil }) { try Contracts.embeddedConstitution(a0 ?? .null) }
        case "contractFromConstitution": return Base.run({ _ in nil }) { try Contracts.contractFromConstitution(a0 ?? .null) }
        case "checkContract": return .value(Contracts.checkContract(a0, a1, a2).json)
        // the options document is passed as the reference received it: absent, null, or an object with members of any type
        case "advanceContract": return .value(advanced(Contracts.advanceContract(a0, a1, a2, options: a3), composed: false))
        case "checkAndAdvanceContract":
            return .value(advanced(Contracts.checkAndAdvanceContract(permitted: a0 == .bool(true), a1, a2, a3, options: c.arg(4)), composed: true))
        default: return nil
        }
    }

    func testEveryCaseOfTheReferenceCorpus() throws {
        let d = Base.Diffs()
        let n = try Base.each("ref-contracts.json.gz", seeds: true) { c in
            guard let got = Self.call(c) else { XCTFail("unhandled fn \(c.fn)"); return }
            d.add(c, Base.diff(c, got))
        }
        XCTAssertEqual(n, 1269)
        d.finish(1267) // two cases carry a lone surrogate
    }
}
