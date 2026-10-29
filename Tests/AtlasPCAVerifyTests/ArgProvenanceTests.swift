import XCTest
import Foundation
@testable import AtlasPCAVerify

/// Provenance by default: replays conformance/arg-provenance-vectors.json (every section; a missing file FAILS: load throws).
final class ArgProvVectorTests: XCTestCase {
    static func doc() throws -> JSONValue { try ConformanceTests.load("arg-provenance-vectors.json") }

    func testFormatAndPin() throws {
        let d = try Self.doc()
        XCTAssertEqual(d.get("format")?.asString, "pca-arg-provenance-vectors/1")
        XCTAssertTrue(PCA.isProvMediatorPin(try XCTUnwrap(d.get("pin"))))
    }

    func testTokens() throws {
        let cases = try XCTUnwrap(Self.doc().get("tokens")?.asArray)
        XCTAssertGreaterThanOrEqual(cases.count, 18)
        for c in cases {
            let t = c.get("text")?.asString ?? "", n = c.get("needle")?.asString ?? ""
            XCTAssertEqual(PCA.occursAsToken(t, n), c.get("expect") == .bool(true), "\(t) / \(n)")
        }
    }

    func testLeaves() throws {
        let cases = try XCTUnwrap(Self.doc().get("leaves")?.asArray)
        XCTAssertGreaterThanOrEqual(cases.count, 11)
        for c in cases {
            let name = c.get("name")?.asString ?? "?"
            let got = PCA.provLeaves(c.get("value") ?? .null)
            if let want = c.get("expect")?.asArray {
                XCTAssertEqual(got, want.compactMap { $0.asString }, name)
            } else {
                XCTAssertNil(got, name)
            }
        }
    }

    func testReadOnly() throws {
        let cases = try XCTUnwrap(Self.doc().get("read_only")?.asArray)
        XCTAssertGreaterThanOrEqual(cases.count, 7)
        for c in cases {
            let a = c.get("action")
            XCTAssertEqual(PCA.isReadOnlyAction(a == .null ? nil : a), c.get("expect") == .bool(true), c.get("name")?.asString ?? "?")
        }
    }

    static func input(_ i: JSONValue) -> ArgProvenanceInput {
        ArgProvenanceInput(bundle: i.get("bundle"), operation: i.get("operation") ?? .null, mediators: i.get("mediators") ?? .null,
                           action: i.get("action"), principalPlan: i.get("principal_plan") == .bool(true),
                           principalControl: i.get("principal_control") == .bool(true), observed: i.get("observed"))
    }

    /// Full equality: escalate reasons exact; a deny compares its code and only requires a non-empty reason.
    func testDecisions() throws {
        let cases = try XCTUnwrap(Self.doc().get("decisions")?.asArray)
        XCTAssertGreaterThanOrEqual(cases.count, 38)
        var bad: [String] = []
        var outcomes: Set<String> = []
        for c in cases {
            let name = c.get("name")?.asString ?? "?"
            let d = PCA.decideArgProvenance(Self.input(c.get("input") ?? .null))
            outcomes.insert(d.outcome)
            var got = d.json.asObject ?? [:]
            let want = c.get("expect")?.asObject ?? [:]
            if d.outcome == "deny" {
                if (d.reason ?? "").isEmpty { bad.append("\(name): a deny without a reason") }
                got["reason"] = want["reason"]
            }
            if JSONValue.object(got) != JSONValue.object(want) { bad.append("\(name): got \(Canonical.canonicalize(.object(got))) want \(Canonical.canonicalize(.object(want)))") }
        }
        XCTAssertEqual(outcomes, ["pass", "escalate", "deny"])
        XCTAssertTrue(bad.isEmpty, bad.joined(separator: "\n"))
    }
}

/// The recorder (the client half): a round trip through the verifier, the byte-for-byte principal-direct bundle of the vectors, the
/// session cap and a hybrid (Ed25519 + ML-DSA-65) receipt.
final class ArgProvRecorderTests: XCTestCase {
    static let NOW: Int64 = 1_793_188_800_000
    static func seed(_ label: String) -> [UInt8] { Canonical.sha256(Array("atlas-pca-conformance/arg-provenance/\(label)".utf8)) }
    static let SEND = PCA.Operation(verb: "email.send", resource: "mail",
                                    params: .object(["to": .string("bob@acme.example"), "subject": .string("Q3 report"), "body": .string("Attached.")]))
    static let SEND_FACTS: JSONValue = .object(["effects": .array([.string("send")]), "traits": .array([.string("pca.exfiltration")])])

    static func opJSON(_ op: PCA.Operation) -> JSONValue { .object(["verb": .string(op.verb), "resource": .string(op.resource), "params": op.params]) }

    func testPrincipalDirectBundleIsByteIdenticalToTheVector() throws {
        let doc = try ArgProvVectorTests.doc()
        let v = try XCTUnwrap(doc.get("decisions")?.asArray?.first { $0.get("name")?.asString == "principal-direct" })
        let want = try XCTUnwrap(v.get("input")?.get("bundle"))
        // the reference's fixed harness key, session and clock; deterministic Ed25519 so the signatures are the vector's bytes
        let key = try Ed25519Deterministic.key(seed: Self.seed("key/harness"))
        let r = try ProvenanceRecorder(mediator: "assistant-harness", kid: "k1", signer: .ed25519(key),
                                       session: Base64URLStrict.encode(Self.seed("session/harness")), now: { Self.NOW })
        XCTAssertEqual(r.pin, doc.get("pin"))
        let op = PCA.Operation(verb: "payments.send", resource: "bank",
                               params: .object(["iban": .string("DE89370400440532013000"), "amount": .int(120)]))
        let got = try PCA.principalDirectProvenance(r, op)
        XCTAssertEqual(Canonical.canonicalize(got), Canonical.canonicalize(want))
        XCTAssertEqual(got, want)
    }

    func testRoundTripLabelsEverySegment() throws {
        var t: Int64 = 1_000
        let r = try ProvenanceRecorder(mediator: "my-harness", kid: "k2", secretKey: [UInt8](repeating: 7, count: 32), now: { t += 10; return t })
        XCTAssertNotNil(IV.digest(.string(r.session)), "a random session is canonical base64url of 32 bytes")
        try r.principal("Email the Q3 report to bob@acme.example")
        try r.tool("search", "results")
        try r.retrieval("docs/q3", "the Q3 numbers")
        try r.web("https://example.test/page", "a page")
        let b = try r.forAction(Self.SEND)
        XCTAssertEqual(r.receipts().count, 5)
        XCTAssertEqual(b.get("receipts")?.asArray?.count, 5)
        XCTAssertEqual(b.get("contents")?.asObject?.keys.map { $0.s }, ["0"])
        // the header decodes back to the bundle
        let text = try XCTUnwrap(PcaGuard.decodeHeader(ProvenanceRecorder.header(b)))
        XCTAssertEqual(try StrictJSON.parse(text), b)
        let d = PCA.decideArgProvenance(ArgProvenanceInput(bundle: b, operation: Self.opJSON(Self.SEND), mediators: .array([r.pin]), action: Self.SEND_FACTS))
        XCTAssertTrue(d.verified)
        XCTAssertEqual(d.outcome, "escalate")
        XCTAssertEqual(d.control, "web")
        XCTAssertEqual(d.path, ["retrieval:docs/q3", "tool:search", "web:https://example.test/page"])
        // the values the principal typed (recipient, subject) stay trusted; the body is untrusted
        XCTAssertEqual(d.labels["to"], .string("trusted"))
        XCTAssertEqual(d.labels["subject"], .string("trusted"))
        XCTAssertEqual(d.tainted, ["body"])
        // the principal message alone: everything trusted
        let p = try ProvenanceRecorder(mediator: "my-harness", kid: "k2", secretKey: [UInt8](repeating: 7, count: 32))
        try p.principal("Email the Q3 report to bob@acme.example")
        let pd = PCA.decideArgProvenance(ArgProvenanceInput(bundle: try p.forAction(Self.SEND), operation: Self.opJSON(Self.SEND), mediators: .array([p.pin]),
                                                            action: Self.SEND_FACTS))
        XCTAssertEqual(pd.outcome, "pass")
        XCTAssertEqual(pd.control, "trusted")
    }

    func testIssuedAtNeverDecreasesAndSourcesAreClipped() throws {
        var t: Int64 = 5_000
        let r = try ProvenanceRecorder(mediator: "m", kid: "k", secretKey: [UInt8](repeating: 7, count: 32), now: { t -= 100; return t })
        try r.tool(String(repeating: "é", count: 300), "x")
        try r.web("", "y")
        let rs = r.receipts()
        XCTAssertEqual(rs[1].get("issued_at"), rs[0].get("issued_at"), "a clock that goes back is held at the previous receipt")
        let src = try XCTUnwrap(rs[0].get("source")?.asString)
        XCTAssertLessThanOrEqual(src.utf8.count, 256)
        XCTAssertFalse(src.isEmpty)
        XCTAssertEqual(rs[1].get("source")?.asString, "-")
        XCTAssertEqual(try ProvenanceRecorder.clip("abc"), "abc")
    }

    /// The source clip halves by UTF-16 code units like the reference; a cut inside a surrogate pair throws.
    func testClipHalvesByUtf16UnitsAndRefusesASplitPair() throws {
        let smile = "\u{1F600}"
        XCTAssertEqual(try ProvenanceRecorder.clip(String(repeating: "a", count: 300)), String(repeating: "a", count: 150))
        XCTAssertEqual(try ProvenanceRecorder.clip(String(repeating: "a", count: 256)), String(repeating: "a", count: 256))
        XCTAssertEqual(try ProvenanceRecorder.clip(""), "-")
        XCTAssertEqual(try ProvenanceRecorder.clip(String(repeating: "é", count: 100) + String(repeating: smile, count: 41) + "b"),
                       String(repeating: "é", count: 91))
        XCTAssertEqual(try ProvenanceRecorder.clip(String(repeating: smile, count: 64) + "é"), String(repeating: smile, count: 32))
        let split = String(repeating: smile, count: 50) + String(repeating: "é", count: 30) + "x"
        XCTAssertThrowsError(try ProvenanceRecorder.clip(split))
        // and so recording a segment from that source throws
        let r = try ProvenanceRecorder(mediator: "m", kid: "k", secretKey: [UInt8](repeating: 7, count: 32))
        XCTAssertThrowsError(try r.tool(split, "x"))
        XCTAssertEqual(r.receipts().count, 0)
    }

    func testRecorderRefusesBadInputAndAFullSession() throws {
        XCTAssertThrowsError(try ProvenanceRecorder(mediator: "", kid: "k"))
        XCTAssertThrowsError(try ProvenanceRecorder(mediator: "m", kid: String(repeating: "k", count: 65)))
        XCTAssertThrowsError(try ProvenanceRecorder(mediator: "m", kid: "k", session: "short"))
        let r = try ProvenanceRecorder(mediator: "m", kid: "k", secretKey: [UInt8](repeating: 7, count: 32))
        for i in 0..<PCA.MAX_PROV_RECEIPTS { try r.tool("t", "\(i)") }
        XCTAssertThrowsError(try r.forAction(Self.SEND)) { XCTAssertTrue("\($0)".contains("start a new session"), "\($0)") }
        // an operation outside the strict JSON profile cannot be bound
        let q = try ProvenanceRecorder(mediator: "m", kid: "k", secretKey: [UInt8](repeating: 7, count: 32))
        XCTAssertThrowsError(try q.forAction(PCA.Operation(verb: "v", resource: "r", params: .object(["x": .double(.nan)]))))
    }

    /// The hybrid suite: the pin carries `pq_pk`; both signatures must verify. Where ML-DSA cannot sign, the suite is refused.
    func testHybridReceiptVerifiesUnderAPinWithPqPk() throws {
        let ed = try PCAEdKey(seed: [UInt8](repeating: 4, count: 32))
        guard PCAPQKey.signingAvailable else {
            XCTAssertThrowsError(try PCAPQKey.fromSeed(.mlDsa65, seed: [UInt8](repeating: 5, count: 32))) { XCTAssertTrue("\($0)".contains("unsupported_suite")) }
            return
        }
        let pq = try PCAPQKey.fromSeed(.mlDsa65, seed: [UInt8](repeating: 5, count: 32))
        let r = try ProvenanceRecorder(mediator: "pq-harness", kid: "k1", signer: try PCASuiteKey(alg: "hybrid-ed25519-ml-dsa-65", ed: ed, pq: pq))
        XCTAssertEqual(r.pin.get("pq_pk")?.asString, pq.pkB64u)
        let b = try PCA.principalDirectProvenance(r, Self.SEND)
        XCTAssertEqual(b.get("receipts")?.asArray?.first?.get("alg")?.asString, "hybrid-ed25519-ml-dsa-65")
        func decide(_ pins: [JSONValue], _ bundle: JSONValue) -> ArgProvenanceDecision {
            PCA.decideArgProvenance(ArgProvenanceInput(bundle: bundle, operation: Self.opJSON(Self.SEND), mediators: .array(pins), action: Self.SEND_FACTS))
        }
        XCTAssertEqual(decide([r.pin], b).outcome, "pass")
        // a pin without the PQ key (or with another one) does not verify a hybrid receipt
        var edOnly = r.pin.asObject!
        edOnly["pq_pk"] = nil
        XCTAssertEqual(decide([.object(edOnly)], b).code, "bad_signature")
        var other = r.pin.asObject!
        other["pq_pk"] = .string(try PCAPQKey.fromSeed(.mlDsa65, seed: [UInt8](repeating: 6, count: 32)).pkB64u)
        XCTAssertEqual(decide([.object(other)], b).code, "bad_signature")
        // a tampered PQ signature is refused even though the Ed25519 one is intact
        guard case var .object(bo) = b, case var .array(rs)? = bo["receipts"], case var .object(r0) = rs[0], let ps = r0["pq_sig"]?.asString else {
            return XCTFail("no pq_sig")
        }
        r0["pq_sig"] = .string((ps.first == "A" ? "B" : "A") + ps.dropFirst())
        rs[0] = .object(r0)
        bo["receipts"] = .array(rs)
        XCTAssertEqual(decide([r.pin], .object(bo)).outcome, "deny")
    }
}

/// Mutation kills: the token boundary, the trusted-context shortcut, the chain links, the last-receipt binding, the pin lookup and
/// the floors.
final class ArgProvKillTests: XCTestCase {
    static let SEND = ArgProvRecorderTests.SEND
    static let FACTS = ArgProvRecorderTests.SEND_FACTS

    static func rec(_ mediator: String = "h", kid: String = "k1", seed: UInt8 = 7, now: (() -> Int64)? = { 1_000 }) -> ProvenanceRecorder {
        try! ProvenanceRecorder(mediator: mediator, kid: kid, secretKey: [UInt8](repeating: seed, count: 32), now: now)
    }

    static func decide(_ bundle: JSONValue?, _ op: PCA.Operation = SEND, pins: [JSONValue], action: JSONValue? = FACTS, observed: JSONValue? = nil,
                       control: Bool = false) -> ArgProvenanceDecision {
        PCA.decideArgProvenance(ArgProvenanceInput(bundle: bundle, operation: ArgProvRecorderTests.opJSON(op), mediators: .array(pins), action: action,
                                                   principalControl: control, observed: observed))
    }

    func testTokenBoundaryBothSidesAndNonAscii() {
        XCTAssertTrue(PCA.occursAsToken("ab", "ab"))
        XCTAssertTrue(PCA.occursAsToken(" ab ", "ab"))
        XCTAssertFalse(PCA.occursAsToken("xab", "ab"), "a word unit before")
        XCTAssertFalse(PCA.occursAsToken("abx", "ab"), "a word unit after")
        XCTAssertFalse(PCA.occursAsToken("_ab", "ab"))
        XCTAssertFalse(PCA.occursAsToken("ab9", "ab"))
        XCTAssertFalse(PCA.occursAsToken("éab", "ab"), "non-ASCII counts as a word unit before")
        XCTAssertFalse(PCA.occursAsToken("abé", "ab"), "non-ASCII counts as a word unit after")
        XCTAssertTrue(PCA.occursAsToken("é ab", "ab"))
        XCTAssertTrue(PCA.occursAsToken("xab ab", "ab"), "a later occurrence is found")
        // a needle that starts or ends with a non-word unit needs no boundary on that side
        XCTAssertTrue(PCA.occursAsToken("a@x", "@x"))
        XCTAssertTrue(PCA.occursAsToken("x)a", "x)"))
        XCTAssertFalse(PCA.occursAsToken("ab", "abc"), "a needle longer than the text")
        XCTAssertFalse(PCA.occursAsToken("ab", ""))
    }

    func testTrustedContextShortcutAndAnObservedToolRaisesIt() {
        let r = Self.rec()
        try! r.principal("please send the report")
        let b = try! r.forAction(Self.SEND)
        // the context is the principal's own message: every value is trusted, even ones the principal did not type
        let ok = Self.decide(b, pins: [r.pin])
        XCTAssertEqual(ok.outcome, "pass")
        XCTAssertEqual(ok.labels["to"], .string("trusted"))
        // a tool the server saw raises the context: the untyped values are now tainted
        let obs: JSONValue = .array([.object(["origin": .string("tool"), "source": .string("inbox")])])
        let raised = Self.decide(b, pins: [r.pin], observed: obs)
        XCTAssertEqual(raised.outcome, "escalate")
        XCTAssertEqual(raised.control, "tool")
        XCTAssertEqual(raised.tainted, ["body", "subject", "to"])
        XCTAssertEqual(raised.path, ["tool:inbox"])
    }

    func mutate(_ b: JSONValue, _ i: Int, _ edit: (inout JObject) -> Void) -> JSONValue {
        guard case var .object(bo) = b, case var .array(rs)? = bo["receipts"], case var .object(r) = rs[i] else { return b }
        edit(&r)
        rs[i] = .object(r)
        bo["receipts"] = .array(rs)
        return .object(bo)
    }

    func testPrevLinkOfTheFirstReceiptAndIssuedAtDirection() {
        var t: Int64 = 100
        let r = Self.rec(now: { t += 100; return t })
        try! r.principal("a")
        try! r.tool("t", "b")
        let b = try! r.forAction(Self.SEND)
        XCTAssertNotEqual(Self.decide(b, pins: [r.pin]).outcome, "deny")
        // receipt 0 must link to nothing
        let linked = mutate(b, 0) { $0["prev"] = .string(Base64URLStrict.encode([UInt8](repeating: 3, count: 32))) }
        let d0 = Self.decide(linked, pins: [r.pin])
        XCTAssertEqual(d0.code, "broken_chain")
        XCTAssertEqual(d0.reason, "receipt 0 does not link to its predecessor")
        // the last receipt older than ITS predecessor (but newer than the first) is refused; equal times are fine
        let older = mutate(b, 2) { $0["issued_at"] = .int(250) }
        let d2 = Self.decide(older, pins: [r.pin])
        XCTAssertEqual(d2.code, "broken_chain")
        XCTAssertEqual(d2.reason, "receipt 2 is older than its predecessor")
        let same = mutate(b, 2) { $0["issued_at"] = .int(300) }
        XCTAssertEqual(Self.decide(same, pins: [r.pin]).code, "bad_signature", "equal times pass the chain; the edit then breaks the signature")
    }

    func testTheLastReceiptBindsVerbResourceAndParams() {
        let r = Self.rec()
        try! r.principal("x")
        let b = try! r.forAction(Self.SEND)
        for (name, op) in [("verb", PCA.Operation(verb: "email.forward", resource: Self.SEND.resource, params: Self.SEND.params)),
                           ("resource", PCA.Operation(verb: Self.SEND.verb, resource: "mail2", params: Self.SEND.params)),
                           ("params", PCA.Operation(verb: Self.SEND.verb, resource: Self.SEND.resource, params: .object(["to": .string("eve@x.example")])))] {
            XCTAssertEqual(Self.decide(b, op, pins: [r.pin]).code, "unbound_action", name)
        }
    }

    func testPinLookupNeedsBothMediatorAndKid() {
        let r = Self.rec("h", kid: "k1")
        try! r.principal("Email the Q3 report to bob@acme.example")
        let b = try! r.forAction(Self.SEND)
        XCTAssertEqual(Self.decide(b, pins: [r.pin]).outcome, "pass")
        var otherKid = r.pin.asObject!
        otherKid["kid"] = .string("k2")
        var otherMediator = r.pin.asObject!
        otherMediator["mediator"] = .string("g")
        for (name, pin) in [("kid", otherKid), ("mediator", otherMediator)] {
            let d = Self.decide(b, pins: [.object(pin)])
            XCTAssertEqual(d.outcome, "escalate", name)
            XCTAssertFalse(d.verified, name)
            XCTAssertEqual(d.path, ["unlabelled"], name)
        }
        // the right (mediator, kid) with another key: a forgery
        let forger = Self.rec("h", kid: "k1", seed: 8)
        XCTAssertEqual(Self.decide(b, pins: [forger.pin]).code, "bad_signature")
    }

    func testFloorsForNonSensitiveAndExplicitFloors() {
        let read: JSONValue = .object(["effects": .array([.string("read")])])
        // no bundle, a read-only action: every parameter is agent, at its floor (agent): pass
        let d = Self.decide(nil, pins: [], action: read)
        XCTAssertEqual(d.outcome, "pass")
        XCTAssertFalse(d.sensitive)
        XCTAssertEqual(d.labels["to"], .string("agent"))
        // an explicit floor below the label taints even a read
        let strict: JSONValue = .object(["effects": .array([.string("read")]), "params": .object(["to": .string("first_party")])])
        let s = Self.decide(nil, pins: [], action: strict)
        XCTAssertEqual(s.outcome, "escalate")
        XCTAssertEqual(s.tainted, ["to"])
        XCTAssertEqual(s.code, "untrusted_args")
        // a sensitive action with the choice from the principal: params at an explicit agent floor are not tainted, the rest are
        let lax: JSONValue = .object(["effects": .array([.string("send")]), "params": .object(["body": .string("agent"), "subject": .string("agent")])])
        let l = Self.decide(nil, pins: [], action: lax, control: true)
        XCTAssertEqual(l.tainted, ["to"])
        XCTAssertEqual(l.code, "untrusted_args")
        // unknown action facts: sensitive
        XCTAssertTrue(Self.decide(nil, pins: [], action: nil).sensitive)
    }

    func testEnvelopeMemberValidation() {
        XCTAssertNil(PCA.provEnvelopeError(.object([:])))
        XCTAssertNil(PCA.provEnvelopeError(.object(["mode": .string("enforce")])))
        XCTAssertNil(PCA.provEnvelopeError(.object(["mode": .string("insecure_off")])))
        XCTAssertNotNil(PCA.provEnvelopeError(.object(["mode": .string("off")])))
        XCTAssertNotNil(PCA.provEnvelopeError(.object(["extra": .int(1)])))
        XCTAssertNotNil(PCA.provEnvelopeError(.string("x")))
        let pin = Self.rec().pin
        XCTAssertNil(PCA.provEnvelopeError(.object(["mediators": .array([pin])])))
        XCTAssertNil(PCA.provEnvelopeError(.object(["mediators": .array([JSONValue](repeating: pin, count: 16))])))
        XCTAssertNotNil(PCA.provEnvelopeError(.object(["mediators": .array([JSONValue](repeating: pin, count: 17))])))
        XCTAssertNotNil(PCA.provEnvelopeError(.object(["mediators": .array([.object(["mediator": .string("m")])])])))
    }
}
