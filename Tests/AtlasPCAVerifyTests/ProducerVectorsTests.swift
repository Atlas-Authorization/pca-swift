import XCTest
import Foundation
@testable import AtlasPCAVerify

/// Replays producer-vectors.json and producer-pq-vectors.json through `PCAProducerVectors.produce` (the same entry point the conformance
/// driver uses): every producer must reproduce the TypeScript reference's output byte for byte (Ed25519 is deterministic), and every
/// refusal with the reference's text. Apple's CryptoKit hedges Ed25519, so the replay signs through the RFC 8032 deterministic signer
/// (`Ed25519Deterministic`); on Linux the platform signer is already deterministic. ML-DSA signs where CryptoKit provides it (macOS / iOS
/// 26); SLH-DSA and FN-DSA are refused as `unsupported_suite`. With `PCA_PRODUCER_OUT` set (CI), the native post-quantum and agent-side
/// output is written for the reference implementation to verify.
final class ProducerVectorsTests: XCTestCase {
    static func canon(_ v: JSONValue) -> String { Canonical.canonicalize(v) }

    /// One vector file: its cases, keys and the member order of its JSON text.
    struct VectorFile {
        let doc: JSONValue
        let orders: [String: [String]]
        init(_ name: String) throws {
            let text = try ConformanceTests.readText(ConformanceTests.conformanceDir.appendingPathComponent(name))
            doc = try ConformanceTests.loadText(text)
            orders = PCAProducerVectors.objectKeyOrders(text)
        }
        var cases: [JSONValue] { doc.get("cases")?.asArray ?? [] }
        func produce(_ i: Int) throws -> JSONValue {
            let c = cases[i]
            return try PCAProducerVectors.produce(op: c.get("op")?.asString ?? "", args: c.get("args") ?? .null, keys: doc.get("keys") ?? doc.get("ed_keys") ?? .null,
                                                  pqKeys: doc.get("pq_keys"), keyOrders: PCAProducerVectors.keyOrders(orders, under: "/cases/\(i)/args"))
        }
    }

    func testEveryCaseIsReproducedByteForByte() throws {
        let f = try VectorFile("producer-vectors.json")
        XCTAssertGreaterThanOrEqual(f.cases.count, 89)
        var failures: [String] = []
        var refusals = 0
        for (i, c) in f.cases.enumerated() {
            let name = c.get("name")?.asString ?? "?"
            let want = c.get("expect") ?? .null
            do {
                let got = try f.produce(i)
                if want.get("error") != nil { failures.append("\(name): signed what the reference refuses") }
                else if Self.canon(got) != Self.canon(want) { failures.append("\(name): output differs\n  got  \(Self.canon(got).prefix(400))\n  want \(Self.canon(want).prefix(400))") }
            } catch {
                // every refusal carries the reference's exact text
                let text = (error as? Canonical.CanonicalError)?.message ?? "\(error)" // a canonical-profile refusal carries its text in `message`
                if let e = want.get("error")?.asString, text == e { refusals += 1 } else { failures.append("\(name): \(text)") }
            }
        }
        XCTAssertTrue(failures.isEmpty, failures.joined(separator: "\n"))
        XCTAssertEqual(refusals, 12)
    }

    /// Every op of the vectors is implemented (`unsupported_op` counts as a failure), and an unknown one is refused as such.
    func testEveryOpIsImplemented() throws {
        for name in ["producer-vectors.json", "producer-pq-vectors.json"] {
            let f = try VectorFile(name)
            for i in f.cases.indices {
                do { _ = try f.produce(i) } catch { XCTAssertFalse("\(error)".hasPrefix("unsupported_op"), "\(name) #\(i): \(error)") }
            }
        }
        XCTAssertThrowsError(try PCAProducerVectors.produce(op: "no_such_op", args: .object([:]), keys: .object([:]))) {
            XCTAssertEqual("\($0)", "unsupported_op: no_such_op")
        }
    }

    /// The post-quantum file: every case listing swift in `exact` matches byte for byte (ML-DSA key generation and the Ed25519 rows);
    /// the other ML-DSA rows sign (randomised, so they are checked by verification instead); SLH-DSA and FN-DSA answer `unsupported_suite`.
    func testPostQuantumVectors() throws {
        let f = try VectorFile("producer-pq-vectors.json")
        var failures: [String] = []
        var exact = 0
        for (i, c) in f.cases.enumerated() {
            let name = c.get("name")?.asString ?? "?"
            let alg = c.get("args")?.get("alg")?.asString ?? c.get("args")?.get("family")?.asString ?? ""
            let isExact = (c.get("exact")?.asArray ?? []).contains(.string("swift"))
            let mlDsa = alg.contains("ml-dsa")
            do {
                let got = try f.produce(i)
                if isExact {
                    exact += 1
                    if Self.canon(got) != Self.canon(c.get("expect") ?? .null) { failures.append("\(name): output differs") }
                } else if !mlDsa {
                    failures.append("\(name): signed with a suite this SDK does not implement")
                } else if c.get("op")?.asString == "sign_pcactn_suite", let p = got.get("pcactn") {
                    let v = PCA.verify(pcactn: p, grant: p.get("cap_chain")?.asArray?.first ?? .null, now: (p.get("iat")?.safeInt ?? 0) + 1000,
                                       audience: p.get("aud")?.asString ?? "", insecureSkipPlanRootCheck: true)
                    if !v.allow { failures.append("\(name): the native PCActn does not verify: \(v.reason)") }
                }
            } catch {
                let unsupported = "\(error)".hasPrefix("unsupported_suite: ")
                if mlDsa && !PCAPQKey.signingAvailable && unsupported { continue } // no ML-DSA below OS 26: refused, as the verifier does
                if !mlDsa && alg != "ed25519" && unsupported { continue }
                failures.append("\(name): \(error)")
            }
        }
        XCTAssertTrue(failures.isEmpty, failures.joined(separator: "\n"))
        XCTAssertEqual(exact, PCAPQKey.signingAvailable ? 9 : 7)
        XCTAssertThrowsError(try PCAProducerVectors.keyGen("slh-dsa-sha2-128f", String(repeating: "A", count: 43))) {
            XCTAssertEqual("\($0)", "unsupported_suite: slh-dsa-sha2-128f")
        }
        XCTAssertThrowsError(try PCAProducerVectors.keyGen("fn-dsa-512", String(repeating: "A", count: 43))) { XCTAssertEqual("\($0)", "unsupported_suite: fn-dsa-512") }
    }

    /// Cross-verification: the TS-produced PCActns pass THIS SDK's verifier.
    func testReferenceActionsVerify() throws {
        let doc = try ConformanceTests.load("producer-vectors.json")
        var n = 0
        for c in doc.get("cases")?.asArray ?? [] where c.get("op")?.asString == "act" {
            let a = c.get("args")!
            if a.get("fresh_at") != nil { continue } // refused without a fresh_at policy (fail closed)
            let v = PCA.verify(pcactn: c.get("expect")!.get("pcactn")!, grant: a.get("grant")!, now: a.get("iat")!.safeInt! + 1000, audience: a.get("aud")!.asString!, insecureSkipPlanRootCheck: true)
            XCTAssertTrue(v.allow, "\(c.get("name")?.asString ?? ""): \(v.reason)")
            n += 1
        }
        XCTAssertGreaterThanOrEqual(n, 4)
    }

    func testKeyOrderScanner() {
        let o = PCAProducerVectors.objectKeyOrders(#"{"b":1,"a":{"z":[{"y":2,"x\"q":3}],"c":null},"d/e":{"2":0,"1":0,"k":0}}"#)
        XCTAssertEqual(o[""], ["b", "a", "d/e"])
        XCTAssertEqual(o["/a"], ["z", "c"])
        XCTAssertEqual(o["/a/z/0"], ["y", "x\"q"])
        XCTAssertEqual(PCAProducerVectors.jsKeyOrder(o["/d~1e"] ?? []), ["1", "2", "k"])
        XCTAssertEqual(PCAProducerVectors.jsKeyOrder(["b", "10", "01", "2", "a"]), ["2", "10", "b", "01", "a"])
        XCTAssertEqual(PCAProducerVectors.objectKeyOrders("{\"a\":"), [:])
    }

    // ---- facade ----

    func testParseLimitAndCompilePolicy() throws {
        XCTAssertEqual(try PCAFacade.parseLimit("$500/day"), PCAParsedLimit(amount: 500, unit: "usd", periodMs: 86_400_000))
        XCTAssertEqual(try PCAFacade.parseLimit(" $ 12.5 "), PCAParsedLimit(amount: 12.5, unit: "usd", periodMs: nil))
        XCTAssertEqual(try PCAFacade.parseLimit("10 / MO"), PCAParsedLimit(amount: 10, unit: "count", periodMs: 2_592_000_000))
        for (s, e) in [("1.", "parseLimit: cannot parse limit '1.'"), ("$/day", "parseLimit: cannot parse limit '$/day'"), ("5/", "parseLimit: cannot parse limit '5/'"),
                       ("5/day/x", "parseLimit: cannot parse limit '5/day/x'"), ("-5", "parseLimit: cannot parse limit '-5'"), ("", "parseLimit: empty limit"),
                       ("5/toString", "parseLimit: unknown period 'toString' in '5/toString'")] {
            XCTAssertThrowsError(try PCAFacade.parseLimit(s), s) { XCTAssertEqual("\($0)", e) }
        }
        // the predicates follow the permissions' order; a later verb's limit overrides via the verb key
        let p = try PCAFacade.compilePolicy(permissions: [("gmail", ["draft"]), ("stripe", ["refund", "charge"])],
                                            limits: ["refund": "$100", "stripe.refund": "$80/day", "charge": "$20"], now: 1000)
        XCTAssertEqual(p.predicates.compactMap { $0.get("verb")?.asString }, ["gmail.draft", "stripe.refund", "stripe.charge"])
        XCTAssertEqual(p.predicates[1].get("where")?.asArray?.first?.get("value"), .int(80))
        XCTAssertEqual(p.riskPolicy["kappa"], .int(80))
        XCTAssertEqual(p.riskPolicy["bMax"], .int(100))
        XCTAssertEqual(p.caveats.last, .object(["type": .string("expires"), "at": .int(Int64(1000 + 86_400_000))]))
        XCTAssertEqual(p.approximations, ["stripe.refund: $80/period is a per-call ceiling plus a one-period grant lifetime, not a renewing window cap"])
        XCTAssertThrowsError(try PCAFacade.compilePolicy(permissions: [("crm", ["export"])], riskPolicy: ["theta1": .int(2)], now: 0)) {
            XCTAssertTrue("\($0)".hasPrefix("compilePolicy: derived risk policy invalid: "), "\($0)")
        }
        XCTAssertEqual(PCACatalog.default.specFor("stripe.issue_refund").verb, "stripe.refund")
        XCTAssertEqual(PCACatalog.default.specFor("crm.export").reversibility, "irreversible")
        XCTAssertEqual(PCAFacade.jsNumberText(1e21), "1e+21")
        XCTAssertEqual(PCAFacade.jsNumberText(12.5), "12.5")
    }

    /// An action with params verifies end to end: the plan node commits the params digest the action carries (the low-level agent and
    /// the facade), and the default nonce is base64url of 16 bytes.
    func testActWithParamsVerifies() throws {
        let principal = PCASuiteKey.ed25519(try PCAEdKey(seed: [UInt8](repeating: 0, count: 32)))
        let me = PCASuiteKey.ed25519(try PCAEdKey(seed: [UInt8](repeating: 1, count: 32)))
        let g = try PCAIssue.mintGrant(principal: principal, holder: me.id!, envelope: envelope(), goal: "g")
        let agent = try PCAAgent(signer: me, aud: "ins_t", grant: g.grant)
        agent.clock = { self.now }
        let params: JSONValue = .object(["amount": .int(42), "currency": .string("usd")])
        let a = try agent.act(verb: "refund", resource: "orders/1", params: params)
        XCTAssertEqual(a.get("action")?.get("params_digest")?.asString, Merkle.paramsDigest(params))
        XCTAssertNotNil(Base64URLStrict.decode(a.get("nonce")?.asString ?? "", length: 16))
        let v = PCA.verify(pcactn: a, grant: g.grant, now: now + 1, audience: "ins_t", insecureSkipPlanRootCheck: true)
        XCTAssertTrue(v.allow, v.reason)

        let fa = try PCAAgent.fromPrincipal(PCAAgentOptions(principal: principal, goal: "refund", permissions: [("stripe", ["refund"])], limits: ["refund": "$500"],
                                                            holder: me, aud: "ins_t", now: now))
        let r = try fa.act(verb: "stripe.refund", resource: "charge:ch_1", params: params, options: PCAActOptions(now: now))
        XCTAssertNil(r.pcactn.get("nonce"))
        XCTAssertEqual(r.pcactn.get("counter"), .int(1))
        XCTAssertEqual(r.pcactn.get("risk_claim"), .object(["r": .double(0.084), "inputs": .object(["blastRadius": .double(0.084)])]))
        XCTAssertEqual(r.headers["PCA-Action"], PCAAgent.headerValue(r.pcactn))
        XCTAssertNotNil(r.headers["PCA-Provenance"])
        XCTAssertEqual(r.dryRun, PCADryRun(allowed: true, reason: nil, t: 1))
        let fv = PCA.verify(pcactn: r.pcactn, grant: fa.grant, now: now + 1, audience: "ins_t", insecureSkipPlanRootCheck: true)
        XCTAssertTrue(fv.allow, fv.reason)
        XCTAssertEqual(try fa.act(verb: "stripe.refund", resource: "charge:ch_1", params: params, options: PCAActOptions(counter: 7, now: now)).pcactn.get("counter"), .int(7))
        XCTAssertEqual(try fa.act(verb: "stripe.refund", resource: "charge:ch_1", params: params, options: PCAActOptions(now: now)).pcactn.get("counter"), .int(8))
        XCTAssertFalse(fa.dryRun(verb: "stripe.refund", resource: "x", params: .object(["amount": .int(501)]), now: now).allowed)
        XCTAssertFalse(fa.dryRun(verb: "gmail.send", resource: "x", now: now).allowed)
        XCTAssertThrowsError(try PCAAgent.fromPrincipal(PCAAgentOptions(principal: principal, goal: "g", permissions: [("x", ["y"])])).act(verb: "x.y", resource: "r")) {
            XCTAssertTrue("\($0)".hasPrefix("act: aud"))
        }
        let sub = try fa.subAgent(addedCaveats: [.object(["type": .string("budget_alloc"), "limit": .int(5)])])
        XCTAssertEqual(sub.chain.count, 2)
        let sv = PCA.verify(pcactn: try sub.act(verb: "stripe.refund", resource: "charge:ch_1", params: params, options: PCAActOptions(now: now)).pcactn,
                            grant: fa.grant, now: now + 1, audience: "ins_t", insecureSkipPlanRootCheck: true)
        XCTAssertTrue(sv.allow, sv.reason)
    }

    /// The built-in catalog equals the reference's generated one (verb, reversibility, blast radius, amount field, aliases, traits).
    func testBuiltinCatalogMatchesReference() throws {
        let url = ConformanceTests.conformanceDir.deletingLastPathComponent().appendingPathComponent("src/catalog-builtin.generated.ts")
        guard FileManager.default.fileExists(atPath: url.path) else { throw XCTSkip("the reference catalog source is not in this checkout") }
        let text = try ConformanceTests.readText(url)
        let line = try NSRegularExpression(pattern: #"\{ connector: "([^"]*)", action: "([^"]*)", verb: "([^"]*)", reversibility: "([^"]*)", blastRadius: ([0-9.]+), (?:amountField: "([^"]*)", )?description: "((?:[^"\\]|\\.)*)", (?:aliases: \[([^\]]*)\], )?traits: \[([^\]]*)\] \}"#)
        func list(_ s: String) -> [String] { s.split(separator: ",").map { $0.trimmingCharacters(in: CharacterSet(charactersIn: "\" ")) }.filter { !$0.isEmpty } }
        let ns = text as NSString
        let ref: [PCACatalogAction] = line.matches(in: text, range: NSRange(location: 0, length: ns.length)).map { m in
            func g(_ i: Int) -> String? { m.range(at: i).location == NSNotFound ? nil : ns.substring(with: m.range(at: i)) }
            return PCACatalogAction(connector: g(1)!, action: g(2)!, verb: g(3)!, reversibility: g(4)!, blastRadius: Double(g(5)!)!, amountField: g(6),
                                    description: g(7)!.replacingOccurrences(of: "\\\"", with: "\""), aliases: list(g(8) ?? ""), traits: list(g(9)!))
        }
        XCTAssertEqual(ref.count, text.components(separatedBy: "{ connector:").count - 1, "every reference entry parsed")
        XCTAssertEqual(PCACatalog.builtin, ref)
    }

    // ---- native output for the reference (PCA_PRODUCER_OUT) ----

    private let now: Int64 = 1_800_000_000_000
    private let aud = "ins_producer_test"
    private func envelope() -> JObject {
        ["predicates": .array([.object(["verb": .string("*")])]), "caveats": .array([]), "risk_policy": .object(PCAFacade.DEFAULT_RISK_POLICY)]
    }

    private func verifies(_ p: JSONValue, _ grant: JSONValue, _ what: String) {
        let v = PCA.verify(pcactn: p, grant: grant, now: now, audience: aud, insecureSkipPlanRootCheck: true)
        XCTAssertTrue(v.allow, "\(what): \(v.reason)")
    }

    /// The args of the first non-refusal producer vector of `op`.
    private func vectorArgs(_ doc: JSONValue, _ op: String) throws -> JObject {
        for c in doc.get("cases")?.asArray ?? [] where c.get("op")?.asString == op && c.get("expect")?.get("error") == nil {
            if let a = c.get("args")?.asObject { return a }
        }
        throw PCAProducerError("no vector for \(op)")
    }

    private func artifact(_ kind: String, _ alg: String, _ a: JSONValue, _ pins: JObject) -> JSONValue {
        .object(["kind": .string(kind), "alg": .string(alg), "artifact": a, "pins": .object(pins)])
    }

    /// One of each artifact kind the reference checks, over the vector bodies (their times bracket the file's now) re-pointed at fresh
    /// keys: the escalation answer and the revocation epoch under a hybrid suite where ML-DSA signs, the rest Ed25519.
    private func nativeArtifacts(_ doc: JSONValue) throws -> [JSONValue] {
        var out: [JSONValue] = []
        let pq = PCAPQKey.signingAvailable ? try PCAPQKey.generate(.mlDsa65) : nil
        func suite(_ k: PCAEdKey) throws -> (PCASuiteKey, String, JObject) {
            guard let q = pq else { return (.ed25519(k), "ed25519", ["pk": .string(k.id)]) }
            return (try PCASuiteKey(alg: "hybrid-ed25519-ml-dsa-65", ed: k, pq: q), "hybrid-ed25519-ml-dsa-65", ["pk": .string(k.id), "pq_pk": .string(q.pkB64u)])
        }

        var k = try PCAEdKey.generate()
        var b = try vectorArgs(doc, "sign_escalation_answer")["body"]!.asObject!
        b["principal"] = .string(k.id)
        var (s, alg, pins) = try suite(k)
        out.append(artifact("escalation_answer", alg, try PCAIssue.signEscalationAnswer(.object(b), principal: s), pins))

        k = try PCAEdKey.generate()
        (s, alg, pins) = try suite(k)
        let epoch = try PCAProducerVectors.epoch(try vectorArgs(doc, "sign_revocation_epoch")["body"]!.asObject!)
        out.append(artifact("revocation_epoch", alg, try PCASigners.signRevocationEpoch(epoch, guardian: s), pins))

        k = try PCAEdKey.generate()
        b = try vectorArgs(doc, "sign_session_root")["body"]!.asObject!
        b["principals"] = .array([.object(["key": .string(k.id)])])
        out.append(artifact("session_root", "ed25519", try PCASigners.signSessionRoot(.object(b), principal: .ed25519(k)), ["pk": .string(k.id)]))

        k = try PCAEdKey.generate()
        var a = try vectorArgs(doc, "sign_action_schema")
        out.append(artifact("action_schema", "ed25519", try PCASigners.signActionSchema(a["doc"]!, kid: a["kid"]!.asString!, site: .ed25519(k)),
                            ["pk": .string(k.id), "kid": a["kid"]!, "alg": .string("ed25519")]))

        k = try PCAEdKey.generate()
        b = try vectorArgs(doc, "sign_labels")["body"]!.asObject!
        out.append(artifact("labels", "ed25519", try PCASigners.signLabels(.object(b), key: .ed25519(k)),
                            ["pk": .string(k.id), "kid": .string(b["kid"]?.asString ?? ""), "site": .string(b["site"]?.asString ?? "")]))

        k = try PCAEdKey.generate()
        a = try vectorArgs(doc, "sign_intent_required")
        out.append(artifact("intent_required", "ed25519", try PCASigners.signIntentRequired(a["body"]!, kid: a["kid"]!.asString!, site: .ed25519(k)),
                            ["pk": .string(k.id), "kid": a["kid"]!, "alg": .string("ed25519")]))

        k = try PCAEdKey.generate()
        out.append(artifact("fact", "ed25519", try PCASigners.signFact(try vectorArgs(doc, "sign_fact")["body"]!, key: .ed25519(k)), ["pk": .string(k.id)]))

        k = try PCAEdKey.generate()
        b = try vectorArgs(doc, "sign_caution")["body"]!.asObject!
        b["holder"] = .string(k.id)
        out.append(artifact("caution", "ed25519", try PCASigners.signCaution(.object(b), holder: k), ["pk": .string(k.id)]))

        k = try PCAEdKey.generate()
        var pqPk = pq?.pkB64u ?? ""
        if pq == nil { pqPk = try vectorArgs(doc, "sign_pq_binding")["pq_pk"]!.asString! }
        out.append(artifact("pq_binding", "ed25519", try PCASigners.signPqBinding(ed: k, pqPk: pqPk, epoch: 1, aud: aud), ["pk": .string(k.id)]))
        return out
    }

    /// One PCActn per suite this SDK signs (Ed25519, and the ML-DSA suites where CryptoKit has them), a post-quantum sub-agent's PCActn,
    /// a facade act with params, and one artifact of each kind; each PCActn verifies here, and the reference verifies the whole file.
    func testEveryNativeOutputVerifiesAndIsWritten() throws {
        var cases: [JSONValue] = []
        func pcactn(_ alg: String, _ grant: JSONValue, _ p: JSONValue) throws {
            verifies(p, grant, alg)
            cases.append(.object(["kind": .string("pcactn"), "alg": .string(alg), "grant": try PCAIssue.norm(grant), "pcactn": try PCAIssue.norm(p)]))
        }
        let params: JSONValue = .object(["amount": .int(5)])
        var suites: [(String, PCAMLDSALevel?)] = [("ed25519", nil)]
        if PCAPQKey.signingAvailable {
            suites += [("ml-dsa-65", .mlDsa65), ("hybrid-ed25519-ml-dsa-65", .mlDsa65), ("hybrid-nested-ed25519-ml-dsa-65", .mlDsa65), ("ml-dsa-87", .mlDsa87),
                       ("hybrid-ed25519-ml-dsa-87", .mlDsa87)]
        }
        for (alg, level) in suites {
            let principal = PCASuiteKey.ed25519(try PCAEdKey.generate())
            let ed = try PCAEdKey.generate()
            let pq = try level.map { try PCAPQKey.generate($0) }
            let me = try PCASuiteKey(alg: alg, ed: ed, pq: pq)
            let g = try PCAIssue.mintGrant(principal: principal, holder: ed.id, holderPqPk: pq?.pkB64u, envelope: envelope(), goal: "refund")
            let agent = try PCAAgent(signer: me, aud: aud, grant: g.grant)
            agent.clock = { self.now }
            let p = try agent.act(verb: "refund", resource: "orders/1", params: params)
            if alg != "ed25519" { XCTAssertEqual(p.get("alg")?.asString, alg) }
            try pcactn(alg, g.grant, p)
            if alg == "hybrid-ed25519-ml-dsa-65" {
                let child = try agent.delegate(to: try PCASuiteKey(alg: alg, ed: try PCAEdKey.generate(), pq: try PCAPQKey.generate(.mlDsa65)),
                                               addedCaveats: [.object(["type": .string("sealed")])])
                let sp = try child.act(verb: "refund", resource: "orders/1", params: params)
                XCTAssertNotEqual(p.get("pq_pk"), sp.get("pq_pk"))
                try pcactn(alg + " (sub-agent)", g.grant, sp)
            }
        }
        let fa = try PCAAgent.fromPrincipal(PCAAgentOptions(principal: .ed25519(try PCAEdKey.generate()), goal: "refund", permissions: [("stripe", ["refund"])],
                                                            limits: ["refund": "$500"], aud: aud, now: now))
        let r = try fa.act(verb: "stripe.refund", resource: "charge:ch_1", params: .object(["amount": .int(42), "currency": .string("usd")]), options: PCAActOptions(now: now))
        try pcactn("ed25519 (facade act)", fa.grant, r.pcactn)
        cases += try nativeArtifacts(try ConformanceTests.load("producer-vectors.json"))
        XCTAssertEqual(cases.count, PCAPQKey.signingAvailable ? 6 + 1 + 1 + 9 : 1 + 1 + 9)

        guard let out = ProcessInfo.processInfo.environment["PCA_PRODUCER_OUT"], !out.isEmpty else { return }
        let doc: JSONValue = .object(["lang": .string("swift"), "aud": .string(aud), "now": .int(now), "cases": .array(cases)])
        try Data((Canonical.canonicalize(doc) + "\n").utf8).write(to: URL(fileURLWithPath: out))
    }

    // ---- native round trips ----

    func testNativeRoundTripEd25519AndDelegation() throws {
        let p = PCASuiteKey.ed25519(try PCAEdKey(seed: [UInt8](repeating: 0, count: 32)))
        let me = PCASuiteKey.ed25519(try PCAEdKey(seed: [UInt8](repeating: 1, count: 32)))
        let sub = PCASuiteKey.ed25519(try PCAEdKey(seed: [UInt8](repeating: 2, count: 32)))
        let g = try PCAIssue.mintGrant(principal: p, holder: me.id!, envelope: envelope(), goal: "g")
        let agent = try PCAAgent(signer: me, aud: "ins_t", grant: g.grant)
        agent.clock = { self.now }
        let a1 = try agent.act(verb: "read", resource: "x")
        XCTAssertEqual(a1.get("counter")?.safeInt, 1)
        let v = PCA.verify(pcactn: a1, grant: g.grant, now: now + 1, audience: "ins_t", insecureSkipPlanRootCheck: true)
        XCTAssertTrue(v.allow, v.reason)
        XCTAssertNotEqual(try agent.act(verb: "read", resource: "x").get("nonce"), a1.get("nonce"))
        let child = try agent.delegate(to: sub, addedCaveats: [.object(["type": .string("max_uses"), "id": .string("u1"), "n": .int(3), "until": .int(now + 3_600_000)])])
        XCTAssertEqual(child.chain.count, 2)
        let v2 = PCA.verify(pcactn: try child.act(verb: "read", resource: "x"), grant: g.grant, now: now + 1, audience: "ins_t", insecureSkipPlanRootCheck: true)
        XCTAssertTrue(v2.allow, v2.reason)
        var tampered = a1.asObject!
        var action = tampered["action"]!.asObject!
        action["resource"] = .string("y")
        tampered["action"] = .object(action)
        XCTAssertFalse(PCA.verify(pcactn: .object(tampered), grant: g.grant, now: now + 1, audience: "ins_t", insecureSkipPlanRootCheck: true).allow)
        XCTAssertEqual(PCAAgent.headerValue(a1), Base64URLStrict.encode(Canonical.utf8(PCAIssue.encode(a1))))
    }

    /// ML-DSA signs where CryptoKit has it; elsewhere the suite is refused with the same `unsupported_suite` reason as the verifier.
    func testMLDSAHybridRoundTripOrRefusal() throws {
        let ed = try PCAEdKey(seed: [UInt8](repeating: 6, count: 32))
        guard PCAPQKey.signingAvailable else {
            XCTAssertThrowsError(try PCAPQKey.generate(.mlDsa65)) { XCTAssertTrue("\($0)".contains("unsupported_suite")) }
            return
        }
        let pPq = try PCAPQKey.fromSeed(.mlDsa65, seed: [UInt8](repeating: 3, count: 32))
        XCTAssertEqual(pPq.pk, try PCAPQKey.fromSeed(.mlDsa65, seed: [UInt8](repeating: 3, count: 32)).pk) // seeded keys are reproducible
        XCTAssertEqual(pPq.pk.count, 1952)
        let principal = try PCASuiteKey(alg: "hybrid-ed25519-ml-dsa-65", ed: try PCAEdKey(seed: [UInt8](repeating: 0, count: 32)), pq: pPq)
        let aPq = try PCAPQKey.generate(.mlDsa65)
        let me = try PCASuiteKey(alg: "hybrid-ed25519-ml-dsa-65", ed: ed, pq: aPq)
        let g = try PCAIssue.mintGrant(principal: principal, holder: ed.id, holderPqPk: aPq.pkB64u, envelope: envelope(), goal: "g")
        let agent = try PCAAgent(signer: me, aud: "ins_t", grant: g.grant)
        agent.clock = { self.now }
        let a = try agent.act(verb: "read", resource: "x")
        XCTAssertEqual(a.get("alg")?.asString, "hybrid-ed25519-ml-dsa-65")
        let v = PCA.verify(pcactn: a, grant: g.grant, now: now + 1, audience: "ins_t", insecureSkipPlanRootCheck: true)
        XCTAssertTrue(v.allow, v.reason)
    }

    func testSuiteKeysFailClosed() throws {
        let ed = try PCAEdKey.generate()
        XCTAssertThrowsError(try PCASuiteKey(alg: "ml-dsa-65", ed: nil))
        XCTAssertThrowsError(try PCASuiteKey(alg: "hybrid-ed25519-ml-dsa-65", ed: ed))
        XCTAssertThrowsError(try PCASuiteKey(alg: "slh-dsa-sha2-128f", ed: ed))
        XCTAssertThrowsError(try PCASuiteKey(alg: "fn-dsa-512", ed: ed))
        XCTAssertThrowsError(try PCAEdKey(seed: [UInt8](repeating: 0, count: 31)))
    }
}
