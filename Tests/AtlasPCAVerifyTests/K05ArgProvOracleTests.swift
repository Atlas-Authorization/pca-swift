import XCTest
import Foundation
@testable import AtlasPCAVerify

/// Differential test of ArgProvenance.swift (and the request reader of PcaGuard/Authorize) against the TS reference
/// (arg-provenance.ts, server/require-pca.ts defaultProvenanceBundle): test-data/k05-argprov.json.gz (9821 cases). Recorder sessions are
/// replayed with the deterministic Ed25519 signer (the reference signature bytes); a non-string tool/retrieval/web content is passed as
/// its canonical JSON text (the generator keeps only values whose JSON text is canonical). provLeaves is compared as a multiset: a
/// parsed object keeps no member order in Swift (the decision only reads membership).
final class K05ArgProvOracleTests: XCTestCase {
    static let file = "k05-argprov.json.gz"
    static let covers = ["ArgProvenance", "IntentWB", "IntentValues", "StrictJSON", "Canonical", "Base64URLStrict", "Ed25519Strict", "Issue", "PQ",
                         "PcaGuard", "JSONValue", "StrictParser", "Keys"]

    static func op(_ v: JSONValue?) -> PCA.Operation? {
        guard let o = v?.asObject, let verb = o["verb"]?.asString, let res = o["resource"]?.asString else { return nil }
        return PCA.Operation(verb: verb, resource: res, params: o["params"] ?? .null)
    }

    static func text(_ v: JSONValue?) -> String { v?.asString ?? K042.canon(v) }

    func testShapesTokensLeavesDigests() throws {
        try K042.requireCovers(Self.covers)
        let d = K05.Diffs()
        try K05.each(Self.file, ["provReceiptWireError", "isProvMediatorPin", "provActionInfoError", "isReadOnlyAction", "provEnvelopeError", "occursAsToken",
                                 "provLeaves", "provActionDigest", "provReceiptRef"]) { c in
            let a = c.arg(0) ?? .null
            switch c.fn {
            case "provReceiptWireError": d.add(c, K05.diff(c, .value(K05.opt(PCA.provReceiptWireError(a)))))
            case "isProvMediatorPin": d.add(c, K05.diff(c, .value(.bool(PCA.isProvMediatorPin(a)))))
            case "provActionInfoError": d.add(c, K05.diff(c, .value(K05.opt(PCA.provActionInfoError(a)))))
            case "isReadOnlyAction": d.add(c, K05.diff(c, .value(.bool(PCA.isReadOnlyAction(a)))))
            case "provEnvelopeError": d.add(c, K05.diff(c, .value(K05.opt(PCA.provEnvelopeError(a)))))
            case "occursAsToken":
                guard let t = a.asString, let n = c.arg(1)?.asString else { d.skip("occursAsToken: non-string args"); return }
                d.add(c, K05.diff(c, .value(.bool(PCA.occursAsToken(t, n)))))
            case "provLeaves":
                let got = PCA.provLeaves(a)
                let want = c.out.asArray?.map { $0.asString ?? "?" }
                d.add(c, got?.sorted() == want?.sorted() ? nil : "\(c.name): want \(K05.canon(c.out).prefix(200)) got \(String(describing: got).prefix(200))")
            case "provActionDigest":
                guard let o = Self.op(a) else { d.skip("provActionDigest: not an operation"); return }
                let got = PCA.provActionDigest(verb: o.verb, resource: o.resource, params: o.params)
                d.add(c, K05.diff(c, got.map { .value(.string($0)) } ?? .threw(nil)))
            default:
                let got = PCA.provReceiptRef(a)
                d.add(c, K05.diff(c, got.map { .value(.string($0)) } ?? .threw(nil)))
            }
        }
        d.finish(2420)   // 2516 cases, 53 carry a lone surrogate (skipped)
    }

    func testDecision() throws {
        try K042.requireCovers(Self.covers)
        let d = K05.Diffs()
        try K05.each(Self.file, ["decideArgProvenance"]) { c in
            guard let o = c.arg(0)?.asObject else { d.skip("decideArgProvenance: a non-object input cannot be an ArgProvenanceInput"); return }
            func flag(_ k: String) -> Bool { if case .bool(true)? = o[JKey(k)] { return true }; return false }
            let r = PCA.decideArgProvenance(ArgProvenanceInput(
                bundle: o["bundle"], operation: o["operation"] ?? .null, mediators: o["mediators"] ?? .null, action: o["action"],
                principalPlan: flag("principalPlan"), principalControl: flag("principalControl"), observed: o["observed"]))
            d.add(c, K05.diff(c, .value(r.json)))
        }
        d.finish(7000)
    }

    /// Replays a recorder spec {mediator, kid, sk, session, clock, steps}: out {pin, outs}; a throwing step is matched against the
    /// reference's throw at that index (messages are not compared).
    func testRecorder() throws {
        try K042.requireCovers(Self.covers)
        let d = K05.Diffs()
        try K05.each(Self.file, ["recorder"]) { c in
            guard let sp = c.arg(0)?.asObject, let seed = sp["sk"]?.asString.flatMap({ Base64URLStrict.decode($0) }) else { d.skip("recorder: bad spec"); return }
            var clock = (sp["clock"]?.asArray ?? []).map { IV.num($0) ?? 0 }
            var last: Int64 = 0
            let now: () -> Int64 = {
                if !clock.isEmpty { last = Int64(clock.removeFirst().rounded(.towardZero)) }
                return last
            }
            let rec: ProvenanceRecorder
            do {
                rec = try ProvenanceRecorder(mediator: sp["mediator"]?.asString ?? "", kid: sp["kid"]?.asString ?? "",
                                             signer: .ed25519(try Ed25519Deterministic.key(seed: seed)), session: sp["session"]?.asString, now: now)
            } catch {
                d.add(c, K05.diff(c, .threw(nil)))
                return
            }
            let wantOuts = c.out.get("outs")?.asArray ?? []
            var outs: [JSONValue] = []
            for (i, st) in (sp["steps"]?.asArray ?? []).enumerated() {
                let s = st.asArray ?? []
                let kind = s.first?.asString ?? ""
                do {
                    switch kind {
                    case "principal": outs.append(try rec.principal(Self.text(s[1])))
                    case "tool": outs.append(try rec.tool(Self.text(s[1]), Self.text(s[2])))
                    case "retrieval": outs.append(try rec.retrieval(Self.text(s[1]), Self.text(s[2])))
                    case "web": outs.append(try rec.web(Self.text(s[1]), Self.text(s[2])))
                    case "action", "direct":
                        guard let o = Self.op(s[1]) else { throw PCAProducerError("not an operation") }
                        outs.append(kind == "action" ? try rec.forAction(o) : try PCA.principalDirectProvenance(rec, o))
                    default: throw PCAProducerError("unknown step")
                    }
                } catch {
                    let w = i < wantOuts.count ? wantOuts[i] : .null
                    outs.append(w.get("$throws") != nil ? w : .object(["$throws": .string("swift: \(error)")]))
                }
            }
            d.add(c, K05.diff(c, .value(.object(["pin": rec.pin, "outs": .array(outs)]))))
        }
        d.finish(20)
    }

    /// defaultProvenanceBundle: the PCA-Provenance header (strict base64url of strict JSON; unreadable throws), else the JSON body member
    /// `pca_provenance` (an unreadable body is none). Swift composes the same primitives (PcaGuard.decodeHeader + StrictJSON.parse).
    func testRequestReader() throws {
        try K042.requireCovers(Self.covers)
        let d = K05.Diffs()
        try K05.each(Self.file, ["defaultProvenanceBundle"]) { c in
            let a = c.arg(0)
            let got: K05Got
            if let h = a?.get("header")?.asString, !h.isEmpty {
                if let text = PcaGuard.decodeHeader(h), let v = try? StrictJSON.parse(text) { got = .value(v) } else { got = .threw(nil) }
            } else if let b = a?.get("body")?.asString, case let .object(o)? = try? StrictJSON.parse(b) {
                got = .value(o["pca_provenance"] ?? .null)
            } else {
                got = .value(.null)
            }
            // the reference's header codes (invalid_pca_header) are its adapter's: Swift refuses the same inputs without a code
            if case .threw = got, c.threw { d.add(c, nil); return }
            d.add(c, K05.diff(c, got))
        }
        d.finish(20)
    }
}
