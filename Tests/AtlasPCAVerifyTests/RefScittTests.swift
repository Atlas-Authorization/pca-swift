import XCTest
import Foundation
import CryptoKit
@testable import AtlasPCAVerify

/// Differential replay of PCAScitt against the reference (@atlasauth/pca-scitt): the deterministic CBOR codec, the RFC 9162 tree, COSE
/// Signed Statements, inclusion proofs, COSE Receipts, consistency proofs, the in-memory and durable transparency services and the
/// file-backed log store. The corpus carries signing keys as `{"$seed": label}` (an ES256 `d` is the label's seed with its top bit
/// cleared); the keys are derived here. ES256 signatures are randomized, so ES256 material is verify-only.
final class RefScittTests: XCTestCase {
    static let file = "ref-scitt.json.gz"

    // MARK: corpus <-> model

    static func fromCj(_ v: JSONValue) throws -> PCAScitt.CborValue {
        switch v {
        case .null: return .null
        case let .bool(b): return .bool(b)
        case .int, .double:
            guard let i = v.safeInt else { throw JSError("not a safe integer") }
            return .int(i)
        case let .string(s): return .text(s)
        case let .array(a): return .array(try a.map(fromCj))
        case let .object(o):
            if let b = Base.bytes(v) { return .bytes(b) }
            if let pairs = o["$map"]?.asArray {
                // a JavaScript Map keeps ONE entry per key (the later value, at the first position): the reference never sees a duplicate
                var entries: [PCAScitt.CborEntry] = []
                for p in pairs {
                    guard let kv = p.asArray, kv.count == 2 else { throw JSError("bad cj") }
                    let key: PCAScitt.CborKey
                    if let s = kv[0].asString { key = .text(s) } else if kv[0].isNumber, let i = kv[0].safeInt { key = .int(i) } else { throw JSError("bad key") }
                    let e = PCAScitt.CborEntry(key, try fromCj(kv[1]))
                    if let at = entries.firstIndex(where: { $0.key == key }) { entries[at] = e } else { entries.append(e) }
                }
                return .map(entries)
            }
            if let t = o["$tag"] {
                guard let n = t.safeInt, let inner = o["v"] else { throw JSError("bad tag") }
                return .tag(n, try fromCj(inner))
            }
            throw JSError("bad cj")
        }
    }

    static func toCj(_ v: PCAScitt.CborValue) -> JSONValue {
        switch v {
        case let .int(i): return .int(i)
        case let .text(s): return .string(s)
        case let .bytes(b): return Base.bytesValue(b)
        case let .bool(b): return .bool(b)
        case .null: return .null
        case let .array(a): return .array(a.map(toCj))
        case let .map(es):
            return .object(["$map": .array(es.map { e in
                let k: JSONValue
                switch e.key { case let .int(i): k = .int(i); case let .text(s): k = .string(s) }
                return .array([k, toCj(e.value)])
            })])
        case let .tag(t, x): return .object(["$tag": .int(t), "v": toCj(x)])
        }
    }

    // MARK: keys

    static func labelSeed(_ v: JSONValue?) throws -> [UInt8] {
        guard let label = v?.get("$seed")?.asString else { throw JSError("no key in the case") }
        return RefKeys.seed(label)
    }

    static func signer(_ spec: JSONValue?) throws -> PCAScitt.CoseSigner {
        switch spec?.get("alg")?.asString {
        case "EdDSA": return .eddsa(try Ed25519Deterministic.key(seed: try labelSeed(spec?.get("seed"))))
        case "ES256":
            var d = try labelSeed(spec?.get("d"))
            d[0] &= 0x7f
            return .es256(try P256.Signing.PrivateKey(rawRepresentation: Data(d)))
        default: throw JSError("bad key spec")
        }
    }

    static func verifier(_ spec: JSONValue?) -> PCAScitt.CoseVerifier? {
        switch spec?.get("alg")?.asString {
        case "EdDSA":
            guard let p = spec?.get("pub")?.asString, let b = Base64URLStrict.decode(p, length: 32) else { return nil }
            return .eddsa(b)
        case "ES256":
            guard let x = spec?.get("x")?.asString, let y = spec?.get("y")?.asString, let xb = Base64URLStrict.decode(x, length: 32),
                  let yb = Base64URLStrict.decode(y, length: 32) else { return nil }
            return .es256(x: xb, y: yb)
        default: return nil
        }
    }

    static func bytesList(_ v: JSONValue?) -> [[UInt8]]? {
        guard let a = v?.asArray else { return nil }
        var out: [[UInt8]] = []
        for x in a { guard let b = Base.bytes(x) else { return nil }; out.append(b) }
        return out
    }

    static func bv(_ b: [UInt8]?) -> JSONValue { b.map { Base.bytesValue($0) } ?? .null }

    static func registration(_ r: ScittRegistration) -> JSONValue {
        .object(["index": .int(r.index), "receipt": Base.bytesValue(r.receipt), "root": .string(r.root)])
    }

    static func consistency(_ c: ScittConsistencyProof) -> JSONValue {
        .object(["oldSize": .int(c.oldSize), "newSize": .int(c.newSize), "oldRoot": .string(c.oldRoot), "newRoot": .string(c.newRoot), "proof": Base.bytesValue(c.proof)])
    }

    static func checkJSON(_ r: (ok: Bool, reason: String?)) -> JSONValue {
        r.ok ? .object(["ok": .bool(true)]) : .object(["ok": .bool(false), "reason": .string(r.reason ?? "")])
    }

    // MARK: the replay

    func testScitt() throws {
        try K042.requireCovers(["Scitt", "ScittRfc9162", "ScittService", "ScittFileStore", "JSInterop"])
        let tmp = FileManager.default.temporaryDirectory.appendingPathComponent("scitt-replay-\(UUID().uuidString)")
        try FileManager.default.createDirectory(at: tmp, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: tmp) }
        var fileN = 0
        func tmpPath() -> String { fileN += 1; return tmp.appendingPathComponent("f\(fileN).log").path }

        let d = Base.Diffs()
        try Base.each(Self.file) { c in
            let a0 = c.arg(0), a1 = c.arg(1), a2 = c.arg(2), a3 = c.arg(3), a4 = c.arg(4)
            if Base.negZero(.array(c.args)) { d.skip("negative zero argument"); return }
            var got: BaseGot
            switch c.fn {
            case "cborEncode": got = Ref.v { Base.bytesValue(try PCAScitt.encode(try Self.fromCj(a0 ?? .null))) }
            case "cborDecode":
                guard let b = Base.bytes(a0) else { d.skip("cborDecode: not bytes"); return }
                got = Ref.v { Self.toCj(try PCAScitt.decode(b)) }
            case "emptyRoot": got = .value(Base.bytesValue(PCARfc9162.emptyRoot()))
            case "leafHash":
                guard let e = Base.bytes(a0) else { d.skip("leafHash: not bytes"); return }
                got = .value(Base.bytesValue(PCARfc9162.leafHash(e)))
            case "nodeHash":
                guard let l = Base.bytes(a0), let r = Base.bytes(a1) else { d.skip("nodeHash: not bytes"); return }
                got = .value(Base.bytesValue(PCARfc9162.nodeHash(l, r)))
            case "treeHash":
                guard let ls = Self.bytesList(a0) else { d.skip("treeHash: not a list of bytes"); return }
                got = .value(Base.bytesValue(PCARfc9162.treeHash(ls)))
            case "inclusionPath":
                guard let ls = Self.bytesList(a0) else { d.skip("inclusionPath: not a list of bytes"); return }
                got = Ref.v { guard let i = a1?.safeInt else { throw JSError("bad index") }; return .array(try PCARfc9162.inclusionPath(ls, i).map { Base.bytesValue($0) }) }
            case "rootFromInclusionPath":
                guard let leaf = Base.bytes(a0), let path = Self.bytesList(a3) else { d.skip("rootFromInclusionPath: not bytes"); return }
                if let i = a1?.safeInt, let n = a2?.safeInt { got = .value(Self.bv(PCARfc9162.rootFromInclusionPath(leaf, i, n, path))) } else { got = .value(.null) }
            case "verifyInclusionPath":
                guard let leaf = Base.bytes(a0), let path = Self.bytesList(a3), let root = Base.bytes(a4) else { d.skip("verifyInclusionPath: not bytes"); return }
                if let i = a1?.safeInt, let n = a2?.safeInt { got = .value(.bool(PCARfc9162.verifyInclusionPath(leaf, i, n, path, root))) } else { got = .value(.bool(false)) }
            case "consistencyPath":
                guard let ls = Self.bytesList(a0) else { d.skip("consistencyPath: not a list of bytes"); return }
                got = Ref.v { guard let m = a1?.safeInt else { throw JSError("bad size") }; return .array(try PCARfc9162.consistencyPath(ls, m).map { Base.bytesValue($0) }) }
            case "verifyConsistencyPath":
                guard let r1 = Base.bytes(a2), let r2 = Base.bytes(a3), let path = Self.bytesList(a4) else { d.skip("verifyConsistencyPath: not bytes"); return }
                if let f = a0?.safeInt, let s = a1?.safeInt { got = .value(.bool(PCARfc9162.verifyConsistencyPath(f, s, r1, r2, path))) } else { got = .value(.bool(false)) }
            case "siblingSides":
                guard let i = a0?.safeInt, let n = a1?.safeInt else { d.skip("siblingSides: non-integer"); return }
                got = .value(.array(PCAScitt.siblingSides(i, n).map { .string($0) }))
            case "encodeInclusionProof": got = Ref.v { Base.bytesValue(try PCAScitt.encodeInclusionProof(a0 ?? .null)) }
            case "decodeInclusionProof":
                guard let b = Base.bytes(a0) else { d.skip("decodeInclusionProof: not bytes"); return }
                got = Ref.v { try PCAScitt.decodeInclusionProof(b) }
            case "signStatement":
                guard a1?.get("alg")?.asString == "EdDSA", a1?.get("key")?.get("alg")?.asString == "EdDSA" else { d.skip("signStatement: ES256 signatures are randomized"); return }
                if let ct = a1?.get("contentType"), ct.asString == nil { d.skip("signStatement: non-string contentType"); return }
                if let s = a1?.get("subject"), s.asString == nil { d.skip("signStatement: non-string subject"); return }
                got = Ref.v {
                    guard let iss = a1?.get("issuer")?.asString else { throw JSError("issuer is required") }
                    return Base.bytesValue(try PCAScitt.signStatement(a0 ?? .null, signer: try Self.signer(a1?.get("key")), issuer: iss, subject: a1?.get("subject")?.asString,
                                                                     contentType: a1?.get("contentType")?.asString))
                }
            case "decodeCoseSign1":
                guard let b = Base.bytes(a0) else { d.skip("decodeCoseSign1: not bytes"); return }
                got = Ref.v {
                    let s = try PCAScitt.decodeCoseSign1(b)
                    return .object(["protectedBytes": Base.bytesValue(s.protectedBytes), "protectedMap": Self.toCj(s.protectedMap), "unprotected": Self.toCj(s.unprotected),
                                    "payload": Self.bv(s.payload), "signature": Base.bytesValue(s.signature)])
                }
            case "checkStatement", "verifyStatement":
                guard let st = Base.bytes(a0) else { d.skip("\(c.fn): not bytes"); return }
                guard let key = Self.verifier(a1) else { got = .threw(nil); break }
                let hi = a2?.get("allowHighS") == .bool(true)
                if c.fn == "verifyStatement" { got = .value(.bool(PCAScitt.verifyStatement(st, key, allowHighS: hi))) } else {
                    var r = Self.checkJSON(PCAScitt.checkStatement(st, key, allowHighS: hi))
                    // the reference's `malformed: <detail>` carries a JavaScript / Node message: only the prefix is comparable
                    if let want = c.out.get("reason")?.asString, want.hasPrefix("malformed:"), r.get("reason")?.asString?.hasPrefix("malformed:") == true { r = c.out }
                    got = .value(r)
                }
            case "statementPayload":
                guard let st = Base.bytes(a0) else { d.skip("statementPayload: not bytes"); return }
                got = Ref.v { Base.bytesValue(try PCAScitt.statementPayload(st)) }
            case "statementLeaf":
                guard let st = Base.bytes(a0) else { d.skip("statementLeaf: not bytes"); return }
                got = .value(.string(PCAScitt.statementLeaf(st)))
            case "buildReceipt":
                guard a2?.get("alg")?.asString == "EdDSA" else { d.skip("buildReceipt: ES256 signatures are randomized"); return }
                got = Ref.v {
                    guard let root = a0?.asString else { throw JSError("bad root") }
                    return Base.bytesValue(try PCAScitt.buildReceipt(root: root, proof: a1 ?? .null, signer: try Self.signer(a2?.get("key")), issuer: a2?.get("issuer")?.asString))
                }
            case "verifyReceipt":
                guard let r = Base.bytes(a0), let st = Base.bytes(a1) else { d.skip("verifyReceipt: not bytes"); return }
                let o = a2?.asObject ?? [:]
                // a key spec the reference cannot build throws before the verifier runs; none occurs in the corpus
                let vk = o["verificationKey"].flatMap { Self.verifier($0) }, sk = o["statementKey"].flatMap { Self.verifier($0) }
                if (o["verificationKey"] != nil && vk == nil) || (o["statementKey"] != nil && sk == nil) { d.skip("verifyReceipt: unusable key spec"); return }
                // a non-string pinned root can never equal a root
                let tr: String? = o["treeRoot"].map { $0.asString ?? "\u{1}" }
                got = .value(.bool(PCAScitt.verifyReceipt(r, st, treeRoot: tr, verificationKey: vk, statementKey: sk, allowHighS: o["allowHighS"] == .bool(true))))
            case "verifyConsistencyProof":
                guard let p = Base.bytes(a0) else { d.skip("verifyConsistencyProof: not bytes"); return }
                if let x = a1?.asString, let y = a2?.asString { got = .value(.bool(PCAScitt.verifyConsistencyProof(p, x, y))) } else { got = .value(.bool(false)) }
            case "constants":
                got = .value(.object(["COSE_SIGN1_TAG": .int(PCAScitt.COSE_SIGN1_TAG), "HDR_ALG": .int(PCAScitt.HDR_ALG), "HDR_CONTENT_TYPE": .int(PCAScitt.HDR_CONTENT_TYPE),
                                      "HDR_CWT_CLAIMS": .int(PCAScitt.HDR_CWT_CLAIMS), "CWT_ISS": .int(PCAScitt.CWT_ISS), "CWT_SUB": .int(PCAScitt.CWT_SUB),
                                      "HDR_VDS": .int(PCAScitt.HDR_VDS), "HDR_VDS_PROOFS": .int(PCAScitt.HDR_VDS_PROOFS), "VDS_RFC9162_SHA256": .int(PCAScitt.VDS_RFC9162_SHA256),
                                      "PROOF_TYPE_INCLUSION": .int(PCAScitt.PROOF_TYPE_INCLUSION), "DEFAULT_CONTENT_TYPE": .string(PCAScitt.DEFAULT_CONTENT_TYPE)]))
            case "es256SignVerify":
                got = Ref.v {
                    guard let iss = a2?.asString, let pub = Self.verifier(a0) else { throw JSError("bad args") }
                    let st = try PCAScitt.signStatement(a1 ?? .null, signer: try Self.signer(a0), issuer: iss)
                    let cose = try PCAScitt.decodeCoseSign1(st)
                    return .object(["check": Self.checkJSON(PCAScitt.checkStatement(st, pub)), "payload": Base.bytesValue(try PCAScitt.statementPayload(st)),
                                    "lowS": .bool(PCAScitt.isCanonicalEs256(cose.signature)), "protectedBytes": Base.bytesValue(cose.protectedBytes)])
                }
            case "es256Receipt":
                got = Ref.v {
                    guard let n = a1?.safeInt, let index = a2?.safeInt, let edKey = Self.signerEd(a3), let pub = Self.verifier(a0), let wrong = Self.verifier(a4) else { throw JSError("bad args") }
                    let svc = PCAScittMemoryService(signer: try Self.signer(a0), issuer: "ts")
                    var sts: [[UInt8]] = []
                    for i in 0..<Int(n) { sts.append(try svc.appendAndReceipt(.object(["i": .int(Int64(i))]), signer: edKey.signer, issuer: "iss").statement) }
                    let r = try svc.getReceipt(index)
                    let st = sts[Int(index)]
                    let other = n > 0 ? sts[Int((index + 1) % n)] : [0, 0, 0]
                    let edPub = PCAScitt.CoseVerifier.eddsa(edKey.pub)
                    return .object([
                        "key": .bool(PCAScitt.verifyReceipt(r.receipt, st, verificationKey: pub)),
                        "root": .bool(PCAScitt.verifyReceipt(r.receipt, st, treeRoot: r.root)),
                        "both": .bool(PCAScitt.verifyReceipt(r.receipt, st, treeRoot: r.root, verificationKey: pub, statementKey: edPub)),
                        "wrongKey": .bool(PCAScitt.verifyReceipt(r.receipt, st, verificationKey: wrong)),
                        "otherStatement": .bool(PCAScitt.verifyReceipt(r.receipt, other, verificationKey: pub)),
                        "none": .bool(PCAScitt.verifyReceipt(r.receipt, st)),
                    ])
                }
            case "service":
                got = Self.runService(a0)
            case "fileStoreBytes":
                let path = tmpPath()
                got = Ref.v {
                    let s = try FileScittLogStore.open(path)
                    for op in a0?.asArray ?? [] {
                        guard let expected = op.get("expected")?.safeInt, let entry = Base.bytes(op.get("entry")), let ns = op.get("nodes")?.asArray else { continue }
                        var nodes: [ScittStoredNode] = []
                        for n in ns {
                            guard let t = n.asArray, t.count == 3, let level = t[0].safeInt, let index = t[1].safeInt, let h = t[2].asString, let hb = Base64URLStrict.decode(h) else { continue }
                            nodes.append(ScittStoredNode(level: Int(level), index: index, hash: hb))
                        }
                        _ = try? s.append(expectedSize: expected, entry: entry, nodes: nodes) // a refused / malformed append writes nothing
                    }
                    s.close()
                    return Base.bytesValue([UInt8](try Data(contentsOf: URL(fileURLWithPath: path))))
                }
            case "fileStoreOpen":
                guard let blob = Base.bytes(a0) else { d.skip("fileStoreOpen: not bytes"); return }
                let path = tmpPath()
                got = Ref.v {
                    try Data(blob).write(to: URL(fileURLWithPath: path))
                    let s = try FileScittLogStore.open(path)
                    defer { s.close() }
                    let size = try s.size()
                    var entries: [JSONValue] = [], nodes0: [JSONValue] = []
                    for i in 0..<size {
                        entries.append(Self.bv(try s.getEntry(i)))
                        nodes0.append(Self.bv(try s.getNode(0, i)))
                    }
                    return .object(["size": .int(size), "entries": .array(entries), "nodes0": .array(nodes0), "after": Base.bytesValue([UInt8](try Data(contentsOf: URL(fileURLWithPath: path))))])
                }
            case "checkScittLogStore":
                let failures: [String]
                if a0?.asString == "memory" { failures = checkScittLogStore { MemoryScittLogStore() } } else { failures = checkScittLogStore { try FileScittLogStore.open(tmpPath()) } }
                got = .value(.array(failures.map { .string($0) }))
            default:
                d.skip("\(c.fn): not mapped"); return
            }
            d.add(c, Base.diff(c, got))
        }
        d.finish(7500)
    }

    /// An Ed25519 key spec as (signer, public key bytes).
    static func signerEd(_ spec: JSONValue?) -> (signer: PCAScitt.CoseSigner, pub: [UInt8])? {
        guard let s = try? labelSeed(spec?.get("seed")), let k = try? Ed25519Deterministic.key(seed: s) else { return nil }
        return (.eddsa(k), k.pub)
    }

    // MARK: transparency services

    final class FaultStore: ScittLogStore {
        let inner = MemoryScittLogStore()
        let f: JSONValue
        init(_ f: JSONValue) { self.f = f }
        func size() throws -> Int64 {
            if f.get("negSize") == .bool(true) { return -1 }
            return try inner.size()
        }
        func getEntry(_ index: Int64) throws -> [UInt8]? { try inner.getEntry(index) }
        func getNode(_ level: Int, _ index: Int64) throws -> [UInt8]? {
            if let p = f.get("dropNode")?.asArray, p.count == 2, p[0].safeInt == Int64(level), p[1].safeInt == index { return nil }
            if let p = f.get("shortNode")?.asArray, p.count == 2, p[0].safeInt == Int64(level), p[1].safeInt == index { return [UInt8](repeating: 0, count: 31) }
            return try inner.getNode(level, index)
        }
        func append(expectedSize: Int64, entry: [UInt8], nodes: [ScittStoredNode]) throws -> Bool {
            if f.get("stale") == .bool(true) { return false }
            return try inner.append(expectedSize: expectedSize, entry: entry, nodes: nodes)
        }
    }

    /// One scenario run against the memory or durable service: `[{ok: ...} | {err: code | true}]` per op.
    static func runService(_ spec: JSONValue?) -> BaseGot {
        guard let spec = spec, let kind = spec.get("kind")?.asString, let key = try? signer(spec.get("key")), let stmt = signerEd(spec.get("stmtKey")), let ops = spec.get("ops")?.asArray else {
            return .threw(nil)
        }
        let issuer = spec.get("issuer")?.asString
        let memory = PCAScittMemoryService(signer: key, issuer: issuer)
        let store: ScittLogStore
        if let f = spec.get("storeFault") { store = FaultStore(f) } else { store = MemoryScittLogStore() }
        let durable = PCAScittDurableService(store: store, signer: key, issuer: issuer)
        let isMemory = kind == "memory"
        func index(_ v: JSONValue?) throws -> Int64 {
            // 1.5 is no index the native API can take; the reference's durable service refuses it as an out-of-range index (its in-memory service as a plain error)
            guard let i = v?.safeInt, v?.isNumber == true else { throw isMemory ? JSError("not an integer") : JSError("index out of range", code: PCAScittLogError.outOfRange) }
            return i
        }
        func append(_ r: ScittAppendResult) -> JSONValue {
            .object(["statement": Base.bytesValue(r.statement), "index": .int(r.registration.index), "receipt": Base.bytesValue(r.registration.receipt), "root": .string(r.registration.root)])
        }
        var res: [JSONValue] = []
        for op in ops {
            do {
                let v: JSONValue
                switch op.get("op")?.asString ?? "" {
                case "append":
                    let payload = op.get("payload") ?? .null, subject = op.get("subject")?.asString, contentType = op.get("contentType")?.asString
                    if isMemory {
                        v = append(try memory.appendAndReceipt(payload, signer: stmt.signer, issuer: "https://issuer.example", subject: subject, contentType: contentType))
                    } else {
                        v = append(try durable.appendAndReceipt(payload, signer: stmt.signer, issuer: "https://issuer.example", subject: subject, contentType: contentType))
                    }
                case "register":
                    guard let st = Base.bytes(op.get("statement")) else { throw JSError("bad statement") }
                    if isMemory { v = registration(try memory.register(st)) } else { v = registration(try durable.register(st)) }
                case "receipt":
                    let i = try index(op.get("i"))
                    if isMemory { v = registration(try memory.getReceipt(i)) } else { v = registration(try durable.getReceipt(i)) }
                case "consistency":
                    let m = try index(op.get("m"))
                    if isMemory { v = consistency(try memory.consistencyProof(m)) } else { v = consistency(try durable.consistencyProof(m)) }
                case "entry":
                    if isMemory { throw JSError("the in-memory service has no getEntry") }
                    v = Base.bytesValue(try durable.getEntry(try index(op.get("i"))))
                case "snapshot":
                    if !isMemory { throw JSError("the durable service has no snapshot") }
                    v = .array(memory.snapshot().map { .string($0) })
                case "root":
                    if isMemory { v = .string(memory.root) } else { v = .string(try durable.root()) }
                case "size":
                    if isMemory { v = .int(memory.size) } else { v = .int(try durable.size()) }
                default: throw JSError("op")
                }
                res.append(.object(["ok": v]))
            } catch {
                res.append(.object(["err": (error as? JSError)?.code.map { .string($0) } ?? .bool(true)]))
            }
        }
        return .value(.array(res))
    }

    func testStatementAndReceiptRoundTrip() throws {
        let tsKey = try Ed25519Deterministic.key(seed: RefKeys.seed("scitt-roundtrip/ts"))
        let issuerKey = try Ed25519Deterministic.key(seed: RefKeys.seed("scitt-roundtrip/issuer"))
        let svc = PCAScittMemoryService(signer: .eddsa(tsKey), issuer: "ts.example")
        var statements: [[UInt8]] = []
        for i in 0..<5 {
            statements.append(try svc.appendAndReceipt(.object(["i": .int(Int64(i))]), signer: .eddsa(issuerKey), issuer: "https://issuer.example").statement)
        }
        let r = try svc.getReceipt(3)
        let tsPub = PCAScitt.CoseVerifier.eddsa(tsKey.pub), issuerPub = PCAScitt.CoseVerifier.eddsa(issuerKey.pub)
        XCTAssertTrue(PCAScitt.verifyReceipt(r.receipt, statements[3], treeRoot: r.root, verificationKey: tsPub, statementKey: issuerPub))
        // another statement, a wrong pinned root and a missing anchor are all refused
        XCTAssertFalse(PCAScitt.verifyReceipt(r.receipt, statements[2], verificationKey: tsPub))
        XCTAssertFalse(PCAScitt.verifyReceipt(r.receipt, statements[3], treeRoot: svc.snapshot().first ?? "x"))
        XCTAssertFalse(PCAScitt.verifyReceipt(r.receipt, statements[3]))
        // the log only ever grows: the first 2 entries are a prefix of the 5
        let c = try svc.consistencyProof(2)
        XCTAssertTrue(PCAScitt.verifyConsistencyProof(c.proof, c.oldRoot, c.newRoot))
        XCTAssertFalse(PCAScitt.verifyConsistencyProof(c.proof, c.newRoot, c.oldRoot))
    }

    func testEs256IsLowSOnly() throws {
        let key = P256.Signing.PrivateKey()
        let x963 = [UInt8](key.publicKey.x963Representation)
        let pub = PCAScitt.CoseVerifier.es256(x: Array(x963[1..<33]), y: Array(x963[33..<65]))
        let st = try PCAScitt.signStatement(.object(["a": .int(1)]), signer: .es256(key), issuer: "iss")
        XCTAssertTrue(PCAScitt.verifyStatement(st, pub))
        // the high-S twin of a valid signature verifies mathematically but is refused unless the caller opts in
        let cose = try PCAScitt.decodeCoseSign1(st)
        let n: [UInt8] = [0xff, 0xff, 0xff, 0xff, 0, 0, 0, 0, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xbc, 0xe6, 0xfa, 0xad, 0xa7, 0x17, 0x9e, 0x84, 0xf3, 0xb9, 0xca, 0xc2, 0xfc, 0x63, 0x25, 0x51]
        var high = Array(cose.signature[32...])
        var borrow = 0
        for i in stride(from: 31, through: 0, by: -1) {
            var v = Int(n[i]) - Int(high[i]) - borrow
            if v < 0 { v += 256; borrow = 1 } else { borrow = 0 }
            high[i] = UInt8(v)
        }
        let twin = try PCAScitt.encode(.tag(18, .array([.bytes(cose.protectedBytes), .map([]), .bytes(cose.payload ?? []), .bytes(Array(cose.signature[0..<32]) + high)])))
        XCTAssertFalse(PCAScitt.verifyStatement(twin, pub))
        XCTAssertEqual(PCAScitt.checkStatement(twin, pub).reason, "non-canonical signature (high-S)")
        XCTAssertTrue(PCAScitt.verifyStatement(twin, pub, allowHighS: true))
    }
}
