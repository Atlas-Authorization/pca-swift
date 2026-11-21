import Foundation
import AtlasPCAVerify

/// BLS aggregation of transparency-ledger witness cosignatures: a quorum of witnesses cosign the same tree-head statement
/// {size, root, prev_root, guardian_epoch} under their own BLS keys; the quorum collapses into one 96-byte aggregate checked by
/// one FastAggregateVerify.
public enum AggsigWitness {
    static let domain = Array("atlas-pca/sth-witness-bls/v1\0".utf8)

    /// The bytes a witness cosigns: the domain separator followed by the canonical statement (guardian_epoch defaults to 0).
    static func message(_ sth: JSONValue) throws -> [UInt8] {
        guard let o = sth.objectValue else { throw PairingError("statement is not an object") }
        var ge = o[JKey("guardian_epoch")] ?? .null
        if ge == .null { ge = .int(0) }
        guard let size = o[JKey("size")], let root = o[JKey("root")], let prev = o[JKey("prev_root")] else { throw PairingError("statement is missing a field") }
        let body: JSONValue = .object(["size": size, "root": root, "prev_root": prev, "guardian_epoch": ge])
        return domain + Array(try PCAWire.canonicalStrict(body).utf8)
    }

    /// A witness cosigns the tree-head statement with its BLS secret key: {key, sig, suite}.
    public static func cosignTreeHead(_ sth: JSONValue, witnessSecret: [UInt8]) throws -> JSONValue {
        let m = try message(sth)
        return .object(["key": .string(PCAWire.b64uEncode(try Aggsig.publicKeyOf(witnessSecret))),
                        "sig": .string(PCAWire.b64uEncode(try Aggsig.sign(witnessSecret, m))), "suite": .string(AggsigChain.blsSuite)])
    }

    /// Verifies ONE cosignature against the exact statement. Never traps.
    public static func verifyWitnessCosignature(_ sth: JSONValue, _ cosig: JSONValue) -> Bool {
        guard cosig.objectValue != nil, AggsigChain.str(cosig, "suite") == AggsigChain.blsSuite,
              let ks = AggsigChain.str(cosig, "key"), let ss = AggsigChain.str(cosig, "sig"),
              let k = PCAWire.b64uDecode(ks), let s = PCAWire.b64uDecode(ss), let m = try? message(sth) else { return false }
        return Aggsig.verify(k, m, s)
    }

    /// Collapses a quorum of cosignatures into one 96-byte aggregate.
    public static func aggregateWitnessCosignatures(_ cosigs: JSONValue) throws -> [UInt8] {
        guard let cs = cosigs.arrayValue, !cs.isEmpty else { throw PairingError("aggregateWitnessCosignatures: empty set") }
        return try Aggsig.aggregate(try cs.map { c in
            guard let s = AggsigChain.str(c, "sig"), let b = PCAWire.b64uDecode(s) else { throw PairingError("aggregateWitnessCosignatures: cosignature sig is not valid base64url") }
            return b
        })
    }

    /// Verifies an aggregate over one statement with a single FastAggregateVerify; a witness may appear once.
    public static func verifyAggregatedWitnessCosignatures(_ sth: JSONValue, witnessKeys: [Aggsig.RegisteredKey], aggSig: [UInt8]) -> Bool {
        guard let m = try? message(sth) else { return false }
        return Aggsig.fastAggregateVerify(witnessKeys, m, aggSig)
    }
}
