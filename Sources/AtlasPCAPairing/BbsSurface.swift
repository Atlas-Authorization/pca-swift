import Foundation
import AtlasPCAVerify

extension Bbs {
    /// The ciphersuite id of the draft (the prefix of every domain-separation tag).
    public static let CIPHERSUITE_ID = "BBS_BLS12381G1_XMD:SHA-256_SSWU_RO_"

    /// A secret key as its 32 big-endian octets.
    public static func skToBytes(_ sk: Fr) -> [UInt8] { sk.bytes }

    /// A secret key from exactly 32 big-endian octets in [1, r).
    public static func skFromBytes(_ bytes: [UInt8]) throws -> Fr {
        guard bytes.count == 32 else { throw PairingError("bbs: SK must be 32 octets") }
        guard let sk = Fr(canonical: bytes), !sk.isZero else { throw PairingError("bbs: SK out of range") }
        return sk
    }
}

extension BbsCredential {
    /// A selective-disclosure proof that reveals only the named attributes; `presentationHeader` binds the proof to a context (an action digest, a nonce).
    /// Fresh randomness per call, so two presentations of one credential are unlinkable.
    public static func presentCredential(_ cred: JSONValue, disclose: [String], presentationHeader: [UInt8] = []) throws -> JSONValue {
        guard let pks = str(cred, "issuerPublicKey"), let hs = str(cred, "header"), let ss = str(cred, "signature"),
              let pk = PCAWire.b64uDecode(pks), let header = PCAWire.b64uDecode(hs), let signature = PCAWire.b64uDecode(ss),
              let attrs = attrsOf(get(cred, "attributes")) else { throw PairingError("presentCredential: malformed credential") }
        var wanted: [String] = []
        for n in disclose where !wanted.contains(where: { $0 == n }) { wanted.append(n) }
        var disclosedIndexes: [Int] = [], disclosed: [JSONValue] = []
        for a in attrs where wanted.contains(where: { $0 == a.name }) {
            disclosedIndexes.append(a.index)
            disclosed.append(attrJSON(a))
        }
        let missing = wanted.filter { n in !attrs.contains { $0.name == n } }
        if !missing.isEmpty { throw PairingError("presentCredential: unknown attribute(s): " + missing.joined(separator: ", ")) }
        let proof = try Bbs.proofGen(pk: pk, signature: signature, header: header, ph: presentationHeader, messages: try encodeAll(attrs), disclosedIndexes: disclosedIndexes)
        return .object(["issuerPublicKey": .string(pks), "header": .string(hs), "presentationHeader": .string(PCAWire.b64uEncode(presentationHeader)),
                        "messageCount": .int(Int64(attrs.count)), "disclosed": .array(disclosed), "proof": .string(PCAWire.b64uEncode(proof))])
    }
}
