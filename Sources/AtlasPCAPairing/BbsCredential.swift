import Foundation
import AtlasPCAVerify

/// A PCA capability as a multi-message BBS credential, presented with selective disclosure and unlinkable proofs. The message
/// vector is: index 0 = iss (issuer key), 1 = sub (holder key), 2.. = one message per caveat, named cav:<i>:<type>, whose value
/// is the strict-canonical JSON of the caveat. Each message's octets are utf8(name) || 0x00 || utf8(value). Credentials and
/// presentations are generic JSON values, so hostile shapes are refused, never trusted.
public enum BbsCredential {
    struct Attr {
        let index: Int
        let name: String
        let value: String
    }

    static func get(_ v: JSONValue, _ k: String) -> JSONValue? { v.objectValue?[JKey(k)] }
    static func str(_ v: JSONValue, _ k: String) -> String? { get(v, k)?.stringValue }

    /// One {index, name, value} attribute; nil for any other shape (non-string name or value, non-integer index).
    static func attrOf(_ v: JSONValue) -> Attr? {
        guard v.objectValue != nil, let name = str(v, "name"), let value = str(v, "value"), case let .int(i)? = get(v, "index") else { return nil }
        return Attr(index: Int(clamping: i), name: name, value: value)
    }

    static func attrsOf(_ v: JSONValue?) -> [Attr]? {
        guard let l = v?.arrayValue else { return nil }
        var out: [Attr] = []
        for a in l { guard let x = attrOf(a) else { return nil }; out.append(x) }
        return out
    }

    static func attrJSON(_ a: Attr) -> JSONValue { .object(["index": .int(Int64(a.index)), "name": .string(a.name), "value": .string(a.value)]) }

    /// The deterministic message octets of one attribute; the NUL separator must be unambiguous.
    static func encodeAttribute(_ name: String, _ value: String) throws -> [UInt8] {
        if name.unicodeScalars.contains(where: { $0.value == 0 }) { throw PairingError("attribute name must not contain NUL") }
        return Array(name.utf8) + [0] + Array(value.utf8)
    }

    static func encodeAll(_ attrs: [Attr]) throws -> [[UInt8]] { try attrs.map { try encodeAttribute($0.name, $0.value) } }

    /// The ordered attribute vector for a capability {issuer, holder, caveats}.
    public static func capabilityAttributes(_ capability: JSONValue) throws -> JSONValue {
        guard let issuer = str(capability, "issuer"), let holder = str(capability, "holder") else { throw PairingError("capability issuer and holder must be strings") }
        var out = [attrJSON(Attr(index: 0, name: "iss", value: issuer)), attrJSON(Attr(index: 1, name: "sub", value: holder))]
        for (i, cv) in (get(capability, "caveats")?.arrayValue ?? []).enumerated() {
            var typ = "undefined" // a caveat without a type, as the reference stringifies it
            if cv.objectValue != nil, let t = get(cv, "type") {
                guard let s = t.stringValue else { throw PairingError("caveat type must be a string") }
                typ = s
            }
            out.append(attrJSON(Attr(index: i + 2, name: "cav:\(i):\(typ)", value: try PCAWire.canonicalStrict(cv))))
        }
        return .array(out)
    }

    /// Signs a capability's attributes as a BBS credential; `header` is bound into the signature.
    public static func issueCapabilityCredential(_ capability: JSONValue, sk: Fr, pk: [UInt8], header: [UInt8]) throws -> JSONValue {
        let attrs = try capabilityAttributes(capability)
        let msgs = try encodeAll(attrsOf(attrs) ?? [])
        let sig = try Bbs.sign(sk: sk, pk: pk, header: header, messages: msgs)
        return .object(["issuerPublicKey": .string(PCAWire.b64uEncode(pk)), "header": .string(PCAWire.b64uEncode(header)),
                        "attributes": attrs, "signature": .string(PCAWire.b64uEncode(sig))])
    }

    /// Verifies a whole credential against its issuer key. Never traps; false on any malformed input.
    public static func verifyCredential(_ cred: JSONValue) -> Bool {
        guard let pks = str(cred, "issuerPublicKey"), let hs = str(cred, "header"), let ss = str(cred, "signature"),
              let pk = PCAWire.b64uDecode(pks), let header = PCAWire.b64uDecode(hs), let sig = PCAWire.b64uDecode(ss),
              let attrs = attrsOf(get(cred, "attributes")), let msgs = try? encodeAll(attrs) else { return false }
        return Bbs.verify(pk: pk, signature: sig, header: header, messages: msgs)
    }

    /// The verifier's own expectations; every field is optional (nil = take the presentation's value).
    public struct PresentOptions {
        public var publicKey: [UInt8]?
        public var disclosed: [JSONValue]?
        public var presentationHeader: [UInt8]?
        public init(publicKey: [UInt8]? = nil, disclosed: [JSONValue]? = nil, presentationHeader: [UInt8]? = nil) {
            self.publicKey = publicKey; self.disclosed = disclosed; self.presentationHeader = presentationHeader
        }
    }

    static func disclosureKeys(_ a: [Attr]) -> [[UInt8]] {
        var keys: [[UInt8]] = []
        for x in a {
            var k: [UInt8] = Array("\(x.index)".utf8)
            k.append(0)
            k += Array(x.name.utf8)
            k.append(0)
            k += Array(x.value.utf8)
            keys.append(k)
        }
        return keys.sorted { $0.lexicographicallyPrecedes($1) }
    }

    /// Checks a selective-disclosure proof; `opts` asserts the verifier's own expectations (a pinned issuer key, the exact
    /// attributes required, the action digest the proof must be bound to).
    public static func verifyPresentation(_ pres: JSONValue, _ opts: PresentOptions = PresentOptions()) -> Bool {
        guard let pks = str(pres, "issuerPublicKey"), let hs = str(pres, "header"), let prs = str(pres, "proof") else { return false }
        var pk = opts.publicKey ?? []
        if opts.publicKey == nil { guard let d = PCAWire.b64uDecode(pks) else { return false }; pk = d }
        guard let header = PCAWire.b64uDecode(hs), let proof = PCAWire.b64uDecode(prs) else { return false }
        // a pinned issuer key must be the one the presentation claims
        if let pinned = opts.publicKey, PCAWire.b64uEncode(pinned) != pks { return false }
        let phs = str(pres, "presentationHeader") ?? ""
        var ph = opts.presentationHeader ?? []
        if opts.presentationHeader == nil { guard let d = PCAWire.b64uDecode(phs) else { return false }; ph = d }
        if let pinned = opts.presentationHeader, !pinned.isEmpty, PCAWire.b64uEncode(ph) != phs { return false }
        guard let shown = attrsOf(get(pres, "disclosed")) else { return false }
        var disclosed = shown
        if let want = opts.disclosed {
            guard let pinned = attrsOf(.array(want)), disclosureKeys(pinned) == disclosureKeys(shown) else { return false }
            disclosed = pinned
        }
        guard case let .int(n)? = get(pres, "messageCount") else { return false }
        let sorted = disclosed.enumerated().sorted { $0.element.index != $1.element.index ? $0.element.index < $1.element.index : $0.offset < $1.offset }.map { $0.element }
        guard let msgs = try? encodeAll(sorted) else { return false }
        for a in sorted where Int64(a.index) >= n || a.index < 0 { return false }
        return Bbs.proofVerify(pk: pk, proof: proof, header: header, ph: ph, disclosedMessages: msgs, disclosedIndexes: sorted.map { $0.index })
    }
}
