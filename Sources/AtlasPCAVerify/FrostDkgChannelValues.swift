import Foundation

extension PCAFrostDkgWire {
    /// `encodeDkgMessage` over a JSON value for the kind: the reference writes `JSON.stringify({v, sid, kind, body})` of whatever it is given (a number
    /// kind is written as a number, an absent one is left out), and refuses only a message above the cap. The typed entry stays strict.
    public static func encodeDkgMessage(_ sessionId: [UInt8], kindValue: JSONValue?, _ body: JSONValue, order: [String] = []) throws -> [UInt8] {
        let kind = kindValue.map { ",\"kind\":\(JS.stringify($0))" } ?? ""
        let text = "{\"v\":\(DKG_WIRE_VERSION),\"sid\":\(Canonical.canonicalize(.string(Base64URLStrict.encode(sessionId))))\(kind),\"body\":\(JS.stringify(body, order: order))}"
        let bytes = Array(text.utf8)
        if bytes.count > DKG_MAX_MESSAGE_BYTES { throw PCADkgChannelError("oversize", nil, "message of \(bytes.count) bytes exceeds the cap") }
        return bytes
    }
}
