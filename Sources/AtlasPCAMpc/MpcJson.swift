import Foundation
import AtlasPCAVerify

// The JSONValue accessors the MPC wire code reads with (the verifier keeps its own internal; distinct names, so a test target importing both @testable is not ambiguous).
extension JSONValue {
    var mpcString: String? { if case let .string(s) = self { return s } else { return nil } }
    var mpcObject: JObject? { if case let .object(o) = self { return o } else { return nil } }
    var mpcArray: [JSONValue]? { if case let .array(a) = self { return a } else { return nil } }
    func mpcGet(_ key: String) -> JSONValue? { mpcObject?[JKey(key)] }
}
