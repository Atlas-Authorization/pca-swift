import Vapor
import AtlasPCAVerify
import AtlasPCAVapor

/// Wires `POST /refunds` behind `protect(...)`. The route runs one operation; a request is allowed only when it carries a PCActn that
/// authorizes exactly that operation (the verb and resource below plus the request body as the params), under a grant you registered.
/// Returns the revoke handle: `revoke(grantId)` refuses every later action under that grant.
@discardableResult
public func configure(_ app: Application, audience: String, grants: [JSONValue], verb: String = "payments.refund",
                      resource: String = "payments/acme", now: (() -> Int64)? = nil) throws -> Protected {
    let p = protect(audience: audience, operation: { req in
        // the params come from this request's body, never from the proof
        guard let params = JSONValue.parse(String(decoding: req.body, as: UTF8.self)) else { return nil }
        return PCA.Operation(verb: verb, resource: resource, params: params)
    }, grants: grants, now: now)
    app.middleware.use(try p.middleware())
    app.post("refunds") { req -> String in
        "refunded:\(req.pca?.operation?.verb ?? "-")"
    }
    return p
}
