import Vapor
import AtlasPCAVerify
import AtlasPCAVapor

/// Wires `POST /refunds` behind `protect(...)`. The route runs one operation; a request is allowed only when it carries a PCActn that
/// authorizes exactly that operation (the verb and resource below plus the request body as the params), under a grant you registered.
/// Returns the revoke handle: `revoke(grantId)` refuses every later action under that grant.
/// `mediators`: the pins of the agent harnesses whose provenance receipts you trust (provenance is checked by default: a request
/// without a verified `PCA-Provenance` bundle for a sensitive refund is refused as an escalation).
@discardableResult
public func configure(_ app: Application, audience: String, grants: [JSONValue], verb: String = "payments.refund",
                      resource: String = "payments/acme", mediators: [JSONValue] = [], now: (() -> Int64)? = nil) throws -> Protected {
    let p = protect(audience: audience, operation: { req in
        // the params come from this request's body, never from the proof
        guard let params = JSONValue.parse(String(decoding: req.body, as: UTF8.self)) else { return nil }
        return PCA.Operation(verb: verb, resource: resource, params: params)
    }, grants: grants, now: now, configure: { $0.authorize?.argProvenance.mediators = mediators })
    app.middleware.use(try p.middleware())
    app.post("refunds") { req -> String in
        "refunded:\(req.pca?.operation?.verb ?? "-")"
    }
    return p
}
