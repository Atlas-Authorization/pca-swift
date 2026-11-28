import Vapor
import AtlasPCAVerify

extension Protected {
    /// The Vapor middleware for `protect(...)`:
    ///
    ///     let p = protect(audience: "ins_acme", operation: { req in ... }, grants: [grant])
    ///     app.middleware.use(try p.middleware())
    ///     p.revoke(grantId)
    public func middleware() throws -> PcaMiddleware {
        try PcaMiddleware(config)
    }
}
