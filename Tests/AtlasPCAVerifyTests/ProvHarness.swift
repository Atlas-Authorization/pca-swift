import Foundation
@testable import AtlasPCAVerify

/// Provenance by default in the authorize harnesses (as the TypeScript harnesses do): every operation the existing authorize tests run
/// comes straight from the principal, so they present a principal-direct bundle recorded with this SDK's own recorder under the pinned
/// harness key (Ed25519 seed = 32 bytes of 0x01, mediator `conformance-harness`, kid `k1`). The gate stays on and passes, and the
/// outcomes are those of the rules under test.
enum ProvHarness {
    static let SEED = [UInt8](repeating: 1, count: 32)
    static let SESSION = Base64URLStrict.encode([UInt8](repeating: 2, count: 32))
    static let NOW: Int64 = 1_793_188_800_000

    static func recorder() -> ProvenanceRecorder {
        // a fresh session per bundle: principal message, then the action
        try! ProvenanceRecorder(mediator: "conformance-harness", kid: "k1", secretKey: SEED, session: SESSION, now: { NOW })
    }

    static let pin: JSONValue = recorder().pin

    /// The principal-direct bundle of `op` (nil when its params are outside the strict JSON profile: nothing can bind them).
    static func bundle(_ op: PCA.Operation) -> JSONValue? { try? PCA.principalDirectProvenance(recorder(), op) }

    /// The `PCA-Provenance` header value for `op`.
    static func header(_ op: PCA.Operation) -> String? { bundle(op).map(ProvenanceRecorder.header) }

    /// The header for the operation the guard tests' mapper derives from a body (verb payments.send on payments/acme).
    static func header(paymentsBody body: [UInt8]) -> String? {
        guard let params = JSONValue.parse(String(decoding: body, as: UTF8.self)) else { return nil }
        return header(PCA.Operation(verb: "payments.send", resource: "payments/acme", params: params))
    }
}

extension PCA.AuthorizeInput {
    /// Pin the harness mediator and present the principal-direct bundle of the CURRENT operation (call it after any edit of `operation`).
    func withProv() -> PCA.AuthorizeInput {
        var x = self
        if !x.argProvenance.mediators.contains(ProvHarness.pin) { x.argProvenance.mediators.append(ProvHarness.pin) }
        x.provenance = x.operation.flatMap(ProvHarness.bundle)
        return x
    }
}

extension PcaAuthorizeConfig {
    /// Pin the harness mediator (the request then carries the bundle: header `PCA-Provenance` or body member `pca_provenance`).
    mutating func pinProvHarness() {
        if !argProvenance.mediators.contains(ProvHarness.pin) { argProvenance.mediators.append(ProvHarness.pin) }
    }
}
