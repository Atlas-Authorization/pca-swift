/// TypeScript export names of the request-guard packages that this SDK carries under another name.
public typealias RequirePcaOptions = PcaGuardConfig

extension PCAFetch {
    /// A guard over a request: the full decision, to compose inside an existing router (the reference's `createPcaFetchGuard`; see `createGuard`).
    public static func createPcaFetchGuard(_ options: Options) throws -> (Request) -> Decision { try createGuard(options) }
}
