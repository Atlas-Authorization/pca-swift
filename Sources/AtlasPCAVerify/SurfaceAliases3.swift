import Foundation

/// TypeScript export names of the attestation and SCITT packages that this SDK carries under another name or as an internal helper.
extension PCAAttestEat {
    /// The EAT SEV-SNP evidence block of a complete report (decimal-string TCB, hex measurement and chip id, the debug bit): the reference's
    /// `evidenceFromReport`. Throws when the buffer is shorter than a full report; `parseReportTolerant` is the degrading form.
    public static func evidenceFromReport(_ report: [UInt8]) throws -> JSONValue {
        guard report.count >= FULL_REPORT_MIN_LEN else { throw JSError("evidenceFromReport: a report is at least \(FULL_REPORT_MIN_LEN) bytes") }
        return fullEvidence(report)
    }

    /// The default measured identity of a complete report (runtime measurement = hex(MEASUREMENT), operator = hex(CHIP_ID)): `measuredFromReport`.
    public static func measuredFromReport(_ report: [UInt8]) throws -> JSONValue {
        guard report.count >= FULL_REPORT_MIN_LEN else { throw JSError("measuredFromReport: a report is at least \(FULL_REPORT_MIN_LEN) bytes") }
        return measuredFromReportBytes(report)
    }
}

extension PCA {
    /// The Sigstore bundle media types this verifier accepts (v0.2 and v0.3).
    public static let SIGSTORE_BUNDLE_MEDIA_TYPES = Sigstore.mediaTypes

    /// Parse a Sigstore `trusted_root.json` (the reference's `parseTrustedRoot`); see `parseSigstoreTrustedRoot`.
    public static func parseTrustedRoot(_ json: JSONValue) throws -> SigstoreRoots { try parseSigstoreTrustedRoot(json) }
}

/// A CBOR tagged value (major type 6), the reference's `CborTag`: the SCITT receipt codec uses it for the COSE_Sign1 tag (18).
public struct CborTag: Equatable {
    public let tag: Int64
    public let value: PCAScitt.CborValue
    public init(_ tag: Int64, _ value: PCAScitt.CborValue) { self.tag = tag; self.value = value }
    /// The value in the codec's own model.
    public var cbor: PCAScitt.CborValue { .tag(tag, value) }
    /// A tag from the codec's value (nil when `v` is not a tagged value).
    public init?(_ v: PCAScitt.CborValue) {
        guard case let .tag(t, inner) = v else { return nil }
        self.tag = t; self.value = inner
    }
}
