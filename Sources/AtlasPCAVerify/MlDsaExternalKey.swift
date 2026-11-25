import Foundation

extension PCAPQKey {
    /// An ML-DSA key whose signatures come from an external backend (an opt-in product that signs ML-DSA itself, for example with the deterministic variant
    /// of FIPS 204 where the platform hedges). `publicKey` is the raw FIPS 204 public key of `level`; `signer` returns the raw signature of a message.
    public init(level: PCAMLDSALevel, publicKey: [UInt8], signer: @escaping ([UInt8]) throws -> [UInt8]) throws {
        let want = MLDSA.lens(level == .mlDsa65 ? .mlDsa65 : .mlDsa87)
        guard publicKey.count == want.pk else { throw PCAProducerError("an ML-DSA public key of the wrong length") }
        self.init(level: level, pk: publicKey, signFn: { msg in
            let sig = try signer(msg)
            guard sig.count == want.sig else { throw PCAProducerError("the ML-DSA signer returned a signature of the wrong length") }
            return sig
        })
    }
}
