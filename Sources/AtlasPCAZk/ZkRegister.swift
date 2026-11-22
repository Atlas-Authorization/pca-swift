import AtlasPCAVerify
import Foundation

extension PCAZkNative {
    private static func json(_ v: JSONValue) -> [UInt8] { Array(PCAWire.canonical(v).utf8) }

    /// Explicit opt-in: makes this library the Groth16 engine of the core zk module (`PCAZk.verifyPolicyVmProof`, the SNARK backends and the
    /// provers). Nothing registers at import; `PCAZkHook.unregister()` undoes it. Verification runs in the default mode, which accepts exactly
    /// what the reference verifier accepts. The curve is the one the verifying key names, read by the library as snarkjs reads it (aliases such as
    /// `alt_bn128` and `bls12-381` name a curve); a key that names none is refused.
    public static func registerCore() {
        PCAZkHook.register(PCAZkHook.Engine(
            verify: { vkey, publicSignals, proof in
                // the library reads the key's curve name itself, as snarkjs does: no curve mapping or alias refusal here
                try verifyFromKey(vkey: json(vkey), proof: json(proof), signals: json(.array(publicSignals))).valid
            },
            prove: { curve, wasm, zkey, input in
                let out = try prove(curve: curve == "bn254" ? .bn254 : .bls12381, wasm: wasm, zkey: zkey, input: json(input))
                return try PCAWire.parseLenient(String(decoding: out, as: UTF8.self))
            }))
    }
}
