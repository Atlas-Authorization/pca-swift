import CSealC
import Foundation

/// The public gate policy: fixed-point weights, kappa-weighted weights and the budget bound (scale S, budget at S^2).
public struct FheRiskPolicy: Equatable, Sendable {
    public var scale: Int64, dim: Int64
    public var weightsScaled: [Int64], kappaWeightsScaled: [Int64]
    public var budgetScaled: Int64
    public var kappa: Double
    public init(scale: Int64, dim: Int64, weightsScaled: [Int64], kappaWeightsScaled: [Int64], budgetScaled: Int64, kappa: Double = 1) {
        self.scale = scale; self.dim = dim; self.weightsScaled = weightsScaled; self.kappaWeightsScaled = kappaWeightsScaled
        self.budgetScaled = budgetScaled; self.kappa = kappa
    }
}

/// Full key material (each a base64 SEAL stream). The key holder keeps `secretKey`; the evaluator only ever gets the public key and Galois keys.
public struct FheKeyset: Sendable {
    public let secretKey: String, publicKey: String, relinKeys: String, galoisKeys: String
}

/// The two encrypted gate outputs, each a base64 SEAL stream.
public struct FheEncryptedGate: Equatable, Sendable { public let encRiskRaw: String, encSlack: String }

/// The opened verdict: `rScaled` is r at scale S^2 clamped to [0, S^2]; `admit` is slack >= 0.
public struct FheVerdict: Equatable, Sendable { public let rScaled: Int64, slack: Int64, admit: Bool }

public enum FheError: Error, Equatable {
    /// A malformed blob, policy or input (refused before SEAL sees it), or a verdict that cannot be opened (no noise budget left).
    case invalid(String)
    /// SEAL reported a failed HRESULT.
    case seal(String)
}

/// Homomorphic evaluation of PCA's risk gate (BFV on Microsoft SEAL), wire-compatible with the TypeScript package (node-seal 5.1.x bundles SEAL 4.1.x).
/// BFV is never reimplemented here: this binds SEAL's own C export API through the CSealC target, so libsealc (built from the pinned SEAL tag into
/// Sources/CSealC/lib by CI) is the only extra requirement; without it the product is absent from the package. Every SEAL object crosses the API as
/// the base64 of its SEAL native stream.
public enum FheSeal {
    public static let polyModulusDegree: UInt64 = 8192
    public static let plainModulusBits: Int32 = 30
    public static let plainModulus: UInt64 = 1_073_692_673
    public static let signedBound: Int64 = Int64(plainModulus / 2)
    public static let riskDim = 6
    static let minNoiseBudgetBits: Int32 = 16
    static let bfv: UInt8 = 1, tc128: Int32 = 128, comprNone: UInt8 = 0, comprZstd: UInt8 = 2

    typealias Handle = UnsafeMutableRawPointer

    /// Releases native handles in reverse order on every exit path.
    final class Scope {
        var fns: [() -> Void] = []
        deinit { release() }
        func release() { while let f = fns.popLast() { f() } }
        func make(_ name: String, _ destroy: @escaping (Handle?) -> Int, _ create: (UnsafeMutablePointer<Handle?>) -> Int) throws -> Handle {
            var h: Handle? = nil
            try chk(name, create(&h))
            guard let p = h else { throw FheError.seal("\(name) returned a null handle") }
            fns.append { _ = destroy(p) }
            return p
        }
        func adopt(_ destroy: @escaping (Handle?) -> Int, _ h: Handle?) { fns.append { _ = destroy(h) } }
    }

    static func chk(_ name: String, _ hr: Int) throws {
        // SEAL's HRESULT convention: negative is failure, S_FALSE (1) is success
        if hr < 0 { throw FheError.seal("seal \(name) failed: 0x" + String(UInt32(truncatingIfNeeded: hr), radix: 16)) }
    }

    /// Rejects anything that is not a well-formed SEAL stream envelope (magic, header size, compression mode, declared size == length).
    @discardableResult
    public static func assertSealBlob(_ blob: String, _ what: String) throws -> [UInt8] {
        let u = Array(blob.utf8)
        var i = u.count
        while i > 0, u[i - 1] == UInt8(ascii: "=") { i -= 1 }
        let alphabet = u[..<i].allSatisfy { ($0 >= 65 && $0 <= 90) || ($0 >= 97 && $0 <= 122) || ($0 >= 48 && $0 <= 57) || $0 == 43 || $0 == 47 }
        guard u.count >= 24, u.count % 4 == 0, u.count - i <= 2, alphabet, let d = Data(base64Encoded: blob) else {
            throw FheError.invalid("\(what): not a serialized SEAL object (bad encoding)")
        }
        let b = [UInt8](d)
        guard b.count >= 16, b[0] == 0x5E, b[1] == 0xA1, b[2] == 16, b[5] <= 2, b[6] == 0, b[7] == 0 else {
            throw FheError.invalid("\(what): not a serialized SEAL object (bad header)")
        }
        var size: UInt64 = 0
        for k in (0..<8).reversed() { size = size << 8 | UInt64(b[8 + k]) }
        guard size == UInt64(b.count) else { throw FheError.invalid("\(what): truncated or padded SEAL object (declared \(size) bytes, got \(b.count))") }
        return b
    }

    /// The policy crosses a trust boundary: validate every coefficient exactly as the policy builder would have produced it.
    public static func requirePolicy(_ p: FheRiskPolicy) throws {
        guard p.scale > 0 else { throw FheError.invalid("policy.scale must be a positive integer") }
        for v in [p.budgetScaled] + p.weightsScaled + p.kappaWeightsScaled where v <= -signedBound || v >= signedBound {
            throw FheError.invalid("policy coefficients must be integers with |value| < SIGNED_BOUND")
        }
        guard p.dim == Int64(riskDim) else { throw FheError.invalid("policy.dim must be \(riskDim)") }
        guard p.weightsScaled.count == riskDim, p.kappaWeightsScaled.count == riskDim else { throw FheError.invalid("policy weight vectors must have length \(riskDim)") }
    }

    struct Ctx { let context: Handle, encoder: Handle, slots: Int }

    static func context(_ s: Scope) throws -> Ctx {
        let parms = try s.make("EncParams_Create1", EncParams_Destroy) { EncParams_Create1(bfv, $0) }
        try chk("EncParams_SetPolyModulusDegree", EncParams_SetPolyModulusDegree(parms, polyModulusDegree))
        var n: UInt64 = 0
        try chk("CoeffModulus_BFVDefault", CoeffModulus_BFVDefault(polyModulusDegree, tc128, &n, nil))
        var coeffs = [Handle?](repeating: nil, count: Int(n))
        try coeffs.withUnsafeMutableBufferPointer { try chk("CoeffModulus_BFVDefault", CoeffModulus_BFVDefault(polyModulusDegree, tc128, &n, $0.baseAddress)) }
        for m in coeffs { s.adopt(Modulus_Destroy, m) }
        try coeffs.withUnsafeMutableBufferPointer { try chk("EncParams_SetCoeffModulus", EncParams_SetCoeffModulus(parms, n, $0.baseAddress)) }
        var bits = plainModulusBits
        var plain: Handle? = nil
        try chk("CoeffModulus_Create1", CoeffModulus_Create1(polyModulusDegree, 1, &bits, &plain))
        s.adopt(Modulus_Destroy, plain)
        var live: UInt64 = 0
        try chk("Modulus_Value", Modulus_Value(plain, &live))
        guard live == plainModulus else { throw FheError.seal("plain modulus drift: live \(live) != documented \(plainModulus)") }
        try chk("EncParams_SetPlainModulus1", EncParams_SetPlainModulus1(parms, plain))
        let ctx = try s.make("SEALContext_Create", SEALContext_Destroy) { SEALContext_Create(parms, true, tc128, $0) }
        var ok = false
        try chk("SEALContext_ParametersSet", SEALContext_ParametersSet(ctx, &ok))
        guard ok else { throw FheError.seal("SEAL rejected the BFV parameters") }
        let enc = try s.make("BatchEncoder_Create", BatchEncoder_Destroy) { BatchEncoder_Create(ctx, $0) }
        var sc: UInt64 = 0
        try chk("BatchEncoder_GetSlotCount", BatchEncoder_GetSlotCount(enc, &sc))
        return Ctx(context: ctx, encoder: enc, slots: Int(sc))
    }

    /// The create/destroy/save/load functions of one SEAL object kind.
    struct Kind {
        let create: (UnsafeMutablePointer<Handle?>) -> Int
        let destroy: (Handle?) -> Int
        let saveSize: (Handle, UInt8, UnsafeMutablePointer<Int64>) -> Int
        let save: (Handle, UnsafeMutablePointer<UInt8>?, UInt64, UInt8, UnsafeMutablePointer<Int64>) -> Int
        let load: (Handle, Handle, UnsafeMutablePointer<UInt8>?, UInt64, UnsafeMutablePointer<Int64>) -> Int
    }
    static let publicKey = Kind(create: { PublicKey_Create1($0) }, destroy: PublicKey_Destroy, saveSize: PublicKey_SaveSize, save: PublicKey_Save, load: PublicKey_Load)
    static let secretKey = Kind(create: { SecretKey_Create1($0) }, destroy: SecretKey_Destroy, saveSize: SecretKey_SaveSize, save: SecretKey_Save, load: SecretKey_Load)
    static let kswitch = Kind(create: { KSwitchKeys_Create1($0) }, destroy: KSwitchKeys_Destroy, saveSize: KSwitchKeys_SaveSize, save: KSwitchKeys_Save, load: KSwitchKeys_Load)
    static let cipher = Kind(create: { Ciphertext_Create1(nil, $0) }, destroy: Ciphertext_Destroy, saveSize: Ciphertext_SaveSize, save: Ciphertext_Save, load: Ciphertext_Load)

    static func newObj(_ s: Scope, _ k: Kind) throws -> Handle { try s.make("create", k.destroy, k.create) }

    static func loadObj(_ ctx: Ctx, _ s: Scope, _ k: Kind, _ blob: String, _ what: String) throws -> Handle {
        var raw = try assertSealBlob(blob, what)
        let p = try newObj(s, k)
        var used: Int64 = 0
        let n = UInt64(raw.count)
        try raw.withUnsafeMutableBufferPointer { try chk("load", k.load(p, ctx.context, $0.baseAddress, n, &used)) }
        return p
    }

    static func saveObj(_ k: Kind, _ p: Handle, _ compr: UInt8 = comprZstd) throws -> String {
        var size: Int64 = 0
        try chk("saveSize", k.saveSize(p, compr, &size))
        var buf = [UInt8](repeating: 0, count: Int(size))
        var out: Int64 = 0
        let n = UInt64(size)
        try buf.withUnsafeMutableBufferPointer { try chk("save", k.save(p, $0.baseAddress, n, compr, &out)) }
        return Data(buf[..<Int(out)]).base64EncodedString()
    }

    static func encode(_ ctx: Ctx, _ s: Scope, _ values: [Int64]) throws -> Handle {
        var slots = [Int64](repeating: 0, count: ctx.slots)
        for (i, v) in values.enumerated() { slots[i] = v }
        let pt = try s.make("Plaintext_Create1", Plaintext_Destroy) { Plaintext_Create1(nil, $0) }
        try chk("BatchEncoder_Encode2", BatchEncoder_Encode2(ctx.encoder, UInt64(ctx.slots), &slots, pt))
        return pt
    }

    /// Generates the key material (the secret key stays with the policy owner).
    public static func keygen() throws -> FheKeyset {
        let s = Scope()
        defer { s.release() }
        let ctx = try context(s)
        let gen = try s.make("KeyGenerator_Create1", KeyGenerator_Destroy) { KeyGenerator_Create1(ctx.context, $0) }
        let sk = try s.make("KeyGenerator_SecretKey", SecretKey_Destroy) { KeyGenerator_SecretKey(gen, $0) }
        let pk = try s.make("KeyGenerator_CreatePublicKey", PublicKey_Destroy) { KeyGenerator_CreatePublicKey(gen, false, $0) }
        let rk = try s.make("KeyGenerator_CreateRelinKeys", KSwitchKeys_Destroy) { KeyGenerator_CreateRelinKeys(gen, false, $0) }
        let gk = try s.make("KeyGenerator_CreateGaloisKeysAll", KSwitchKeys_Destroy) { KeyGenerator_CreateGaloisKeysAll(gen, false, $0) }
        return FheKeyset(secretKey: try saveObj(secretKey, sk), publicKey: try saveObj(publicKey, pk), relinKeys: try saveObj(kswitch, rk), galoisKeys: try saveObj(kswitch, gk))
    }

    /// BFV-encrypts the quantized risk-input vector (length 6, each a non-negative integer below the signed bound).
    public static func encryptRiskInputs(publicKey pkBlob: String, inputsScaled: [Int64]) throws -> String {
        guard inputsScaled.count == riskDim else { throw FheError.invalid("inputsScaled must have length \(riskDim)") }
        guard inputsScaled.allSatisfy({ $0 >= 0 && $0 < signedBound }) else { throw FheError.invalid("each scaled input must be a non-negative integer below the signed bound") }
        let s = Scope()
        defer { s.release() }
        let ctx = try context(s)
        let pk = try loadObj(ctx, s, publicKey, pkBlob, "publicKey")
        let enc = try s.make("Encryptor_Create", Encryptor_Destroy) { Encryptor_Create(ctx.context, pk, nil, $0) }
        let pt = try encode(ctx, s, inputsScaled)
        let ct = try newObj(s, cipher)
        try chk("Encryptor_Encrypt", Encryptor_Encrypt(enc, pt, ct, nil))
        return try saveObj(cipher, ct)
    }

    /// Evaluates the gate blind with the reference's operation order (multiplyPlain, sumElements, negate, addPlain). Never builds a decryptor.
    public static func evalRiskGate(publicKey pkBlob: String, galoisKeys: String, encInputs: String, policy: FheRiskPolicy) throws -> FheEncryptedGate {
        try requirePolicy(policy)
        let s = Scope()
        defer { s.release() }
        let ctx = try context(s)
        let gk = try loadObj(ctx, s, kswitch, galoisKeys, "galoisKeys")
        let pk = try loadObj(ctx, s, publicKey, pkBlob, "publicKey")
        let ev = try s.make("Evaluator_Create", Evaluator_Destroy) { Evaluator_Create(ctx.context, $0) }
        let enc = try s.make("Encryptor_Create", Encryptor_Destroy) { Encryptor_Create(ctx.context, pk, nil, $0) }
        let x = try loadObj(ctx, s, cipher, encInputs, "encInputs")

        func total(_ prod: Handle) throws -> Handle {
            let temp = try s.make("Ciphertext_Create2", Ciphertext_Destroy) { Ciphertext_Create2(prod, $0) }
            let dest = try newObj(s, cipher)
            try chk("RotateColumns", Evaluator_RotateColumns(ev, temp, gk, dest, nil))
            try chk("Add", Evaluator_Add(ev, temp, dest, temp))
            var steps = Int32(polyModulusDegree / 4)
            while steps >= 1 {
                try chk("RotateRows", Evaluator_RotateRows(ev, temp, steps, gk, dest, nil))
                try chk("RotateColumns", Evaluator_RotateColumns(ev, dest, gk, dest, nil))
                try chk("Add", Evaluator_Add(ev, temp, dest, temp))
                steps /= 2
            }
            return temp
        }
        func dot(_ coeffs: [Int64]) throws -> Handle {
            // SEAL refuses multiplyPlain by an all-zero plaintext (transparent result): the dot product is then a fresh encryption of zero.
            if coeffs.allSatisfy({ $0 == 0 }) {
                let ct = try newObj(s, cipher)
                try chk("Encryptor_Encrypt", Encryptor_Encrypt(enc, try encode(ctx, s, []), ct, nil))
                return ct
            }
            let prod = try newObj(s, cipher)
            try chk("MultiplyPlain", Evaluator_MultiplyPlain(ev, x, try encode(ctx, s, coeffs), prod, nil))
            return try total(prod)
        }

        let riskRaw = try dot(policy.weightsScaled)
        let kappaRisk = try dot(policy.kappaWeightsScaled)
        let neg = try newObj(s, cipher), slack = try newObj(s, cipher)
        try chk("Negate", Evaluator_Negate(ev, kappaRisk, neg))
        try chk("AddPlain", Evaluator_AddPlain(ev, neg, try encode(ctx, s, [policy.budgetScaled]), slack))
        return FheEncryptedGate(encRiskRaw: try saveObj(cipher, riskRaw), encSlack: try saveObj(cipher, slack))
    }

    /// Decrypts the gate outputs and reads the verdict; fails closed when the noise budget is exhausted (wrong key, corrupt or foreign ciphertext).
    public static func decryptVerdict(secretKey skBlob: String, encRiskRaw: String, encSlack: String, policy: FheRiskPolicy) throws -> FheVerdict {
        try requirePolicy(policy)
        let s = Scope()
        defer { s.release() }
        let ctx = try context(s)
        let sk = try loadObj(ctx, s, secretKey, skBlob, "secretKey")
        let dec = try s.make("Decryptor_Create", Decryptor_Destroy) { Decryptor_Create(ctx.context, sk, $0) }
        let cts = [try loadObj(ctx, s, cipher, encRiskRaw, "encRiskRaw"), try loadObj(ctx, s, cipher, encSlack, "encSlack")]
        for ct in cts {
            var nb: Int32 = 0
            try chk("Decryptor_InvariantNoiseBudget", Decryptor_InvariantNoiseBudget(dec, ct, &nb))
            if nb < minNoiseBudgetBits { throw FheError.invalid("decryptVerdict: ciphertext has no noise budget left (wrong key, corrupted, or not produced by the gate)") }
        }
        func first(_ ct: Handle) throws -> Int64 {
            let pt = try s.make("Plaintext_Create1", Plaintext_Destroy) { Plaintext_Create1(nil, $0) }
            try chk("Decryptor_Decrypt", Decryptor_Decrypt(dec, ct, pt))
            var n: UInt64 = 0 // two calls, as SEAL.NET does: the first reports the slot count, the second fills the buffer
            try chk("Decode2", BatchEncoder_Decode2(ctx.encoder, pt, &n, nil, nil))
            if n == 0 { n = UInt64(ctx.slots) } // a count-only call that leaves the count untouched: the batch encoder always has `slots` slots
            var out = [Int64](repeating: 0, count: Int(n))
            try chk("Decode2", BatchEncoder_Decode2(ctx.encoder, pt, &n, &out, nil))
            guard let head = out.first else { throw FheError.invalid("decryptVerdict: the plaintext has no slots") }
            return head
        }
        let raw = try first(cts[0]), slack = try first(cts[1])
        return FheVerdict(rScaled: min(max(raw, 0), policy.scale * policy.scale), slack: slack, admit: slack >= 0)
    }

    /// Re-saves a base64 SEAL ciphertext uncompressed, for byte comparison independent of the zstd build.
    public static func canonicalCipher(_ blob: String) throws -> String {
        let s = Scope()
        defer { s.release() }
        let ctx = try context(s)
        return try saveObj(cipher, try loadObj(ctx, s, cipher, blob, "ciphertext"), comprNone)
    }
}
