# pca-swift — Proof-Carrying Authority for Swift (iOS, macOS)

An **offline verifier for Proof-Carrying Actions (PCActns)** in Swift, plus the principal's phone-side
**step-up** client. A PCActn is the credential an autonomous agent presents with *every* action it takes:
a self-contained, cryptographically-checkable object proving the action is a faithful execution of
authority its principal actually granted. Your resource server verifies it locally — no token
introspection, no network call on the hot path.

This package is the Swift member of the PCA verifier family. It is a faithful port of the TypeScript
reference implementation and passes the **same shared conformance corpus** as every other language
verifier, so a PCActn that verifies here verifies identically everywhere.

Two products ship from the package:

- **`AtlasPCAVerify`** — the native offline verifier for the eight core PCActn checks.
- **`AtlasPCAStepUp`** — the principal-device client for the threshold (step-up) co-sign flow.

## Install

Add the package with Swift Package Manager:

```swift
// Package.swift
dependencies: [
    .package(url: "https://github.com/Atlas-Authorization/pca-swift", branch: "main"),
],
// then depend on the product(s) you need:
.product(name: "AtlasPCAVerify", package: "pca-swift"),
.product(name: "AtlasPCAStepUp", package: "pca-swift"),
```

Ed25519 uses Apple **CryptoKit** on Apple platforms (and **swift-crypto** elsewhere) for the signature
equation, layered with a pure-Swift prime-order gate: CryptoKit alone does not reject small-order keys, so
a forged `(R = identity, S = 0)` signature would otherwise pass. There are no other third-party
dependencies.

## Verify a PCActn

A verifier is stateless. Give it the received PCActn (raw JSON via `PCA.verify(json:…)`, or a parsed value
via `PCA.verify(pcactn:…)`), the Root Intent Grant it claims to derive from, the current time (epoch
**milliseconds**), and *your own* audience id. It returns an allow/deny verdict plus the per-check results.

```swift
import AtlasPCAVerify

// `pcactnText` is the PCActn as received (strict canonical JSON, wire version 2).
// `grant` is the Root Intent Grant the action's capability chain roots in.
let now = Int64(Date().timeIntervalSince1970 * 1000)
let verdict = PCA.verify(json: pcactnText, grant: grant, now: now, audience: "https://api.example.com")

if verdict.allow {
    // every core check passed — execute the action
} else {
    print("denied: \(verdict.reason)", verdict.checks)   // verdict.checks: [String: Bool]
}
```

`verdict.checks` reports each core check (`wire`, `version`, `audience`, `validity`, `chain`,
`plan_inclusion`, `leaf_signature`, `counter`). Every check is **fail-closed** — the action is allowed
only if none reports failure — and a `wire` failure is terminal (nothing else is evaluated).

## Step-up co-sign (principal device)

`AtlasPCAStepUp` is the principal's phone side of PCA: approve or deny a high-risk (t=3) agent action.

```swift
import AtlasPCAStepUp

let key = PrincipalDeviceKey()                       // Keychain-backed
try key.importSecret(principalSecretB64u)            // or key.generate() -> register this public key as the grant's principal
let client = StepUpClient(dashboardURL: URL(string: "https://api.atlasauth.net")!,
                          instanceURL: URL(string: "https://auth.example.com")!,
                          accountId: "acc_...", instanceId: "ins_...",
                          token: { try await myDashboardToken() }, key: key)
let pending = try await client.pending()             // [PendingStepUp]
if let s = pending.first { /* show s.summary, require Face ID */ try await client.approve(s) }  // or client.deny(s, reason: "not me")
```

`approve` signs the decoded `threshold_message` and POSTs `{ role: "principal", publicKey, sig }` to the
public `POST /v1/pca/stepups/:id/cosign` (the signature is the credential, no token needed); `pending` /
`deny` use the dashboard API with a bearer token.

**Security note (honest):** the Secure Enclave supports only P-256, not Ed25519, and PCA principal keys
are Ed25519. The key is therefore a **software key**, stored in the Keychain as
`kSecAttrAccessibleWhenUnlockedThisDeviceOnly` (OS-encrypted, not synced or backed up, unreadable while
locked) but **not hardware-bound**. Gate `approve` behind a LocalAuthentication (Face ID) prompt for user
presence.

## Conformance

The repo ships a vendored copy of the shared **conformance corpus** (`conformance/vectors.json` +
`conformance/keys.json`): over a hundred golden and adversarial PCActns with their expected verdicts, plus
canonical-JSON, strict-base64url, and Merkle primitive vectors. `swift test` runs the verifier against
every vector; it must reproduce `allow` and every listed check exactly. The suite is green across the
classical and post-quantum corpora.

## Supported signature suites

- `ed25519` (default)
- `ml-dsa-65` (FIPS-204, post-quantum)
- `hybrid-ed25519-ml-dsa-65` (classical + post-quantum)

The suite id and the post-quantum key are part of the signed body, so a downgrade is a signature failure;
a hybrid PCActn requires **both** signatures to verify.

## Capability maturity

The PCActn wire format and the eight core offline checks are stable and conformance-covered, and this
package implements all of them — including the post-quantum suites — green against the shared corpus. The
broader framework surface is implemented and tested in the reference implementation: threshold/step-up
co-signing (a real FROST threshold signature over a DKG-established group key, released only on a Policy-VM
allow — the `AtlasPCAStepUp` client here is the principal's side of that flow), TEE/hardware and
model-weights attestation, zero-knowledge proof-of-compliance (a real Groth16 proof), optimistic bonds and
the contestable dispute game, and the malicious-secure MPC Policy VM (SPDZ-style MACs with abort). A few
rungs carry a remaining production requirement, stated plainly rather than hidden behind a label: a live
TEE/hardware attestation needs real SEV-SNP/TDX silicon (the verifier is tested against real-crypto mock
reports); unforgeable FROST guardian custody needs each share in a separate trust domain / HSM with a
network signing protocol (the reference runs the signing round in-process); the MPC Policy VM's offline
triple generation is trusted-dealer today (a no-dealer OT/HE phase is designed); and the zero-knowledge
circuit proves a decision subset (plan-membership + risk ≤ budget), with fuller policy coverage ongoing.
See the [PCA framework repo](https://github.com/Atlas-Authorization/pca) for the full model.

## License

See `LICENSE`.
