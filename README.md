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
`plan_inclusion`, `leaf_signature`, `counter_format`). Every check is **fail-closed** — the action is allowed
only if none reports failure — and a `wire` failure is terminal (nothing else is evaluated).

## Authorize an operation

`PCA.authorize` is the full decision for one operation. It runs the core checks, then binds the proof to the operation
your code will execute (the signed verb, resource and params digest must equal it, so a proof signed for $50 cannot pay
$400), evaluates the grant's envelope predicates (default deny), the envelope's caveats, caveats placed on the root grant
and caveats added by delegation (`max_spend`, `predicates`, `tool_schema`, `expires`, `rate`, ...; an unknown type is
refused), checks revocation with your `isRevoked`, and consumes the replay counter through an atomic store, only when
everything else passed.

<!-- pca-readme-sample: authorize -->
```swift
import AtlasPCAVerify

let replayStore = MemoryStateStore() // one process; several processes need a shared store (see below)

/// POST /payments: `pcactnText` is the PCActn the agent presented, `body` the request body.
func sendPayment(pcactnText: String?, body: String, grants: [String: JSONValue],
                 revokedGrantIds: Set<String>) -> (status: Int, message: String) {
    guard let params = JSONValue.parse(body) else { return (400, "the body is not JSON") }
    // What this handler will execute, from its own route and body (never from the PCActn).
    let operation = PCA.Operation(verb: "payments.send", resource: "payments/acme", params: params)
    let result = PCA.authorize(json: pcactnText, PCA.AuthorizeInput(
        operation: operation,
        audience: "payments-rs",
        resolveGrant: { ref in grants[ref] }, // grant_ref -> grant, from your own store
        stateStore: replayStore,
        isRevoked: { _, grant in
            guard case let .object(g) = grant, case let .string(id)? = g["id"] else { return nil } // nil denies
            return revokedGrantIds.contains(id)
        },
        plan: PCA.SINGLE_STEP))
    guard result.allow else {
        return (result.status, result.reason ?? "denied") // e.g. 403 "policy: caveat(s) not satisfied: max_spend"
    }
    // ... send the payment with exactly `params` ...
    return (200, "paid")
}
```

- `PCA.SINGLE_STEP` accepts a proof whose plan is this one operation. For a multi-step plan, return an
  `AuthorizeContext(plan:, planAuthorized: true)` from `context`.
- `result.status` is 200, 401 (no proof, or one that fails authentication) or 403. `result.checks` maps every check to
  `.pass`, `.fail` or `.notEnforced`, and `result.reason` is the decisive failure. On success `result.operation` is the
  bound operation (verb, resource, params digest, and an `id` for the proof), and
  `PCA.isAuthorized(result, for: operation)` re-checks it where the side effect runs.
- The operation comes from your own routing and parsed request, never from the proof. Its params must be a JSON object.
- Every component is required: without `audience`, `resolveGrant`, `stateStore`, `isRevoked` or `operation` the call is
  refused and `result.missing` names what is absent. `authorize` never throws: an internal error is a denial. Only an
  `isRevoked` that returns `false` passes (`true`, `nil` or a throw denies).
- `MemoryStateStore` is for a single process. A shared deployment implements `PCAStateStore.claim(key:counter:)` as ONE
  atomic operation of its database (insert, or update only when the new counter is greater) and returns
  `ClaimResult(ok:lastCounter:)`. There is no HTTP middleware in this package: call `authorize` where you handle the request.
- The check names: `counter_format` is the stateless well-formed-counter check of the core verifier; `replay` is the
  stateful check `authorize` adds (the counter must be strictly greater than the last one the store saw). The required
  list is `counter_format, replay, revocation, plan_root_authorized, audience, validity, grant_ref_bound, operation,
  params_digest, policy` plus `AuthorizeInput.require`; an entry `counter` in `require` is an alias of `replay`.
- A refusal of an envelope limit names the limit: `policy: amount <= 100 not satisfied for payments.send on payments/acme`
  (`currency in ["usd", "eur"]`, `approval present`, `all of (...)`). When no predicate covers the verb and resource the
  reason stays `policy: no predicate permits <verb> on <resource>`; an empty list stays `envelope grants no predicates`.
- A replay is `replay: 1 is not greater than last seen 1 (replay)`.
- Not covered by `authorize` here: the risk score, trust budget and threshold co-signature from the grant's
  `risk_policy`, revocation epochs and liveness beacons. A grant that pins the agent (`agent_binding`) needs an
  attestation verifier and is refused, and so is a proof carrying `zk_compliance`. The TypeScript `authorize` covers
  these.

### Which entry point to use

There is no HTTP middleware in this package. `PCA.authorize` is the recommended entry point: call it where you handle the
request. The core verifier (`PCA.verify`) is signature-only: it checks the signature, chain, audience, validity and counter
format, and nothing about the operation, predicates, caveats, revocation or replay.

### Upgrading to 0.5

- The core check `counter` is `counter_format` (in `verdict.checks` and in its failure reason
  `counter_format: missing or not a non-negative safe integer`). The stateful check in `authorize` results is `replay`, and
  its reasons start with `replay:`. Rename any code that reads `checks["counter"]`. `PCA.DEFAULT_REQUIRED_CHECKS` lists the
  new names.
- An envelope-limit refusal now names the limit instead of `no predicate permits ...`.

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

## One call: protect, and explaining a refusal

**One call: `protect(...)`.** It fills in the secure defaults and returns the guard config plus a revoke handle:

```swift
let p = protect(audience: "payments-rs", operation: { req in
    guard let params = JSONValue.parse(String(decoding: req.body, as: UTF8.self)) else { return nil }
    return PCA.Operation(verb: "payments.refund", resource: "payments/acme", params: params)
}, grants: [grant])           // or resolveGrant: { ref in ... }
app.middleware.use(try p.middleware())   // Vapor (AtlasPCAVapor); Hummingbird: PcaMiddleware<AppContext>(p.config)
p.revoke(grantId)                         // every later action under that grant is refused
```

Defaults: the grant is looked up from your list or closure (never the request), an in-memory replay store (pass `stateStore:` for a
durable one), a revocation source, and the single-step plan. Options you pass win; `configure:` edits the whole config last. Unlike the
TypeScript `protect()`, there is no connector catalog here, so server-side risk is not priced for you. A runnable server is in
`examples/vapor-server`.

**Refusals explain themselves.** Every refusal body from the guard (and so from the Vapor and Hummingbird middleware) has a `doc` member,
a link to the explanation of the failed check; the `reason` text is unchanged. `explainRefusal(reason)` returns `RefusalHelp`
(`check`, `meaning`, `fix`, `docs`) for any reason string and never fails.

## What a passing result does not cover

`counter_format: pass` is a format check (a non-negative integer); it does **not** mean the action was not replayed.
Verification is stateless and this package has no replay store, so the resource server must persist, per grant and
agent, the last accepted counter and refuse anything not strictly greater, atomically across all of its processes.

The verifier is the core verifier only (this package has no HTTP middleware). It does not check replay, revocation, caveats, envelope predicates, plan authorization, risk or
thresholds, and it does not compare the request body with the signed `params_digest`. Do those checks in your
handler (the caveat helpers, the params digest of the body you will execute, your replay and revocation stores), or
delegate the decision to a full verifier such as `requirePCA` from `@atlasauth/pca`.

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
