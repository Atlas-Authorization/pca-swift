# Vapor server guarded by Atlas PCA

A minimal Vapor app with one route, `POST /refunds`, that only runs when the request carries a proof (a PCActn) that authorizes exactly
this refund under a grant the server knows. It uses `protect(...)`: the grant comes from your own list (never from the request), replays
are refused, `revoke(grantId)` stops a grant, and a proof for another action is refused before the handler runs.

```swift
let p = protect(audience: "payments-rs", operation: { req in
    guard let params = JSONValue.parse(String(decoding: req.body, as: UTF8.self)) else { return nil }
    return PCA.Operation(verb: "payments.refund", resource: "payments/acme", params: params)
}, grants: [grant])
app.middleware.use(try p.middleware())
app.post("refunds") { req in "refunded" }
```

Run it:

```sh
PCA_AUDIENCE=payments-rs PCA_GRANT_FILE=grant.json swift run Run
```

Send the proof in the `PCA-Action` header (or as `{"pcactn": ...}` in the body). A refusal is a JSON body with the `reason`, and a `doc` link
to the explanation of that check; `explainRefusal(reason)` returns the same guidance in code.

Test it: `swift test` runs a smoke test with a real signed proof: one request is allowed, the same proof again is refused with a `doc` link.
