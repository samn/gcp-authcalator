# Plan: Stubbed refresh token on the metadata proxy

## Context

Container processes sometimes want to drive a standard OAuth2 refresh-token
flow (`grant_type=refresh_token` against a token endpoint) instead of — or in
addition to — polling the GCE metadata token endpoint. Today the metadata
proxy only serves short-lived access tokens; the two credentials that could
actually _extend_ access are deliberately kept out of the container:

- the engineer's real ADC refresh token (lives on the host, inside the gate)
- the gate prod-session ID (lives in the `with-prod` parent process closure)

**Goal:** let authenticated processes inside the devcontainer perform a
refresh-token flow, without ever putting a refresh credential in the container
that could extend the session or be replayed outside it. The only exfiltratable
GCP credential remains the short-lived OAuth access token.

## Design

Each metadata-proxy instance (the long-lived container proxy _and_ the
temporary `with-prod` proxy — they share the same server code) mints a
**stubbed refresh token** at startup:

- 32 bytes of crypto randomness, hex-encoded, with a
  `gcp-authcalator-stub-` prefix so it is self-evidently not a Google
  credential (Google user refresh tokens start with `1//`).
- Held in memory only; never written to disk, never sent to the gate,
  never derived from any GCP secret.

**Issuance** — the GCE token endpoint response gains a `refresh_token` field:

```
GET /computeMetadata/v1/instance/service-accounts/default/token
→ { "access_token": "...", "expires_in": N, "token_type": "Bearer",
    "refresh_token": "gcp-authcalator-stub-<64 hex>" }
```

Issuance therefore requires the same authentication as any token request:
the `Metadata-Flavor: Google` header, plus PID-tree validation on `with-prod`
temporary proxies. google-auth for Python/Go, gcloud, and gcp-metadata drop
the unknown field; Node's google-auth-library propagates it into
`client.credentials` and its `'tokens'` event, so apps persisting tokens
through that hook store the stub alongside the access token (documented as a
caveat in README/SPEC).

**Redemption** — a new OAuth2-style token endpoint, mirroring
`https://oauth2.googleapis.com/token`:

```
POST /token
Content-Type: application/x-www-form-urlencoded
grant_type=refresh_token&refresh_token=<stub>

→ 200 { "access_token": "...", "expires_in": N,
        "scope": "<space-delimited scopes>", "token_type": "Bearer" }
→ 400 { "error": "invalid_grant", ... }          (unknown stub)
→ 400 { "error": "unsupported_grant_type", ... } (grant_type ≠ refresh_token)
→ 400 { "error": "invalid_request", ... }        (missing/malformed params)
```

- Stub comparison is constant-time (SHA-256 both sides + `timingSafeEqual`).
- The response deliberately does **not** include a `refresh_token`
  (matches Google's refresh-grant behavior) and sets `Cache-Control:
no-store` per RFC 6749 §5.1.
- No `Metadata-Flavor` header requirement — real OAuth clients don't send
  one, and possession of the stub already proves the caller obtained it
  through the authenticated channel. Because the endpoint is header-free it
  is strict everywhere else: exact path, case-insensitive form media type,
  and a declared `Content-Length` ≤ 8 KB (rejects chunked/oversized bodies
  so it can't be used to force large body buffering).
- Provider failures return `503 temporarily_unavailable` (the RFC 6749
  `error` member is a registered code, not prose).
- PID validation applies (it wraps every request in `server.fetch`).

## Security properties

- **Cannot extend the session.** Redeeming the stub just calls the proxy's
  existing token provider; refreshes still flow through the gate, which
  enforces session expiry (default 8 h) and per-token TTL. The stub grants
  nothing the metadata GET endpoint didn't already grant.
- **Worthless outside the container.** The stub is not a GCP credential and
  the proxy binds 127.0.0.1; exfiltrating it gives an attacker nothing.
  The stub also dies with the proxy process.
- **Only authenticated processes can refresh.** The stub is only issued via
  the header-gated (and, under `with-prod`, PID-validated) token endpoint,
  and the refresh endpoint rejects anything but the exact issued stub.
- **The real refresh credentials stay where they were**: ADC refresh token on
  the host, gate session ID in the `with-prod` parent process.

## Implementation steps

1. `src/metadata-proxy/types.ts` — add `refreshToken: string` to
   `MetadataProxyDeps`; add `MetadataTokenResponse` (TokenResponse +
   `refresh_token`) and `OAuthRefreshResponse` shapes.
2. `src/metadata-proxy/handlers.ts` — include `refresh_token` in
   `handleToken`; add `POST /token` handling with OAuth-style errors and
   constant-time stub comparison; keep 405 for all other non-GET.
3. `src/metadata-proxy/server.ts` — mint the stub
   (`gcp-authcalator-stub-` + 32-byte hex) per instance, wire into deps,
   mention the endpoint in startup logging.
4. Tests — `handlers.test.ts` (issuance, happy-path redemption, invalid
   grant/request/grant_type, malformed body, no refresh_token in refresh
   response, 405 unaffected) and `server.test.ts` (end-to-end issue→redeem,
   PID validation on POST /token, per-instance uniqueness).
5. Docs — README (endpoint table + security model), SPEC.md (section 3),
   CHANGELOG.md (Unreleased → Added).

## Non-goals

- Writing an `authorized_user`-style ADC file or configuring gcloud's
  `auth/token_host` to point at the proxy — client wiring is left to users;
  this change only provides the endpoint.
- Rotation/expiry of the stub: its lifetime is the proxy process lifetime,
  which is already bounded by the session (`with-prod`) or container.
- Any gate-side change: the gate API and session model are untouched.
