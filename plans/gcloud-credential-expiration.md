# Plan: Handle expired gcloud credentials cleanly

## Context

The host-side `gate` daemon uses the engineer's gcloud Application Default
Credentials (ADC) via `google-auth-library` to mint prod tokens, dev tokens,
and PAM grants. When ADC's refresh token has been revoked or the user's
reauth cadence forces a re-login, `client.getAccessToken()` throws an
opaque `invalid_grant` / `reauth_required` error.

Today those errors surface as:

- Gate side: `500 Internal Server Error` with `{error: <raw google-auth message>}`.
- `with-prod` startup: `with-prod: failed to acquire prod token: gcp-gate
returned 500: invalid_grant: reauth related error (rapt_required)`.
- `with-prod` mid-session refresh: the temporary metadata proxy returns
  `500` to the wrapped process (gcloud/terraform/etc). The user sees a
  cryptic metadata-server error with no indication that re-running
  `gcloud auth application-default login` would fix it.
- The gate's cached source client survives the failure, so even after
  the user re-runs `gcloud auth application-default login` on the host,
  subsequent requests keep hitting the same dead refresh token until the
  gate is restarted.

If we increase the org's gcloud reauth frequency for security, these
mid-session failures become routine. We need them to be self-explanatory
and self-healing.

## Goals

1. Detect `invalid_grant` / reauth signals from `google-auth-library`
   centrally and convert them into a typed `CredentialsExpiredError`
   with an action-oriented message that names `gcloud auth
application-default login` and the gate host.
2. After detecting the error, drop the gate's cached source client so a
   subsequent request re-reads `application_default_credentials.json`.
   No gate restart required after the user re-authenticates.
3. Return a structured response from the gate (`code:
"credentials_expired"`) so that `with-prod` and any future client
   can recognise the condition and surface a tailored message.
4. Make `with-prod` print the user-facing instruction at every layer
   it can: startup failure, session refresh failure (logged to
   stderr), and per-request fetch failure.
5. Document the integration in README and CHANGELOG so operators
   understand the round-trip when they tighten reauth windows.

## Non-goals

- Eager validation of ADC at gate startup. The daemon should still
  start in degraded form so the operator can fix ADC without wrestling
  with restart loops.
- Changing token TTLs or session TTLs.
- Pushing a notification from the gate to the user when ADC fails. The
  in-band error path is sufficient.

## Changes

### Gate

- **New:** `src/gate/credentials-error.ts` — `CredentialsExpiredError`
  class, regex-based detector for the well-known
  google-auth/OAuth reauth strings (`invalid_grant`, `reauth_required`,
  `rapt_required`, `invalid_rapt`, `reauthentication required`,
  `Token has been expired or revoked`), and a `mapAdcError(err)` helper
  that returns the typed error or the original.
- **Update:** `src/gate/auth.ts` — wrap every `getAccessToken()` call
  (`mintDevToken`, `mintProdToken`, `getIdentityEmail`,
  `getProjectNumber`, the inner source-client call) with a helper that
  invokes `mapAdcError` and clears the cached `sourceClient` +
  impersonated client cache when the error is a credentials-expired
  one. Expose nothing new on the public API.
- **Update:** `src/gate/handlers.ts` — every catch block that already
  serialises `err.message` adds `code: "credentials_expired"` to the
  response body when the error is a `CredentialsExpiredError`, leaving
  the HTTP status as 500. The session refresh path returns the same
  shape so the client can distinguish ADC-expired from
  session-expired (which is a 401 with no code).
- **Update:** `src/gate/server.ts` — PAM source-client wrapper also
  uses `mapAdcError`; when ADC is dead, the PAM call surfaces the same
  typed error.

### Client (with-prod / metadata-proxy)

- **Update:** `src/with-prod/fetch-prod-token.ts` — `fetchProdAccessToken`
  parses non-OK responses, recognises `code === "credentials_expired"`,
  and throws `CredentialsExpiredError` with the gate's message. Same in
  `createProdSession` for the initial 500 response.
- **Update:** `src/with-prod/session-token-provider.ts` — when the
  refresh hits a credentials-expired response, log a clearly-formatted
  message to `stderr` (the with-prod parent process's stderr is what
  the user actually sees) and throw the typed error. The 401
  session-expired path is unchanged.
- **Update:** `src/with-prod/per-request-token-provider.ts` — inherits
  the new behaviour through `fetchProdAccessToken`.
- **Update:** `src/commands/with-prod.ts` — the startup catch block
  treats `CredentialsExpiredError` specially and prints just the
  error's message (which is already action-oriented) rather than
  prefixing it with `failed to acquire prod token:`.

### Tests

- New `src/__tests__/gate/credentials-error.test.ts` for the detector +
  mapper.
- Extend `src/__tests__/gate/auth.test.ts`: invalid_grant in
  `getAccessToken` becomes `CredentialsExpiredError`; cached source
  client is cleared so the next call sees a freshly-built client.
- Extend `src/__tests__/gate/handlers.test.ts`: every endpoint that
  catches errors emits `code: "credentials_expired"` for the typed
  error.
- Extend `src/__tests__/with-prod/session-token-provider.test.ts`:
  a 500 with `code: "credentials_expired"` produces the tailored
  client-side error.
- Extend `src/__tests__/with-prod/fetch-prod-token.test.ts` (or the
  per-request provider tests): same coverage for the per-request and
  session-creation paths.
- Extend `src/__tests__/commands/with-prod.test.ts`: when the gate
  responds with `credentials_expired`, the CLI prints the actionable
  message verbatim.

### Documentation

- README: add a sub-section under "Prerequisites" describing
  reauth-frequency integration — what the user sees when ADC expires,
  how to recover (`gcloud auth application-default login`), and that
  no gate restart is needed.
- CHANGELOG: Unreleased entry under "Changed" / "Added" describing the
  new error code and the auto-recovery behaviour.

## Open questions

None — the design is mechanical once the error class exists.
