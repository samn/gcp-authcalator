# Configurable PAM grant TTL

## Problem

The PAM grant lifetime is hardwired to `token_ttl_seconds` in
`src/gate/server.ts`:

```ts
const defaultTokenTtlSeconds = config.token_ttl_seconds ?? 3600;
// ...
pam = createPamModule(auth.getSourceAccessToken, {
  grantDurationSeconds: defaultTokenTtlSeconds,
});
```

When tokens are kept short (the security-driven default, 1 h) the grant
expires on the same cadence. Because the cache rotation window opens
`DRAIN_MARGIN_MS` (5 min) before the grant's actual end, callers can
observe a PAM `createGrant` round-trip every hour — and PAM/IAM
propagation latency means the first request after rotation can stall
visibly while the new grant's IAM binding lands. The result is a
periodic "poor user experience" pause unrelated to anything the engineer
did.

## Solution

Separate the PAM grant TTL from the token TTL, so operators can pick a
longer grant (e.g. 4 h) while keeping tokens short (1 h). One cached
grant then serves four token refreshes; PAM/IAM propagation cost is paid
once per grant rotation instead of once per token refresh.

The drain-margin clamp on minted tokens stays exactly as today, so
individual token lifetimes are unchanged — the longer grant only reduces
the rotation cadence (and therefore the frequency of any propagation
pause).

## Changes

- `src/config.ts`
  - New `pam_grant_ttl_seconds` Zod field, same range as
    `token_ttl_seconds` (60–43200 s).
  - Added to `cliToConfigKey` mapping and the `configKeys` env-var list.
- `src/cli.ts`
  - New `--pam-grant-ttl-seconds` flag + help text.
- `src/gate/server.ts`
  - New `pamGrantTtlSeconds = config.pam_grant_ttl_seconds ??
defaultTokenTtlSeconds`; passed to `createPamModule`.
  - Startup log line `pam grant TTL: <n>s` when PAM is enabled.
- Tests
  - `config.test.ts`: schema validation (range, coerce, undefined,
    longer-than-token-TTL), kebab-to-snake mapping, env-var loader.
  - `pam.test.ts`: explicit 4-hour grant duration test.
  - `server.test.ts`: smoke test for `pam_policy` +
    `pam_grant_ttl_seconds`.
- Docs
  - `README.md`: CLI table, env-var table, TOML example.
  - `SPEC.md`: paragraph explaining grant-TTL/token-TTL decoupling and
    rationale.
  - `config.example.toml`: commented example with the 4-hour case.
  - `CHANGELOG.md`: Unreleased / Added entry.

## Behaviour summary

| Setting                                         | Token TTL | PAM grant TTL | Rotations per hour |
| ----------------------------------------------- | --------- | ------------- | ------------------ |
| both unset                                      | 3600 s    | 3600 s        | ~1                 |
| only `token_ttl_seconds = 3600`                 | 3600 s    | 3600 s        | ~1 (back-compat)   |
| `token_ttl_seconds = 3600`, `pam_grant = 14400` | 3600 s    | 14400 s       | ~0.25              |

The grant-expiry clamp (`grant_expiry - DRAIN_MARGIN_MS`) on minted
tokens applies in every row, so no row changes the per-token TTL.

## Non-goals

- No change to `DRAIN_MARGIN_MS` (still 5 min) — that's the
  concurrent-client safety margin and is orthogonal.
- No change to the per-token clamp logic in `handlers.ts`.
- No automatic relationship between the two values is enforced; a grant
  shorter than the token TTL is legal (the clamp just makes the
  minted token expire earlier than the token TTL).
