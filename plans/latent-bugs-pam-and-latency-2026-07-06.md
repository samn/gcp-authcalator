# Latent-bug fixes for PAM grants & long command waits

Review date: 2026-07-06
Scope: latent bugs that could prevent PAM grants from registering, or cause
users to wait a long time for a command to complete.

## Findings

### F1 — metadata-proxy gate-client fetches have no timeout **[high]**

`src/metadata-proxy/gate-client.ts:143,171,193` — `getToken`,
`getNumericProjectId`, `getUniverseDomain` call the gate with `extraOpts` only
(`{unix}` / `{tls}`) and no `AbortSignal`. Every dev-token request from every
container process funnels through `getToken`, so a wedged gate socket hangs the
container indefinitely on the OS TCP retransmission timeout (~15 min on Linux).

Every other gate fetch in the codebase is bounded (3 s healthcheck, 5 s
kube-token, 10 s PAM, 600 s prod acquisition, 480 s session refresh, 30 s
identity). The dev-token path was missed.

**Fix:** `AbortSignal.timeout(30_000)` on each fetch; wrap aborts into an
actionable "gcp-gate request timed out after 30000ms: <url>" error mirroring
`fetchWithGateTimeout` in `with-prod/fetch-prod-token.ts`. 30 s matches
`IDENTITY_FETCH_TIMEOUT_MS` and covers slow ADC/impersonation comfortably —
dev tokens involve no human confirmation.

### F2 — `approve`/`deny` CLI fetch has no timeout **[high]**

`src/commands/approve.ts:37` — `fetch` to the admin socket with no signal. A
wedged admin socket hangs the approval CLI indefinitely; the pending request
itself auto-denies at 120 s, leaving the user's prod command failed and the
`approve` command stuck — confusing in an already-stressful flow.

**Fix:** `AbortSignal.timeout(5_000)`; on abort print
`error: admin socket not responding (timed out after 5s)` and exit 1. Matches
the kube-token neighbourhood.

### F3 — `computeGrantExpiry` fallback can overstate a reused grant's lifetime **[medium]**

`src/gate/pam.ts:695-708` — when PAM returns a grant missing `createTime` or
`requestedDuration` (or with an unparseable duration), the fallback is
`new Date(now() + 15 * 60 * 1000)`. Correct for a freshly-created grant, but
`computeGrantExpiry` is also called in `scanForOpenGrants` to decide whether a
**pre-existing** grant (409-conflict recovery path) is reusable. For an old
reused grant, `now()+15min` can be later than the grant's real expiry, so
`hasUsableLifetime` returns true and the gate reuses a grant whose actual
remaining life is below the drain margin. Minted tokens are then clamped to
`computed_expiry - DRAIN_MARGIN_MS` (up to 15 min) rather than the real
(shorter) expiry — so tokens can outlive the grant's real end by up to the
drain margin, the exact failure the clamp was designed to prevent.

Likelihood low (fields are documented as output-only and present), but the
correctness gap is real.

**Fix:** split `computeGrantExpiry` so callers can detect "fields
missing/unparseable". In `scanForOpenGrants`, treat a reused grant whose
expiry can't be determined as **non-usable** (push to `blocking`, not
`usable`), forcing withdraw + fresh create on the conflict path. For
`cacheGrant` (a freshly created grant), keep the conservative fallback — a
freshly-created grant's real expiry is bounded by the `requestedDuration` we
just sent.

### F4 — `scanForOpenGrants` fails entirely if `getRequesterEmail()` throws **[medium]**

`src/gate/pam.ts:539` — `getRequesterEmail()` runs at the top of every scan.
If `getIdentityEmail()` fails independently of ADC — e.g.
`tokeninfo.googleapis.com` is down but the ADC access token is fine — the scan
throws, and `createGrantWithRecovery` propagates the error. The initial
`createGrantOnce` doesn't need the email, but the 409-conflict recovery path
does. Result: if a PAM grant is already open (from a previous interrupted run)
and tokeninfo is flaky, grant creation fails repeatedly until the existing
grant expires naturally.

**Fix:** wrap `getRequesterEmail()` so a failure throws a typed
`PamRequesterLookupError` with a clear message naming the underlying cause, so
it surfaces distinctly from a generic PAM API failure in the gate log and
client error. Do **not** fall back to no-filtering (would risk touching a
teammate's grant on shared entitlements).

### F5 — `pam_grant_ttl_seconds` floor of 301 s mints ~1 s tokens **[low]**

`src/config.ts:97-104` — schema floor is `> DRAIN_MARGIN_SECONDS` (300 s),
i.e. 301 s minimum. A 301 s grant is "usable" for 1 s (`hasUsableLifetime`
needs `> 5 min`), and minted tokens are clamped to `grant_expiry -
DRAIN_MARGIN_MS` = 1 s. Technically valid but causes a refresh storm (every
request re-rotates).

**Fix:** raise the floor to 600 s (2× drain margin). Update `SPEC.md`,
`README.md`, `config.example.toml`, `src/cli.ts` `--help` text. Also update
the `GateConfigSchema` effective-grant-TTL refine (line 217-218) to use the
same 600 s floor for the `token_ttl_seconds` fallback path.

## Out of scope

- **F6** — `getAccessToken` inside `pamFetch` is not covered by the fetch
  `AbortSignal` (upstream `google-auth-library` limitation; documented
  residual in `plans/pam-acquisition-timeouts.md`).
- **F7** — external PAM grant withdrawal isn't detected by the cache. Would
  require periodic re-validation; low priority.

## Verification

`bun run format && bun run lint && bun run typecheck && bun test` per
`AGENTS.md`. `CHANGELOG.md` entries under `[Unreleased]` for each fix.
