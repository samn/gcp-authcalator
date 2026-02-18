# Plan: Nested `with-prod` Session Reuse

## Context

When `with-prod` is invoked inside an already-running `with-prod` session (e.g., a build script that internally calls `with-prod`), it currently fetches a new prod token from gcp-gate, which triggers another GUI confirmation dialog. This is redundant — the parent session already has a valid prod token and a running metadata proxy. We should detect the nested case and reuse the parent's session.

## Approach

1. **Sentinel env var** — The parent `with-prod` sets `GCP_AUTHCALATOR_PROD_SESSION=<metadata_host>` in the child environment. This is distinct from `GCE_METADATA_HOST` (which the dev metadata proxy also sets) and explicitly signals "you are inside a prod session."

2. **Early detection with health check** — At the start of `runWithProd`, before config parsing, check for the sentinel. If present, validate the parent's proxy is alive by probing its token endpoint. If healthy, skip token fetch and proxy creation; just spawn the command with the inherited environment.

3. **Graceful fallback** — If the sentinel is set but the proxy is dead or the token is expired, log a warning and fall through to the normal flow (new confirmation dialog).

## File Changes

### New: `src/with-prod/detect-nested-session.ts`

Exports `PROD_SESSION_ENV_VAR` constant and `detectNestedSession(env, fetchFn?)` function.

Detection logic:

1. Read `GCP_AUTHCALATOR_PROD_SESSION` from env — return `null` if missing
2. Probe `http://<host>/` — verify 200 + `Metadata-Flavor: Google` header
3. Probe `http://<host>/computeMetadata/v1/instance/service-accounts/default/token` — verify 200 + `expires_in > 0` (catches expired tokens)
4. Read email from `/computeMetadata/v1/instance/service-accounts/default/email`
5. Read project from `/computeMetadata/v1/project/project-id`
6. Return `{ metadataHost, email, projectId }` on success, `null` on any failure
7. All fetches use `AbortSignal.timeout(2000)` to avoid blocking on hung proxies
8. Accepts injectable `fetchFn` for testing (matches existing pattern in `fetch-prod-token.ts`)

### Modify: `src/commands/with-prod.ts`

**Add nested early-return path** (after empty-command check, before full config parsing):

- Parse base `ConfigSchema` to get optional `project_id` from CLI/config (this already happens in `cli.ts` before calling `runWithProd`, so `config.project_id` is available but may be `undefined`)
- Call `detectNestedSession(process.env, ...)`
- If valid session detected:
  - If `config.project_id` is set AND differs from the parent proxy's project → log warning, fall through to normal flow (new session with new confirmation dialog)
  - Otherwise: log `"with-prod: reusing existing prod session (proxy at <host>)"`, strip credential env vars, spawn child with inherited env (including sentinel), forward signals, propagate exit code
- If null: fall through to existing flow unchanged

**In normal flow** — add `GCP_AUTHCALATOR_PROD_SESSION: metadataHost` to the child env object (line ~134).

Placing detection before `WithProdConfigSchema.parse()` means `--project-id` is not required when nested (as long as projects match or no project is specified), since the project is inherited from the parent's proxy.

### New: `src/__tests__/with-prod/detect-nested-session.test.ts`

Tests for:

- Returns null when env var missing/empty
- Returns session info when proxy is healthy
- Returns null on connection failure, non-200 responses, missing Metadata-Flavor header
- Returns null when token expired (`expires_in <= 0`)
- Returns null on fetch timeout

### Modify: `src/__tests__/commands/with-prod.test.ts`

Add nested session tests:

- Reuses session without fetching new token (mock gate to reject `/token?level=prod` to prove it's never called)
- Passes through `GCE_METADATA_HOST`, `CLOUDSDK_CONFIG`, `CLOUDSDK_CORE_ACCOUNT` from parent
- Strips credential env vars even when nested
- Propagates exit code
- Falls back to normal flow when proxy is dead
- Falls back to normal flow when `--project-id` differs from parent session's project
- Reuses session when `--project-id` matches parent session's project
- Reuses session when `--project-id` is not specified (inherits parent)
- Normal flow sets `GCP_AUTHCALATOR_PROD_SESSION` in child env

### Modify: `CHANGELOG.md`

Add under `[Unreleased] > Added`:

```
- `with-prod`: nested sessions automatically reuse the parent's prod token and metadata proxy, eliminating redundant confirmation dialogs
```

## Security Notes

- The sentinel env var does not introduce a new attack vector. If an attacker can set env vars, they can already set `GCE_METADATA_HOST` to their own proxy. The health check (including PID-validated token fetch) provides defense-in-depth.
- PID ancestry validation naturally works for nested sessions: the nested with-prod and its children are all descendants of the original with-prod PID.
- Credential env vars are still stripped in the nested path.

## Verification

1. `bun run typecheck` — no type errors
2. `bun test` — all tests pass
3. `bun run lint && bun run format` — clean
4. Manual: `gcp-authcalator with-prod -- gcp-authcalator with-prod -- gcloud auth list` — first invocation shows dialog, second prints "reusing existing prod session"
