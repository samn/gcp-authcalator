# PAM: withdraw own grants instead of revoking, filter scans by requester

## Problem

A user reported that PAM grant refresh fails permanently when the revoke step
fails: `gate.log` shows `pam: revoke ... failed: 403 PERMISSION_DENIED`
(missing `privilegedaccessmanager.grants.revoke`) and no new grant is ever
created until the old grant ages out naturally.

Root cause analysis (verified against GCP docs and the PAM discovery
documents on 2026-06-11):

1. **The gate calls the wrong PAM operation.** `grants:revoke` requires the
   `privilegedaccessmanager.grants.revoke` permission — an approver/admin
   permission that grant _requesters_ do not (and should not) have. The
   operation a requester uses to end **their own** grants is
   `grants:withdraw`, which works on any non-terminal grant state (pending,
   scheduled, and active). Because the gate always operates on grants it
   requested itself, withdraw is the correct verb everywhere the gate
   currently revokes.

   Failure cascade today: rotation pre-revoke 403s (best-effort, swallowed)
   → `createGrantOnce` 409s on the still-open grant →
   `scanForOpenGrants` buckets it as stale → recovery revoke 403s →
   retry create 409s → `createGrantWithRecovery` throws "conflict persists".
   The thrown error reaches the client (500) and the audit file but is never
   written to the console, so `gate.log` makes the failure look silent.

2. **`scanForOpenGrants` ignores the grant requester.** PAM's open-grant rule
   is per `(entitlement, requester)` (the code comments already say so), but
   `grants.list` returns every requester's grants and the scan buckets all of
   them. On a shared entitlement (e.g. org-scoped, used by a whole team) the
   gate can (a) try to end _teammates'_ stale grants — guaranteed permission
   failure, and wrong even if it succeeded — and (b) classify a teammate's
   active grant as `usable` and reuse it: wrong identity, wrong expiry
   clamping.

## API facts (verified against the PAM discovery docs)

- `grants:withdraw` exists only on the **v1beta** surface. v1 grant methods:
  `list, search, get, create, approve, deny, revoke`. v1beta adds `withdraw`.
- `POST v1beta/{grant}:withdraw` — request body must be empty
  (`WithdrawGrantRequest` has no properties). Returns a long-running
  `Operation`, same shape as revoke.
- "`WithdrawGrant` is used to immediately withdraw the grant. This method can
  be called when the grant is in a non-terminal state." Requesters can
  withdraw pending/scheduled grants and end their own active grants.
- `Grant.requester` (output only): "Username of the user who created this
  grant" — present in both v1 and v1beta `Grant` resources.

## Changes

### `src/gate/pam.ts`

1. Replace `grants:revoke` with `grants:withdraw` everywhere the gate ends a
   grant (rotation pre-clear, stale-grant recovery, shutdown):
   - Add `PAM_API_BASE_V1BETA`; withdraw POSTs and the polling of the
     withdraw Operation go through v1beta (the Operation was created by a
     v1beta method, so it is polled on the same surface). All other calls
     stay on v1.
   - Withdraw request has an empty body (no `reason` field). The local
     log-context "reason" strings remain in our console messages only.
   - Rename `revokeGrantAndWait` → `withdrawGrantAndWait`,
     `pollRevokeOperation` → `pollWithdrawOperation`,
     `revokeAll` → `withdrawAll` (public interface; update `server.ts`).
   - Withdraw remains best-effort: failures are logged and swallowed; the
     create/retry flow is unchanged.

2. Filter grant scans by requester:
   - Add `PamModuleOptions.getRequesterEmail?: () => Promise<string>` and
     `requester?: string` to the grant response type.
   - `scanForOpenGrants` resolves the email once per scan and skips grants
     whose `requester` does not match (case-insensitive). Grants with no
     `requester` field are skipped too — never touch a grant we cannot
     attribute to ourselves. When the option is not provided the scan is
     unfiltered (back-compat for tests).
   - `server.ts` wires `auth.getIdentityEmail` in.

3. Surface rotation failures in the console: `ensureGrant` logs
   `pam: grant rotation failed for <entitlement>: <message>` before
   rethrowing, so `gate.log` no longer shows only the withdraw failures.

### Tests (`src/__tests__/gate/pam.test.ts`)

- Update mocks and assertions from `:revoke` to `:withdraw`.
- New: withdraw uses the v1beta base URL and sends no request body.
- New: scan skips other requesters' grants — does not reuse a teammate's
  usable grant, does not withdraw a teammate's stale grant, and reports
  "no active grant" when only other requesters' grants exist.
- New: requester comparison is case-insensitive; grants lacking `requester`
  are skipped when filtering is active.
- New: rotation failure is logged to the console (spy on `console.error`).

### Docs

- `SPEC.md`: update the grant-lifecycle paragraph (revoke → withdraw,
  v1beta note, requester filtering).
- `README.md`: "Grants are revoked on a best-effort basis when the gate
  shuts down" → withdraw; note that no `grants.revoke` permission is needed.
- `CHANGELOG.md`: Fixed entries under `[Unreleased]`.

## Out of scope

- Falling back to `revoke` when withdraw fails (adds complexity for no known
  scenario — the gate is always the requester of grants it manages).
- Graceful degradation when withdraw fails and the old grant is still open:
  behaviour is unchanged (error until the grant ages out), but it is now
  visible in the console log.
