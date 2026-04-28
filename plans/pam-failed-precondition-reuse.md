# Handle PAM `FAILED_PRECONDITION` "open Grant" the same as 409 Conflict

## Context

Running `with-prod` while a prior PAM grant is still active fails with:

```
with-prod: failed to acquire prod token: gcp-gate returned 500: {"error":"PAM API error (400):
  { \"error\": { \"code\": 400,
      \"message\": \"You have an open Grant \\\"projects/.../grants/0cc552a2-...\\\"
                    that gives the same privileged access.\",
      \"status\": \"FAILED_PRECONDITION\" } }"}
```

The PAM module already knows how to recover from this condition — when GCP returns
`409 Conflict`, `createGrant()` falls through to `findActiveGrant()` and reuses
the existing grant. But GCP is returning `400 FAILED_PRECONDITION` for the same
underlying condition (an "open Grant" that gives the same privileged access).
The current `if (res.status === 409)` check at `src/gate/pam.ts:180` doesn't
match, the response falls through to the generic `if (!res.ok)` branch at line
200, the error wraps up through the gate's 500 response, and the user sees the
opaque message above instead of seamlessly reusing their existing grant.

This makes `with-prod` unusable in the common case where a developer's prior
session left a grant alive (e.g. they Ctrl-C'd a previous `with-prod`, or the
grant duration outlasts a single shell session).

## Approach

Extend `createGrant()` in `src/gate/pam.ts` to recognize the `400
FAILED_PRECONDITION` "open Grant" response as functionally equivalent to `409
Conflict` and route it through the same `findActiveGrant()` path.

**Detection (narrow, by design):**

A response qualifies for the reuse path when **all** of these hold:

1. `res.status === 400`
2. The parsed body's `error.status === "FAILED_PRECONDITION"`
3. The parsed body's `error.message` contains the substring `"open Grant"`

Narrow matching avoids swallowing unrelated `FAILED_PRECONDITION` causes
(disabled entitlement, ineligible requester, requested duration out of range,
etc.) — those should continue to surface their original error message to the
user.

**Reuse path (unchanged):** Call existing `findActiveGrant(entitlementPath)`,
which lists grants with `state="ACTIVATED"`. If no active grant is returned,
keep the existing "PAM grant conflict but no active grant found" error — same
behavior as the 409 path today. Mid-approval (APPROVAL_AWAITED / ACTIVATING)
grants intentionally do **not** qualify for reuse; the user gets a clear error
rather than a silent long poll.

**No changes** to `findActiveGrant()`, `pollGrant()`, the cache, the gate
handlers, or the `with-prod` client. The fix is contained to one branch in
`createGrant()`.

## Files to modify

- `src/gate/pam.ts` — add the `FAILED_PRECONDITION` + "open Grant" detection
  branch in `createGrant()` between the existing 409 handler (line 180) and the
  403 handler (line 185). Read the response body once (carefully — `Response`
  bodies can only be consumed once), JSON-parse defensively, and route to
  `findActiveGrant()` on match. On non-match, fall through to the existing
  generic-error path.
- `src/__tests__/gate/pam.test.ts` — add tests mirroring the existing 409
  coverage (lines 237-257):
  - `"handles 400 FAILED_PRECONDITION 'open Grant' by finding active grant"`
    — 400 body with `error.status="FAILED_PRECONDITION"` and `"open Grant"`
    in message → list returns one ACTIVATED grant → resolves to that grant.
  - `"throws on 400 FAILED_PRECONDITION 'open Grant' when no active grant
found"` — same 400, list returns empty grants → throws the
    "no active grant found" error.
  - `"throws on 400 FAILED_PRECONDITION without 'open Grant' phrase"` —
    400 with FAILED_PRECONDITION but a different message (e.g. "Entitlement
    is disabled") → throws the generic `PAM API error (400)` with original
    body preserved (does **not** call findActiveGrant).
  - `"throws on 400 with non-FAILED_PRECONDITION status"` — 400 with
    `INVALID_ARGUMENT` → throws generic error, does not call findActiveGrant.
- `CHANGELOG.md` — add a one-line entry under `[Unreleased]` → `Fixed`:
  > Reuse existing PAM grant when GCP returns `400 FAILED_PRECONDITION`
  > ("open Grant"), matching prior behavior for `409 Conflict`.

## Reused code

- `findActiveGrant()` in `src/gate/pam.ts:208` — already does exactly the
  lookup we need; called identically from both the 409 and the new 400 branch.
- The existing test fixtures `makeModule()` / `makeActivatedGrant()` in
  `src/__tests__/gate/pam.test.ts` — patterned after the 409 tests at line 237.

## Verification

1. Unit tests: `bun test src/__tests__/gate/pam.test.ts` — all four new
   cases pass; existing 409 cases still pass.
2. Pre-commit suite (per `AGENTS.md`):
   - `bun run format`
   - `bun run lint`
   - `bun run typecheck`
   - `bun test`
3. End-to-end manual verification:
   - In a dev project with a real PAM entitlement, run `with-prod -- gcloud
auth print-access-token` and confirm a grant is created.
   - Without exiting the grant window (or after Ctrl-C'ing during the first
     run so revoke is skipped), run `with-prod` again. **Expected:** the
     command proceeds and reuses the existing grant rather than failing with
     `failed to acquire prod token: ... FAILED_PRECONDITION ...`.
   - Check the gate's audit log: the second invocation should record a
     `pam_grant` entry pointing to the same grant resource as the first.
4. Confirm no behavior regression for unrelated `FAILED_PRECONDITION` causes
   by inspecting the test that asserts a non-"open Grant" 400 still surfaces
   its original message.

## Out of scope (intentionally)

- Widening `findActiveGrant()` to also return `APPROVAL_AWAITED` / `ACTIVATING`
  grants. Discussed; deferred. Can be added later if the mid-approval edge
  case shows up in practice.
- Parsing the conflicting grant's resource name out of the error message.
  Faster but tighter coupling to PAM's unstructured message format; not worth
  the maintenance risk for the saving.
- Client-side (`with-prod`) error message improvements. The gate now does the
  right thing transparently; no client change needed.
