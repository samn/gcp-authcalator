---
name: gcloud metadata proxy fix
overview: Fix the metadata proxy to support gcloud CLI by listing the service account email in the service-accounts directory and handling email-based service account paths.
todos:
  - id: alias-email-paths
    content: Add email-to-default path aliasing before the switch statement in handleRequest()
    status: completed
  - id: update-listing
    content: Update handleServiceAccounts() to include email in both recursive and non-recursive responses
    status: completed
  - id: update-tests
    content: Update existing tests and add new tests for email-based path routing
    status: completed
  - id: update-changelog
    content: Add CHANGELOG entry for gcloud compatibility fix
    status: completed
  - id: todo-1771265221204-b0byud0es
    content: Add this plan to plans/
    status: pending
isProject: false
---

# Fix gcloud CLI Compatibility with Metadata Proxy

## Problem

The `gcloud` CLI's `Metadata().Accounts()` method fetches `/computeMetadata/v1/instance/service-accounts/`, filters out `default`, and only recognizes real email addresses. The proxy currently returns only `"default/\n"`, so `gcloud` sees zero accounts and throws `NoCredentialsForAccountException`.

Additionally, `google-auth` refreshes tokens using the email-based path (e.g., `.../service-accounts/{email}/token`), which the proxy doesn't handle.

## Changes

### 1. Add email-based path aliasing in the request handler

In `[src/metadata-proxy/handlers.ts](src/metadata-proxy/handlers.ts)`, before the `switch` statement, detect paths that use the configured service account email and rewrite them to use `default`. This keeps all existing handler logic intact:

```typescript
// Before the switch, alias email-based paths to default-based paths
const saBase = "/computeMetadata/v1/instance/service-accounts/";
if (deps.serviceAccountEmail && pathname.startsWith(saBase + deps.serviceAccountEmail)) {
  pathname = pathname.replace(deps.serviceAccountEmail, "default");
}
```

This will transparently support:

- `.../{email}/token` -> `.../default/token`
- `.../{email}/email` -> `.../default/email`
- `.../{email}` -> `.../default` (recursive info)

### 2. Update service-accounts listing to include email

In `handleServiceAccounts()` in the same file:

**Non-recursive** (text listing): return both `default/` and `{email}/`

```
default/
dev-test-runner@monitron-dev.iam.gserviceaccount.com/
```

**Recursive** (JSON): include the email as a second key with identical content:

```json
{
  "default": { "aliases": ["default"], "email": "...", "scopes": [...] },
  "dev-test-runner@monitron-dev.iam.gserviceaccount.com": { "aliases": ["default"], "email": "...", "scopes": [...] }
}
```

### 3. Update tests

Update existing tests in `[src/__tests__/metadata-proxy/handlers.test.ts](src/__tests__/metadata-proxy/handlers.test.ts)`:

- Update the non-recursive listing test (`"default/\n"` -> include email)
- Update the recursive listing test (expect email key in JSON)
- Add new tests for email-based path routing (token, email, info endpoints)
- Add edge case: when `serviceAccountEmail` is undefined, listing only shows `default/`

### 4. Update CHANGELOG

Add entry under `[Unreleased]` in `[CHANGELOG.md](CHANGELOG.md)` documenting the fix.
