# GCP PAM Integration for Just-in-Time Privilege Escalation

## Context

Currently, the prod token flow (`GET /token?level=prod`) uses the engineer's ADC directly, which requires the engineer to already have full prod permissions. This means credential exfiltration from the host gives an attacker full prod access.

With PAM integration, the engineer's ADC can be downscoped by default. When prod access is needed, the gate requests a PAM grant to temporarily elevate the engineer's IAM roles, then mints a token using the now-elevated credentials. When the grant expires, elevated access is automatically revoked.

## Design

### Flow

```
with-prod --pam-policy=my-entitlement -- command
  → fetchProdToken(gate, { pamPolicy: "my-entitlement" })
    → GET /token?level=prod&pam_policy=my-entitlement
      → gate: validate pam_policy against allowlist
      → gate: rate limit check
      → gate: confirmation dialog (shows entitlement name)
      → gate: PAM grant request → poll until ACTIVATED
      → gate: mintProdToken (ADC now has elevated roles from PAM)
      → return token
```

### Key Decisions

1. **PAM complements the confirmation dialog** — confirmation is local intent verification, PAM is organizational privilege escalation. Both fire. The dialog shows the entitlement being activated.
2. **REST API directly, no new npm package** — follows the existing pattern in `auth.ts` (see `getProjectNumber` using fetch + ADC bearer token).
3. **Short-form entitlement ID or full resource path** — if value contains `/`, treat as full path (validated against `projects/*/locations/*/entitlements/*` pattern and matching `config.project_id`). Otherwise, short-form must match `^[a-z][a-z0-9-]*$` and is expanded to `projects/{project_id}/locations/{pam_location}/entitlements/{id}`.
4. **Gate caches active PAM grants** — keyed by entitlement path, reused until 5 min before expiry (same margin as token cache).
5. **pam_policy flows as a query param** — follows the same pattern as `scopes`. with-prod sends it to gate in the fetchProdToken call. The gate also has a default from config.
6. **service_account becomes optional when pam_policy is set** — PAM-elevated ADC can be used directly for prod tokens without impersonation. If service_account IS set alongside pam_policy, dev token impersonation still works as before.
7. **Fixed 1-hour grant duration** — matches token TTL, keeps config surface small.
8. **Entitlement allowlist on the gate** — the gate config declares which PAM entitlements are permitted (`pam_policy` as the default, `pam_allowed_policies` as the full allowlist). The query param `pam_policy` is rejected with 403 if it's not in the allowlist. This prevents container-side code from requesting arbitrary entitlements.
9. **Best-effort grant revocation on shutdown** — the gate's SIGTERM handler calls `RevokeGrant` on any active cached grants to minimize the window of elevated access.

### Security Properties

- **Entitlement allowlist**: Container cannot escalate to arbitrary PAM entitlements — only those declared in gate config are accepted.
- **Input validation**: Short-form entitlement IDs are validated against `^[a-z][a-z0-9-]*$`. Full resource paths are validated against the expected pattern and must reference `config.project_id`.
- **Confirmation shows entitlement**: The engineer sees which entitlement is being activated in the dialog, preventing blind approval.
- **Grant revocation on exit**: Best-effort `RevokeGrant` on shutdown reduces the window where exfiltrated ADC retains elevated permissions.
- **Explicit error on misconfiguration**: If `pam_policy` query param is present but PAM module is not wired (no config), gate returns an explicit error — never silently skips PAM.

## Implementation

### 1. Config (`src/config.ts`)

Add to `ConfigSchema`:
```typescript
pam_policy: z.string().min(1).optional(),              // default entitlement ID or full path
pam_allowed_policies: z.array(z.string().min(1)).optional(), // additional allowed entitlements
pam_location: z.string().min(1).optional(),            // default: "global"
```

Add to `cliToConfigKey`:
- `"pam-policy": "pam_policy"`
- `"pam-allowed-policies": "pam_allowed_policies"` (comma-separated on CLI, split like `scopes`)
- `"pam-location": "pam_location"`

Add all three to `configKeys` array for env var support.

**GateConfigSchema change**: Currently requires `service_account`. Make it conditional:
- If `pam_policy` is set, `service_account` is optional (gate can operate with just PAM-elevated ADC for prod tokens; dev tokens disabled without service_account)
- If `pam_policy` is not set, `service_account` remains required (current behavior)
- Use a Zod `.refine()` or `.superRefine()` to express this: at least one of `service_account` or `pam_policy` must be provided.

### 2. CLI (`src/cli.ts`)

Add to `parseArgs` options:
- `--pam-policy` (string)
- `--pam-allowed-policies` (string, comma-separated)
- `--pam-location` (string)

Add to USAGE text under Options.

### 3. PAM Module (`src/gate/pam.ts`) — new file

```typescript
export interface PamModuleOptions {
  fetchFn?: typeof globalThis.fetch;
  now?: () => number;
}

export interface PamModule {
  /** Ensure an active PAM grant exists for the entitlement. Caches grants. */
  ensureGrant: (entitlementPath: string, justification?: string) => Promise<PamGrantResult>;
  /** Best-effort revoke all cached active grants. Called on shutdown. */
  revokeAll: () => Promise<void>;
}

export interface PamGrantResult {
  name: string;           // full grant resource path
  state: string;          // "ACTIVATED"
  cached: boolean;        // whether this was a cache hit
}
```

Core functions:
- `resolveEntitlementPath(policy, projectId, location)` — expand short ID to full resource path. Validates short-form against `^[a-z][a-z0-9-]*$`. Validates full paths against `projects/{projectId}/locations/*/entitlements/*` pattern.
- `createPamModule(getAccessToken, options)` → `PamModule`
- Grant cache: `Map<string, { grant: PamGrant; expiresAt: Date }>`, reuse active grants within 5-min margin
- `createGrant()` — `POST https://privilegedaccessmanager.googleapis.com/v1/{entitlement}/grants` with `requestedDuration: "3600s"` and justification
- `pollGrant()` — poll `GET https://privilegedaccessmanager.googleapis.com/v1/{grantName}` with exponential backoff (1s→5s, 120s total timeout). States: `ACTIVATED` = success, `DENIED`/`REVOKED`/`ENDED` = fail, else continue.
- `revokeGrant()` — `POST https://privilegedaccessmanager.googleapis.com/v1/{grantName}:revoke` (best-effort, errors logged not thrown)
- Handle 409 Conflict (grant already exists) by listing/reusing active grants
- `revokeAll()` — iterate cached active grants and call `revokeGrant` on each

### 4. Gate Types (`src/gate/types.ts`)

Add to `GateDeps`:
```typescript
ensurePamGrant?: (entitlementPath: string, justification?: string) => Promise<PamGrantResult>;
/** Allowlist of resolved entitlement paths. If set, pam_policy query params must match. */
pamAllowedPolicies?: Set<string>;
/** Default resolved entitlement path from config. */
pamDefaultPolicy?: string;
```

Add to `AuditEntry`:
```typescript
pam_policy?: string;       // resolved entitlement path
pam_grant?: string;        // grant resource name
pam_cached?: boolean;      // whether the grant was a cache hit
```

### 5. Gate Handlers (`src/gate/handlers.ts`)

In `handleToken`, parse `pam_policy` query param:
```typescript
const pamPolicyParam = url.searchParams.get("pam_policy") ?? undefined;
```

In `handleProdToken`:
1. Resolve the effective PAM policy: query param `pam_policy` > `deps.pamDefaultPolicy` > none.
2. **Allowlist check**: If a `pam_policy` is resolved and `deps.pamAllowedPolicies` exists, verify the resolved entitlement path is in the set. Return 403 `"PAM policy not in allowlist"` if not.
3. **Misconfiguration check**: If `pam_policy` is resolved but `deps.ensurePamGrant` is undefined, return 500 `"PAM policy requested but PAM module not configured"` — never silently skip.
4. Confirmation dialog: pass entitlement name to `confirmProdAccess` so the dialog shows it.
5. After confirmation, before `mintProdToken`:
```typescript
const grantResult = await deps.ensurePamGrant(resolvedEntitlementPath, justification);
```
6. Include `pam_policy`, `pam_grant`, `pam_cached` in audit log entry.

When `service_account` is not configured and no `pam_policy` is provided, `handleDevToken` should return 501 `"Dev tokens unavailable: no service_account configured"`.

### 6. Gate Server (`src/gate/server.ts`)

- Resolve all entitlement paths at startup: `pam_policy` (default) + `pam_allowed_policies` (additional). Build the `Set<string>` allowlist from all resolved paths.
- Create PAM module using ADC token accessor from auth module.
- Wire `ensurePamGrant`, `pamAllowedPolicies`, `pamDefaultPolicy` into deps.
- Log PAM config on startup (default policy, allowed policies count).
- In SIGTERM/SIGINT handler, call `pam.revokeAll()` before `process.exit(0)`.

### 7. Confirmation dialog (`src/gate/confirm.ts`)

Add optional `pamPolicy?: string` parameter to `confirmProdAccess`. Update dialog text:
- With PAM: `"Grant prod-level GCP access to user@co.com via PAM entitlement 'my-entitlement'?\n\nReported command: ..."`
- Without PAM: unchanged from current behavior.

### 8. with-prod (`src/with-prod/fetch-prod-token.ts`, `src/commands/with-prod.ts`)

Add `pamPolicy?: string` to `FetchProdTokenOptions`.
In `fetchProdToken`, append `&pam_policy=...` to the token URL (same pattern as `scopes`).
In `runWithProd`, pass `config.pam_policy` through.

### 9. Documentation

- `config.example.toml`: Add commented `pam_policy`, `pam_allowed_policies`, and `pam_location` examples
- `CHANGELOG.md`: Add entry under `[Unreleased]` / `Added`
- `SPEC.md`: Update gate endpoint table, add PAM section, document security properties

### 10. Tests

- **`src/__tests__/gate/pam.test.ts`** (new):
  - `resolveEntitlementPath`: short ID expansion, full path passthrough, short ID validation rejects invalid chars, full path validation rejects wrong project
  - `createGrant`: success, 403/404/409 error cases
  - `pollGrant`: immediate activation, delayed activation, timeout, denied state
  - `ensureGrant`: caching (second call returns cached), cache expiry triggers re-request
  - `revokeAll`: revokes all cached grants, tolerates individual revoke failures
- **`src/__tests__/gate/handlers.test.ts`** (extend):
  - Prod token with `pam_policy` in allowlist calls `ensurePamGrant`
  - Prod token with `pam_policy` NOT in allowlist returns 403
  - Prod token with `pam_policy` but no `ensurePamGrant` wired returns 500
  - Prod token without `pam_policy` skips PAM
  - Audit entries include `pam_policy`, `pam_grant`, `pam_cached`
  - Confirmation dialog receives entitlement name
- **`src/__tests__/config.test.ts`** (extend):
  - `pam_policy`, `pam_allowed_policies`, `pam_location` parse from TOML/CLI/env
  - GateConfigSchema: service_account optional when pam_policy set, required when not
- **`src/__tests__/with-prod/fetch-prod-token.test.ts`** (extend):
  - `pamPolicy` appended to token URL when provided

## File Changes

| File | Type | Description |
|------|------|-------------|
| `src/config.ts` | Modify | Add pam_policy, pam_allowed_policies, pam_location fields; conditional GateConfigSchema |
| `src/cli.ts` | Modify | Add --pam-policy, --pam-allowed-policies, --pam-location options |
| `src/gate/pam.ts` | **New** | PAM grant creation, polling, caching, revocation |
| `src/gate/types.ts` | Modify | Add PAM fields to GateDeps and AuditEntry |
| `src/gate/handlers.ts` | Modify | Parse pam_policy, allowlist check, call PAM before minting |
| `src/gate/server.ts` | Modify | Wire PAM module, build allowlist, revoke on shutdown |
| `src/gate/confirm.ts` | Modify | Show entitlement name in confirmation dialog |
| `src/with-prod/fetch-prod-token.ts` | Modify | Accept/pass pamPolicy |
| `src/commands/with-prod.ts` | Modify | Pass config.pam_policy to fetchProdToken |
| `config.example.toml` | Modify | Add PAM config examples |
| `CHANGELOG.md` | Modify | Document new feature |
| `SPEC.md` | Modify | Document PAM integration and security properties |
| `src/__tests__/gate/pam.test.ts` | **New** | PAM module tests |
| Existing test files | Modify | Add PAM-related test cases |

## Verification

1. `bun run typecheck` — no type errors
2. `bun test` — all tests pass including new PAM tests
3. `bun run lint && bun run format` — clean
4. Manual: start gate with `--pam-policy=test-entitlement`, verify:
   - Startup logs show PAM config and allowlist
   - Confirmation dialog includes entitlement name
   - Audit log includes pam_policy, pam_grant, pam_cached fields
   - Query param with unlisted policy returns 403
   - SIGTERM triggers grant revocation attempt in logs
