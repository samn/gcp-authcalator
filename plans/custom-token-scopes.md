# Plan: Custom OAuth Scopes for Token Minting

## Context

Currently, all tokens (dev and prod) are minted with the hardcoded `cloud-platform` scope. Some tools (e.g., Cloud SQL Auth Proxy) require narrower scopes like `sqlservice.login`. This change adds support for configuring custom OAuth scopes via the TOML config file (`scopes = [...]`) and CLI (`--scopes=...` on `with-prod`), matching gcloud's `--scopes` flag UX.

**Design principle**: The gate daemon remains stateless regarding scopes — scopes are passed per-request as URL query parameters. The metadata proxy and `with-prod` each read scopes from config and pass them to the gate.

## Data Flow

### with-prod flow

```
CLI --scopes or config scopes
  → fetchProdToken(socketPath, { scopes })
  → GET /token?level=prod&scopes=scope1,scope2  (gate)
  → mintProdToken(scopes)  (fresh GoogleAuth with those scopes)
  → token returned
  → temp metadata proxy started with scopes in deps
  → scopes endpoint reports correct scopes
```

### metadata-proxy flow (dev tokens)

```
config scopes
  → gate client created with scopes option
  → GET /token?scopes=scope1,scope2  (gate)
  → mintDevToken(scopes)  (per-scope cached Impersonated client)
  → token returned
  → scopes endpoint reports correct scopes from deps
```

## Changes (in dependency order)

### 1. Config schema — `src/config.ts`

- Add `scopes` field to `ConfigSchema`: `z.array(z.string().min(1)).optional()`
- Add `scopes: "scopes"` to `cliToConfigKey`
- In `mapCliArgs`, split comma-separated `--scopes` string into array
- Export `DEFAULT_SCOPES = ["https://www.googleapis.com/auth/cloud-platform"]`

### 2. CLI — `src/cli.ts`

- Add `scopes: { type: "string" }` to `parseArgs` options
- Update `USAGE` string with `--scopes` documentation

### 3. Gate types — `src/gate/types.ts`

- Update `GateDeps` signatures:
  - `mintDevToken: (scopes?: string[]) => Promise<CachedToken>`
  - `mintProdToken: (scopes?: string[]) => Promise<CachedToken>`

### 4. Gate auth — `src/gate/auth.ts`

- Import `DEFAULT_SCOPES` from config (remove local constant)
- Update `AuthModule` interface to accept optional scopes on both mint functions
- **Dev tokens**: Replace single `devTokenCache`/`impersonatedClient` with `Map<string, ...>` keyed by sorted scope set. Each unique scope set gets its own `Impersonated` client and cached token.
- **Prod tokens**: When custom scopes provided, create fresh `GoogleAuth({ scopes })` instead of reusing cached source client. Default scopes still use cached source client.
- `getSourceClient()` unchanged — always `cloud-platform` (needed for IAM impersonation API)

### 5. Gate handlers — `src/gate/handlers.ts`

- In `handleToken`: extract `scopes` query param, split by `,`, pass to handleDevToken/handleProdToken
- `handleDevToken(deps, scopes?)`: pass scopes to `deps.mintDevToken(scopes)`
- `handleProdToken(req, deps, scopes?)`: pass scopes to `deps.mintProdToken(scopes)`

### 6. Metadata proxy types — `src/metadata-proxy/types.ts`

- Add `scopes: string[]` to `MetadataProxyDeps`

### 7. Metadata proxy handlers — `src/metadata-proxy/handlers.ts`

- `handleScopes(deps)`: return `deps.scopes.join("\n") + "\n"` instead of hardcoded string
- `handleServiceAccountInfo`: use `deps.scopes` instead of hardcoded array
- `handleServiceAccounts`: use `deps.scopes` instead of hardcoded array

### 8. Gate client — `src/metadata-proxy/gate-client.ts`

- Add `scopes?: string[]` to `GateClientOptions`
- When scopes configured, include `?scopes=scope1,scope2` in token request URL

### 9. Metadata proxy server — `src/metadata-proxy/server.ts`

- Add `scopes?: string[]` to `StartMetadataProxyServerOptions`
- Pass scopes to gate client creation
- Set `deps.scopes = options.scopes ?? DEFAULT_SCOPES`

### 10. Fetch prod token — `src/with-prod/fetch-prod-token.ts`

- Add `scopes?: string[]` to `FetchProdTokenOptions`
- Append `&scopes=...` to token URL when scopes provided

### 11. with-prod command — `src/commands/with-prod.ts`

- Pass `config.scopes` to `fetchProdToken` options
- Pass `config.scopes` to `startMetadataProxyServer` options

### 12. metadata-proxy command — `src/commands/metadata-proxy.ts`

- Pass `config.scopes` to `startMetadataProxyServer` options

### 13. Config example — `config.example.toml`

- Add commented-out `scopes` example

### 14. CHANGELOG.md

- Add entry under `[Unreleased] / Added`

## Tests

### Config tests (`src/__tests__/config.test.ts`)

- Schema accepts scope array, rejects invalid, allows undefined
- `mapCliArgs` splits comma-separated scopes string into array
- `loadConfig` merges TOML and CLI scopes (CLI wins)

### Gate handler tests (`src/__tests__/gate/handlers.test.ts`)

- `GET /token?scopes=scope1,scope2` passes scopes to `mintDevToken`
- `GET /token?level=prod&scopes=scope1` passes scopes to `mintProdToken`
- No `scopes` param → `undefined` passed (backward compat)
- Existing tests pass unchanged (optional param)

### Metadata proxy handler tests (`src/__tests__/metadata-proxy/handlers.test.ts`)

- Update `makeDeps` to include `scopes: DEFAULT_SCOPES`
- Test scopes endpoint with custom scopes
- Test service account info/listing with custom scopes

### Gate client tests (`src/__tests__/metadata-proxy/gate-client.test.ts`)

- Client with scopes includes `?scopes=...` in URL
- Client without scopes uses bare `/token`

### Fetch prod token tests (`src/__tests__/with-prod/fetch-prod-token.test.ts`)

- Scopes included in URL query parameter
- No scopes omits parameter

### with-prod tests (`src/__tests__/commands/with-prod.test.ts`)

- Scopes from config flow through to fetchProdToken and metadata proxy

## Verification

1. `bun run typecheck` — all types compile
2. `bun test` — all tests pass
3. `bun run lint` — no lint errors
4. `bun run format` — formatting consistent
5. Manual: `gcp-authcalator with-prod --scopes="https://www.googleapis.com/auth/sqlservice.login" -- gcloud auth print-access-token` should mint a token with the requested scope
