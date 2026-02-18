# Plan: Write access token to file for with-prod gcloud auth

## Context

Some gcloud commands under `with-prod` don't fetch tokens from the temporary metadata proxy, even though the proxy is running and PID-validated correctly. Setting `CLOUDSDK_AUTH_ACCESS_TOKEN` env var works, but exposes the raw token in the process environment where it can be read by any same-UID process via `/proc/<pid>/environ` and is inherited by all child processes.

**Goal:** Write the token to a file and configure gcloud via `auth/access_token_file` in the gcloud properties file, keeping the metadata proxy as a belt-and-suspenders approach.

## Security Analysis Summary

**Token file is strictly better than the env var:**

| Concern                       | Env var                             | Token file                        |
| ----------------------------- | ----------------------------------- | --------------------------------- |
| Other users (primary threat)  | Protected by `/proc` permissions    | Protected by 0700 dir + 0600 file |
| Same-user processes           | Token directly in `/proc/*/environ` | Requires multi-step discovery     |
| Inherited by child processes  | Yes (all descendants)               | No                                |
| Captured by env-dumping tools | Yes                                 | No                                |
| Persists after process exit   | No                                  | Yes (until cleanup)               |

Neither approach prevents a determined same-user attacker, but the token file raises the bar meaningfully: the token isn't in any process environment, isn't inherited by children, and isn't captured by crash reporters or monitoring tools.

## Implementation

### Step 1: Write token file and properties file in `with-prod.ts`

**File:** `src/commands/with-prod.ts`

After creating the temp gcloud config directory (line 96-97) and before spawning the child (line 125), add:

1. Write the raw access token to `${gcloudConfigDir}/access_token` with mode `0o600`
2. Write a gcloud `properties` file at `${gcloudConfigDir}/properties` with:
   ```ini
   [auth]
   access_token_file = <absolute path to access_token file>
   ```
   Also with mode `0o600`

Both files live inside the already-0700 temp directory. Cleanup is already handled by the existing `rmSync(gcloudConfigDir, { recursive: true, force: true })`.

Add `writeFileSync` to the existing `node:fs` import.

### Step 2: Update tests in `with-prod.test.ts`

**File:** `src/__tests__/commands/with-prod.test.ts`

Add tests that verify:

1. Token file exists during child execution at `${CLOUDSDK_CONFIG}/access_token` with mode 0600
2. Token file contains the expected token value (`"prod-token-abc"`)
3. Properties file exists at `${CLOUDSDK_CONFIG}/properties` with mode 0600
4. Properties file contains `[auth]` section with `access_token_file` pointing to the token file
5. Both files are cleaned up after child exits (already covered by existing cleanup test that checks `existsSync(capturedConfigDir) === false`)

Add `readFileSync` to the existing `node:fs` import in the test file.

### Step 3: Update CHANGELOG.md

**File:** `CHANGELOG.md`

Add under `[Unreleased] > Fixed`:

- `with-prod`: write access token to a file and configure `auth/access_token_file` in gcloud config so commands that don't use the metadata server still authenticate correctly

## Files to modify

1. **`src/commands/with-prod.ts`** — add token file + properties file writes (~10 lines)
2. **`src/__tests__/commands/with-prod.test.ts`** — add 2-3 test cases
3. **`CHANGELOG.md`** — add entry

## Verification

1. `bun run typecheck` — no type errors
2. `bun test` — all tests pass (existing + new)
3. `bun run lint` — no lint warnings
4. `bun run format` — formatting clean
5. Manual: `gcp-authcalator with-prod -- gcloud auth list` should show the elevated account (requires running gcp-gate)
