# Plan: automatic `GOOGLE_CLOUD_QUOTA_PROJECT` for `with-prod`

## Goal

Let `with-prod` set `GOOGLE_CLOUD_QUOTA_PROJECT` on the wrapped command's
environment so end-user-credential (prod) API calls have a quota/billing
project, eliminating the `"authenticated using end user credentials..."`
warnings and quota errors that hit user-credential callers.

## Why this is scoped to `with-prod` only

- **Prod tokens** are the engineer's own ADC (user credentials) — Google APIs
  frequently require a quota project for these. This is where the value is.
- **Dev tokens** are impersonated service-account tokens — quota attaches to the
  SA's project automatically, so a quota project is irrelevant.
- The gate / metadata-proxy serve tokens to whatever lives in the container but
  do **not** control that environment. `with-prod` is the only place authcalator
  builds the child process env, so it's the only place we can inject this var.

## Behavior (default: follow the selected project)

Two config fields (per the decision in "Open questions" below): a **string-only**
`quota_project` for a static override, and a separate boolean `no_quota_project`
that takes precedence to turn the behavior off.

| State                                    | Effect                                                           |
| ---------------------------------------- | ---------------------------------------------------------------- |
| both unset (default)                     | set `GOOGLE_CLOUD_QUOTA_PROJECT` = resolved `effectiveProjectId` |
| `quota_project = "some-billing-project"` | set `GOOGLE_CLOUD_QUOTA_PROJECT` = that static id                |
| `no_quota_project = true`                | do **not** touch it — leave the user's env exactly as-is         |

`no_quota_project` wins over `quota_project` if both are set. The resolved
project is the same `effectiveProjectId` already used for `CLOUDSDK_CORE_PROJECT`
/ `GOOGLE_CLOUD_PROJECT`, so the quota project tracks `--project` /
nested-session inheritance for free.

**Precedence (highest first):** explicit `[env] GOOGLE_CLOUD_QUOTA_PROJECT`
(escape hatch) > `no_quota_project` > `quota_project` > follow-selected. Document
this order; in particular an explicit `[env]` value wins even over
`no_quota_project`, because `applyExtraEnvVars` applies `config.env` last.

**Caveat to document:** following the selected project requires the active
credential to hold `serviceusage.services.use` on that project. `no_quota_project`
exists for environments where that permission isn't granted.

### Opt-out leaves the user's environment untouched (decision)

`stripCredentialEnvVars` does **not** strip `GOOGLE_CLOUD_QUOTA_PROJECT` (correct
— it isn't a credential), so a parent value is already present in the base env.
`no_quota_project` affects **only authcalator's own behavior**: we don't set,
override, or delete the var. If the user already has `GOOGLE_CLOUD_QUOTA_PROJECT`
set, it passes through unchanged; if they don't, it stays unset. We only ever
_set_ the var when opted in (default or static). This is the deliberate choice
over forcibly deleting an inherited value.

## Schema / flag encoding (revised per decision)

- **`quota_project`:** `z.string().min(1).optional()` — static override only, no
  union, no preprocess. Env-settable (`GCP_AUTHCALATOR_QUOTA_PROJECT`, a string).
- **`no_quota_project`:** strict boolean that is also env-settable, with
  **predictable** coercion — accept only the literal strings `"true"`/`"false"`
  (and native booleans from TOML/CLI); reject anything else loudly:

  ```ts
  no_quota_project: z.preprocess(
    (v) => (v === "true" ? true : v === "false" ? false : v),
    z.boolean(),
  ).optional();
  ```

  Plain `z.coerce.boolean()` is wrong here (any non-empty string → `true`, so
  `"false"` would enable opt-out). The preprocess maps the two valid strings and
  lets `z.boolean()` reject any other string (e.g. `yes`, `1`) with a clear error.
  Add `"no_quota_project"` to `configKeys` so `GCP_AUTHCALATOR_NO_QUOTA_PROJECT`
  works.

- **CLI:** `--quota-project <id>` → `quota_project`; `--no-quota-project`
  (boolean) → `no_quota_project`. Both flow through normal
  `mapCliArgs`/`cliToConfigKey` — **no with-prod-only special-casing needed.**
  Unlike `--project` (a non-config per-invocation concept that must not leak into
  `project_id`), these are genuine optional config fields that gate/metadata-proxy
  simply ignore, so the merge is harmless.

## Changes

### 1. `src/config.ts`

- Add to `ConfigSchema` (after `env`, ~line 124):
  `quota_project: z.string().min(1).optional()` and
  `no_quota_project: z.boolean().optional()`.
- Add `"quota-project": "quota_project"` and
  `"no-quota-project": "no_quota_project"` to `cliToConfigKey` (~line 211).
- Add **both** `"quota_project"` and `"no_quota_project"` to the `configKeys`
  env-var list (~line 261) so `GCP_AUTHCALATOR_QUOTA_PROJECT` and
  `GCP_AUTHCALATOR_NO_QUOTA_PROJECT` work. The `no_quota_project` preprocess (see
  "Schema / flag encoding") makes the string→bool coercion predictable.

### 2. `src/cli.ts`

- Add `"quota-project": { type: "string" }` and
  `"no-quota-project": { type: "boolean" }` to the `parseArgs` options
  (~line 122, near `scopes`).
- No special-casing needed: both map through `mapCliArgs`/`cliToConfigKey` like
  any other field. (`parseArgs` yields a real boolean for `--no-quota-project`;
  `mapCliArgs` passes it through since `value !== undefined`.)
- Update the `USAGE` string with both flags.

### 3. `src/commands/with-prod.ts`

Add a helper resolving the two fields against the selected project:

```ts
// Returns the quota project to set, or undefined to leave the env untouched (opt-out).
function resolveQuotaProject(
  projectId: string,
  quotaProject: string | undefined,
  noQuotaProject: boolean | undefined,
): string | undefined {
  if (noQuotaProject) return undefined; // opt out: don't touch the env
  return quotaProject ?? projectId; // static id, else follow selected
}
```

Apply it in **both** env-building sites. When it returns a string, set
`env.GOOGLE_CLOUD_QUOTA_PROJECT`; when it returns `undefined`, **do nothing** —
never delete, so any inherited value passes through unchanged (opt-out affects
only authcalator's behavior):

- **Nested-session reuse path** (~lines 175–194): base project is
  `nestedSession.projectId`; read `config.quota_project` /
  `config.no_quota_project` (parse hasn't run yet here, but `config` is already
  validated by `loadConfig`).
- **Main flow** (~lines 364–387): base project is `effectiveProjectId`; read off
  the parsed `wpConfig`.

Set the key on the base env object _before_ the `applyExtraEnvVars(...,
config.env)` call so an explicit `[env]` value still wins.

Note: do **not** add `GOOGLE_CLOUD_QUOTA_PROJECT` to `stripCredentialEnvVars` —
it isn't a credential, and opt-out intentionally preserves a user-set value.

## Tests (`src/commands/with-prod.test.ts` or equivalent)

Drive `runWithProd` with a fake `spawnFn` and assert on the child `env`:

1. Default (both unset) → `GOOGLE_CLOUD_QUOTA_PROJECT === effectiveProjectId`.
2. `--project alt` (and/or config `project_id`) → quota project follows the
   resolved project, not a leaked parent value.
3. Static `quota_project = "billing-proj"` → that exact value, regardless of
   selected project.
4. `no_quota_project = true` (TOML) and `--no-quota-project` (CLI), with **no**
   inherited value → key absent from child env.
5. **Opt-out leaves env untouched:** parent env has
   `GOOGLE_CLOUD_QUOTA_PROJECT=inherited` + `no_quota_project = true` → child env
   still has `=inherited` (we don't set, override, or delete it).
6. **Precedence:** `quota_project="p"` + `no_quota_project=true` → opt-out wins
   (we don't set; if a parent value exists it passes through). Explicit
   `[env] GOOGLE_CLOUD_QUOTA_PROJECT=x` → `x` wins over the auto value.
7. Nested-session reuse path sets the quota project from the session's project.

Also `config.ts` unit tests for `no_quota_project` env coercion:
`GCP_AUTHCALATOR_NO_QUOTA_PROJECT="true"` → `true`, `"false"` → `false`, and an
invalid value (e.g. `"yes"`) → schema parse error. Plus `quota_project` rejects
empty string via `min(1)`.

## Docs (keep in sync — required by AGENTS.md)

- `CHANGELOG.md` — `[Unreleased] > Added`: auto `GOOGLE_CLOUD_QUOTA_PROJECT`.
- `README.md` — config table + with-prod section; document default-follows-
  selected-project, static override, opt-out, and the
  `serviceusage.services.use` caveat.
- `SPEC.md` — env-var table for the with-prod child environment.
- `config.example.toml` — `quota_project` + `no_quota_project` entries with
  commented examples of all three states.
- `src/cli.ts` `--help` / `USAGE` — covered in change #2.

## Verification

`bun run format && bun run lint && bun run typecheck && bun test`

## Decisions (resolved)

- Opt-out spelling: **`--no-quota-project` + TOML `no_quota_project = true`.**
- `quota_project` is **string-only** (static override); a separate optional
  boolean `no_quota_project` (maps to `--no-quota-project`) takes precedence to
  turn the behavior off.

## Resolved red-team decisions (folded into design above)

- **Opt-out leaves the user's env untouched** — authcalator never deletes or
  overrides an existing `GOOGLE_CLOUD_QUOTA_PROJECT`; it only _sets_ the var when
  opted in (default/static).
- **`no_quota_project` is env-settable** via `GCP_AUTHCALATOR_NO_QUOTA_PROJECT`,
  accepting only `"true"`/`"false"` (predictable strict coercion; other values
  error).
- **Both-set combo is allowed**, resolved by precedence (opt-out wins). No
  validation refine added — say if you'd prefer it to error instead.
