# Plan: Stub CLI Commands and Config System

## Context

gcp-authcalator is an early-stage TypeScript/Bun project with only a placeholder `index.ts`. SPEC.md defines three subcommands (`gate`, `metadata-proxy`, `with-prod`) that should be part of a single CLI tool. This plan stubs out the CLI structure, subcommand routing, and configuration system (TOML file + CLI args, validated with zod).

## Dependencies to Add

- `zod` (runtime) — config schema validation
- `smol-toml` (runtime) — TOML config file parsing (small, modern, zero-dep)

```sh
bun add zod smol-toml
```

## File Structure

```
index.ts                          # Update: thin entry → import & call src/cli.ts main()
src/
  cli.ts                          # CLI entry: parseArgs, subcommand routing, help text
  config.ts                       # Zod schemas, TOML loading, CLI-arg merging
  commands/
    gate.ts                       # gate subcommand stub
    metadata-proxy.ts             # metadata-proxy subcommand stub
    with-prod.ts                  # with-prod subcommand stub
src/__tests__/
  config.test.ts                  # Config schema & loading tests
  cli.test.ts                     # CLI parsing & routing tests
  commands/
    gate.test.ts                  # gate stub tests
    metadata-proxy.test.ts        # metadata-proxy stub tests
    with-prod.test.ts             # with-prod stub tests
```

## 1. `src/config.ts` — Configuration

### Zod Schema

```typescript
import { z } from "zod";

export const ConfigSchema = z.object({
  project_id: z.string().min(1).optional(),
  service_account: z.string().email().optional(),
  socket_path: z.string().min(1).default("/run/gcp-gate.sock"),
  port: z.coerce.number().int().min(1).max(65535).default(8173),
});

export type Config = z.infer<typeof ConfigSchema>;
```

Per-command schemas that require specific fields:

- `GateConfigSchema` — requires `project_id`, `service_account`
- `MetadataProxyConfigSchema` — requires `project_id`
- `WithProdConfigSchema` — requires `project_id`

### TOML Config Format

```toml
project_id = "my-gcp-project"
service_account = "dev-runner@my-gcp-project.iam.gserviceaccount.com"
socket_path = "/run/gcp-gate.sock"
port = 8173
```

### Config Loading

`loadConfig(cliValues, configPath?)`:

1. If `configPath` provided, read and parse TOML file via `smol-toml`
2. Merge: TOML values as base, CLI args override (skip `undefined` CLI values)
3. Validate merged object through `ConfigSchema.parse()` (applies defaults)

### CLI-to-Config Mapping

CLI uses kebab-case (`--project-id`), config uses snake_case (`project_id`). A mapping function converts between them.

## 2. `src/cli.ts` — CLI Entry Point

Uses `util.parseArgs` (Node built-in, works in Bun) with `strict: true` and `allowPositionals: true`. Strict mode ensures typos in flag names produce immediate errors rather than being silently ignored.

### Global Options

| Flag                | Short | Type    | Description              |
| ------------------- | ----- | ------- | ------------------------ |
| `--project-id`      |       | string  | GCP project ID           |
| `--service-account` |       | string  | SA email to impersonate  |
| `--socket-path`     |       | string  | Unix socket path         |
| `--port`            | `-p`  | string  | Metadata proxy port      |
| `--config`          | `-c`  | string  | Path to TOML config file |
| `--help`            | `-h`  | boolean | Show help                |
| `--version`         | `-v`  | boolean | Show version             |

### Subcommand Routing

1. Parse args (single pass, `strict: true`)
2. First positional = subcommand name (`gate` | `metadata-proxy` | `with-prod`)
3. No subcommand → print usage, exit 1
4. Unknown subcommand → error, exit 1
5. Load config (merge TOML + CLI args)
6. Dispatch to command handler
7. Catch `ZodError` → format field-level error messages, exit 1

For `with-prod`, remaining positionals after the subcommand (everything after `--`) become the wrapped command + args.

## 3. Command Stubs

Each command file exports an async `run*` function that:

1. Validates config against its command-specific schema (throws ZodError if missing required fields)
2. Logs what it would do (config values, planned endpoints/steps)
3. Prints `[STUB] Not yet implemented.`

### `gate.ts` — `runGate(config)`

Logs: project, service account, socket path, endpoint list.

### `metadata-proxy.ts` — `runMetadataProxy(config)`

Logs: project, port, socket path, endpoint list.

### `with-prod.ts` — `runWithProd(config, wrappedCommand)`

Validates `wrappedCommand` is non-empty (error + exit 1 if empty). Logs: project, socket path, command to wrap, planned execution steps.

## 4. Update `index.ts`

Replace `console.log("Hello via Bun!")` with:

```typescript
import { main } from "./src/cli.ts";
await main();
```

## 5. Update `package.json`

- Add `dependencies`: `zod`, `smol-toml`
- Add scripts: `"test": "bun test"`, `"start": "bun run index.ts"`

## 6. Tests

Use `bun:test`. Two approaches:

- **Unit tests**: Import functions directly, test parsing/validation/routing logic
- **Integration tests**: Use `Bun.spawn` to run the CLI as a subprocess, assert on exit codes and stdout/stderr

### config.test.ts

- Valid config parses correctly, defaults applied
- Invalid values rejected (bad port, empty project_id)
- TOML file loading works
- CLI args override TOML values
- Command-specific schemas reject missing required fields

### cli.test.ts

- No subcommand → exit 1, usage printed to stderr
- Unknown subcommand → exit 1, error message
- `--help` → exit 0, usage printed
- `--version` → exit 0, version printed
- Each subcommand routes correctly with valid config

### commands/\*.test.ts

- Each stub logs expected output with valid config
- Each stub throws ZodError when required fields missing
- `with-prod` errors on empty wrapped command

## 7. CI Update

Add test job to `.github/workflows/ci.yml`:

```yaml
test:
  name: Test
  runs-on: ubuntu-latest
  steps:
    - uses: actions/checkout@v4
    - uses: jdx/mise-action@v2
    - run: bun install --frozen-lockfile
    - run: bun test
```

## Implementation Order

1. `bun add zod smol-toml`
2. Create `src/config.ts`
3. Create `src/commands/gate.ts`, `metadata-proxy.ts`, `with-prod.ts`
4. Create `src/cli.ts`
5. Update `index.ts`
6. Update `package.json` scripts
7. Write tests
8. Update CI workflow
9. Verify: `bun test`, `bun run lint`, `bunx tsc --noEmit`

## Notes

- `verbatimModuleSyntax: true` in tsconfig — must use `import type` for type-only imports
- `strict: true` in parseArgs ensures typos in flag names produce immediate errors
- `process.exit()` calls in CLI code — integration tests use `Bun.spawn` to test exit codes without affecting the test process
