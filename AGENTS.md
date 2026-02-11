- Use `mise` to manage the toolchain for this project to ensure a consistent development environment. Pin versions.
- Use `bun` to test and run this project
- Make sure that all types compile without warnings.
- Write tests for all functionality that you create. The tests should be robust and reliable.
- Minimize complexity wherever possible, simplicity is what makes this secure.
- Use the latest versions of all dependencies and tools, this should be a modern project with no baggage.
- Fix all warnings when you see them
- Ask the user for clarifications if anything is unclear. DO NOT MAKE ASSUMPTIONS!
- Save the plan you're working on as markdown in plans/

## Pre-commit checks

Before committing code, always run the full verification suite:

1. `bun run format` — auto-fix formatting with Prettier
2. `bun run lint` — run ESLint (also auto-fixes via prek)
3. `bunx tsc --noEmit` — ensure no type errors
4. `bun test` — ensure all tests pass

These checks mirror what CI runs (`prek run --all-files` in CI triggers ESLint and Prettier, plus there are separate CI jobs for typecheck and test). The pre-commit hooks are managed by `prek` (configured in `prek.toml`), which runs ESLint with `--fix` and Prettier with `--write` on staged files. If `prek` is available locally, you can run `prek run --all-files` to execute all hooks.
