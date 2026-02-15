# Releasing

## Prerequisites

- You must be on the `main` branch with a clean working tree
- All changes for the release must already be merged

## Steps

1. **Update the version** in `package.json`:

   ```json
   "version": "0.2.0"
   ```

2. **Update `CHANGELOG.md`** — move entries from `[Unreleased]` to a new version section:

   ```markdown
   ## [Unreleased]

   ## [0.2.0] - 2026-03-01

   ### Added

   - New feature X

   ### Fixed

   - Bug Y
   ```

3. **Commit** the version bump and changelog:

   ```sh
   git add package.json CHANGELOG.md
   git commit -m "release: v0.2.0"
   ```

4. **Run the release script**:

   ```sh
   bun run release
   ```

   The script will:
   - Validate you're on `main` with a clean working tree
   - Verify the changelog has an entry for the version
   - Create a `v0.2.0` git tag
   - Push the commit and tag to the remote

5. **GitHub Actions takes over** — the `release.yml` workflow will:
   - Build binaries for Linux amd64 and macOS arm64
   - Generate SHA256 checksums
   - Create a GitHub Release with the changelog entry as the body
   - Attach the binaries and checksums as release assets

## Version format

We use [Semantic Versioning](https://semver.org/) with a `v` prefix for git tags (e.g., `v0.1.0`).

## Binary targets

| Platform     | Binary name                    |
| ------------ | ------------------------------ |
| Linux x86_64 | `gcp-authcalator-linux-amd64`  |
| macOS ARM64  | `gcp-authcalator-darwin-arm64` |
