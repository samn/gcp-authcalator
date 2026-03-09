# Plan: Fetch latest GitHub release instead of hardcoding version

## Problem

The devcontainer setup skill (`.claude/commands/devcontainer-setup.md`) hardcodes
version `0.1.5`. Every time we cut a release, someone must remember to update
this file. This is fragile and has already drifted.

## Solution

Modify the shell scripts in the skill to automatically fetch the latest release
tag from the GitHub API at runtime, eliminating the need to hardcode a version.

### Changes

1. **Initialize script** (`gcp-authcalator-initialize.sh`):
   - Add a `fetch_latest_version()` function that queries
     `https://api.github.com/repos/samn/gcp-authcalator/releases/latest`
   - Extract the tag name, strip the `v` prefix
   - Fall back to an explicit `--version` argument if the API call fails (offline)
   - Remove the hardcoded `AUTHCALATOR_VERSION` variable

2. **Post-start script** (`gcp-authcalator-post-start.sh`):
   - Remove the hardcoded `AUTHCALATOR_VERSION` variable
   - Remove the strict version check in `verify_binary()` — just verify the
     binary exists and is executable, log whatever version it reports
   - The initialize script already ensures the correct binary is present

3. **Skill markdown**:
   - Remove `**Current version: 0.1.5**` from the header
   - Replace "Step 4: Version selection" with description of automatic latest
     version detection, with an override option
   - Remove `<VERSION>` replacement instructions from Steps 5 and 6

4. **Releasing docs**: Remove any mention of updating the skill version

5. **CHANGELOG.md**: Add entry under [Unreleased]
