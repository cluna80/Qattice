---
name: ci-triage
description: >
  Diagnose and fix CI failures for Qattice. Use this skill when a CI run has failed, when a
  PR shows red checks, or when asked to investigate why tests are failing in CI. Triggers on:
  "CI is failing", "tests are red", "the checks failed", "why is CI broken", "fix the CI",
  "PR is failing", or any situation where GitHub Actions or test runs are not passing.
  Read the actual logs before guessing — never blindly retry or comment out failing tests.
---

# CI Triage

CI failures have a root cause. Find it before fixing anything.

## Step 1: Get the failure details

Use GitHub MCP tools:
- `actions_list` to find the most recent failed run
- `get_job_logs` to fetch the actual log output for the failed job

Read the full log. Don't skim — the actual error is often buried below a wall of output.

## Step 2: Classify the failure

Identify which category the failure falls into:

**Compile error** — the code doesn't build
- Find the exact error message and file/line
- Check if it's in your changes or a pre-existing issue in the branch

**Test failure** — code builds but a test panics or returns wrong result
- Get the exact test name and failure message
- Distinguish: is this a logic bug, a missing fixture, or a flaky test?

**Environment issue** — the CI environment itself is the problem
- Missing dependency, wrong toolchain version, network timeout
- These usually look like "command not found", "failed to download", or timeout errors

**Linter / fmt** — `cargo fmt` or `cargo clippy` failures
- These are always fixable — run them locally and push the fix

## Step 3: Reproduce locally (if possible)

For compile errors and test failures, reproduce with:
```bash
cargo test --no-run -p <crate>          # compile check
cargo test -p <crate> -- --nocapture    # run tests with output
```

Per CLAUDE.md policy, the developer must confirm live integration tests pass on Windows (MINGW64).
For sandbox-reproducible failures, fix and verify here first.

## Step 4: Fix the root cause

Fix only the root cause. Do not:
- Comment out or `#[ignore]` a failing test to get green (this is explicitly prohibited)
- Add `--no-verify` to skip hooks
- Push an empty commit to kick CI
- Blindly change unrelated code hoping it helps

If the failure is in a locked area (crypto, consensus engine), apply the `arch-guard` skill
before making any fix.

## Step 5: Verify and push

After fixing:
1. Run `code-complete` checklist
2. Commit the fix with a clear message: `fix(<scope>): resolve CI failure — <brief cause>`
3. Push and confirm CI goes green

## Step 6: Report

Tell the user:
- What the root cause was (one sentence)
- What you changed to fix it
- Whether any follow-up is needed (e.g., a flaky test that needs a proper fix later)
