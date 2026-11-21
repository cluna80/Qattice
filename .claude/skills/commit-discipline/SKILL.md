---
name: commit-discipline
description: >
  Clean commit hygiene for Qattice. Use this skill before every git commit to ensure the commit
  is well-formed, on the right branch, free of secrets, and correctly attributed. Triggers on:
  "commit", "git commit", "stage and commit", "save my work", "checkpoint this", or any action
  that results in a git commit being created. Also triggers if you notice the working tree has
  uncommitted changes at the start of a new task.
---

# Commit Discipline

A good commit is atomic, clean, and correctly attributed. Work through this before every commit.

## 1. Verify the branch

```bash
git branch --show-current
```

Must be `claude/fervent-davinci-trcjdd`. If not, stop — do not commit to main or any other branch
without explicit instruction from the user.

## 2. Review what's staged

```bash
git status
git diff --staged
```

Before staging anything broad (`git add .` or `git add -A`), review the full diff.

Look for and DO NOT commit:
- `.env` files or any file containing API keys, tokens, passwords
- Private keys or seed phrases (even test ones if they look real)
- Large binary files that don't belong in git
- Build artifacts (`target/`, `*.rlib`, `*.d`)
- Editor temp files (`.DS_Store`, `*.swp`, `Thumbs.db`)
- Debug output or log files

If you see anything suspicious, check the file contents before proceeding.

## 3. Keep commits atomic

One commit = one logical change. Do not bundle unrelated fixes together.
If you've made changes to multiple unrelated things, stage them separately and make separate commits.

## 4. Write the commit message

```
<type>(<scope>): <short imperative description, ≤72 chars>

<optional body: explain WHY this change was needed, not WHAT it does>

Co-Authored-By: Claude Sonnet 4.6 <noreply@anthropic.com>
Claude-Session: https://claude.ai/code/session_01KfcXvaByGMhRSqjuRXHiVN
```

**Types:** `feat` · `fix` · `refactor` · `test` · `chore` · `docs` · `perf`

**Scope:** the crate or subsystem changed — e.g., `chain-forge-crypto`, `devnet`, `p2p`, `consensus`

**Rules:**
- Subject line is imperative ("add", "fix", "remove" — not "added", "fixing")
- No period at end of subject line
- Do not mention the model in the subject or body — attribution goes in the trailers only
- Body explains the motivation, not a restatement of the diff

**Example:**
```
feat(chain-forge-crypto): add ML-DSA-65 batch verification

Batch verification reduces consensus overhead by ~40% when validating
validator sets during block finalization.

Co-Authored-By: Claude Sonnet 4.6 <noreply@anthropic.com>
Claude-Session: https://claude.ai/code/session_01KfcXvaByGMhRSqjuRXHiVN
```

## 5. Push

```bash
git push -u origin claude/fervent-davinci-trcjdd
```

Retry on network errors (up to 4 times with backoff). If the push is rejected because the remote
has commits you don't have, fetch and merge — do not force push.
