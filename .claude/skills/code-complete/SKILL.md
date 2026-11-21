---
name: code-complete
description: >
  Pre-push completion checklist for Qattice. Run this skill before every commit or push to make
  sure the work is actually done and clean. Triggers on: "ready to commit", "ready to push",
  "commit this", "push this", "I think it's done", "mark as complete", or any signal that a
  task is finishing. Also run it proactively at the end of any coding session before stopping work.
  Never mark a milestone complete without passing this checklist.
---

# Code Complete Checklist

Work through every item before committing. This is the last gate before the code leaves your machine.

## 1. Compile check

```bash
cargo test --no-run -p <crate-name>
```

Must compile with zero errors. Warnings are acceptable but note any new ones — don't introduce
warnings silently. If it doesn't compile, it's not done.

## 2. Test coverage

- Did you write tests for the new behaviour?
- Are existing tests still passing (`cargo test -p <crate-name>`)?
- If this is a live integration test, have you noted that the developer must confirm it passes
  locally on Windows (MINGW64) per CLAUDE.md policy?

Do NOT mark a milestone ✅ based on sandbox compile/run alone. The CLAUDE.md test policy requires
local developer confirmation.

## 3. Architecture alignment

- Does this change touch anything locked in CLAUDE.md? If yes, was it explicitly approved?
- Are you on the correct branch (`claude/fervent-davinci-trcjdd`)?
- Did you accidentally modify any Ed25519 genesis files or re-enable retired paths?

## 4. Staged file review

```bash
git status
git diff --staged
```

Check for:
- No `.env` files, secrets, or API keys
- No unrelated files dragged in
- No large binary files committed accidentally
- No debug prints left in (`println!`, `dbg!`, `eprintln!` that aren't intentional)

## 5. Commit message

Format:
```
<type>(<scope>): <short description>

<optional body explaining why, not what>

Co-Authored-By: Claude Sonnet 4.6 <noreply@anthropic.com>
Claude-Session: https://claude.ai/code/session_01KfcXvaByGMhRSqjuRXHiVN
```

Types: `feat`, `fix`, `refactor`, `test`, `chore`, `docs`
Scope: the crate or subsystem (e.g., `chain-forge-crypto`, `devnet`, `consensus`)

Do not put the model identifier in the subject line or body — attribution goes in the trailer only.

## 6. ROADMAP update

If this work closes a milestone:
- Update `ROADMAP.md` to reflect current state
- Do NOT add ✅ until the developer confirms it passes locally on their machine
- Add a note like "sandbox passes, awaiting local confirmation" if needed
