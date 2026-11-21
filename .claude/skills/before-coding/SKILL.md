---
name: before-coding
description: >
  Pre-task discipline checkpoint for Qattice development. Load this skill BEFORE writing any code,
  making any file edits, or starting any implementation work. Triggers on: "implement X", "add X",
  "fix X", "write X", "build X", "create X", or any request that will result in code being written.
  Also triggers when an agent is about to start a new task without first confirming scope. Use this
  even if the task seems simple — skipping it is how agents end up writing the wrong thing.
---

# Before Coding

You are about to write code. Stop. Work through this checklist first — the goal is to make sure
you understand exactly what you're building before you build it.

## Step 1: Read the locked decisions

Read `CLAUDE.md` in the repo root right now. Note:
- Which cryptographic primitives are locked (ML-DSA-65, no Ed25519 on devnet)
- Which consensus engine is active (Tendermint on devnet, PQ-HotStuff is target — not yet)
- The test validation policy (never mark ✅ from sandbox alone — developer must confirm locally)
- The active dev branch (`claude/fervent-davinci-trcjdd`)

If your task touches anything in those locked decisions, stop and flag it to the user before proceeding.

## Step 2: Check ROADMAP.md

Read `ROADMAP.md`. Identify:
- Which phase is currently active
- Whether the task you're about to do is in scope for the current phase
- Whether it's blocked by an earlier gate that hasn't passed

If the task is out of scope for the current phase, say so clearly rather than just doing it.

## Step 3: Find existing code first

Before writing anything new, search for:
- Existing types, traits, or functions that already do what you need
- The crate that owns the domain you're touching (e.g., `chain-forge-crypto` for crypto, `chain-forge-consensus` for consensus)
- Any tests that already cover the area

Use `grep` or `Glob` to find relevant code. Never duplicate something that already exists.

## Step 4: State your plan

Write out in plain language:
- What files you will touch
- What you will add or change (not how — just what)
- What you will NOT do (explicitly name things that are out of scope)
- Any locked decisions this touches and why your approach respects them

Share this with the user and get confirmation before writing a single line of code.

## Step 5: Then code

Only after the user confirms the plan, begin implementation. If anything unexpected comes up
during implementation that changes the plan, stop and re-confirm rather than silently expanding scope.
