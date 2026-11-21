---
name: issue-to-task
description: >
  Convert a GitHub issue into a concrete, scoped implementation plan before any code is written.
  Use this skill whenever starting work from a GitHub issue, bug report, or feature request.
  Triggers on: "work on issue #X", "fix issue #X", "implement the issue", "pick up this ticket",
  "start on this GitHub issue", or any task that originates from a GitHub issue or ticket.
  Never start coding from an issue without first running this skill — issues are requirements,
  not implementation plans.
---

# Issue to Task

A GitHub issue describes a problem or desired outcome — it is not an implementation plan.
This skill turns one into the other.

## Step 1: Read the issue

Use `issue_read` from the GitHub MCP tools to fetch the full issue including:
- Description and body
- Comments (often contain important clarifications)
- Labels (priority, component, type)
- Any linked PRs or issues

Read all of it before proceeding.

## Step 2: Identify what's actually being asked

Issues are often written from the user's perspective, not the implementer's. Extract:

- **The actual problem** (not the proposed solution, which may be wrong)
- **Acceptance criteria** — what does "done" look like? If the issue doesn't state this, write your best interpretation and confirm with the user
- **Scope boundaries** — what is explicitly out of scope, or would be a separate issue?

## Step 3: Map to ROADMAP phase

Read `ROADMAP.md`. Is this issue:
- In scope for the current phase? → proceed
- In scope for a future phase? → flag this to the user before starting
- Not on the roadmap at all? → flag this — it may be unplanned work

## Step 4: Locate the relevant code

Search the codebase for the area the issue touches. Identify:
- Which crate(s) own the affected behaviour
- Existing types/traits/functions that are relevant
- Any existing tests for this area

## Step 5: Produce the task plan

Write a task plan with these sections:

**Issue summary:** One sentence restating the problem in implementation terms.

**Acceptance criteria:** Bullet list — what must be true for this issue to be closed.

**Approach:** How you'll implement it (2-4 sentences, not a full design).

**Files / crates to touch:** Explicit list.

**Out of scope:** Things you will not do in this task.

**Arch-guard check:** Does this touch anything locked in CLAUDE.md? State explicitly yes or no,
and if yes, what the conflict or alignment is.

**Test plan:** What tests will you write or modify to verify the fix?

## Step 6: Confirm before coding

Share the task plan with the user. Wait for confirmation.
Only after approval, begin implementation using the `before-coding` skill as your next step.
