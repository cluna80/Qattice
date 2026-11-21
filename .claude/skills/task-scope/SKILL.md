---
name: task-scope
description: >
  Break down a vague or large task into a concrete scoped plan before any work begins.
  Use this skill whenever a task is ambiguous, spans multiple crates, or the user has given
  a high-level goal without specifying implementation details. Triggers on: "figure out how to",
  "we need to", "can you handle", "take care of", "do X for the whole project", or any task
  that isn't a single clearly-defined change. Also use it when you're unsure where to start.
  A written plan the user approves is always faster than rewriting wrong code.
---

# Task Scoping

Before doing any work on a large or ambiguous task, produce a written scope document and get
the user's sign-off. This takes 2 minutes and saves hours of rework.

## Produce a scope document

Write a short document with these sections:

### Goal
One sentence: what does success look like? What is the user actually trying to achieve?

### In scope
Bullet list of specific things you will do. Be concrete — name files, crates, types, functions.

### Out of scope
Bullet list of related things you will NOT do in this task. This is as important as "in scope"
because it prevents silent scope creep. If something feels tempting to fix along the way, put it here.

### Approach
2-4 sentences on how you'll do it. Not a full design doc — just enough for the user to spot if
you're headed in the wrong direction.

### Crates / files touched
List every file or crate you expect to modify. If you later find you need to touch something
not on this list, stop and flag it.

### Risks / locked decisions
Does this touch anything locked in CLAUDE.md? Any areas where you're uncertain?
Name them upfront rather than discovering them mid-implementation.

### Not doing yet
Things you noticed along the way that should probably be done eventually, but are out of scope
for this task. Capture them here so they don't get lost and don't distract you.

## Get approval

Share the scope document with the user. Wait for explicit confirmation ("looks good", "yes", "go ahead")
before starting. If the user changes something, update the doc and confirm again.

## During implementation

- If you need to touch a file not on the list, stop and ask
- If you discover the approach needs to change significantly, stop and re-scope
- Do not add "while I'm here" improvements — put them in "Not doing yet" and move on
