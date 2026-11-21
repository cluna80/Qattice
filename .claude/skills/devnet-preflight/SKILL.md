---
name: devnet-preflight
description: >
  Pre-flight checklist for running Qattice devnet integration tests locally on
  BossKing (Windows / MINGW64). Load this skill before running any *_live test,
  or when a test fails immediately with "did not come up", genesis hash mismatch,
  "corrupt or incomplete snapshot", or port-already-in-use. Triggers on:
  "run the jail test", "run devnet", "cargo test validator_jail_live",
  "genesis_hash mismatch", "stale data", "node did not come up".
---

# Devnet Pre-flight Checklist

Run these checks **before** `cargo test … --nocapture` on BossKing.

## 1 — Clear stale chain data

The test derives its temp directory from the base API port (e.g.
`%TEMP%\qcb-val-jail-23828`). If a previous run used the same port, leftover
`data-{name}` directories inside it will cause an instant genesis-hash mismatch
and the test will panic before height 1.

The test harness now auto-wipes these at startup (fix landed in
`validator_jail_live.rs`), but if you see a genesis-hash error it means the
binary is stale — recompile first, or clean manually:

```bat
for /d %d in ("%TEMP%\qcb-val-jail-*") do rmdir /s /q "%d"
```

```bash
# MINGW64 equivalent
rm -rf "$TEMP"/qcb-val-jail-*
```

## 2 — Confirm binary is fresh

A `Finished … in <2s` with no "Compiling …" lines means the cached binary was
used. Check the last fix commit is present on the branch:

```bash
git log --oneline -5
```

If the memory-fix commits (`880f2b7`, `60c8f98`) are missing, merge the branch:

```bash
git fetch origin claude/blissful-ptolemy-9x2as9
git merge origin/claude/blissful-ptolemy-9x2as9
```

Then force a recompile by touching node.rs or doing a `cargo clean -p chain-forge-node`.

## 3 — Check Avast exclusion

Avast flags the compiled test binary as a threat and silently kills child
processes, preventing the devnet from ever reaching height 3. Confirm that
`C:\Dev\chain-forge-engine\target` is in the Avast exclusion list.

Symptom: test panics at "devnet did not reach height 3" with node logs showing
no blocks committed.

## 4 — Run the test

```bash
cargo test -p chain-forge-node --test validator_jail_live --features pq-hotstuff -- --nocapture
```

Expected runtime: 20–25 minutes. Do not cancel unless you see an OOM kill or
the test has been stuck for > 5 minutes without a height advance.

## 5 — Collect results

Paste the **full** terminal output when it finishes. Per CLAUDE.md policy, the
milestone is only ✅ after BossKing confirms passing — a sandbox compile is not
sufficient.
