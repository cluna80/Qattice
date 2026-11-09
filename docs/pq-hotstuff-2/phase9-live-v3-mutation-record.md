# PQ-HotStuff-2 live profile-v3 recovery — process-level mutation record (exact)

Code under test: `00e17a958af5c7a9013dad65c4384058a9b1083f` (`feat/pq-hotstuff-2-live-v3-recovery`), one mutant at a time in a disposable git worktree with its own target directory; the committed tree was not modified. Each mutant ran the live test named in the table (real OS processes, real ML-DSA-65, TCP) after a baseline of both live tests passed (4 baseline passes in total across two campaign invocations; the first invocation's four multi-line patterns did not match because of a script escaping error, so those four are reported only from the second invocation).

**Accounting: 6 mutants; 4 caught; 2 survived; 0 timeouts; 0 build errors.** The two survivors are explained and NOT counted as caught.

## Where each signing gate is covered

| Gate | Process level (this record) | In-process, deterministic (`phase7-mutation-record.md`, #143 campaign) |
|---|---|---|
| vote | caught | caught (`vote gate`) |
| timeout | caught | caught (`timeout gate`) |
| proposal | **survived (reachability)** | caught (`propose gate`) |
| re-send of a stored vote | caught | caught (`resend vote gate`) |
| re-send of a stored timeout | **survived (unreachable over processes)** | caught (`resend timeout gate`) |

The runtime monitor in the node has two parts: the signing counter must not move while the engine is `Recovering` (it cannot see a re-send, which commits no new signature), and no vote, timeout or proposal authored by this node may be SENT while `Recovering` (it can). Both are exercised above.

## Results

| # | Mutation | Result | Seconds | Test | Failure observed |
|---|---|---|---|---|---|
| 1 | vote gate | CAUGHT | 29.9 | `live_v3_four_processes` | after install A: node 3 reported a fatal error: "SAFETY: the signing counter moved while recovering" |
| 2 | staging order: application state before evidence | CAUGHT | 21.2 | `live_v3_a_crash` | the evidence is on disk |
| 3 | proposal gate | SURVIVED | 148.8 | `live_v3_four_processes` | (none: it survived) |
| 4 | timeout gate | CAUGHT | 24.3 | `live_v3_four_processes` | pq-devnet-node 3: DEVNET ONLY: fixed validator set,  |
| 5 | resend-vote gate | CAUGHT | 21.2 | `live_v3_four_processes` | pq-devnet-node 3: DEVNET O |
| 6 | resend-timeout gate | SURVIVED | 159.0 | `live_v3_four_processes` | (none: it survived) |

## Notes

* **vote gate** — caught by the runtime signing-counter monitor (the node stops itself)
* **staging order: application state before evidence** — caught by the crash-injection test: a crash injected "after the evidence" found no evidence on disk
* **proposal gate** — SURVIVED at the process level: the victim proposes only if it is the leader of its post-install round, which the test does not control, so the mutated path is not reached in these runs. NOT evidence the gate is weak: the same gate is caught deterministically in-process (see below). Open improvement: report the leader slot in the status and re-stage until the victim leads.
* **timeout gate** — caught: a pacemaker timeout fired while recovering; the node stopped itself (SAFETY)
* **resend-vote gate** — caught by the new outbound monitor: the stored vote was re-sent at start while recovering (the signing counter does not move on a re-send)
* **resend-timeout gate** — SURVIVED at the process level, as predicted: a stored timeout is re-sent only if the node's high QC round equals the one it was signed on, and a staged snapshot cannot arrange that over processes. Caught deterministically in-process (see below).

## The exact diffs

### 1. vote gate — CAUGHT
```diff
--- a/chain-forge-consensus/src/pq_hotstuff/engine.rs
+++ b/chain-forge-consensus/src/pq_hotstuff/engine.rs
@@ -311 +311 @@
-        if self.recovering { return Ok(()); } // no vote (and no re-send of a stored one) while recovering
+        // no vote (and no re-send of a stored one) while recovering
```

### 2. staging order: application state before evidence — CAUGHT
```diff
--- a/chain-forge-node/src/pq_devnet.rs
+++ b/chain-forge-node/src/pq_devnet.rs
@@ -515 +514,0 @@
-    bs.put_seed_evidence(cref.height, &cref.block_id, &enc).map_err(|e| e.to_string())?;
@@ -522,0 +522 @@
+    bs.put_seed_evidence(cref.height, &cref.block_id, &enc).map_err(|e| e.to_string())?;
```

### 3. proposal gate — SURVIVED
```diff
--- a/chain-forge-consensus/src/pq_hotstuff/engine.rs
+++ b/chain-forge-consensus/src/pq_hotstuff/engine.rs
@@ -626 +625,0 @@
-        self.refuse_if_recovering()?;
```

### 4. timeout gate — CAUGHT
```diff
--- a/chain-forge-consensus/src/pq_hotstuff/engine.rs
+++ b/chain-forge-consensus/src/pq_hotstuff/engine.rs
@@ -433 +432,0 @@
-        self.refuse_if_recovering()?;
```

### 5. resend-vote gate — CAUGHT
```diff
--- a/chain-forge-consensus/src/pq_hotstuff/engine.rs
+++ b/chain-forge-consensus/src/pq_hotstuff/engine.rs
@@ -594 +593,0 @@
-        if self.recovering { return Ok(vec![]); }
```

### 6. resend-timeout gate — SURVIVED
```diff
--- a/chain-forge-consensus/src/pq_hotstuff/engine.rs
+++ b/chain-forge-consensus/src/pq_hotstuff/engine.rs
@@ -606 +605,0 @@
-        if self.recovering { return Ok(vec![]); }
```


---

## Review follow-up — the proposal-gate survivor, and the two review fixes (code `a929c94fafba9b0939545d3c2787c4d5bdb04ea3`)

Run one at a time in a disposable git worktree with its own target directory, after a baseline for each command (all passed: live controlled-leader test 184.5 s, crash-injection test 30.8 s, restart test 47.8 s). **3 mutants; 3 caught; 0 survived; 0 timeouts; 0 build errors.**

| # | Mutation | Result | Seconds | Failure observed |
|---|---|---|---|---|
| 1 | proposal gate (the surviving process-level mutant) | CAUGHT | 72.7 | node 3 exited (exit status: 2) while waiting for: the gate is reached: the engine is asked to propose while recovering and refuses; pq-devnet-node: SAFETY: the signing co |
| 2 | staging: refuse a snapshot below the target's executed height | CAUGHT | 78.8 | installing a snapshot below the executed height (executed 59) must be refused:  |
| 3 | restart: complete recovery before the re-sends (the fix) | CAUGHT | 35.4 | every dependency is present, so the restart completes recovery |

**Status of the two process-level survivors recorded above:**
* **Proposal gate — NOT CLOSED (under revision); one run caught the mutant, a later run of the same design never reached a leader state, so this is not recorded as closed.** The earlier survivor was a reachability limit: a recovering node proposes only if it is the leader of its post-install round, which an uncontrolled run leaves to chance. `live_v3_a_recovering_node_that_leads_its_round_is_asked_to_propose_refuses_and_signs_nothing` now controls it: it re-stages the victim (the staging tool's `--lag K` ends the evidence K blocks before the donor's tip, with an older valid QC) until its first status says it leads its round, then waits for the node itself to report that its engine was ASKED to propose while recovering and REFUSED (`propose_refused_while_recovering >= 1`; 10 refusals in the recorded run) - positive evidence that the gate was reached and held - and checks that nothing was signed or sent. With the gate removed the node stopped itself (`SAFETY`) in that scenario. A structural fact found while building it: while the victim is down no QC can form for the round just before its own slot (it would have to aggregate those votes), so the donors' recent chains never contain the one QC round that puts it on its slot; the evidence must reach back across the moment it went down (observed: 24 attempts with a recent-tip evidence, never the leader).
* **Re-send of a stored timeout — remains IN-PROCESS coverage only, by label.** A stored timeout is re-sent only if the node's high QC round equals the one the timeout was signed on; a staged snapshot's high QC is the donor's, so a process test cannot arrange that without stalling the whole network at a controlled round. It is mutation-caught deterministically in-process (`phase7-mutation-record.md`, `resend timeout gate`). No process test reaches it, and none is claimed.


### The exact diffs

#### 1. proposal gate (the surviving process-level mutant) — CAUGHT
```diff
--- a/chain-forge-consensus/src/pq_hotstuff/engine.rs
+++ b/chain-forge-consensus/src/pq_hotstuff/engine.rs
@@ -626 +625,0 @@
-        self.refuse_if_recovering()?;
```

#### 2. staging: refuse a snapshot below the target's executed height — CAUGHT
```diff
--- a/chain-forge-node/src/pq_devnet.rs
+++ b/chain-forge-node/src/pq_devnet.rs
@@ -506 +506 @@
-        if cur.height > cref.height { return Err(format!("stale: the target's application state is already at height {}, above the checkpoint at {}; installing an older snapshot would rewind it; nothing was changed", cur.height, cref.height)); }
+        if false { return Err(format!("stale: the target's application state is already at height {}, above the checkpoint at {}; installing an older snapshot would rewind it; nothing was changed", cur.height, cref.height)); }
```

#### 3. restart: complete recovery before the re-sends (the fix) — CAUGHT
```diff
--- a/chain-forge-consensus/src/pq_hotstuff/driver.rs
+++ b/chain-forge-consensus/src/pq_hotstuff/driver.rs
@@ -209 +208,0 @@
-        d.try_complete_recovery();
```
