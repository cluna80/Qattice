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
