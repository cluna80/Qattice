# PQ-HotStuff-2 seed persistence — mutation campaign (exact record)

Code under test: commit `308d9dc96d345d73f325e19570f33e8c02a20abf` (`feat/pq-hotstuff-2-seed-persistence`), run one mutant at a time in a disposable git worktree with its own target directory; the committed tree was not modified. Tests run per mutant: the 26 tests of `pq_seed_suite.rs`, `pq_seed_persist_suite.rs` and the operational/recovery decoder test (`reserved_and_unknown_kinds_are_unavailable...`), test doubles, `PQHS_SEEDS=10`, release mode.

Baseline (unmutated, same command): **PASS test result: ok. 26 passed; 0 failed; 0 ignored; 0 measured; 141 filtered out; finished in 27.59s** in 27.8 s. Per-mutant timeout 900 s; none timed out.

**Accounting of the 31-mutant campaign on `308d9dc`: 29 caught; 2 survived; 0 timeouts; 0 build errors; 0 not applicable.** One survivor was later closed (see the addendum at the end); the other is explained below and is NOT counted as caught.

An earlier run of a 33-mutant list on `b9cd042` caught 23 and left 10 survivors: 5 test gaps (executor block id at the base; the base root re-persisted; completion at start; the base-height boundary of sync windows; trailing bytes inside a checksummed evidence body), closed by new assertions; 2 redundant checks (the completion trigger after a sync response and the explicit below-base length check), removed together with their mutants; 1 (completion on tick) that was only redundant with the removed trigger and is now caught; and the 2 survivors recorded below. The two lists differ because the code differs; this record is of the final code.

## Survivors

* **driver: commit marker offset** — EQUIVALENT in effect: with the offset removed the start re-puts commit markers for blocks whose markers already exist; `put_commit` of identical content is idempotent, so the on-disk result is the same (only extra writes). Not killable by a behavioural test.

* **driver: base root recorded** — NOT proven equivalent - an acknowledged TEST GAP. Removing the engine-side `record_root` of the checkpoint leaves the outcome for a matching reference unchanged (the final-reference path also yields Match, and the start still refuses a conflicting stored root through `put_root`), but a block carrying a DIFFERENT root at exactly the checkpoint height would be classified `Unknown` instead of `Mismatch` (evidence/alarm classification). No test crafts that block yet.


| # | Mutation | Result | Seconds | Failing test(s) |
|---|---|---|---|---|
| 1 | driver: name/content consistency | CAUGHT | 27.9 | a_start_with_missing_damaged_mismatched_or_unauthentic_evide, result: FAILED. 25 passed; 1 failed; 0 ignored; 0 measured;  |
| 2 | driver: seed from evidence | CAUGHT | 23.4 | a_seeded_node_answers_a_request_below_its_base_explicitly_an, a_start_with_missing_damaged_mismatched_or_unauthentic_evide, live_v3_snapshot_recovery_restart_successive_installs_and_ag, result: FAILED. 23 passed; 3 failed; 0 ignored; 0 measured;  |
| 3 | driver: commit marker offset | SURVIVED | 29.1 | (none: survived) |
| 4 | driver: executor behind base | CAUGHT | 27.1 | a_start_with_missing_damaged_mismatched_or_unauthentic_evide, result: FAILED. 25 passed; 1 failed; 0 ignored; 0 measured;  |
| 5 | driver: executor block at base | CAUGHT | 25.7 | a_start_with_missing_damaged_mismatched_or_unauthentic_evide, result: FAILED. 25 passed; 1 failed; 0 ignored; 0 measured;  |
| 6 | driver: executor state at base | CAUGHT | 24.8 | a_start_with_missing_damaged_mismatched_or_unauthentic_evide, result: FAILED. 25 passed; 1 failed; 0 ignored; 0 measured;  |
| 7 | driver: diverged check at base | CAUGHT | 23.9 | a_seeded_node_answers_a_request_below_its_base_explicitly_an, a_start_with_missing_damaged_mismatched_or_unauthentic_evide, live_v3_snapshot_recovery_restart_successive_installs_and_ag, result: FAILED. 23 passed; 3 failed; 0 ignored; 0 measured;  |
| 8 | driver: base root persisted | CAUGHT | 23.0 | live_v3_snapshot_recovery_restart_successive_installs_and_ag, result: FAILED. 25 passed; 1 failed; 0 ignored; 0 measured;  |
| 9 | driver: base root recorded | SURVIVED | 24.7 | (none: survived) |
| 10 | driver: complete recovery at start | CAUGHT | 24.0 | live_v3_snapshot_recovery_restart_successive_installs_and_ag, result: FAILED. 25 passed; 1 failed; 0 ignored; 0 measured;  |
| 11 | driver: complete recovery on tick | CAUGHT | 32.1 | a_seeded_node_answers_a_request_below_its_base_explicitly_an, live_v3_snapshot_recovery_restart_successive_installs_and_ag, result: FAILED. 24 passed; 2 failed; 0 ignored; 0 measured;  |
| 12 | driver: serve below-base | CAUGHT | 25.0 | a_seeded_node_answers_a_request_below_its_base_explicitly_an, result: FAILED. 25 passed; 1 failed; 0 ignored; 0 measured;  |
| 13 | driver: advice counter | CAUGHT | 24.4 | a_seeded_node_answers_a_request_below_its_base_explicitly_an, result: FAILED. 25 passed; 1 failed; 0 ignored; 0 measured;  |
| 14 | engine: skip blocks at/below base | CAUGHT | 187.6 | a_committed_history_that_conflicts_with_the_authenticated_ch, a_sync_window_that_straddles_the_base_delivers_the_blocks_ab, a_seeded_node_answers_a_request_below_its_base_explicitly_an, live_v3_snapshot_recovery_restart_successive_installs_and_ag, result: FAILED. 22 passed; 4 failed; 0 ignored; 0 measured;  |
| 15 | engine: skip boundary | CAUGHT | 40.4 | a_sync_window_that_straddles_the_base_delivers_the_blocks_ab, result: FAILED. 25 passed; 1 failed; 0 ignored; 0 measured;  |
| 16 | engine: below-base for the base itself | CAUGHT | 25.3 | a_seeded_node_answers_a_request_below_its_base_explicitly_an, result: FAILED. 25 passed; 1 failed; 0 ignored; 0 measured;  |
| 17 | engine: below-base for ancestors | CAUGHT | 24.4 | a_seeded_node_answers_a_request_below_its_base_explicitly_an, result: FAILED. 25 passed; 1 failed; 0 ignored; 0 measured;  |
| 18 | engine: recovery_available | CAUGHT | 24.4 | a_seeded_node_answers_a_request_below_its_base_explicitly_an, result: FAILED. 25 passed; 1 failed; 0 ignored; 0 measured;  |
| 19 | engine: below-base root | CAUGHT | 24.5 | a_seeded_node_answers_a_request_below_its_base_explicitly_an, result: FAILED. 25 passed; 1 failed; 0 ignored; 0 measured;  |
| 20 | engine: evidence genesis binding | CAUGHT | 20.6 | a_seeded_node_answers_a_request_below_its_base_explicitly_an, a_start_with_missing_damaged_mismatched_or_unauthentic_evide, evidence_is_authenticated_against_this_nodes_own_genesis_pro, live_v3_snapshot_recovery_restart_successive_installs_and_ag, seed_evidence_round_trips_and_its_decoder_is_strict, result: FAILED. 21 passed; 5 failed; 0 ignored; 0 measured;  |
| 21 | store: stale evidence | CAUGHT | 25.5 | the_block_store_keeps_seed_evidence_forward_only_never_falls, live_v3_snapshot_recovery_restart_successive_installs_and_ag, result: FAILED. 24 passed; 2 failed; 0 ignored; 0 measured;  |
| 22 | store: conflicting evidence | CAUGHT | 25.0 | the_block_store_keeps_seed_evidence_forward_only_never_falls, result: FAILED. 25 passed; 1 failed; 0 ignored; 0 measured;  |
| 23 | store: newest evidence | CAUGHT | 25.5 | the_block_store_keeps_seed_evidence_forward_only_never_falls, live_v3_snapshot_recovery_restart_successive_installs_and_ag, result: FAILED. 24 passed; 2 failed; 0 ignored; 0 measured;  |
| 24 | store: markers below the checkpoint | CAUGHT | 25.8 | the_block_store_keeps_seed_evidence_forward_only_never_falls, live_v3_snapshot_recovery_restart_successive_installs_and_ag, result: FAILED. 24 passed; 2 failed; 0 ignored; 0 measured;  |
| 25 | store: marker continuity from the checkpoint | CAUGHT | 23.4 | live_v3_snapshot_recovery_restart_successive_installs_and_ag, the_block_store_keeps_seed_evidence_forward_only_never_falls, result: FAILED. 24 passed; 2 failed; 0 ignored; 0 measured;  |
| 26 | codec: checksum | CAUGHT | 25.6 | seed_evidence_round_trips_and_its_decoder_is_strict, result: FAILED. 25 passed; 1 failed; 0 ignored; 0 measured;  |
| 27 | codec: version | CAUGHT | 22.2 | a_seeded_node_answers_a_request_below_its_base_explicitly_an, a_start_with_missing_damaged_mismatched_or_unauthentic_evide, live_v3_snapshot_recovery_restart_successive_installs_and_ag, seed_evidence_round_trips_and_its_decoder_is_strict, result: FAILED. 22 passed; 4 failed; 0 ignored; 0 measured;  |
| 28 | codec: trailing bytes | CAUGHT | 25.4 | seed_evidence_round_trips_and_its_decoder_is_strict, result: FAILED. 25 passed; 1 failed; 0 ignored; 0 measured;  |
| 29 | codec: header bound | CAUGHT | 25.9 | seed_evidence_round_trips_and_its_decoder_is_strict, result: FAILED. 25 passed; 1 failed; 0 ignored; 0 measured;  |
| 30 | codec: tag | CAUGHT | 23.4 | a_seeded_node_answers_a_request_below_its_base_explicitly_an, a_start_with_missing_damaged_mismatched_or_unauthentic_evide, live_v3_snapshot_recovery_restart_successive_installs_and_ag, seed_evidence_round_trips_and_its_decoder_is_strict, result: FAILED. 22 passed; 4 failed; 0 ignored; 0 measured;  |
| 31 | wire: flag strictness | CAUGHT | 25.2 | a_seeded_node_answers_a_request_below_its_base_explicitly_an, result: FAILED. 25 passed; 1 failed; 0 ignored; 0 measured;  |

## The exact diffs

### 1. driver: name/content consistency — CAUGHT
```diff
--- a/chain-forge-consensus/src/pq_hotstuff/driver.rs
+++ b/chain-forge-consensus/src/pq_hotstuff/driver.rs
@@ -158 +158 @@
-            if seed.base().height != h || seed.base().id != id || loaded.seeded_height != h { return Err(DriverError::SeedEvidence("the stored evidence does not describe the checkpoint its name and record claim".into())); }
+            if false { return Err(DriverError::SeedEvidence("the stored evidence does not describe the checkpoint its name and record claim".into())); }
```

### 2. driver: seed from evidence — CAUGHT
```diff
--- a/chain-forge-consensus/src/pq_hotstuff/driver.rs
+++ b/chain-forge-consensus/src/pq_hotstuff/driver.rs
@@ -159 +158,0 @@
-            engine.seed(seed.clone()).map_err(|e| DriverError::SeedEvidence(e.to_string()))?;
```

### 3. driver: commit marker offset — SURVIVED
```diff
--- a/chain-forge-consensus/src/pq_hotstuff/driver.rs
+++ b/chain-forge-consensus/src/pq_hotstuff/driver.rs
@@ -167 +167 @@
-        for c in engine.committed_after(loaded.seeded_height + loaded.committed.len() as u64) { store.put_commit(c.height, &c.id)?; }
+        for c in engine.committed_after(loaded.committed.len() as u64) { store.put_commit(c.height, &c.id)?; }
```

### 4. driver: executor behind base — CAUGHT
```diff
--- a/chain-forge-consensus/src/pq_hotstuff/driver.rs
+++ b/chain-forge-consensus/src/pq_hotstuff/driver.rs
@@ -175 +175 @@
-            if cur.height < bh { return Err(DriverError::ExecutorBehindBase { exec: cur.height, base: bh }); }
+
```

### 5. driver: executor block at base — CAUGHT
```diff
--- a/chain-forge-consensus/src/pq_hotstuff/driver.rs
+++ b/chain-forge-consensus/src/pq_hotstuff/driver.rs
@@ -176 +176 @@
-            if cur.height == bh && (cur.block_id != bid || cur.state_digest != bref.state_root) { return Err(DriverError::BaseMismatch("the executor's cursor at the checkpoint height is not the authenticated checkpoint (block or state root)".into())); }
+            if cur.height == bh && (cur.state_digest != bref.state_root) { return Err(DriverError::BaseMismatch("the executor's cursor at the checkpoint height is not the authenticated checkpoint (block or state root)".into())); }
```

### 6. driver: executor state at base — CAUGHT
```diff
--- a/chain-forge-consensus/src/pq_hotstuff/driver.rs
+++ b/chain-forge-consensus/src/pq_hotstuff/driver.rs
@@ -176 +176 @@
-            if cur.height == bh && (cur.block_id != bid || cur.state_digest != bref.state_root) { return Err(DriverError::BaseMismatch("the executor's cursor at the checkpoint height is not the authenticated checkpoint (block or state root)".into())); }
+            if cur.height == bh && (cur.block_id != bid) { return Err(DriverError::BaseMismatch("the executor's cursor at the checkpoint height is not the authenticated checkpoint (block or state root)".into())); }
```

### 7. driver: diverged check at base — CAUGHT
```diff
--- a/chain-forge-consensus/src/pq_hotstuff/driver.rs
+++ b/chain-forge-consensus/src/pq_hotstuff/driver.rs
@@ -178 +178 @@
-        if cur.height > 0 && seeded.map_or(true, |((bh, _), _)| cur.height > bh) {
+        if cur.height > 0 && true {
```

### 8. driver: base root persisted — CAUGHT
```diff
--- a/chain-forge-consensus/src/pq_hotstuff/driver.rs
+++ b/chain-forge-consensus/src/pq_hotstuff/driver.rs
@@ -189 +188,0 @@
-            store.put_root(k, bref.height, &bref.state_root).map_err(|e| DriverError::BaseMismatch(e.to_string()))?;
```

### 9. driver: base root recorded — SURVIVED
```diff
--- a/chain-forge-consensus/src/pq_hotstuff/driver.rs
+++ b/chain-forge-consensus/src/pq_hotstuff/driver.rs
@@ -190 +189,0 @@
-            engine.record_root(bref.height, bref.state_root).map_err(|e| DriverError::BaseMismatch(e.to_string()))?;
```

### 10. driver: complete recovery at start — CAUGHT
```diff
--- a/chain-forge-consensus/src/pq_hotstuff/driver.rs
+++ b/chain-forge-consensus/src/pq_hotstuff/driver.rs
@@ -212 +211,0 @@
-        d.try_complete_recovery();
```

### 11. driver: complete recovery on tick — CAUGHT
```diff
--- a/chain-forge-consensus/src/pq_hotstuff/driver.rs
+++ b/chain-forge-consensus/src/pq_hotstuff/driver.rs
@@ -374 +373,0 @@
-        self.try_complete_recovery();
```

### 12. driver: serve below-base — CAUGHT
```diff
--- a/chain-forge-consensus/src/pq_hotstuff/driver.rs
+++ b/chain-forge-consensus/src/pq_hotstuff/driver.rs
@@ -301 +301 @@
-                        ServeSync::BelowBase(b) => { self.stats.below_base_served += 1; out.push(Outbound { to: Some(from), bytes: net::encode(&NetMsg::SyncBelowBase(b)) }); }
+                        ServeSync::BelowBase(_) => {}
```

### 13. driver: advice counter — CAUGHT
```diff
--- a/chain-forge-consensus/src/pq_hotstuff/driver.rs
+++ b/chain-forge-consensus/src/pq_hotstuff/driver.rs
@@ -309 +309 @@
-            NetMsg::SyncBelowBase(_) => { self.stats.below_base_advice += 1; Ok(vec![]) }
+            NetMsg::SyncBelowBase(_) => Ok(vec![]),
```

### 14. engine: skip blocks at/below base — CAUGHT
```diff
--- a/chain-forge-consensus/src/pq_hotstuff/engine.rs
+++ b/chain-forge-consensus/src/pq_hotstuff/engine.rs
@@ -265 +264,0 @@
-        if let Some(base) = &self.base { if b.height <= base.height { return Ok(None); } }
```

### 15. engine: skip boundary — CAUGHT
```diff
--- a/chain-forge-consensus/src/pq_hotstuff/engine.rs
+++ b/chain-forge-consensus/src/pq_hotstuff/engine.rs
@@ -265 +265 @@
-        if let Some(base) = &self.base { if b.height <= base.height { return Ok(None); } }
+        if let Some(base) = &self.base { if b.height < base.height { return Ok(None); } }
```

### 16. engine: below-base for the base itself — CAUGHT
```diff
--- a/chain-forge-consensus/src/pq_hotstuff/engine.rs
+++ b/chain-forge-consensus/src/pq_hotstuff/engine.rs
@@ -507 +507 @@
-            if req.want == b.id || b.ancestors.iter().any(|(_, id)| *id == req.want) {
+            if b.ancestors.iter().any(|(_, id)| *id == req.want) {
```

### 17. engine: below-base for ancestors — CAUGHT
```diff
--- a/chain-forge-consensus/src/pq_hotstuff/engine.rs
+++ b/chain-forge-consensus/src/pq_hotstuff/engine.rs
@@ -507 +507 @@
-            if req.want == b.id || b.ancestors.iter().any(|(_, id)| *id == req.want) {
+            if req.want == b.id {
```

### 18. engine: recovery_available — CAUGHT
```diff
--- a/chain-forge-consensus/src/pq_hotstuff/engine.rs
+++ b/chain-forge-consensus/src/pq_hotstuff/engine.rs
@@ -508 +508 @@
-                return ServeSync::BelowBase(BelowBase { want: req.want, base_height: b.height, base_id: b.id, state_root: r.state_root, recovery_available: false });
+                return ServeSync::BelowBase(BelowBase { want: req.want, base_height: b.height, base_id: b.id, state_root: r.state_root, recovery_available: true });
```

### 19. engine: below-base root — CAUGHT
```diff
--- a/chain-forge-consensus/src/pq_hotstuff/engine.rs
+++ b/chain-forge-consensus/src/pq_hotstuff/engine.rs
@@ -508 +508 @@
-                return ServeSync::BelowBase(BelowBase { want: req.want, base_height: b.height, base_id: b.id, state_root: r.state_root, recovery_available: false });
+                return ServeSync::BelowBase(BelowBase { want: req.want, base_height: b.height, base_id: b.id, state_root: [0; 32], recovery_available: false });
```

### 20. engine: evidence genesis binding — CAUGHT
```diff
--- a/chain-forge-consensus/src/pq_hotstuff/engine.rs
+++ b/chain-forge-consensus/src/pq_hotstuff/engine.rs
@@ -657 +657 @@
-        let p = ChainParams { protocol_profile: &self.cfg.protocol_profile, chain_id: &self.cfg.chain_id, set: &self.cfg.set, genesis_hash: self.cfg.genesis_hash, seed: self.cfg.seed, checkpoint: self.cfg.checkpoint.map(|c| c.params) };
+        let p = ChainParams { protocol_profile: &self.cfg.protocol_profile, chain_id: &self.cfg.chain_id, set: &self.cfg.set, genesis_hash: [0; 32], seed: self.cfg.seed, checkpoint: self.cfg.checkpoint.map(|c| c.params) };
```

### 21. store: stale evidence — CAUGHT
```diff
--- a/chain-forge-consensus/src/pq_hotstuff/blockstore.rs
+++ b/chain-forge-consensus/src/pq_hotstuff/blockstore.rs
@@ -177 +177 @@
-            if have > height { return Err(StoreError::StaleSeedEvidence { have, got: height }); }
+
```

### 22. store: conflicting evidence — CAUGHT
```diff
--- a/chain-forge-consensus/src/pq_hotstuff/blockstore.rs
+++ b/chain-forge-consensus/src/pq_hotstuff/blockstore.rs
@@ -183 +183 @@
-            return match unseal(&bytes, K_SEED) { Some(b) if b == &body[..] => Ok(()), _ => Err(StoreError::SeedEvidenceConflict(height)) };
+            return Ok(());
```

### 23. store: newest evidence — CAUGHT
```diff
--- a/chain-forge-consensus/src/pq_hotstuff/blockstore.rs
+++ b/chain-forge-consensus/src/pq_hotstuff/blockstore.rs
@@ -190 +190 @@
-        let Some(&h) = self.seed_heights()?.last() else { return Ok(None) };
+        let Some(&h) = self.seed_heights()?.first() else { return Ok(None) };
```

### 24. store: markers below the checkpoint — CAUGHT
```diff
--- a/chain-forge-consensus/src/pq_hotstuff/blockstore.rs
+++ b/chain-forge-consensus/src/pq_hotstuff/blockstore.rs
@@ -238 +237,0 @@
-        markers.retain(|m| m.0 > out.seeded_height);
```

### 25. store: marker continuity from the checkpoint — CAUGHT
```diff
--- a/chain-forge-consensus/src/pq_hotstuff/blockstore.rs
+++ b/chain-forge-consensus/src/pq_hotstuff/blockstore.rs
@@ -240 +240 @@
-            let expected = out.seeded_height + i as u64 + 1;
+            let expected = i as u64 + 1;
```

### 26. codec: checksum — CAUGHT
```diff
--- a/chain-forge-consensus/src/pq_hotstuff/seed.rs
+++ b/chain-forge-consensus/src/pq_hotstuff/seed.rs
@@ -173 +173 @@
-        if Sha3_256::digest(body)[..] != *sum { return Err(bad("checksum")); }
+
```

### 27. codec: version — CAUGHT
```diff
--- a/chain-forge-consensus/src/pq_hotstuff/seed.rs
+++ b/chain-forge-consensus/src/pq_hotstuff/seed.rs
@@ -176 +176 @@
-        if u16::from_be_bytes(r.take(2)?.try_into().unwrap()) != EV_VERSION { return Err(bad("version")); }
+
```

### 28. codec: trailing bytes — CAUGHT
```diff
--- a/chain-forge-consensus/src/pq_hotstuff/seed.rs
+++ b/chain-forge-consensus/src/pq_hotstuff/seed.rs
@@ -186 +186 @@
-        if r.p != body.len() { return Err(bad("trailing bytes")); }
+
```

### 29. codec: header bound — CAUGHT
```diff
--- a/chain-forge-consensus/src/pq_hotstuff/seed.rs
+++ b/chain-forge-consensus/src/pq_hotstuff/seed.rs
@@ -180 +180 @@
-        if n > max_headers.min(MAX_EVIDENCE_HEADERS) { return Err(bad("too many headers")); }
+
```

### 30. codec: tag — CAUGHT
```diff
--- a/chain-forge-consensus/src/pq_hotstuff/seed.rs
+++ b/chain-forge-consensus/src/pq_hotstuff/seed.rs
@@ -175 +175 @@
-        if r.take(EV_TAG.len())? != EV_TAG { return Err(bad("tag")); }
+
```

### 31. wire: flag strictness — CAUGHT
```diff
--- a/chain-forge-consensus/src/pq_hotstuff/netmsg.rs
+++ b/chain-forge-consensus/src/pq_hotstuff/netmsg.rs
@@ -327 +327 @@
-            let recovery_available = match r.u8()? { 0 => false, 1 => true, _ => return Err(NetError::Malformed("flag")) };
+            let recovery_available = r.u8()? != 0;
```


## Addendum — the surviving `driver: base root recorded` mutant (code `dc89d456ae148a66d7634c6cc617c4796950f106`)
Between `308d9dc` and `dc89d45` only test code and docs changed (`git diff 308d9dc dc89d45 -- chain-forge-consensus/src chain-forge-node` is empty), so the 28 results above for the other mutants still describe the production source; they were not re-run. Only the following were re-run, one at a time in a disposable worktree after a baseline (28 tests passed, 17.1 s):

| Mutation | Result | Failing test |
|---|---|---|
| driver: base root recorded (the previously surviving mutant: the driver's `record_root` of the authenticated checkpoint root removed) | **CAUGHT** | `a_correctly_signed_proposal_with_a_conflicting_root_at_exactly_the_installed_base_height_is_mismatch_evidence_and_is_never_signed_for` |
| engine: a mismatch classified `Unknown` instead of `Mismatch` | **CAUGHT** | same test |
| engine: vote despite a mismatch (`vote_for` called after noting the evidence) | **CAUGHT** | same test |

**Why it survived before, and what closed it.** When the executor's cursor is exactly at the base (how the first test started), the driver's older reconcile step already records the root from the cursor, so the base-root call was redundant there. It is the only source of that root when the executor is AHEAD of the base and the root log lacks the base height (a restart). The test now starts that way. Run with the mutant, the engine has no root for the base height, the conflicting reference is classified `Unknown`, and the assertions on `Mismatch` and on `engine.root(height)` fail.

**`driver: commit marker offset` remains a survivor and is documented separately.** What is demonstrated (`rewriting_an_existing_commit_marker_with_the_same_content_changes_nothing_but_the_number_of_writes`): rewriting an existing commit marker with identical content yields byte-identical files and an identical loaded history, so the mutant's observable logical result is unchanged. What is NOT demonstrated or claimed: that the extra writes are free (each is a write, a sync and a rename), or what a crash in the middle of one of them would leave. It is equivalent only in the first sense.
