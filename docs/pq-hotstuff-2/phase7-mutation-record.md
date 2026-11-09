# PQ-HotStuff-2 checkpoint-start — mutation campaign (exact record)

Code under test: commit `46c2de70734fe1e3319c0f7299802da8b2cce183` (`feat/pq-hotstuff-2-engine-seeding`), run in a disposable git worktree with its own target directory; the committed tree was not modified. Tests run per mutant: the 18 seed tests (`tests/common/pq_seed_suite.rs`, test doubles), `PQHS_SEEDS=10`, release mode.

Baseline (unmutated, same command): **PASS test result: ok. 18 passed; 0 failed; 0 ignored; 0 measured; 142 filtered out; finished in 18.38s** in 18.6 s. Per-mutant timeout: 900 s (a hang would have been counted as detection only because the baseline terminates in 18.6 s under the same conditions; none occurred).

**Final accounting: 31 mutants; 31 caught; 0 survived; 0 timeouts; 0 build errors (none excluded); 0 not applicable.** A build error is never counted; each mutant below compiled.

| # | Mutation | Result | Seconds | Failing test(s) |
|---|---|---|---|---|
| 1 | vote gate | CAUGHT | 19.6 | a_seeded_engine_signs_nothing_until_its_dependencies_arrive_and_the_sa, result: FAILED. 17 passed; 1 failed; 0 ignored; 0 measured; 142 filter |
| 2 | timeout gate | CAUGHT | 21.6 | a_seeded_engine_signs_nothing_until_its_dependencies_arrive_and_the_sa, missing_dependencies_keep_the_node_recovering_and_silent_until_every_r, two_successive_installs_move_only_forward_and_the_second_replaces_the_, result: FAILED. 15 passed; 3 failed; 0 ignored; 0 measured; 142 filter |
| 3 | propose gate | CAUGHT | 14.6 | a_seeded_engine_signs_nothing_until_its_dependencies_arrive_and_the_sa, two_successive_installs_move_only_forward_and_the_second_replaces_the_, result: FAILED. 16 passed; 2 failed; 0 ignored; 0 measured; 142 filter |
| 4 | resend vote gate | CAUGHT | 18.9 | a_recovering_engine_does_not_even_re_send_what_it_signed_before, result: FAILED. 17 passed; 1 failed; 0 ignored; 0 measured; 142 filter |
| 5 | resend timeout gate | CAUGHT | 18.8 | a_recovering_engine_does_not_even_re_send_what_it_signed_before, result: FAILED. 17 passed; 1 failed; 0 ignored; 0 measured; 142 filter |
| 6 | complete ignores missing | CAUGHT | 19.0 | a_seeded_engine_signs_nothing_until_its_dependencies_arrive_and_the_sa, missing_dependencies_keep_the_node_recovering_and_silent_until_every_r, evidence_older_than_the_validators_own_record_leaves_it_recovering_and, result: FAILED. 15 passed; 3 failed; 0 ignored; 0 measured; 142 filter |
| 7 | hqr check | CAUGHT | 18.8 | evidence_older_than_the_validators_own_record_leaves_it_recovering_and, result: FAILED. 17 passed; 1 failed; 0 ignored; 0 measured; 142 filter |
| 8 | high qc block check | CAUGHT | 18.9 | a_seeded_engine_signs_nothing_until_its_dependencies_arrive_and_the_sa, missing_dependencies_keep_the_node_recovering_and_silent_until_every_r, result: FAILED. 16 passed; 2 failed; 0 ignored; 0 measured; 142 filter |
| 9 | stale check | CAUGHT | 19.6 | a_stale_snapshot_a_repeat_and_a_rewind_are_refused_and_change_nothing, two_successive_installs_move_only_forward_and_the_second_replaces_the_, result: FAILED. 16 passed; 2 failed; 0 ignored; 0 measured; 142 filter |
| 10 | same-height conflict | CAUGHT | 19.2 | a_different_block_committed_at_the_checkpoint_height_is_a_conflict_not, result: FAILED. 17 passed; 1 failed; 0 ignored; 0 measured; 142 filter |
| 11 | history conflict | CAUGHT | 18.8 | a_committed_history_that_conflicts_with_the_authenticated_checkpoint_i, result: FAILED. 17 passed; 1 failed; 0 ignored; 0 measured; 142 filter |
| 12 | seed does not enter recovering | CAUGHT | 14.6 | a_recovering_engine_does_not_even_re_send_what_it_signed_before, a_seeded_engine_signs_nothing_until_its_dependencies_arrive_and_the_sa, a_stale_snapshot_a_repeat_and_a_rewind_are_refused_and_change_nothing, missing_dependencies_keep_the_node_recovering_and_silent_until_every_r, evidence_older_than_the_validators_own_record_leaves_it_recovering_and, two_successive_installs_move_only_forward_and_the_second_replaces_the_, result: FAILED. 12 passed; 6 failed; 0 ignored; 0 measured; 142 filter |
| 13 | keep old blocks | CAUGHT | 18.7 | two_successive_installs_move_only_forward_and_the_second_replaces_the_, result: FAILED. 17 passed; 1 failed; 0 ignored; 0 measured; 142 filter |
| 14 | seed round floor | CAUGHT | 18.6 | evidence_older_than_the_validators_own_record_leaves_it_recovering_and, result: FAILED. 17 passed; 1 failed; 0 ignored; 0 measured; 142 filter |
| 15 | adopt high qc | CAUGHT | 13.5 | a_recovered_node_rejoins_the_network_commits_each_block_once_and_never, a_recovering_engine_does_not_even_re_send_what_it_signed_before, missing_dependencies_keep_the_node_recovering_and_silent_until_every_r, two_successive_installs_move_only_forward_and_the_second_replaces_the_, result: FAILED. 14 passed; 4 failed; 0 ignored; 0 measured; 142 filter |
| 16 | tip not set | CAUGHT | 18.8 | a_recovered_node_rejoins_the_network_commits_each_block_once_and_never, a_late_certificate_for_the_checkpoints_child_is_absorbed_without_error, a_recovering_engine_does_not_even_re_send_what_it_signed_before, a_seeded_engine_signs_nothing_until_its_dependencies_arrive_and_the_sa, after_seeding_the_engine_applies_the_reference_rules_from_the_base_exa, a_stale_snapshot_a_repeat_and_a_rewind_are_refused_and_change_nothing, missing_dependencies_keep_the_node_recovering_and_silent_until_every_r, two_successive_installs_move_only_forward_and_the_second_replaces_the_, result: FAILED. 10 passed; 8 failed; 0 ignored; 0 measured; 142 filter |
| 17 | commit_through base | CAUGHT | 19.7 | a_late_certificate_for_the_checkpoints_child_is_absorbed_without_error, result: FAILED. 17 passed; 1 failed; 0 ignored; 0 measured; 142 filter |
| 18 | child_state base | CAUGHT | 19.3 | the_seeded_engine_judges_the_first_references_above_the_base_from_the_, result: FAILED. 17 passed; 1 failed; 0 ignored; 0 measured; 142 filter |
| 19 | ancestor_at base ancestors | CAUGHT | 20.5 | the_seeded_engine_judges_the_first_references_above_the_base_from_the_, result: FAILED. 17 passed; 1 failed; 0 ignored; 0 measured; 142 filter |
| 20 | genesis cert after seed | CAUGHT | 19.4 | a_committed_history_that_conflicts_with_the_authenticated_checkpoint_i, result: FAILED. 17 passed; 1 failed; 0 ignored; 0 measured; 142 filter |
| 21 | final_refs seeding | CAUGHT | 19.1 | the_seeded_base_is_exactly_what_the_header_verifier_computes_and_the_c, result: FAILED. 17 passed; 1 failed; 0 ignored; 0 measured; 142 filter |
| 22 | auth: not final | CAUGHT | 19.5 | only_signed_final_evidence_authenticates_a_checkpoint_and_every_missin, result: FAILED. 17 passed; 1 failed; 0 ignored; 0 measured; 142 filter |
| 23 | auth: final carrier | CAUGHT | 18.6 | an_install_record_cross_checks_a_local_operation_and_never_authenticat, only_signed_final_evidence_authenticates_a_checkpoint_and_every_missin, the_high_certificate_and_the_carrier_must_themselves_be_valid_and_fina, result: FAILED. 15 passed; 3 failed; 0 ignored; 0 measured; 142 filter |
| 24 | auth: carrier must be final | CAUGHT | 18.4 | the_high_certificate_and_the_carrier_must_themselves_be_valid_and_fina, result: FAILED. 17 passed; 1 failed; 0 ignored; 0 measured; 142 filter |
| 25 | auth: verify high qc | CAUGHT | 18.3 | the_high_certificate_and_the_carrier_must_themselves_be_valid_and_fina, result: FAILED. 17 passed; 1 failed; 0 ignored; 0 measured; 142 filter |
| 26 | auth: high qc on chain | CAUGHT | 18.9 | only_signed_final_evidence_authenticates_a_checkpoint_and_every_missin, result: FAILED. 17 passed; 1 failed; 0 ignored; 0 measured; 142 filter |
| 27 | auth: high qc >= checkpoint | CAUGHT | 18.9 | only_signed_final_evidence_authenticates_a_checkpoint_and_every_missin, result: FAILED. 17 passed; 1 failed; 0 ignored; 0 measured; 142 filter |
| 28 | auth: high qc is a qc | CAUGHT | 20.4 | the_high_certificate_and_the_carrier_must_themselves_be_valid_and_fina, result: FAILED. 17 passed; 1 failed; 0 ignored; 0 measured; 142 filter |
| 29 | record root check | CAUGHT | 19.3 | the_high_certificate_and_the_carrier_must_themselves_be_valid_and_fina, result: FAILED. 17 passed; 1 failed; 0 ignored; 0 measured; 142 filter |
| 30 | ancestor window | CAUGHT | 19.2 | after_seeding_the_engine_applies_the_reference_rules_from_the_base_exa, the_seeded_base_is_exactly_what_the_header_verifier_computes_and_the_c, result: FAILED. 16 passed; 2 failed; 0 ignored; 0 measured; 142 filter |
| 31 | parent round | CAUGHT | 21.9 | the_seeded_base_is_exactly_what_the_header_verifier_computes_and_the_c, result: FAILED. 17 passed; 1 failed; 0 ignored; 0 measured; 142 filter |

## The exact diffs

### 1. vote gate
```diff
--- a/chain-forge-consensus/src/pq_hotstuff/engine.rs
+++ b/chain-forge-consensus/src/pq_hotstuff/engine.rs
@@ -303 +303 @@
-        if self.recovering { return Ok(()); } // no vote (and no re-send of a stored one) while recovering
+        // no vote (and no re-send of a stored one) while recovering
```

### 2. timeout gate
```diff
--- a/chain-forge-consensus/src/pq_hotstuff/engine.rs
+++ b/chain-forge-consensus/src/pq_hotstuff/engine.rs
@@ -425 +424,0 @@
-        self.refuse_if_recovering()?;
```

### 3. propose gate
```diff
--- a/chain-forge-consensus/src/pq_hotstuff/engine.rs
+++ b/chain-forge-consensus/src/pq_hotstuff/engine.rs
@@ -608 +607,0 @@
-        self.refuse_if_recovering()?;
```

### 4. resend vote gate
```diff
--- a/chain-forge-consensus/src/pq_hotstuff/engine.rs
+++ b/chain-forge-consensus/src/pq_hotstuff/engine.rs
@@ -576 +575,0 @@
-        if self.recovering { return Ok(vec![]); }
```

### 5. resend timeout gate
```diff
--- a/chain-forge-consensus/src/pq_hotstuff/engine.rs
+++ b/chain-forge-consensus/src/pq_hotstuff/engine.rs
@@ -588 +587,0 @@
-        if self.recovering { return Ok(vec![]); }
```

### 6. complete ignores missing
```diff
--- a/chain-forge-consensus/src/pq_hotstuff/engine.rs
+++ b/chain-forge-consensus/src/pq_hotstuff/engine.rs
@@ -652 +652 @@
-        if let Some(why) = self.recovery_missing() { return Err(EngineError::Recovering(why)); }
+
```

### 7. hqr check
```diff
--- a/chain-forge-consensus/src/pq_hotstuff/engine.rs
+++ b/chain-forge-consensus/src/pq_hotstuff/engine.rs
@@ -646 +646 @@
-        if q.round() < hqr { return Some(format!("the high QC round {} is below the highest QC round this validator has signed against ({hqr})", q.round())); }
+        if false { return Some(format!("the high QC round {} is below the highest QC round this validator has signed against ({hqr})", q.round())); }
```

### 8. high qc block check
```diff
--- a/chain-forge-consensus/src/pq_hotstuff/engine.rs
+++ b/chain-forge-consensus/src/pq_hotstuff/engine.rs
@@ -644 +644 @@
-        if self.height_of(&q.block_id()).is_none() && !matches!(q, Cert::Genesis(_)) { return Some(format!("the block certified by the high QC (round {}) has not arrived", q.round())); }
+        if false { return Some(format!("the block certified by the high QC (round {}) has not arrived", q.round())); }
```

### 9. stale check
```diff
--- a/chain-forge-consensus/src/pq_hotstuff/engine.rs
+++ b/chain-forge-consensus/src/pq_hotstuff/engine.rs
@@ -665 +665 @@
-        if self.committed_height > b.height { return Err(EngineError::Seed(format!("stale checkpoint: height {} is below the committed height {}", b.height, self.committed_height))); }
+        if false { return Err(EngineError::Seed(format!("stale checkpoint: height {} is below the committed height {}", b.height, self.committed_height))); }
```

### 10. same-height conflict
```diff
--- a/chain-forge-consensus/src/pq_hotstuff/engine.rs
+++ b/chain-forge-consensus/src/pq_hotstuff/engine.rs
@@ -667 +667 @@
-            return if self.committed_tip == b.id { Ok(SeedOutcome::AlreadyAtBase) } else { Err(EngineError::Seed("a different block is already committed at the checkpoint height".into())) };
+            return if true { Ok(SeedOutcome::AlreadyAtBase) } else { Err(EngineError::Seed("a different block is already committed at the checkpoint height".into())) };
```

### 11. history conflict
```diff
--- a/chain-forge-consensus/src/pq_hotstuff/engine.rs
+++ b/chain-forge-consensus/src/pq_hotstuff/engine.rs
@@ -673 +673 @@
-            if let Some(id) = at { if id != self.committed_tip { return Err(EngineError::Seed("the committed history conflicts with the authenticated checkpoint".into())); } }
+            if let Some(id) = at { if false { return Err(EngineError::Seed("the committed history conflicts with the authenticated checkpoint".into())); } }
```

### 12. seed does not enter recovering
```diff
--- a/chain-forge-consensus/src/pq_hotstuff/engine.rs
+++ b/chain-forge-consensus/src/pq_hotstuff/engine.rs
@@ -696 +695,0 @@
-        self.recovering = true;
```

### 13. keep old blocks
```diff
--- a/chain-forge-consensus/src/pq_hotstuff/engine.rs
+++ b/chain-forge-consensus/src/pq_hotstuff/engine.rs
@@ -685 +685 @@
-        self.blocks.retain(|id, _| keep.contains(id));
+
```

### 14. seed round floor
```diff
--- a/chain-forge-consensus/src/pq_hotstuff/engine.rs
+++ b/chain-forge-consensus/src/pq_hotstuff/engine.rs
@@ -694 +694 @@
-        self.round = next_round(self.round, self.high_qc.round()).max(self.store.record().hvr.unwrap_or(0));
+        self.round = next_round(self.round, self.high_qc.round());
```

### 15. adopt high qc
```diff
--- a/chain-forge-consensus/src/pq_hotstuff/engine.rs
+++ b/chain-forge-consensus/src/pq_hotstuff/engine.rs
@@ -691 +691 @@
-        if seed.high_qc.round() > self.high_qc.round() { self.high_qc = seed.high_qc.clone(); }
+
```

### 16. tip not set
```diff
--- a/chain-forge-consensus/src/pq_hotstuff/engine.rs
+++ b/chain-forge-consensus/src/pq_hotstuff/engine.rs
@@ -676 +675,0 @@
-        self.committed_tip = b.id;
```

### 17. commit_through base
```diff
--- a/chain-forge-consensus/src/pq_hotstuff/engine.rs
+++ b/chain-forge-consensus/src/pq_hotstuff/engine.rs
@@ -392 +392 @@
-        if target == self.genesis_id || self.is_base(&target) { return Ok(()); } // the base is final by construction (authenticated), never re-emitted
+        if target == self.genesis_id { return Ok(()); } // the base is final by construction (authenticated), never re-emitted
```

### 18. child_state base
```diff
--- a/chain-forge-consensus/src/pq_hotstuff/engine.rs
+++ b/chain-forge-consensus/src/pq_hotstuff/engine.rs
@@ -706 +706 @@
-        if let Some(b) = self.base.as_ref().filter(|b| b.id == *parent) {
+        if let Some(b) = self.base.as_ref().filter(|b| b.id == *parent && false) {
```

### 19. ancestor_at base ancestors
```diff
--- a/chain-forge-consensus/src/pq_hotstuff/engine.rs
+++ b/chain-forge-consensus/src/pq_hotstuff/engine.rs
@@ -722 +722 @@
-                return b.ancestors.iter().find(|(h, _)| *h == height).map(|(_, id)| *id);
+                return None;
```

### 20. genesis cert after seed
```diff
--- a/chain-forge-consensus/src/pq_hotstuff/engine.rs
+++ b/chain-forge-consensus/src/pq_hotstuff/engine.rs
@@ -266 +266 @@
-        if self.base.is_some() && matches!(b.qc, Cert::Genesis(_)) { return Err(EngineError::Invalid("does not extend the seeded checkpoint")); }
+        if false { return Err(EngineError::Invalid("does not extend the seeded checkpoint")); }
```

### 21. final_refs seeding
```diff
--- a/chain-forge-consensus/src/pq_hotstuff/engine.rs
+++ b/chain-forge-consensus/src/pq_hotstuff/engine.rs
@@ -687,2 +687 @@
-        if let Some(r) = b.state.last_ref { self.final_refs.insert(r.height, r); }
-        self.final_refs.insert(seed.cref.height, seed.cref);
+
```

### 22. auth: not final
```diff
--- a/chain-forge-consensus/src/pq_hotstuff/seed.rs
+++ b/chain-forge-consensus/src/pq_hotstuff/seed.rs
@@ -86 +86 @@
-    if !is_final(&cref.block_id) { return Err(SeedError::NotFinal); }
+
```

### 23. auth: final carrier
```diff
--- a/chain-forge-consensus/src/pq_hotstuff/seed.rs
+++ b/chain-forge-consensus/src/pq_hotstuff/seed.rs
@@ -87 +87 @@
-    if !vc.points.iter().any(|x| x.carried == Some(*cref) && is_final(&x.point.id)) { return Err(SeedError::NoFinalCarrier); }
+    if false { return Err(SeedError::NoFinalCarrier); }
```

### 24. auth: carrier must be final
```diff
--- a/chain-forge-consensus/src/pq_hotstuff/seed.rs
+++ b/chain-forge-consensus/src/pq_hotstuff/seed.rs
@@ -87 +87 @@
-    if !vc.points.iter().any(|x| x.carried == Some(*cref) && is_final(&x.point.id)) { return Err(SeedError::NoFinalCarrier); }
+    if !vc.points.iter().any(|x| x.carried == Some(*cref)) { return Err(SeedError::NoFinalCarrier); }
```

### 25. auth: verify high qc
```diff
--- a/chain-forge-consensus/src/pq_hotstuff/seed.rs
+++ b/chain-forge-consensus/src/pq_hotstuff/seed.rs
@@ -94 +94 @@
-    verify_cert(&vctx, high_qc).map_err(|e| SeedError::HighCert(e.to_string()))?;
+
```

### 26. auth: high qc on chain
```diff
--- a/chain-forge-consensus/src/pq_hotstuff/seed.rs
+++ b/chain-forge-consensus/src/pq_hotstuff/seed.rs
@@ -97 +97 @@
-    if !vc.points.iter().any(|x| x.point.id == top && x.point.height >= cref.height) { return Err(SeedError::HighQcNotOnChain); }
+    if false { return Err(SeedError::HighQcNotOnChain); }
```

### 27. auth: high qc >= checkpoint
```diff
--- a/chain-forge-consensus/src/pq_hotstuff/seed.rs
+++ b/chain-forge-consensus/src/pq_hotstuff/seed.rs
@@ -97 +97 @@
-    if !vc.points.iter().any(|x| x.point.id == top && x.point.height >= cref.height) { return Err(SeedError::HighQcNotOnChain); }
+    if !vc.points.iter().any(|x| x.point.id == top) { return Err(SeedError::HighQcNotOnChain); }
```

### 28. auth: high qc is a qc
```diff
--- a/chain-forge-consensus/src/pq_hotstuff/seed.rs
+++ b/chain-forge-consensus/src/pq_hotstuff/seed.rs
@@ -93 +93 @@
-    if !matches!(high_qc, Cert::Qc(_)) { return Err(SeedError::HighCert("not a QC".into())); }
+
```

### 29. record root check
```diff
--- a/chain-forge-consensus/src/pq_hotstuff/seed.rs
+++ b/chain-forge-consensus/src/pq_hotstuff/seed.rs
@@ -119 +119 @@
-    if c.height != seed.cref.height || c.block_id != seed.cref.block_id || c.state_root != seed.cref.state_root {
+    if c.height != seed.cref.height || c.block_id != seed.cref.block_id {
```

### 30. ancestor window
```diff
--- a/chain-forge-consensus/src/pq_hotstuff/seed.rs
+++ b/chain-forge-consensus/src/pq_hotstuff/seed.rs
@@ -105 +105 @@
-    ancestors.retain(|(h, _)| *h >= lo && *h < cref.height);
+    ancestors.retain(|(h, _)| *h < cref.height);
```

### 31. parent round
```diff
--- a/chain-forge-consensus/src/pq_hotstuff/seed.rs
+++ b/chain-forge-consensus/src/pq_hotstuff/seed.rs
@@ -100 +100 @@
-    let parent_round = if k > 0 { vc.points[k - 1].point.round } else { match &start { Start::Anchor(a) => a.round, Start::Genesis => 0 } };
+    let parent_round = if k > 0 { vc.points[k].point.round } else { match &start { Start::Anchor(a) => a.round, Start::Genesis => 0 } };
```
