# Session status — 2026-11-11

Branch: `feat/pq-hotstuff-2-qat06-merge-an3`
HEAD: `a169fe6`

---

## Where we are: QAT-07 / PQHS-P1

QAT-07 is the Phase 1 gate for PQ-HotStuff-2 (§7 persistence + §8 reconfiguration).
It is **open**. Work this session:

| Gap | Status | Evidence |
|-----|--------|----------|
| G7-W — safety store Windows confirmation | ✅ Closed | 76/76 + 11/11 BossKing |
| G8-A — ML-DSA-only admission | ✅ Closed | 1/1 BossKing @ `0bd37ce` |
| G7.1.1-P — §7.1.1 Case A + B tests | **BossKing confirmed 2/2 (0.17 s, `339f262`)** — ready for owner approval |
| G8-E — epoch transitions design | Decision doc written (`decision-epoch-transitions.md`) — **pending owner approval** |
| G8-R, G8-K — revocation / rotation | Blocked on SSI design acceptance (G8-E) |
| G8-P — personhood power cap | Blocked on owner approval |
| G7.1-P — §7.1 counter backend | Blocked on owner backend choice |

PO-4 (cross-epoch commit rule / dynamic membership) is **open by owner instruction**.
Implementation of epoch transitions, revocation, and rotation is blocked until PO-4 is resolved.

---

## Decisions the owner still needs to make (from decision docs)

### `decision-epoch-transitions.md`

1. **Epoch-boundary block type for B_child** — owner recommended explicit type; not yet formally approved.
2. **Epoch-set store** — owner recommended separate authenticated store surviving pruning; not yet formally approved.
3. **SSI activation rule and TC activation table** — drafted; pending approval.
4. **PO-4 scope** — open; dynamic membership blocked until resolved.
5. **Cross-epoch commit rule** — trace shows B_ec committed when B_{e+1,1} arrives carrying QC_B_child (S_e, cross-epoch). SSI map required. This is PO-4 implementation territory.

### `decision-trusted-counter.md`

6. **Backend choice** — A (TPM), B (HSM), C (remote), D (devnet file); owner has not approved any for concrete evaluation.
7. **§7.1 as Phase 1 required interface** — not yet approved; Track C blocked.
8. **§7.1.1** — tests confirmed BossKing; pending owner approval to close G7.1.1-P.

---

## What comes after QAT-07

Per ROADMAP.md critical path:

```
QAT-05 → QAT-06 ✅ → QAT-07 (open) → QAT-08 → QAT-09 → QAT-10 → QAT-11
```

| Gate | What it requires |
|------|-----------------|
| **QAT-08 / PQHS-P2** | Private four-node PQ-HotStuff devnet, fresh genesis, OS-RNG keys, live partitions, crash/restart, committed slashing, state-root agreement, Linux + Windows. **Blocked on QAT-07.** |
| **QAT-09 / PQHS-P3** | Adversarial + independent review, bandwidth/finality benchmarks (4/7/16/31 validators), operator runbooks, no unresolved safety-critical findings. |
| **QAT-10 / PQ NETWORK** | Peer-auth, transport confidentiality, gossip security, threat model, owner approval for limited-alpha exceptions. |
| **QAT-11 / PUBLIC ALPHA** | All G0–G7 readiness gates, security closure, independent operators, soak + incident drills, explicit launch authorization. **NOT AUTHORIZED.** |

Also blocking QAT-08:
- PR #130 unmerged draft: PO-4, K1/K2 persistence conflicts, U5 tx encoding, U19 membership semantics.
- Phase 2 private-key handling (PR #109 review): blocked separately.

---

## Immediate next actions (in priority order)

1. **Owner: review `decision-epoch-transitions.md` and `decision-trusted-counter.md`** at `a169fe6`  
   — approve or redirect on the 8 open decisions above before any Track B/C implementation begins.

2. **If G7.1.1-P approved:** close the gap in `qat07-gap-review.md` and update ROADMAP.md.

3. **If epoch-transitions design approved:** implement G8-E (epoch-change block, SSI map, cross-epoch QC verification) on a new branch; write acceptance tests per §12 Phase 1 gates.

4. **PO-4:** owner decides scope of bounded model check for cross-epoch safety before G8-E merges.

5. **G7-F, G7-S** (Windows fault injection, stale-file open test): medium-priority; can proceed in parallel with Track B once owner approves.
