# PQ-HotStuff-2 epoch-transition model (PO-4 research)

Research only. Nothing here changes Rust, Cargo, Tendermint, keys, the roadmap or PR #130.

**Subject.** The epoch-transition rules proposed in `docs/pq-hotstuff-001-spec.md` §3.6 (chain-global rounds) and §3.7 (EC-1 to EC-10), as of PR #130 head `72c24df31b4e67a573374bb8102f69dde6996c01`. The model checks the *proposed* rules; it does not redesign them.

**Result summary and counterexamples:** see `REPORT.md`. Raw TLC logs are in `out/`, counterexample traces in `traces/`.

## Tool

* TLA+ / TLC **2.19** (`tla2tools.jar` from the TLA+ release v1.7.4, TLC "Version 2.19 of 08 August 2024"), Java 21 (OpenJDK 21.0.12), 4 cores, 15 GB RAM.
* Python 3.13 is used only to generate configuration files and to run/collect TLC results (`gen_configs.py`, `run_all.py`, `sim_hunt.py`); it contains no protocol logic.
* A bounded model check explores *all* behaviours within its bounds; it is **not** a proof of unbounded safety. Randomised simulation runs (`sim_hunt.py`) are *not* exhaustive and are labelled as such everywhere.

## Files

| File | Purpose |
|---|---|
| `EpochTransition.tla` | The model. Every protocol rule and every mutation is a constant, so a mutant is a configuration, not a code edit |
| `SelfTest.tla` | Static assertions on the helper operators (quorum arithmetic, chain structure, the completing pair, suffix rules) |
| `gen_configs.py` | Generates every `cfg/*.cfg` (scenarios x {safety, crash, mutants, witness, liveness}) |
| `run_all.py` | Runs TLC on one configuration, writes `out/<cfg>.log`, `out/<cfg>.json`, `traces/<cfg>.trace.txt` |
| `sim_hunt.py` | TLC simulation mode with fixed seeds (non-exhaustive) |
| `cfg/` | Generated TLC configurations |
| `out/`, `traces/` | Raw results and counterexample traces |
| `REPORT.md` | Findings, bounds, state counts, runtimes, ambiguities, limitations |

## Reproduce

```bash
# 1. get TLC (any machine with Java 11+)
curl -sSL -o tla2tools.jar https://github.com/tlaplus/tlaplus/releases/download/v1.7.4/tla2tools.jar
export TLA_JAR=$PWD/tla2tools.jar            # or leave it in this directory

# 2. generate configurations (deterministic)
python3 gen_configs.py

# 3. model self-tests (static assertions)
python3 run_all.py selftest

# 4. one exhaustive run (example) and the summary it writes
python3 run_all.py safety_t3_overlap --max-minutes 30
cat out/safety_t3_overlap.json

# 5. replay a counterexample exactly: TLC is deterministic with one worker,
#    so the same configuration yields the same shortest trace
TLC_WORKERS=1 python3 run_all.py mut_M1_no_seal__t3_disjoint --workers 1
diff <(sed -n '/^Error:/,$p' out/mut_M1_no_seal__t3_disjoint.log) traces/mut_M1_no_seal__t3_disjoint.trace.txt
```

Every JSON result stores the exact command line used.

## Constants (rules and mutations)

| Constant | Baseline | Meaning |
|---|---|---|
| `SealOn` | TRUE | EC-6: a voter of the completing block never again signs epoch-0 objects above that round |
| `SealOnLearn` | FALSE | alternative reading of EC-6: seal when the completing certificate is *learned*, not when the vote is cast |
| `BoundaryCheck` | TRUE | verifiers reject certificates inconsistent with their persisted boundary row (R4) |
| `EmptySuffix` | TRUE | EC-3: blocks between the epoch-change block and its commit must be empty |
| `FloorPersist` | TRUE | persisted `hvr`/`hqr`/seal survive an epoch change (FALSE = the merged safety store's behaviour, finding K1) |
| `AtomicPersist` | TRUE | the vote record is durable before the vote leaves (FALSE = send first, persist later) |
| `StageVotes` | FALSE | persist and send as two separate steps (needed whenever `CrashOn`) |
| `CrashOn` | FALSE | crash/restart events: volatile knowledge and any unpersisted vote are lost |
| `ByzActive` | TRUE | Byzantine validators contribute votes/timeouts to any certificate (FALSE = silent, liveness runs) |
| `ByzProposeOn` | TRUE | Byzantine leaders may propose, including several blocks per round (`MaxBP`) |
| `Sync` | FALSE | liveness mode: timeouts only at global quiescence |

See `REPORT.md` for the modelling assumptions and what is *not* covered.
