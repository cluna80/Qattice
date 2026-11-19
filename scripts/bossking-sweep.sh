#!/usr/bin/env bash
# Phase 0 / 0.5 live-test sweep on one pinned commit (PQ-HotStuff-2, ML-DSA-65).
# Runs every live test one at a time and writes sweep-<commit>/summary.md.
#
#   git fetch origin && git checkout feat/pqhs2-fips204-signing && git pull
#   bash scripts/bossking-sweep.sh            # all tests
#   bash scripts/bossking-sweep.sh mn8_reward_exclusion_live   # just some
set -uo pipefail
# Ensure Cargo is on PATH (Git Bash doesn't source the Rust env automatically)
[ -f "$HOME/.cargo/env" ] && source "$HOME/.cargo/env"
export PATH="$HOME/.cargo/bin:$PATH"
cd "$(dirname "$0")/.."
export CARGO_INCREMENTAL=0

COMMIT=$(git rev-parse --short HEAD)
OUT="sweep-$COMMIT"
mkdir -p "$OUT"

# Extra features a test needs (pq-hotstuff is always on).
features_for() {
  case "$1" in
    storage_v2_live|validator_precommit_delay_live) echo "pq-hotstuff,fault-injection" ;;
    governance_quorum_live|validator_eviction_live) echo "pq-hotstuff,insecure-dev-quorum" ;;
    *) echo "pq-hotstuff" ;;
  esac
}

# Known failures, recorded in ROADMAP; anything else failing is new.
expected_failure() {
  case "$1" in
    validator_jail_live) echo "JL-08 round-drift livelock after a validator restart" ;;
    validator_key_live) echo "post_genesis_validator_admission: same restart livelock after Alice is killed" ;;
    adversarial_gossip) echo "garbage-signature vote: inbound vote signatures not verified yet" ;;
    pqhs2_4node_epoch_live) echo "epoch handoff signs/verifies different message formats" ;;
    h0_3_crash_recovery_live) echo "C-01: a single-validator PQ-HotStuff node produces no blocks" ;;
    storage_v2_live) echo "4 Tendermint-era signing-guard/crash-point tests (to be ported)" ;;
    *) echo "" ;;
  esac
}

TESTS=("$@")
if [ ${#TESTS[@]} -eq 0 ]; then
  for f in chain-forge-node/tests/*.rs; do
    n=$(basename "$f" .rs)
    case "$n" in tokio_timer_regression|dis_parity) continue ;; esac
    TESTS+=("$n")
  done
fi

{
  echo "# Sweep at $COMMIT ($(date -u +%Y-%m-%dT%H:%MZ))"
  echo
  echo "| Test | Result | Time | Note |"
  echo "|---|---|---|---|"
} > "$OUT/summary.md"

for t in "${TESTS[@]}"; do
  feats=$(features_for "$t")
  echo "=== $t (features: $feats)"
  start=$(date +%s)
  timeout 1800 cargo test -p chain-forge-node --test "$t" --features "$feats" -- --nocapture --test-threads=1 \
    > "$OUT/$t.log" 2>&1
  rc=$?
  [ $rc -eq 124 ] && echo "TIMEOUT after 1800s" >> "$OUT/$t.log"
  secs=$(( $(date +%s) - start ))
  line=$(grep -E '^test result' "$OUT/$t.log" | tail -1 | sed 's/test result: //; s/; finished.*//')
  [ -z "$line" ] && line="did not run (see log)"
  exp=$(expected_failure "$t")
  if [ $rc -eq 0 ]; then res="PASS"; note=""
  elif [ -n "$exp" ]; then res="FAIL (expected)"; note="$exp"
  else res="**FAIL (new)**"; note=$(grep -m1 -A1 'panicked at' "$OUT/$t.log" | tail -1 | cut -c1-150 | tr '|' '/')
  fi
  echo "| $t | $res — $line | ${secs}s | $note |" >> "$OUT/summary.md"
  echo "    $res ($line, ${secs}s)"
done

echo
echo "Summary: $OUT/summary.md"
