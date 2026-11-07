#!/usr/bin/env bash
# Usage: ./run_tlc.sh <config.cfg> [extra TLC args...]
# Requires: java >= 11 and tla2tools.jar (TLC 2.19). Set TLA_JAR to its path (see README.md).
set -u
CFG="$1"; shift
HERE="$(cd "$(dirname "$0")" && pwd)"
JAR="${TLA_JAR:-$HERE/tla2tools.jar}"
META="${TLC_META:-$(mktemp -d)}"
exec java -XX:+UseParallelGC -Xmx${TLC_HEAP:-6g} -cp "$JAR" tlc2.TLC -workers "${TLC_WORKERS:-4}" \
     -metadir "$META" -config "$CFG" "$@" "$HERE/EpochTransition.tla"
