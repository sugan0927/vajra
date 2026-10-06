#!/usr/bin/env bash
# Benchmark Vajra against Nginx with wrk (throughput) and vegeta (fixed-rate latency).
#
#   bench/run.sh [-w WORKERS] [-d SECONDS] [-c CONNECTIONS] [-r VEGETA_RATE] [-o OUTDIR]
#
# Requirements: nginx, wrk, vegeta (optional), a release build of vajra.
# The load generator is pinned to the *last* CPUs, the servers to the first
# WORKERS CPUs, so they never compete. Run on a quiet machine, ideally bare
# metal, with `cpupower frequency-set -g performance`.
set -euo pipefail

WORKERS=4; DUR=20; CONNS=256; RATE=20000
HERE="$(cd "$(dirname "$0")" && pwd)"; ROOT_DIR="$(dirname "$HERE")"
OUT="$ROOT_DIR/bench/results/$(date +%Y%m%d-%H%M%S)"
while getopts "w:d:c:r:o:" o; do
  case $o in w) WORKERS=$OPTARG;; d) DUR=$OPTARG;; c) CONNS=$OPTARG;; r) RATE=$OPTARG;; o) OUT=$OPTARG;; *) exit 2;; esac
done
VAJRA="$ROOT_DIR/target/release/vajra"
[ -x "$VAJRA" ] || { echo "build first: cargo build --release" >&2; exit 1; }
command -v nginx >/dev/null || { echo "nginx not found" >&2; exit 1; }
command -v wrk   >/dev/null || { echo "wrk not found"   >&2; exit 1; }

NCPU=$(nproc); LOAD_CPUS="$WORKERS-$((NCPU-1))"
[ "$WORKERS" -lt "$NCPU" ] || { echo "need more CPUs than workers ($WORKERS >= $NCPU)" >&2; exit 1; }
SRV_CPUS="0-$((WORKERS-1))"
TMP="$(mktemp -d)"; mkdir -p "$OUT" "$TMP/www"
trap 'kill $(jobs -p) 2>/dev/null || true; [ -f "$TMP/nginx.pid" ] && kill "$(cat "$TMP/nginx.pid")" 2>/dev/null || true; rm -rf "$TMP"' EXIT

# --- fixtures -------------------------------------------------------------
printf 'hello, world\n' > "$TMP/www/hello.txt"
head -c 1024    /dev/urandom | base64 -w0 > "$TMP/www/1k.bin"
head -c 1048576 /dev/urandom > "$TMP/www/1m.bin"

sed -e "s|@ROOT@|$TMP/www|g" -e "s|@WORKERS@|$WORKERS|g" -e "s|@TMP@|$TMP|g" "$HERE/nginx.conf" > "$TMP/nginx.conf"
sed -e "s|@ROOT@|$TMP/www|g" "$HERE/vajra-bench.toml" > "$TMP/vajra.toml"

# Nginx also serves the shared upstream on :9000 (pinned with the server CPUs).
taskset -c "$SRV_CPUS" nginx -c "$TMP/nginx.conf" -e "$TMP/nginx-error.log"
"$VAJRA" --config "$TMP/vajra.toml" --workers "$WORKERS" --no-pin >"$TMP/vajra.log" 2>&1 &
VPID=$!
# Pin Vajra's process to the server CPUs; its workers then pin 1:1 inside that set.
taskset -a -cp "$SRV_CPUS" "$VPID" >/dev/null
sleep 1
curl -sf http://127.0.0.1:8080/hello.txt >/dev/null || { echo "vajra did not start"; cat "$TMP/vajra.log"; exit 1; }
curl -sf http://127.0.0.1:8081/hello.txt >/dev/null || { echo "nginx did not start"; exit 1; }

SCENARIOS=("static-small:/hello.txt" "static-1k:/1k.bin" "static-1m:/1m.bin" "proxy:/api/x")
declare -A PORT=( [vajra]=8080 [nginx]=8081 )
THREADS=$(( NCPU - WORKERS )); [ "$THREADS" -ge 1 ] || THREADS=1

for sc in "${SCENARIOS[@]}"; do
  name=${sc%%:*}; path=${sc#*:}
  for srv in vajra nginx; do
    url="http://127.0.0.1:${PORT[$srv]}$path"
    echo "== $name / $srv ($url)"
    taskset -c "$LOAD_CPUS" wrk -t"$THREADS" -c"$CONNS" -d"${DUR}s" --latency "$url" > "$OUT/$name.$srv.wrk.txt"
    grep -E "Requests/sec|Transfer/sec| 99%|Non-2xx|Socket errors" "$OUT/$name.$srv.wrk.txt" || true
    sleep 2
  done
done

# --- fixed-rate latency (coordinated-omission-safe) -------------------------
if command -v vegeta >/dev/null; then
  for srv in vajra nginx; do
    echo "== vegeta static-small / $srv @ ${RATE}/s"
    echo "GET http://127.0.0.1:${PORT[$srv]}/hello.txt" | \
      taskset -c "$LOAD_CPUS" vegeta attack -rate="$RATE" -duration="${DUR}s" -keepalive -max-workers=2000 | \
      tee "$OUT/vegeta.$srv.bin" | vegeta report | tee "$OUT/vegeta.$srv.txt"
    vegeta report -type=hist[0,100us,250us,500us,1ms,2ms,5ms,10ms,50ms] < "$OUT/vegeta.$srv.bin" > "$OUT/vegeta.$srv.hist.txt"
  done
else
  echo "vegeta not found: skipping fixed-rate latency runs"
fi

python3 "$HERE/summarize.py" "$OUT" | tee "$OUT/summary.md"
{ echo "workers=$WORKERS conns=$CONNS duration=${DUR}s rate=$RATE"; uname -a; nginx -v 2>&1; "$VAJRA" --check 2>&1 | head -1; lscpu | grep -E "Model name|^CPU\(s\)"; } > "$OUT/environment.txt"
echo "results in $OUT"
