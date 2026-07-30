#!/bin/sh
set -eu

root=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
make_tool=${MAKE:-make}
python=${PYTHON:-python3}
build="$root/build/x86"
tmp="$root/build/tmp"
mkdir -p "$build" "$tmp"
export TMPDIR="$tmp"
export TMP="$tmp"
export TEMP="$tmp"

case "$(uname -m)" in
  x86_64|amd64|AMD64) ;;
  *)
    echo "FAIL: validate-x86 requires a native x86-64 host" >&2
    exit 1
    ;;
esac

run_logged() {
  log=$1
  shift
  if ! "$@" >"$log" 2>&1; then
    cat "$log"
    return 1
  fi
  cat "$log"
}

"$make_tool" -C "$root" \
  build/test_symcrypto build/test_x86_backends build/test_openssl_diff \
  build/bench_symcrypto

run_logged "$build/test_symcrypto.log" "$root/build/test_symcrypto"
run_logged "$build/test_x86_backends.log" \
  env SC_REQUIRE_MODERN_X86=1 "$root/build/test_x86_backends"
run_logged "$build/test_openssl_diff.log" "$root/build/test_openssl_diff"
run_logged "$build/sanitize.log" "$make_tool" -C "$root" \
  test-sanitize test-sanitize-x86
run_logged "$build/disassembly.log" "$make_tool" -C "$root" check-x86
run_logged "$build/benchmark.log" "$make_tool" -C "$root" bench-x86

"$python" "$root/scripts/write_x86_status.py" \
  --generic-log "$build/test_symcrypto.log" \
  --x86-log "$build/test_x86_backends.log" \
  --openssl-log "$build/test_openssl_diff.log" \
  --summary "$root/results/summary/x86_summary.json" \
  --raw "$root/results/raw/x86_samples.csv" \
  --output "$root/results/summary/x86_status.json"

printf '%s\n' \
  "PASS: native x86-64 correctness, sanitizers, ISA execution, disassembly and benchmarks" \
  "Status: results/summary/x86_status.json"
