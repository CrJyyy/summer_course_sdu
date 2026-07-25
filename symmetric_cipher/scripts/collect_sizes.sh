#!/bin/sh
set -eu

root=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
out="$root/results/summary/object_sizes.csv"
printf '%s\n' "object,text_segment_bytes,data_segment_bytes,objc_bytes,other_bytes,total_bytes" > "$out"
for object in "$root"/build/src/*.o "$root"/build/src/arm64/*.o "$root"/build/src/x86/*.o
do
  [ -f "$object" ] || continue
  set -- $(size "$object" | tail -1)
  printf '%s,%s,%s,%s,%s,%s\n' "${object#"$root/"}" "$1" "$2" "$3" "$4" "$5" >> "$out"
done
printf '%s\n' \
  "ttable-layout,bytes" \
  "AES-four-table,4096" \
  "SM4-four-table,4096" \
  "SM4-one-table-rotate,1024" \
  "SM4-overlap,2048" > "$root/results/summary/table_sizes.csv"
