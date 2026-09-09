#!/usr/bin/env bash
set -euo pipefail

binary=${1:?usage: check-kernel.sh <linked-binary>}
read -r start_hex end_hex < <(
  nm -n "$binary" | awk '
    /(_runtime\.root|_root)\.evaluate$/ { start=$1; found=1; next }
    found && $1 ~ /^[0-9a-fA-F]+$/ && $1 != start { print start, $1; exit }
  '
)

if [[ -z ${start_hex:-} || -z ${end_hex:-} ]]; then
  echo "policy VM symbol or its linked end could not be measured" >&2
  exit 1
fi

start=$((16#$start_hex))
end=$((16#$end_hex))
size=$((end - start))
offset=$((start & 4095))

if (( offset + size > 4096 )); then
  echo "policy VM spans an instruction page: size=$size offset=$offset" >&2
  exit 1
fi

echo "policy VM linked size=$size bytes page_offset=$offset bytes"
