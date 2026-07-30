#!/bin/sh
set -eu

root=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
build="$root/build/x86"
cc=${CC:-clang}
ar_tool=${AR:-ar}
objdump_tool=${OBJDUMP:-objdump}
host_arch=$(uname -m)
host_os=$(uname -s)
mkdir -p "$build"

native=0
target_flags=""
case "$host_arch" in
  x86_64|amd64|AMD64)
    native=1
    ;;
  *)
    target_flags="-target x86_64-apple-macos13"
    ;;
esac

# shellcheck disable=SC2086
"$cc" $target_flags -std=c11 -O3 -Wall -Wextra -Wpedantic \
  -Werror -maes -mavx2 -mvaes -mgfni -mpclmul -mvpclmulqdq -msm4 \
  -c "$root/src/x86/isa_probes.c" -o "$build/isa_probes.o"

full="$build/full"
mkdir -p "$full"
objects=""
for source in \
  src/util.c src/aes.c src/sm4.c src/sm4_aes_assist.c src/gift64.c src/twine.c src/dispatch.c \
  src/modes.c src/arm64/aes_arm64.c src/arm64/shuffle_arm64.c \
  src/arm64/ghash_pmull.c src/x86/gfni_model.c src/x86/sm4_gfni_x86.c \
  src/x86/ghash_pclmul.c src/x86/shuffle_x86.c src/x86/aes_vaes.c \
  src/arm64/sm4_hw_arm64.c src/x86/sm4_hw_x86.c
do
  object="$full/$(basename "${source%.c}").o"
  # The runtime library deliberately has no global ISA flags.  Each optimized
  # function carries its own target attribute and is reached through dispatch.
  # shellcheck disable=SC2086
  "$cc" $target_flags -I"$root/include" -std=c11 -O3 \
    -Wall -Wextra -Wpedantic -Werror -c "$root/$source" -o "$object"
  objects="$objects $object"
done
# shellcheck disable=SC2086
"$ar_tool" rcs "$build/libsymcrypto_x86.a" $objects

"$objdump_tool" -d "$build/isa_probes.o" > "$build/isa_probes.disasm"
"$objdump_tool" -d "$full/aes_arm64.o" "$full/sm4_gfni_x86.o" \
  "$full/ghash_pclmul.o" "$full/shuffle_x86.o" \
  "$full/aes_vaes.o" "$full/sm4_hw_x86.o" \
  "$full/sm4_aes_assist.o" > "$build/runtime.disasm"

for mnemonic in aesenc vaesenc vpshufb pclmulqdq vpclmul gf2p8affineinv vsm4rnds4
do
  if ! grep -qi "$mnemonic" "$build/isa_probes.disasm"; then
    echo "FAIL: missing x86 instruction $mnemonic" >&2
    exit 1
  fi
done
for mnemonic in aesenc aesdec vaesenc vaesdec pclmulqdq vpclmul \
  gf2p8affineinv pshufb vsm4rnds4 vsm4key4
do
  if ! grep -qi "$mnemonic" "$build/runtime.disasm"; then
    echo "FAIL: missing x86 runtime instruction $mnemonic" >&2
    exit 1
  fi
done

if [ "$native" -eq 1 ]; then
  printf '%s\n' \
    "PASS: x86-64 native compilation and runtime-object disassembly" \
    "NOTE: execution coverage is checked separately by test_x86_backends."
else
  printf '%s\n' \
    "PASS: x86-64 cross compilation and disassembly" \
    "NOTE: execution skipped on non-x86 host."
fi

if [ "$host_os" = "Darwin" ] &&
   { [ "$host_arch" = "arm64" ] || [ "$host_arch" = "aarch64" ]; }
then
  "$cc" -target arm64-apple-macos13 -std=c11 -O3 -Wall -Wextra -Wpedantic \
    -Werror -march=armv8.4-a+crypto+sm4 \
    -c "$root/src/arm64/isa_probes.c" -o "$build/arm_isa_probes.o"
  "$objdump_tool" -d "$build/arm_isa_probes.o" > "$build/arm_isa_probes.disasm"
  for mnemonic in pmull sm4e
  do
    if ! grep -qi "$mnemonic" "$build/arm_isa_probes.disasm"; then
      echo "FAIL: missing ARM instruction $mnemonic" >&2
      exit 1
    fi
  done

  "$cc" -target arm64-apple-macos13 -I"$root/include" -std=c11 -O3 \
    -Wall -Wextra -Wpedantic -Werror -march=armv8.4-a+crypto \
    -c "$root/src/arm64/aes_arm64.c" -o "$build/arm_aes.o"
  "$cc" -target arm64-apple-macos13 -I"$root/include" -std=c11 -O3 \
    -Wall -Wextra -Wpedantic -Werror -march=armv8.4-a+crypto \
    -c "$root/src/arm64/shuffle_arm64.c" -o "$build/arm_shuffle.o"
  "$cc" -target arm64-apple-macos13 -I"$root/include" -std=c11 -O3 \
    -Wall -Wextra -Wpedantic -Werror -march=armv8.4-a+crypto+sm4 \
    -c "$root/src/arm64/sm4_hw_arm64.c" -o "$build/arm_sm4_runtime.o"
  "$objdump_tool" -d "$build/arm_aes.o" "$build/arm_shuffle.o" \
    "$build/arm_sm4_runtime.o" > "$build/arm_runtime.disasm"
  for mnemonic in aese aesd tbl sm4e sm4ekey
  do
    if ! grep -qi "$mnemonic" "$build/arm_runtime.disasm"; then
      echo "FAIL: missing ARM runtime instruction $mnemonic" >&2
      exit 1
    fi
  done
  printf '%s\n' \
    "PASS: ARM AESE/AESD/TBL/PMULL and SM4E/SM4EKEY instruction witnesses"
fi
