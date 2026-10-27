#!/usr/bin/env bash
# Radeon F32 module test suite: everything that needs no firmware.
#
#   GHIDRA_INSTALL_DIR=<Ghidra 12.1.x/12.2 with this module linked into Ghidra/Processors/RadeonF32> test/run-tests.sh [workdir]
#
# 1. both specs compile
# 2. decode differential against fail0verflow's f32dis.py (run as a black box, on a copy whose branch labels print as
#    addresses): 673,792 words (every opcode x b x rs x rd x edge immediates, every register-register function code,
#    100,000 random words), both languages
# 3. every SLEIGH constructor is reached by that corpus
# 4. p-code: 55 hand-computed emulator sequences (53 + 2 deliberately wrong expectations that must be reported), both languages
# 5. (LOADER_GHIDRA set) the firmware loader on synthetic images
# Needs f32dis.py: set F32DIS or clone https://github.com/fail0verflow/radeon-tools (no licence file: used as a black box, never copied).
# Environment: GHIDRA_INSTALL_DIR, JAVA_HOME (optional), PROJ_DIR (headless projects; no path component may start with a dot), JOBS.
set -euo pipefail
HERE=$(cd "$(dirname "$0")" && pwd)
MOD=$(cd "$HERE/.." && pwd)
: "${GHIDRA_INSTALL_DIR:?set GHIDRA_INSTALL_DIR}"
W=$(readlink -m "${1:-${TMPDIR:-/tmp}/f32-tests}")
mkdir -p "$W"
export TMPDIR=$W PROJ_DIR=${PROJ_DIR:-$W} JOBS=${JOBS:-4} PIECE_BYTES=1048576
F32DIS=${F32DIS:-$HOME/.cache/ghidra-rare-scratch/community-src/fail0verflow__radeon-tools/f32/f32dis.py}
fail=0
P="$GHIDRA_INSTALL_DIR/Ghidra/Processors/RadeonF32"
if [[ ! -e $P ]]; then ln -s "$MOD" "$P"; elif [[ $(readlink -f "$P") != "$MOD" ]]; then echo "warning: $P exists and is not this module" >&2; fi

echo "== 1. SLEIGH compiles"
for e in be le; do
	"$GHIDRA_INSTALL_DIR/support/sleigh" "$MOD/data/languages/f32$e.slaspec" 2>&1 | grep -E "^ERROR" && exit 1 || true
	sz=$(stat -c %s "$MOD/data/languages/f32$e.sla")
	echo "   f32$e.sla: $sz bytes"
	((sz < 16 * 1024 * 1024))
done

echo "== 2. decode differential against f32dis.py"
python3 "$HERE/gen_corpus.py" "$W/all.bin" 100000 7
python3 - "$W/all.bin" "$W/all_le.bin" <<'PY'
import sys
d = open(sys.argv[1], 'rb').read()
open(sys.argv[2], 'wb').write(b''.join(d[i:i + 4][::-1] for i in range(0, len(d), 4)))
PY
mkdir -p "$W/oracle"
sed 's/^def loc(off):/def loc(off):\n    return "0x%x" % (off*4)\n\ndef loc_orig(off):/' "$F32DIS" > "$W/oracle/f32dis_patched.py"
cp "$W/all.bin" "$W/oracle/ALL.BIN"          # upper-case name: big-endian words, no header
python3 "$W/oracle/f32dis_patched.py" "$W/oracle/ALL.BIN" > "$W/oracle/out.txt"
for v in BE LE; do
	f=$([[ $v == BE ]] && echo all.bin || echo all_le.bin)
	"$HERE/decode-corpus.sh" F32:$v:64:default "$W/$f" "$W/gh_$v.txt" 4
	echo "   $v:"
	python3 "$HERE/compare.py" "$W/gh_$v.txt" "$W/oracle/out.txt" "$W/all.bin" --show 3 | tee "$W/compare_$v.txt" | cut -c1-170
	grep -q ", different 0$" "$W/compare_$v.txt" || fail=1
done

echo "== 3. every constructor is reached"
"$HERE/decode-corpus.sh" F32:BE:64:default "$W/all.bin" "$W/reach.txt" 4 Reach.java
python3 "$HERE/reach_check.py" "$MOD/data/languages/f32.sinc" "$W/reach.txt" || fail=1

echo "== 4. p-code: hand-computed emulator tests"
python3 "$HERE/emu_tests.py" "$W/emu"
for v in be le; do
	V=$(echo $v | tr a-z A-Z)
	"$HERE/ghidra-script.sh" raw F32:$V:64:default "$W/emu/emu_$v.bin" EmuCheck.java "$W/emu/tests_$v.txt" "$W/emu/out_$v.txt"
	echo "   F32:$V: $(tail -1 "$W/emu/out_$v.txt")"
	grep -q " 0 failed" "$W/emu/out_$v.txt" || { grep ^FAIL "$W/emu/out_$v.txt" | head -20; fail=1; }
	grep -q "[1-9][0-9]* broken expectations detected" "$W/emu/out_$v.txt" || { echo "   the deliberately wrong expectations were not detected"; fail=1; }
done
if [[ -n ${LOADER_GHIDRA:-} ]]; then
	echo "== 5. firmware loader on synthetic images (needs the built extension installed in LOADER_GHIDRA)"
	python3 "$HERE/gen_images.py" "$W/img" "$W/gh_BE.txt" "$W/all.bin"
	chk() {   # file expected-language table-entries code-bytes
		GHIDRA_INSTALL_DIR=$LOADER_GHIDRA "$HERE/ghidra-script.sh" auto - "$W/img/$1" LoaderCheck.java "$W/img/$1.out" "$2" "$3" "$4"
		echo "   $1: $(cat "$W/img/$1.out")"
		grep -q '^OK' "$W/img/$1.out" || fail=1
	}
	chk old_table.bin F32:BE:64:default 3 4096
	chk old_plain.bin F32:BE:64:default 0 4096
	chk new_table.bin F32:LE:64:default 3 4096
	if "$LOADER_GHIDRA/support/analyzeHeadless" "$PROJ_DIR" noise -import "$W/img/noise.bin" -noanalysis -overwrite -deleteProject 2>&1 | grep -q "Using Loader: AMD Radeon F32"; then
		echo "   noise.bin: claimed by the F32 loader"; fail=1
	else
		echo "   noise.bin: not claimed"
	fi
fi
if ((fail)); then echo "FAILED"; exit 1; fi
echo "all tests passed"
