# Ghidra-Rare notes: AMD Radeon F32

Processor module for the F32 core, the command-processor microengine of Radeon GPUs of the GCN era (PFP, ME, CE, MEC,
RLC firmware). Upstream: cyrozap/ghidra-radeon-f32 (see [CREDITS.md](CREDITS.md)). Languages: `F32:BE:64:default`
(big-endian instruction words: the old bare firmware layout), `F32:LE:64:default` (little-endian words: the new layout
with a 0x100-byte header). Both use word-addressed spaces IM (code), DM, RM, SM, XM.

## Tests

`GHIDRA_INSTALL_DIR=<ghidra with this module in Ghidra/Processors/RadeonF32> test/run-tests.sh [workdir]`
(f32dis.py from https://github.com/fail0verflow/radeon-tools is needed as the oracle: set `F32DIS`). With
`LOADER_GHIDRA=<ghidra with the built extension installed>` the loader test (synthetic images) runs as well.

| Area | Result |
|---|---|
| Builds | both `.slaspec` compile on Ghidra 12.1.3, 12.1.4, 12.2; `.sla` about 9 KB |
| Decode | 673,792 words (every opcode x b x rs x rd x edge immediates; every register-register function code with random registers; 100,000 random words) against `f32dis.py`: 164,445 identical, 509,347 invalid in both, **0 different**, in both languages |
| Every entry reachable | 124/124 constructors |
| Semantics | 53 hand-computed emulator sequences pass in both languages (32/64-bit wrap and carry, shifts, sets, bit-field forms, immediates, branches, `bl`/`ret`, all four memory spaces, `push`/`pop`, `stm`, r0 and r1 behaviour); 2 deliberately wrong expectations are reported |
| Loader | synthetic old-style, new-style and header-less images are recognised, laid out and labelled; random data is not claimed |
| Real code | no freely licensed F32 microcode was found; none is committed or used here |

## Display differences from f32dis (explained, not errors)

`f32dis.py` prints shifted-field immediates as unbounded integers (for example `orr r0, r1, #0x1ff80000000`) and
signed immediates as 32/64-bit masks; the module prints them as the 32-bit (64-bit for the `d` forms) value. The
differential compares immediates modulo 2^32 / 2^64. Branch targets are compared as byte addresses (word number x 4).

## Modelling decisions nothing public settles (unverified)

- 32-bit operations read the low half of the 64-bit registers and write the result zero-extended.
- `setgt`/`setge` are signed (ARM-style names); `mul` multiplies the low 16 bits of each source (the oracle only says "16x16?").
- `lsra rd,rs,#s,#m` = `(rs >> s) & m`; the `and`/`mov`/`orr` field forms clear or insert a shifted field as f32dis describes them.
- The four spaces are addressed in 32-bit words; `ldd`/`std` use two consecutive words, low half first.
- `push`/`pop` use a dummy stack pointer into DM, one dword each; `bl` writes the dummy link register `lr` and `ret` jumps to it
  (the real hardware call stack is unknown); `stm` stores `rs` to consecutive words `ctr` times, re-reading `rs` each time.
- `btab` (hardware jump-table dispatch on the packet header in r2) and reads of `r1` (command-queue pop) are pcodeops.

## Doesn't work / known gaps

- No calling convention exists to describe (hand-written code with global register allocation).
- Semantics beyond the encodings cannot be checked without hardware or a simulator.

## Reference-tool bugs

None confirmed.
