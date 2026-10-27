# Credits and provenance: AMD Radeon F32 module

## Upstream

| | |
|---|---|
| Source | https://github.com/cyrozap/ghidra-radeon-f32, HEAD `6693e36` ("Use task list for to-do list", 2024-10-03) |
| Ghidra-Rare fork | branch `ghidra-rare` of the aleph-void fork; the history below the Ghidra-Rare commits is the original repository's |
| License | Apache-2.0 (`LICENSE`, the same text as upstream's `LICENSE.txt`) |
| Original authors | from `git log` (3 commits): "cyrozap" (Forest Crossman, GitHub @cyrozap): the whole module |
| Based on | fail0verflow's `radeon-tools` (`f32/f32dis.py`, https://github.com/fail0verflow/radeon-tools) and the 33C3 talk "Console Hacking 2016" (as stated in upstream's README) |

## Other implementations

`gh search repos` for "ghidra radeon f32" and "f32 sleigh radeon" found no other Ghidra F32 module. No code was borrowed from elsewhere.

## Ghidra-Rare changes

1. `f32.sinc` rewritten around small sub-tables. All 64-bit and 32-bit ALU forms, immediates, shifts, bit-field
   forms, set-on-condition, `mul`, `push`/`pop`, `mov rd,ctr` / `mov ctr,rs`, `ldw`/`ldd`/`stw`/`std`/`stm`/`stw #imm` in
   all four memory spaces, and `bl` (writes the dummy link register) now have p-code; upstream had `unimpl` for most.
2. Four word-addressed memory spaces DM, RM, SM, XM for the plain / `reg[` / `mem[` / `unk[` operands (upstream: all four decoded
   to `unimpl`). `cp_queue_read` pcodeop: reading `r1` pops the command queue.
3. The big-endian-instructions language is now declared `endian="big"` (upstream compiled it big-endian but declared it
   little-endian, so every `rs:4` truncation took the wrong half of the register).
4. 64-bit `andd` / `orrd` / `mov` masks are exported as 8-byte constants (upstream printed them truncated to 32 bits);
   32-bit field constants are exported as 4-byte constants.
5. `setgt`/`setge` compare signed (upstream: unsigned); `mov rx,rs` is 32-bit like the `add` it is; writes to `r0` are lost
   instead of being written through a constant.
6. cspec: global ranges for the new spaces; r1 (command queue) removed from the prototype's inputs.
7. New `radeonf32.F32FirmwareLoader` (`src/main/java`): detects the old (bare, big-endian) and new (0x100-byte header,
   little-endian) microcode image layouts, maps the code at IM:0, disassembles it linearly, keeps the jump table in its own
   block and labels/entries every handler `PKT_0x<n>`.
8. Build files (`build.gradle`, `extension.properties`), README updates, `GHIDRA-RARE.md`, `CREDITS.md`, `test/`.

## Sources and reference tools

Used as black boxes, facts or test inputs; nothing copied into the module:

- `f32dis.py` from fail0verflow's radeon-tools (the repository has no licence file): run unmodified except for a one-line
  copy that prints branch targets as addresses; the decode oracle in `test/`.
- The user-visible format of the microcode images (header fields, trailing jump table) as used by the loader is public
  knowledge from the Linux kernel's firmware headers and from f32dis.py's output; no vendor firmware is committed.
