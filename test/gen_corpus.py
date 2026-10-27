#!/usr/bin/env python3
"""gen_corpus.py <out.bin> [random-count] [seed]: 32-bit words, big-endian byte order, padded to 4 KB.
Structured part: every (opcode a, b) x (rs, rd) x edge immediates; every register-register
function code c x register fields; then random words."""
import random, struct, sys
out = sys.argv[1]
nrand = int(sys.argv[2]) if len(sys.argv) > 2 else 100000
rnd = random.Random(int(sys.argv[3]) if len(sys.argv) > 3 else 7)
words = []
imms = [0, 1, 0x1f, 0x20, 0x7fff, 0x8000, 0xffff]
for a in range(64):
    for b in range(4):
        for rs in range(16):
            for rd in range(16):
                for imm in imms + [rnd.randrange(65536) for _ in range(1)]:
                    words.append(a << 26 | rs << 22 | rd << 18 | b << 16 | imm)
for c in range(0x4000):
    for _ in range(3):
        rs, rd, rx = (rnd.randrange(16) for _ in range(3))
        words.append(0x1f << 26 | rs << 22 | rd << 18 | rx << 14 | c)
for _ in range(nrand):
    words.append(rnd.randrange(1 << 32))
while len(words) % 1024:
    words.append(0)
open(out, 'wb').write(b''.join(struct.pack('>I', w) for w in words))
print(len(words), 'words')
