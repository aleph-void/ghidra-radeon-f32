#!/usr/bin/env python3
"""gen_images.py <dir> <decoded-corpus.txt> <corpus.bin>: synthetic microcode images for the loader test
(built from instruction words the module decodes; no vendor firmware).
  old_table.bin   big-endian, 4 KB of code + a 3-entry jump table
  old_plain.bin   big-endian, 4 KB of code, no table
  new_table.bin   little-endian with the 0x100-byte header, 4 KB of code + 3-entry table
  noise.bin       random bytes (must not be claimed by the loader)"""
import os, random, struct, sys
d, txt, cor = sys.argv[1:4]
os.makedirs(d, exist_ok=True)
words = struct.unpack('>%dI' % (os.path.getsize(cor) // 4), open(cor, 'rb').read())
ok = [words[int(l.split(' ', 2)[0])] for l in open(txt) if not l.startswith('    ') and l.split(' ', 2)[1] != '0' and not l.split(' ', 2)[2].startswith('BAD')]
rnd = random.Random(5)
code = [rnd.choice(ok) for _ in range(1024)]
code[0] = 0x04000000 | 1   # a harmless first instruction; handlers below
table = [0x10 << 16 | 8, 0x37 << 16 | 0x40, 0x11 << 16 | 8]
def pack(ws, e): return b''.join(struct.pack(e + 'I', w & 0xffffffff) for w in ws)
open(f'{d}/old_table.bin', 'wb').write(pack(code + table, '>'))
open(f'{d}/old_plain.bin', 'wb').write(pack(code, '>'))
body = pack(code + table, '<')
hdr = struct.pack('<9I', 0x100 + len(body), 44, 1, 0x10007, 226, len(body), 0x100, 0, 27).ljust(0x100, b'\0')
open(f'{d}/new_table.bin', 'wb').write(hdr + body)
open(f'{d}/noise.bin', 'wb').write(bytes(rnd.randrange(256) for _ in range(4096)))
