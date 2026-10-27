#!/usr/bin/env python3
"""compare.py <ghidra.txt> <f32dis.txt> [--show N]: bucket module vs f32dis output."""
import re, sys, collections, struct
gh = [l.rstrip('\n').split(' ', 2) for l in open(sys.argv[1]) if not l.startswith('    ')]
orc = [l[4:].rstrip() for l in open(sys.argv[2]) if l.startswith('    ')]
corpus = open(sys.argv[3], 'rb').read() if len(sys.argv) > 3 and not sys.argv[3].startswith('--') else None
show = int(sys.argv[sys.argv.index('--show') + 1]) if '--show' in sys.argv else 3
assert len(gh) == len(orc), (len(gh), len(orc))

def norm_o(s):
    s = s.strip()
    s = re.sub(r'\s+#.*$', '', s) if s.startswith('dw ') else s
    return s

def norm_g(s):
    s = s.strip()
    return re.sub(r'\s+', ' ', s)

import os
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from compare_lib import canon

buckets = collections.defaultdict(list)
agree = both_bad = 0
for i, ((idx, ln, gtxt), otxt) in enumerate(zip(gh, orc)):
    o = re.sub(r'\s+', ' ', otxt.strip())
    ob = o.startswith('dw 0x')
    gb = gtxt.strip() == 'BAD'
    if ob and gb:
        both_bad += 1
        continue
    g = norm_g(gtxt)
    if not ob and not gb and canon(g) == canon(o):
        agree += 1
        continue
    key = ('oracle-bad' if ob else 'ghidra-bad' if gb else 'text', (g.split()[0] if not gb else '-'), (o.split()[0] if not ob else '-'))
    buckets[key].append((i, g, o))
tot = len(gh)
print(f'{tot} words: exact {agree}, both invalid {both_bad}, different {tot - agree - both_bad}')
for k, v in sorted(buckets.items(), key=lambda kv: -len(kv[1])):
    print(f'  {len(v):7d}  {k}')
    for i, g, o in v[:show]:
        w = struct.unpack('>I', corpus[4*i:4*i+4])[0] if corpus else 0
        print(f'           {w:08x}  ghidra: {g:40s} f32dis: {o}')
