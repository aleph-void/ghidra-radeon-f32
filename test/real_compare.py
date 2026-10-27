#!/usr/bin/env python3
"""real_compare.py <ghidra-listing> <f32dis-output>: every instruction Ghidra disassembled (address/text, one per line)
against f32dis at the same instruction number.  Prints: compared, equal, differences (first few)."""
import re, sys
sys.path.insert(0, __import__('os').path.dirname(__import__('os').path.abspath(__file__)))
import importlib.util
spec = importlib.util.spec_from_file_location('cmp', __import__('os').path.join(__import__('os').path.dirname(__import__('os').path.abspath(__file__)), 'compare_lib.py'))
cmp = importlib.util.module_from_spec(spec); spec.loader.exec_module(cmp)
orc = [re.sub(r'\s+', ' ', l[4:].strip()) for l in open(sys.argv[2]) if l.startswith('    ')]
n = eq = 0
bad = []
for l in open(sys.argv[1]):
    a, ln, txt = l.rstrip('\n').split(' ', 2)
    i = int(a, 16) // 4
    if i >= len(orc):
        continue
    n += 1
    g = re.sub(r'\s+', ' ', txt.strip())
    if cmp.canon(g) == cmp.canon(orc[i]):
        eq += 1
    else:
        bad.append((i, g, orc[i]))
print(f'compared {n}, equal {eq}, different {len(bad)}')
for i, g, o in bad[:int(sys.argv[3]) if len(sys.argv) > 3 else 5]:
    print(f'  word {i:#x}: ghidra {g!r}  f32dis {o!r}')
sys.exit(1 if bad else 0)
