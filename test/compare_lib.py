import re
def num(t):
    m = re.fullmatch(r'#?(-?)0x(-?)([0-9a-f]+)', t) or re.fullmatch(r'#?(-?)()([0-9]+)', t)
    if not m:
        return None
    v = int(m.group(3), 16 if 'x' in t else 10)
    return -v if (m.group(1) or m.group(2)) else v

D64 = {'addd', 'subd', 'lsld', 'lsrd', 'andd', 'orrd', 'eord', 'seteqd', 'setned', 'setgtd', 'setged', 'lsrad', 'lsrd'}

def canon(s):
    """mnemonic + operands; '#' immediates compared modulo 2^32 (2^64 for the 64-bit 'd' forms)."""
    mn, _, rest = s.partition(' ')
    mask = (1 << 64) - 1 if mn in D64 else (1 << 32) - 1
    br = mn in ('b', 'bl', 'cbz', 'cbnz')
    out = []
    for t in re.split(r'[,\s]+', rest.strip()):
        if not t:
            continue
        v = num(t) if (t.startswith('#') or t.startswith('0x')) else None
        if v is not None:
            out.append('@%x' % v if br else '#%x' % (v & mask))
        else:
            out.append(t)
    return mn + ' ' + ' '.join(out)

