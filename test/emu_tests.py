#!/usr/bin/env python3
"""emu_tests.py <workdir>: encode the hand-computed p-code test sequences below and write
emu_be.bin / emu_le.bin (same program, instruction words in either byte order) and tests.txt for EmuCheck.java.

Each case: (name, [instruction words], init, expect).  Expectations are worked out by hand from the
module's documented model (README / GHIDRA-RARE.md), never from its output.  Instruction encoders
follow the field layout  op[31:26] rs[25:22] rd[21:18] b[17:16] imm[15:0]  and, for op 0x1f,
rs[25:22] rt[21:18] rx[17:14]... (see f32.sinc).  Memory items: DM@4:<word> etc. (little-endian, word-addressed spaces).
"""
import os, re, struct, sys

def ri(a, rd, rs, imm, b=0):   # register-immediate family
    return a << 26 | rs << 22 | rd << 18 | b << 16 | (imm & 0xffff)
def rr(c, rx, rs, rt):         # register-register family (op 0x1f)
    return 0x1f << 26 | rs << 22 | rt << 18 | rx << 14 | c
def ld(a, rd, rs, imm, b=0): return ri(a, rd, rs, imm, b)       # ldw 0x31, ldd 0x32
def st(a, rs, rd, imm, b=0): return a << 26 | rs << 22 | rd << 18 | b << 16 | imm   # stw 0x33, std 0x34, stm 0x35
def sti(v, rd, imm, b=0): return 0x36 << 26 | v << 22 | rd << 18 | b << 16 | imm
B, BL, CBZ, CBNZ = 0x20, 0x23, 0x25, 0x26
def br(op, rs=0, imm=0): return op << 26 | rs << 22 | (imm & 0xffff)
RET = 0x24 << 26
BTAB = 0x22 << 26
NOP = 0
def abs_br(op, nwords): return lambda s: br(op, imm=s // 4 + nwords)   # target = nwords instructions after the start
def push(r): return 0x37 << 26 | r << 22 | 1 << 16
def pop(r): return 0x37 << 26 | r << 18
def movctr_from(rs): return 0x37 << 26 | rs << 22 | 3 << 16
def movctr_to(rd): return 0x37 << 26 | rd << 18 | 2 << 16
def lsra(rd, rs, sh, mask): return ri(0x6, rd, rs, mask << 5 | sh)
def andm(rd, rs, sh, f): return ri(0x7, rd, rs, f << 5 | sh)
def orm(rd, rs, sh, f): return ri(0x8, rd, rs, f << 5 | sh)
def lsrad(rd, rs, sh, mask): return ri(0x16, rd, rs, mask << 6 | sh)
def andd_m(rd, rs, sh, f): return ri(0x17, rd, rs, f << 6 | sh)
def ord_m(rd, rs, sh, f): return ri(0x18, rd, rs, f << 6 | sh)
ADD, SUB, LSL, LSR, AND, ORR, EOR, SEQ, SNE, SGT, SGE, MUL = 1, 2, 4, 5, 9, 10, 11, 12, 13, 14, 15, 16
D = 16   # 64-bit variants are +16 (c/a codes 17, 18, 20, 21, 25..31)

M32 = 0xffffffff
M64 = 0xffffffffffffffff
H = lambda *r: ','.join(r)

CASES = []
def case(name, words, init, expect): CASES.append((name, words, init, expect))

# ---- 32-bit versus 64-bit ALU
case('add32_wraps_and_zero_extends', [rr(ADD, 4, 2, 3)], 'r2=ffffffff,r3=1,r4=dead00000000', 'r4=0')
case('addd_carries_into_upper_half', [rr(ADD + D, 4, 2, 3)], 'r2=ffffffff,r3=1', 'r4=100000000')
case('sub32_borrow', [rr(SUB, 4, 2, 3)], 'r2=0,r3=1', 'r4=ffffffff')
case('subd_borrow', [rr(SUB + D, 4, 2, 3)], 'r2=0,r3=1', 'r4=ffffffffffffffff')
case('lsl32_drops_bit31', [rr(LSL, 4, 2, 3)], 'r2=80000001,r3=1', 'r4=2')
case('lsld_keeps_bit31', [rr(20, 4, 2, 3)], 'r2=80000001,r3=1', 'r4=100000002')
case('lsr32', [rr(LSR, 4, 2, 3)], 'r2=80000001,r3=4', 'r4=8000000')
case('lsrd_from_upper_half', [rr(21, 4, 2, 3)], 'r2=123400000000,r3=20', 'r4=1234')
case('logic_and_orr_eor', [rr(AND, 4, 2, 3), rr(ORR, 5, 2, 3), rr(EOR, 6, 2, 3)], 'r2=f0f0,r3=ff00', 'r4=f000,r5=fff0,r6=0ff0')
case('logic64_and_orr_eor', [rr(25, 4, 2, 3), rr(26, 5, 2, 3), rr(27, 6, 2, 3)], 'r2=ff00000000000000,r3=f00000000000000f', 'r4=f000000000000000,r5=ff0000000000000f,r6=0f0000000000000f')
case('set_eq_ne', [rr(SEQ, 4, 2, 3), rr(SNE, 5, 2, 3), rr(SEQ, 6, 2, 2)], 'r2=7,r3=8', 'r4=0,r5=1,r6=1')
case('set_gt_ge_signed', [rr(SGT, 4, 2, 3), rr(SGE, 5, 2, 3), rr(SGT, 6, 3, 2), rr(SGE, 7, 2, 2)], 'r2=ffffffff,r3=1', 'r4=0,r5=0,r6=1,r7=1')
case('set64_gt_signed', [rr(30, 4, 2, 3), rr(28, 5, 2, 2), rr(31, 6, 3, 2)], 'r2=ffffffffffffffff,r3=1', 'r4=0,r5=1,r6=1')
case('mul_low16', [rr(MUL, 4, 2, 3)], 'r2=10003,r3=20005,r4=ffff00000000', 'r4=f')
case('mov_reg_reg_and_r0_reads_zero', [rr(ADD, 4, 2, 0), rr(ADD, 5, 0, 0), rr(ADD, 6, 2, 0)], 'r2=1234567890,r5=55', 'r4=34567890,r5=0')
case('write_to_r0_is_lost', [ri(ADD, 0, 2, 1), ri(ADD, 4, 0, 0)], 'r2=9', 'r4=0')
# ---- immediates
case('add_imm_zero_ext', [ri(ADD, 4, 2, 0x7fff), ri(ADD, 5, 2, 0xffff)], 'r2=2', 'r4=8001,r5=10001')
case('add_imm_sign_ext_32', [ri(ADD, 4, 2, 0xffff, b=1)], 'r2=5', 'r4=4')
case('addd_imm_sign_ext_64', [ri(17, 4, 2, 0xffff, b=1), ri(17, 5, 2, 0xffff)], 'r2=0', 'r4=ffffffffffffffff,r5=ffff')
case('sub_imm', [ri(SUB, 4, 2, 1)], 'r2=10000', 'r4=ffff')
case('and_orr_eor_imm_sign_ext', [ri(AND, 4, 2, 0x8000, b=1), ri(ORR, 5, 2, 0x8000, b=1), ri(EOR, 6, 2, 0xff00)], 'r2=12345678', 'r4=12340000,r5=ffffd678,r6=1234a978')
case('lsl_lsr_imm', [ri(LSL, 4, 2, 4), ri(LSR, 5, 2, 8)], 'r2=12345678', 'r4=23456780,r5=123456')
case('set_imm', [ri(SEQ, 4, 2, 5), ri(SGT, 5, 2, 5), ri(SGE, 6, 2, 6)], 'r2=5', 'r4=1,r5=0,r6=0')
case('mov_imm_forms', [ri(ADD, 4, 0, 0x1234), ri(ADD, 5, 0, 0x8000, b=1), ri(0x30, 6, 0, 0x1234, b=1), ri(0x30, 7, 0, 0x1234, b=2), ri(0x30, 8, 0, 0x1234, b=3), ri(0x30, 9, 0, 0xbeef)],
     '-', 'r4=1234,r5=ffff8000,r6=ffff1234,r7=12340000,r8=1234ffff,r9=beef')
case('lsra_bitfield_extract', [lsra(4, 2, 8, 0xff)], 'r2=abcd1234', 'r4=12')
case('and_field_mask32', [andm(4, 2, 8, 0xff)], 'r2=ffffffff', 'r4=fff8ffff')
case('mov_orr_shifted_field', [orm(4, 0, 4, 3), orm(5, 2, 4, 3)], 'r2=1', 'r4=30,r5=31')
case('lsrad_extract64', [lsrad(4, 2, 4, 0xff)], 'r2=123456789', 'r4=78')
case('andd_field_mask64', [andd_m(4, 2, 32, 0)], 'r2=ffffffffffffffff', 'r4=fffffc00ffffffff')
case('movd_orrd_shifted_field64', [ord_m(4, 0, 40, 1), ord_m(5, 2, 40, 1)], 'r2=7', 'r4=10000000000,r5=10000000007')
# ---- control flow (instruction memory is byte-addressed; a branch target is the word number * 4)
case('b_skips', [abs_br(B, 2), ri(ADD, 4, 0, 1), ri(ADD, 5, 0, 2)], '-', 'r4=0,r5=2')
case('b_reg', [lambda s: ri(ADD, 3, 0, s // 4 + 3), br(0x21, rs=3), ri(ADD, 4, 0, 1), ri(ADD, 5, 0, 2)], '-', 'r4=0,r5=2')
case('cbz_taken', [br(CBZ, rs=2, imm=2), ri(ADD, 4, 0, 1), ri(ADD, 5, 0, 2)], 'r2=0', 'r4=0,r5=2')
case('cbz_not_taken', [br(CBZ, rs=2, imm=2), ri(ADD, 4, 0, 1), ri(ADD, 5, 0, 2)], 'r2=3', 'r4=1,r5=2')
case('cbnz_taken_and_not', [br(CBNZ, rs=2, imm=2), ri(ADD, 4, 0, 1), br(CBNZ, rs=0, imm=2), ri(ADD, 5, 0, 2), ri(ADD, 6, 0, 3)], 'r2=3', 'r4=0,r5=2,r6=3')
case('cbz_backwards_loop', [ri(ADD, 4, 4, 1), ri(SUB, 2, 2, 1), br(CBNZ, rs=2, imm=-2)], 'r2=4', 'r4=4,r2=0')
case('bl_ret', [abs_br(BL, 3), ri(ADD, 5, 0, 7), abs_br(B, 5), ri(ADD, 4, 0, 9), RET], '-', 'r4=9,r5=7,lr=@S4@')
# ---- memory
case('stw_ldw_data', [st(0x33, 2, 3, 2), ld(0x31, 4, 3, 2)], 'r2=1122334455,r3=10', 'DM@4:12=22334455,r4=22334455')
case('std_ldd_data', [st(0x34, 2, 3, 4), ld(0x32, 4, 3, 4)], 'r2=1122334455667788,r3=10', 'DM@4:14=55667788,DM@4:15=11223344,r4=1122334455667788')
case('stw_ldw_reg_space', [st(0x33, 2, 3, 1, b=1), ld(0x31, 4, 3, 1, b=1)], 'r2=a5a5,r3=100', 'RM@4:101=a5a5,r4=a5a5')
case('stw_ldw_mem_space', [st(0x33, 2, 3, 1, b=2), ld(0x31, 4, 3, 1, b=2)], 'r2=b6b6,r3=200', 'SM@4:201=b6b6,r4=b6b6')
case('stw_ldw_unk_space', [st(0x33, 2, 3, 1, b=3), ld(0x31, 4, 3, 1, b=3)], 'r2=c7c7,r3=300', 'XM@4:301=c7c7,r4=c7c7')
case('spaces_are_separate', [st(0x33, 2, 0, 5), st(0x33, 3, 0, 5, b=1), ld(0x31, 4, 0, 5), ld(0x31, 5, 0, 5, b=1)], 'r2=11,r3=22', 'DM@4:5=11,RM@4:5=22,r4=11,r5=22')
case('stw_stores_low_32_bits', [st(0x33, 2, 0, 0)], 'r2=123456789abc', 'DM@4:0=56789abc')
case('stw_imm', [sti(9, 3, 1), sti(15, 3, 2, b=2)], 'r3=20', 'DM@4:21=9,SM@4:22=f')
case('ldw_zero_extends', [ld(0x31, 4, 0, 1)], 'r4=ffffffffffffffff,DM@4:1=80000000', 'r4=80000000')
case('push_pop', [push(2), push(3), pop(4), pop(5)], 'r2=11223344,r3=55667788,sp=10', 'r4=55667788,r5=11223344,sp=10,DM@4:10=11223344,DM@4:11=55667788')
case('ctr_moves', [movctr_from(2), movctr_to(4)], 'r2=123456789,r4=ffff00000000', 'ctr=23456789,r4=23456789')
case('stm_repeats_ctr_times', [st(0x35, 2, 3, 4)], 'r2=aa,r3=40,ctr=3', 'DM@4:44=aa,DM@4:45=aa,DM@4:46=aa,DM@4:47=0,ctr=0')
case('stm_zero_count', [st(0x35, 2, 3, 4)], 'r2=aa,r3=40,ctr=0', 'DM@4:44=0,ctr=0')
# ---- hardware side effects stay pcodeops
case('btab_is_a_pcodeop', [BTAB], '-', 'TRAP=btab')
case('r1_read_pops_the_queue', [rr(ADD, 4, 1, 0)], '-', 'TRAP=cp_queue_read')
case('stm_from_r1_pops_the_queue', [st(0x35, 1, 3, 0)], 'ctr=2', 'TRAP=cp_queue_read')
# ---- the check itself must be able to fail
case('XFAIL_wrong_sum', [rr(ADD, 4, 2, 3)], 'r2=1,r3=1', 'r4=3')
case('XFAIL_wrong_memory', [st(0x33, 2, 0, 0)], 'r2=1', 'DM@4:0=2')

BASE, STRIDE = 0x1000, 0x100

def main():
    work = os.path.abspath(sys.argv[1])
    os.makedirs(work, exist_ok=True)
    img = bytearray(BASE + len(CASES) * STRIDE)
    lines = []
    for n, (name, words, init, expect) in enumerate(CASES):
        s = BASE + n * STRIDE
        for i, w in enumerate(words):
            struct.pack_into('>I', img, s + 4 * i, (w(s) if callable(w) else w) & M32)
        e = s + 4 * len(words)
        wordaddr = lambda t: re.sub(r'\b([A-Z]M)@(\d+):([0-9a-f]+)', lambda m: f'{m.group(1)}@{m.group(2)}:{int(m.group(3), 16) * 4:x}', t)   # Address offsets in a word-addressed space are byte offsets
        fix = lambda t: wordaddr(t.replace('@END@', f'{e:x}').replace('@S4@', f'{s + 4:x}'))
        lines.append(f'{name} {s:x} {e:x} {fix(init)} {fix(expect)}')
    open(os.path.join(work, 'tests_le.txt'), 'w').write('\n'.join(lines) + '\n')
    open(os.path.join(work, 'tests_be.txt'), 'w').write('\n'.join(lines).replace('@', '#') + '\n')   # the BE language stores words big-endian
    open(os.path.join(work, 'emu_be.bin'), 'wb').write(img)
    le = bytearray(len(img))
    for i in range(0, len(img), 4):
        le[i:i+4] = img[i:i+4][::-1]
    open(os.path.join(work, 'emu_le.bin'), 'wb').write(le)
    print(len(CASES), 'cases')

if __name__ == '__main__':
    main()
