#!/usr/bin/env python3
"""amc - the andromach precompiler: an Android arm64 ELF file in, a signable Mach-O image out.

iOS only runs machine code from signed files, so every ELF the guest will map executable is
turned into a Mach-O image at build time. The image is

    [0, 0x4000)            Mach-O header and load commands, plus an andromach marker
    [0x4000, 0x4000 + P)   the payload: the ELF file, rewritten, then a stub segment
    [0x4000 + P, ...)      __LINKEDIT, where codesign puts the signature

and the runtime shows the guest only the payload, so the guest's dynamic linker sees an
ordinary ELF file and maps it where it likes. Pages are hashed by content, so the signed code
stays valid at whatever address it lands.

The payload differs from the original ELF in three kinds of instruction, which on Darwin cannot
run as written:

    svc #0               Linux system call; Darwin would take x16 as a Darwin syscall number
    mrs xN, tpidr_el0    guest thread pointer; Darwin keeps the CPU number in TPIDR_EL0
    msr tpidr_el0, xN    setting it (once per thread, in bionic)

Each `svc` and `mrs` becomes a branch to a stub in a new PT_LOAD segment appended after the
last one (made from a PT_NOTE entry, which the dynamic linker does not need). The stubs reach
the runtime through Darwin's per-thread data, whose base is in TPIDRRO_EL0:

    mrs:  mrs xN, tpidrro_el0 ; ldr xN, [xN, #TSD_GUEST_TP*8] ; b back
    svc:  stp x16, x30, [sp, #-16]! ; mrs x16, tpidrro_el0 ; ldr x16, [x16, #TSD_ENTRY*8]
          blr x16 ; ldp x16, x30, [sp], #16 ; b back

Anything else (msr, or a file without a PT_NOTE to repurpose) becomes `brk #TRAP_*`, which the
runtime handles in its SIGTRAP handler. Code that verifies its own bytes (BoringSSL's FIPS
module) gets its expected hash recomputed over the rewritten code. The constants are shared with runtime/am.h.

    amc.py [--platform ios|macos] <in.elf> <out.image>
"""
import argparse, hashlib, hmac, struct, sys

PAGE = 0x4000
HEADER = 0x4000
MARKER_OFF = 0x3000
MARKER = b'ANDROMACH-IMAGE\0'
IMAGE_VERSION = 1

TSD_GUEST_TP = 110       # __PTK_FRAMEWORK_GC_KEY0: reserved by libpthread, unused since ObjC GC
TSD_ENTRY = 111          # address of am_syscall_entry

TRAP_SVC = 0xA500
TRAP_MRS_TP = 0xA520     # | register
TRAP_MSR_TP = 0xA540     # | register

SVC0 = 0xD4000001
MRS_TP = 0xD53BD040      # mrs xN, tpidr_el0
MSR_TP = 0xD51BD040      # msr tpidr_el0, xN

PT_LOAD, PT_NOTE = 1, 4
PF_X, PF_R = 1, 4
SHF_EXECINSTR = 4
STUB_SVC_WORDS = 6
STUB_MRS_WORDS = 3
B_RANGE = 1 << 27        # +-128 MiB


def align(x, a=PAGE):
    return (x + a - 1) // a * a


def brk(imm):
    return 0xD4200000 | (imm << 5)


def b(frm, to):
    off = (to - frm) // 4
    assert -(1 << 25) <= off < (1 << 25)
    return 0x14000000 | (off & 0x3FFFFFF)


def ldr_tsd(rt, rn, slot):
    return 0xF9400000 | (slot << 10) | (rn << 5) | rt


def mrs_tpidrro(rt):
    return 0xD53BD060 | rt


class Elf:
    def __init__(self, data):
        self.b = bytearray(data)
        if self.b[:4] != b'\x7fELF' or self.b[4] != 2 or struct.unpack_from('<H', self.b, 18)[0] != 183:
            raise ValueError('not an arm64 ELF64 file')
        (self.phoff, self.shoff) = struct.unpack_from('<QQ', self.b, 0x20)
        (self.phentsize, self.phnum, self.shentsize, self.shnum) = struct.unpack_from('<HHHH', self.b, 0x36)
        self.phdrs = [list(struct.unpack_from('<IIQQQQQQ', self.b, self.phoff + i * self.phentsize))
                      for i in range(self.phnum)]

    def exec_ranges(self):
        """(file offset, size, vaddr) of each executable section; falls back to PF_X segments."""
        out = []
        if self.shoff and self.shnum:
            for i in range(self.shnum):
                sh = struct.unpack_from('<IIQQQQIIQQ', self.b, self.shoff + i * self.shentsize)
                typ, flags, addr, off, size = sh[1], sh[2], sh[3], sh[4], sh[5]
                if typ == 1 and flags & SHF_EXECINSTR and size:   # SHT_PROGBITS
                    out.append((off, size, addr))
        if not out:
            out = [(p[2], p[5], p[3]) for p in self.phdrs if p[0] == PT_LOAD and p[1] & PF_X]
        return out

    def dynamic_symbols(self):
        """{name: value} from .dynsym."""
        out = {}
        if not (self.shoff and self.shnum):
            return out
        shs = [struct.unpack_from('<IIQQQQIIQQ', self.b, self.shoff + i * self.shentsize) for i in range(self.shnum)]
        for sh in shs:
            if sh[1] != 11:  # SHT_DYNSYM
                continue
            stroff = shs[sh[6]][4]
            for k in range(sh[5] // 24):
                name, _, _, _, value, _ = struct.unpack_from('<IBBHQQ', self.b, sh[4] + 24 * k)
                end = self.b.index(0, stroff + name)
                out[self.b[stroff + name:end].decode('latin-1')] = value
        return out

    def file_offset(self, vaddr):
        for p in self.phdrs:
            if p[0] == PT_LOAD and p[3] <= vaddr < p[3] + p[5]:
                return vaddr - p[3] + p[2]
        raise ValueError('vaddr %#x not in the file' % vaddr)

    def write_phdrs(self):
        for i, p in enumerate(self.phdrs):
            struct.pack_into('<IIQQQQQQ', self.b, self.phoff + i * self.phentsize, *p)


def fips_hash(elf, data):
    """BoringSSL's FIPS module checks an HMAC of its own code at startup. Returns (hash, ranges)
    for a library that carries one, or None. The construction is HMAC-SHA256 with a zero key
    over len(text) || text || len(rodata) || rodata, lengths as little-endian u64."""
    syms = elf.dynamic_symbols()
    names = ['BORINGSSL_bcm_text_start', 'BORINGSSL_bcm_text_end', 'BORINGSSL_bcm_rodata_start', 'BORINGSSL_bcm_rodata_end']
    if not all(n in syms for n in names):
        return None
    ts, te, rs, re_ = (elf.file_offset(syms[n]) if 'end' not in n else elf.file_offset(syms[n] - 1) + 1 for n in names)
    return lambda d: hmac.new(bytes(64), struct.pack('<Q', te - ts) + bytes(d[ts:te]) +
                              struct.pack('<Q', re_ - rs) + bytes(d[rs:re_]), hashlib.sha256).digest()


def rewrite(data):
    """Returns (payload, stats) for one ELF file."""
    elf = Elf(data)
    fips = fips_hash(elf, data)
    words = []  # (file offset, vaddr, kind, reg)
    for off, size, addr in elf.exec_ranges():
        for k, w in enumerate(struct.unpack_from('<%dI' % (size // 4), elf.b, off)):
            if w == SVC0:
                words.append((off + 4 * k, addr + 4 * k, 'svc', 0))
            elif w & ~31 == MRS_TP:
                words.append((off + 4 * k, addr + 4 * k, 'mrs', w & 31))
            elif w & ~31 == MSR_TP:
                words.append((off + 4 * k, addr + 4 * k, 'msr', w & 31))

    loads = [p for p in elf.phdrs if p[0] == PT_LOAD]
    end_vaddr = align(max(p[3] + p[6] for p in loads))   # vaddr + memsz
    stub_off = align(len(elf.b))
    note = next((i for i, p in enumerate(elf.phdrs) if p[0] == PT_NOTE), None)

    stubs = []
    stats = {'svc': 0, 'mrs': 0, 'msr': 0, 'trap': 0}
    for off, vaddr, kind, reg in words:
        stats[kind] += 1
        target = end_vaddr + 4 * len(stubs)
        stubbable = (note is not None and kind != 'msr' and abs(target - vaddr) < B_RANGE - 64
                     and reg != 31)
        if not stubbable:
            imm = {'svc': TRAP_SVC, 'mrs': TRAP_MRS_TP | reg, 'msr': TRAP_MSR_TP | reg}[kind]
            struct.pack_into('<I', elf.b, off, brk(imm))
            stats['trap'] += 1
            continue
        back = vaddr + 4
        if kind == 'svc':
            seq = [0xA9BF7BF0, mrs_tpidrro(16), ldr_tsd(16, 16, TSD_ENTRY), 0xD63F0200, 0xA8C17BF0]
        else:
            seq = [mrs_tpidrro(reg), ldr_tsd(reg, reg, TSD_GUEST_TP)]
        seq.append(b(target + 4 * len(seq), back))
        stubs.extend(seq)
        struct.pack_into('<I', elf.b, off, b(vaddr, target))

    if fips:
        # The expected value is stored once, outside the hashed ranges; replace it.
        old, new = fips(data), fips(elf.b)
        at = data.find(old)
        if at < 0 or data.find(old, at + 1) >= 0:
            raise ValueError('FIPS module hash not found exactly once')
        elf.b[at:at + 32] = new
        stats['fips'] = 1

    payload = elf.b
    if stubs:
        size = 4 * len(stubs)
        # PT_NOTE becomes the stub PT_LOAD, moved to just after the last PT_LOAD so the
        # segments stay in address order.
        new = [PT_LOAD, PF_R | PF_X, stub_off, end_vaddr, end_vaddr, size, size, PAGE]
        rest = [p for i, p in enumerate(elf.phdrs) if i != note]
        last_load = max(i for i, p in enumerate(rest) if p[0] == PT_LOAD)
        elf.phdrs = rest[:last_load + 1] + [new] + rest[last_load + 1:]
        elf.write_phdrs()
        payload = elf.b + bytes(stub_off - len(elf.b)) + struct.pack('<%dI' % len(stubs), *stubs)
    stats['stub_bytes'] = 4 * len(stubs)
    return bytes(payload), stats


def macho(payload, name, platform):
    """Wraps the payload in a Mach-O dylib whose __TEXT covers it, ready for codesign."""
    text_size = HEADER + align(len(payload))
    linkedit = struct.pack('<4sI', b'\0' * 4, 0)  # empty string table, so codesign has a __LINKEDIT
    cmds = []
    cmds.append(struct.pack('<II16sQQQQIIII', 0x19, 72, b'__TEXT', 0, text_size, 0, text_size, 5, 5, 0, 0))
    cmds.append(struct.pack('<II16sQQQQIIII', 0x19, 72, b'__LINKEDIT', text_size, PAGE, text_size,
                            len(linkedit), 1, 1, 0, 0))
    idname = ('@rpath/' + name).encode() + b'\0'
    idname += b'\0' * (-(24 + len(idname)) % 8)
    cmds.append(struct.pack('<IIIIII', 0xD, 24 + len(idname), 24, 0, 0x10000, 0x10000) + idname)
    cmds.append(struct.pack('<IIIIII', 0x2, 24, text_size, 0, text_size, len(linkedit)))   # LC_SYMTAB
    cmds.append(struct.pack('<II', 0xB, 80) + bytes(72))                                    # LC_DYSYMTAB
    plat, minos = {'ios': (2, 0x110000), 'macos': (1, 0xE0000)}[platform]
    cmds.append(struct.pack('<IIIIII', 0x32, 24, plat, minos, minos, 0))                    # LC_BUILD_VERSION
    body = b''.join(cmds)
    hdr = struct.pack('<IiiIIIII', 0xFEEDFACF, 0x0100000C, 0, 6, len(cmds), len(body), 0x100085, 0)
    head = bytearray(HEADER)
    head[:len(hdr) + len(body)] = hdr + body
    head[MARKER_OFF:MARKER_OFF + 32] = MARKER + struct.pack('<QQ', IMAGE_VERSION, len(payload))
    return bytes(head) + payload + bytes(text_size - HEADER - len(payload)) + linkedit


def is_arm64_elf(data):
    """An arm64 executable or shared object (kernel modules and object files are left alone)."""
    return (data[:4] == b'\x7fELF' and len(data) > 20 and data[4] == 2 and data[18] == 183
            and data[16] in (2, 3))


def compile_file(src, dst, platform='ios'):
    with open(src, 'rb') as f:
        data = f.read()
    payload, stats = rewrite(data)
    with open(dst, 'wb') as f:
        f.write(macho(payload, src.rsplit('/', 1)[-1], platform))
    return stats


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--platform', default='ios', choices=['ios', 'macos'])
    ap.add_argument('src')
    ap.add_argument('dst')
    a = ap.parse_args()
    print(compile_file(a.src, a.dst, a.platform))


if __name__ == '__main__':
    main()
