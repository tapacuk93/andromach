// Program start, as the Linux kernel's ELF loader does it: map the executable and its
// interpreter (Android's linker64), build the initial stack with argv, envp and auxv, and jump
// to the interpreter. Everything after that, shared libraries included, is the guest linker's
// work through ordinary system calls.
#include "am.h"
#include "linux.h"
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <unistd.h>

// The ELF definitions used here (Darwin has no <elf.h>).
typedef struct {
    unsigned char e_ident[16];
    uint16_t e_type, e_machine;
    uint32_t e_version;
    uint64_t e_entry, e_phoff, e_shoff;
    uint32_t e_flags;
    uint16_t e_ehsize, e_phentsize, e_phnum, e_shentsize, e_shnum, e_shstrndx;
} Elf64_Ehdr;
typedef struct {
    uint32_t p_type, p_flags;
    uint64_t p_offset, p_vaddr, p_paddr, p_filesz, p_memsz, p_align;
} Elf64_Phdr;
#define ELFMAG "\177ELF"
#define SELFMAG 4
#define EM_AARCH64 183
enum { PT_LOAD = 1, PT_INTERP = 3, PT_PHDR = 6 };
enum { PF_X = 1, PF_W = 2, PF_R = 4 };
enum { AT_NULL = 0, AT_PHDR = 3, AT_PHENT = 4, AT_PHNUM = 5, AT_PAGESZ = 6, AT_BASE = 7, AT_FLAGS = 8,
       AT_ENTRY = 9, AT_UID = 11, AT_EUID = 12, AT_GID = 13, AT_EGID = 14, AT_PLATFORM = 15,
       AT_HWCAP = 16, AT_CLKTCK = 17, AT_SECURE = 23, AT_RANDOM = 25, AT_HWCAP2 = 26 };

typedef struct { uint64_t base, entry, phdr; uint16_t phnum; char interp[256]; } loaded;

#define PAGE_DOWN(x) ((x) & ~(uint64_t)(AM_PAGE - 1))
#define PAGE_UP(x) PAGE_DOWN((x) + AM_PAGE - 1)

static long load_elf(const char *gpath, loaded *out, char *canon, size_t canonsz) {
    am_file *f;
    long r = am_open(gpath, LINUX_AT_FDCWD, LINUX_O_RDONLY, 0, &f);
    if (r < 0) return r;
    if (canon) {
        snprintf(canon, canonsz, "%s", f->gpath);
    }
    Elf64_Ehdr eh;
    if (am_pread(f, &eh, sizeof eh, 0) != sizeof eh || memcmp(eh.e_ident, ELFMAG, SELFMAG) ||
        eh.e_machine != EM_AARCH64 || eh.e_phentsize != sizeof(Elf64_Phdr)) {
        am_file_put(f);
        return AM_ERR(8);  // ENOEXEC
    }
    Elf64_Phdr ph[eh.e_phnum];
    am_pread(f, ph, sizeof ph, eh.e_phoff);
    uint64_t lo = ~0ull, hi = 0;
    out->interp[0] = 0;
    out->phdr = 0;
    for (int i = 0; i < eh.e_phnum; i++) {
        if (ph[i].p_type == PT_LOAD) {
            if (PAGE_DOWN(ph[i].p_vaddr) < lo) lo = PAGE_DOWN(ph[i].p_vaddr);
            if (PAGE_UP(ph[i].p_vaddr + ph[i].p_memsz) > hi) hi = PAGE_UP(ph[i].p_vaddr + ph[i].p_memsz);
        } else if (ph[i].p_type == PT_INTERP) {
            size_t n = ph[i].p_filesz < sizeof out->interp ? ph[i].p_filesz : sizeof out->interp - 1;
            am_pread(f, out->interp, n, ph[i].p_offset);
            out->interp[n] = 0;
        } else if (ph[i].p_type == PT_PHDR) {
            out->phdr = ph[i].p_vaddr;
        }
    }
    // PIE and shared objects only: reserve the whole span, then place each segment in it.
    long res_r = am_mmap(0, hi - lo, 0, LINUX_MAP_PRIVATE | LINUX_MAP_ANONYMOUS, -1, 0);
    if (res_r < 0) { am_file_put(f); return AM_ERR(LINUX_ENOMEM); }
    void *res = (void *)res_r;
    uint64_t bias = (uint64_t)res - lo;
    int fd = am_fd_install(am_self->proc, f, 3, true);
    for (int i = 0; i < eh.e_phnum; i++) {
        if (ph[i].p_type != PT_LOAD) continue;
        Elf64_Phdr *p = &ph[i];
        int prot = (p->p_flags & PF_R ? LINUX_PROT_READ : 0) | (p->p_flags & PF_W ? LINUX_PROT_WRITE : 0) |
                   (p->p_flags & PF_X ? LINUX_PROT_EXEC : 0);
        uint64_t start = PAGE_DOWN(bias + p->p_vaddr);
        uint64_t file_end = bias + p->p_vaddr + p->p_filesz;
        uint64_t mem_end = PAGE_UP(bias + p->p_vaddr + p->p_memsz);
        if (p->p_filesz) {
            r = am_mmap(start, PAGE_UP(file_end) - start, prot | (p->p_memsz > p->p_filesz ? LINUX_PROT_WRITE : 0),
                        LINUX_MAP_PRIVATE | LINUX_MAP_FIXED, fd, PAGE_DOWN(p->p_offset));
            if (r < 0) { fprintf(stderr, "andromach: mapping %s: %ld\n", gpath, r); goto fail; }
        }
        if (p->p_memsz > p->p_filesz) {
            if (file_end % AM_PAGE) memset((void *)file_end, 0, PAGE_UP(file_end) - file_end);
            if (mem_end > PAGE_UP(file_end))
                am_mmap(PAGE_UP(file_end), mem_end - PAGE_UP(file_end), prot,
                        LINUX_MAP_PRIVATE | LINUX_MAP_FIXED | LINUX_MAP_ANONYMOUS, -1, 0);
            if (!(prot & LINUX_PROT_WRITE)) mprotect((void *)start, PAGE_UP(file_end) - start, PROT_READ);
        }
    }
    out->base = bias;
    out->entry = bias + eh.e_entry;
    out->phdr = out->phdr ? bias + out->phdr : bias + lo + eh.e_phoff;
    out->phnum = eh.e_phnum;
    // The kernel does not leave the file open in the new process.
    am_self->proc->fds[fd] = NULL;
    am_file_put(f);
    return 0;
fail:
    am_self->proc->fds[fd] = NULL;
    am_file_put(f);
    return r;
}

// Hardware capabilities to advertise: what Apple's cores have and needs no kernel help (no
// CPUID register emulation, no PAC key management, no SVE).
#define HWCAP_M1 (0x7FF & ~(1u << 11)) | (1u << 12) | (1u << 13) | (1u << 14) | (1u << 15) | \
    (1u << 16) | (1u << 17) | (1u << 20) | (1u << 21) | (1u << 23) | (1u << 24) | (1u << 25) | \
    (1u << 26) | (1u << 27) | (1u << 28) | (1u << 29)

// Builds the initial stack and fills c so that resuming it starts the program.
long am_exec(am_ctx *c, const char *gpath, char *const argv[], char *const envp[]) {
    loaded exe, interp;
    char canon[1024];
    long r = load_elf(gpath, &exe, canon, sizeof canon);
    if (r < 0) return r;
    uint64_t entry = exe.entry, interp_base = 0;
    if (exe.interp[0]) {
        r = load_elf(exe.interp, &interp, NULL, 0);
        if (r < 0) { fprintf(stderr, "andromach: interpreter %s: %ld\n", exe.interp, r); return r; }
        entry = interp.entry;
        interp_base = interp.base;
    }
    am_proc *p = am_self->proc;
    snprintf(p->exe, sizeof p->exe, "%s", canon);
    size_t cl = 0;
    for (int i = 0; argv[i]; i++) cl += strlen(argv[i]) + 1;
    free(p->cmdline);
    p->cmdline = malloc(cl ? cl : 1);
    p->cmdline_len = 0;
    for (int i = 0; argv[i]; i++) {
        size_t n = strlen(argv[i]) + 1;
        memcpy(p->cmdline + p->cmdline_len, argv[i], n);
        p->cmdline_len += n;
    }

    size_t stack_size = 8 << 20;
    long stack_r = am_mmap(0, stack_size, LINUX_PROT_READ | LINUX_PROT_WRITE, LINUX_MAP_PRIVATE | LINUX_MAP_ANONYMOUS, -1, 0);
    if (stack_r < 0) return AM_ERR(LINUX_ENOMEM);
    uint8_t *stack = (uint8_t *)stack_r;
    uint8_t *sp = stack + stack_size;
    int argc = 0, envc = 0;
    while (argv[argc]) argc++;
    while (envp[envc]) envc++;
    uint64_t argp[argc + 1], envpp[envc + 1];
#define PUSH_STR(s) ({ size_t _n = strlen(s) + 1; sp -= _n; memcpy(sp, s, _n); (uint64_t)sp; })
    uint64_t execfn = PUSH_STR(canon);
    uint64_t platform = PUSH_STR("aarch64");
    for (int i = envc - 1; i >= 0; i--) envpp[i] = PUSH_STR(envp[i]);
    for (int i = argc - 1; i >= 0; i--) argp[i] = PUSH_STR(argv[i]);
    argp[argc] = envpp[envc] = 0;
    sp = (uint8_t *)((uintptr_t)sp & ~15ul) - 16;
    arc4random_buf(sp, 16);
    uint64_t random = (uint64_t)sp;
    uint64_t aux[][2] = {
        {AT_PHDR, exe.phdr}, {AT_PHENT, sizeof(Elf64_Phdr)}, {AT_PHNUM, exe.phnum},
        {AT_PAGESZ, AM_PAGE}, {AT_BASE, interp_base}, {AT_FLAGS, 0}, {AT_ENTRY, exe.entry},
        {AT_UID, 0}, {AT_EUID, 0}, {AT_GID, 0}, {AT_EGID, 0}, {AT_PLATFORM, platform},
        {AT_HWCAP, HWCAP_M1}, {AT_CLKTCK, 100}, {AT_SECURE, 0}, {AT_RANDOM, random},
        {AT_HWCAP2, 0}, {31 /* AT_EXECFN */, execfn}, {51 /* AT_MINSIGSTKSZ */, 5120}, {AT_NULL, 0},
    };
    size_t words = 1 + argc + 1 + envc + 1 + 2 * (sizeof aux / sizeof *aux);
    sp -= words * 8;
    sp = (uint8_t *)((uintptr_t)sp & ~15ul);
    uint64_t *w = (uint64_t *)sp;
    *w++ = argc;
    memcpy(w, argp, (argc + 1) * 8); w += argc + 1;
    memcpy(w, envpp, (envc + 1) * 8); w += envc + 1;
    memcpy(w, aux, sizeof aux);

    memset(c, 0, sizeof *c);
    c->sp = (uint64_t)sp;
    c->pc = entry;
    return 0;
}
