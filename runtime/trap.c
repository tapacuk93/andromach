// The SIGTRAP side of the guest/host boundary: the `brk` traps amc leaves where it could not use
// a stub, am_resume's context switch, and reports of guest faults.
#include "am.h"
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/ucontext.h>

static inline uint64_t *tsd_base(void) {
    uint64_t v;
    __asm__ volatile("mrs %0, tpidrro_el0" : "=r"(v));
    return (uint64_t *)v;
}

void am_thread_tsd_init(uint64_t guest_tp) {
    uint64_t *t = tsd_base();
    t[AM_TSD_GUEST_TP] = guest_tp;
    t[AM_TSD_ENTRY] = (uint64_t)am_syscall_entry;
}

static void ctx_from_mc(am_ctx *c, const struct __darwin_mcontext64 *m) {
    memcpy(c->x, m->__ss.__x, sizeof m->__ss.__x);
    c->x[29] = m->__ss.__fp;
    c->x[30] = m->__ss.__lr;
    c->sp = m->__ss.__sp;
    c->pc = m->__ss.__pc;
    c->pstate = m->__ss.__cpsr;
    memcpy(c->v, m->__ns.__v, sizeof c->v);
    c->fpsr = m->__ns.__fpsr;
    c->fpcr = m->__ns.__fpcr;
}

static void ctx_to_mc(struct __darwin_mcontext64 *m, const am_ctx *c) {
    memcpy(m->__ss.__x, c->x, sizeof m->__ss.__x);
    m->__ss.__fp = c->x[29];
    m->__ss.__lr = c->x[30];
    m->__ss.__sp = c->sp;
    m->__ss.__pc = c->pc;
    // Only the condition flags are the guest's to set.
    m->__ss.__cpsr = (m->__ss.__cpsr & ~0xF0000000u) | ((uint32_t)c->pstate & 0xF0000000u);
    memcpy(m->__ns.__v, c->v, sizeof c->v);
    m->__ns.__fpsr = c->fpsr;
    m->__ns.__fpcr = c->fpcr;
}

static void dump(const char *what, const struct __darwin_mcontext64 *m, uint64_t addr) {
    fprintf(stderr, "andromach: %s at pc=%#llx addr=%#llx tid=%d\n", what,
            (unsigned long long)m->__ss.__pc, (unsigned long long)addr, am_self ? am_self->tid : -1);
    for (int i = 0; i < 29; i++)
        fprintf(stderr, "  x%-2d %016llx%s", i, (unsigned long long)m->__ss.__x[i], i % 4 == 3 ? "\n" : "");
    fprintf(stderr, "  fp  %016llx  lr  %016llx  sp  %016llx\n", (unsigned long long)m->__ss.__fp,
            (unsigned long long)m->__ss.__lr, (unsigned long long)m->__ss.__sp);
}

static void on_trap(int sig, siginfo_t *si, void *uv) {
    (void)sig; (void)si;
    struct __darwin_mcontext64 *m = ((ucontext_t *)uv)->uc_mcontext;
    uint32_t insn = *(uint32_t *)m->__ss.__pc;
    if ((insn & 0xFFE0001F) != 0xD4200000) {
        dump("SIGTRAP", m, 0);
        _exit(133);
    }
    unsigned imm = (insn >> 5) & 0xFFFF;
    uint64_t *tsd = tsd_base();
    if (imm == AM_TRAP_SVC) {
        am_ctx c;
        ctx_from_mc(&c, m);
        c.pc += 4;
        am_syscall(&c);
        ctx_to_mc(m, &c);
    } else if ((imm & ~31u) == AM_TRAP_MRS_TP) {
        if ((imm & 31) < 29) m->__ss.__x[imm & 31] = tsd[AM_TSD_GUEST_TP];
        else if ((imm & 31) == 29) m->__ss.__fp = tsd[AM_TSD_GUEST_TP];
        else m->__ss.__lr = tsd[AM_TSD_GUEST_TP];
        m->__ss.__pc += 4;
    } else if ((imm & ~31u) == AM_TRAP_MSR_TP) {
        unsigned r = imm & 31;
        tsd[AM_TSD_GUEST_TP] = r < 29 ? m->__ss.__x[r] : r == 29 ? m->__ss.__fp : r == 30 ? m->__ss.__lr : 0;
        m->__ss.__pc += 4;
    } else if (imm == AM_TRAP_RESUME) {
        ctx_to_mc(m, (const am_ctx *)m->__ss.__x[0]);
    } else {
        // A guest's own breakpoint (__builtin_trap, abort). Signal delivery to the guest
        // comes later; for now report it.
        dump("guest brk", m, imm);
        _exit(133);
    }
}

static void on_fault(int sig, siginfo_t *si, void *uv) {
    struct __darwin_mcontext64 *m = ((ucontext_t *)uv)->uc_mcontext;
    dump(sig == SIGSEGV ? "SIGSEGV" : sig == SIGBUS ? "SIGBUS" : sig == SIGILL ? "SIGILL" : "SIGFPE",
         m, (uint64_t)si->si_addr);
    _exit(128 + sig);
}

void am_trap_init(void) {
    struct sigaction sa = {0};
    sa.sa_sigaction = on_trap;
    sa.sa_flags = SA_SIGINFO | SA_NODEFER;
    sigaction(SIGTRAP, &sa, NULL);
    sa.sa_sigaction = on_fault;
    sa.sa_flags = SA_SIGINFO;
    sigaction(SIGSEGV, &sa, NULL);
    sigaction(SIGBUS, &sa, NULL);
    sigaction(SIGILL, &sa, NULL);
    sigaction(SIGFPE, &sa, NULL);
}
