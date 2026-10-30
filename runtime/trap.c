// The SIGTRAP side of the guest/host boundary: the `brk` traps amc leaves where it could not use
// a stub, am_resume's context switch, and reports of guest faults.
#include "am.h"
#include <dlfcn.h>
#include <mach/mach.h>
#include <mach/mach_vm.h>
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
    t[AM_TSD_HOST_STACK] = am_self ? (uint64_t)am_self->host_stack_top : 0;
}

static void trap_syscall(void *c) { am_syscall(c, 1); }

void am_ctx_from_mc(am_ctx *c, const void *mv) {
    const struct __darwin_mcontext64 *m = mv;
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

void am_ctx_to_mc(void *mv, const am_ctx *c) {
    struct __darwin_mcontext64 *m = mv;
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

static void where(const char *name, uint64_t a) {
    Dl_info d;
    if (dladdr((void *)a, &d) && d.dli_sname)
        fprintf(stderr, "  %s %#llx = %s+%#llx (%s)\n", name, (unsigned long long)a, d.dli_sname,
                (unsigned long long)(a - (uint64_t)d.dli_saddr), strrchr(d.dli_fname, '/') + 1);
}

static void dump(const char *what, const struct __darwin_mcontext64 *m, uint64_t addr) {
    fprintf(stderr, "andromach: %s at pc=%#llx addr=%#llx tid=%d\n", what,
            (unsigned long long)m->__ss.__pc, (unsigned long long)addr, am_self ? am_self->tid : -1);
    for (int i = 0; i < 29; i++)
        fprintf(stderr, "  x%-2d %016llx%s", i, (unsigned long long)m->__ss.__x[i], i % 4 == 3 ? "\n" : "");
    fprintf(stderr, "  fp  %016llx  lr  %016llx  sp  %016llx\n", (unsigned long long)m->__ss.__fp,
            (unsigned long long)m->__ss.__lr, (unsigned long long)m->__ss.__sp);
    if (am_self) {
        am_proc *p = am_self->proc;
        int hit = 0;
        for (int i = 0; i < p->nvma; i++)
            if (addr >= p->vmas[i].start && addr < p->vmas[i].end) {
                fprintf(stderr, "  addr in pid %d range %#llx-%#llx\n", p->pid, (unsigned long long)p->vmas[i].start,
                        (unsigned long long)p->vmas[i].end);
                hit = 1;
            }
        if (!hit) fprintf(stderr, "  addr in none of pid %d's %d ranges\n", p->pid, p->nvma);
    }
    mach_vm_address_t r = addr;
    mach_vm_size_t sz;
    vm_region_extended_info_data_t info;
    mach_msg_type_number_t cnt = VM_REGION_EXTENDED_INFO_COUNT;
    mach_port_t obj;
    if (!mach_vm_region(mach_task_self(), &r, &sz, VM_REGION_EXTENDED_INFO, (vm_region_info_t)&info, &cnt, &obj))
        fprintf(stderr, "  kernel: region %#llx+%#llx prot %d share_mode %d pages resident %u\n", (unsigned long long)r,
                (unsigned long long)sz, info.protection, info.share_mode, info.pages_resident);
    where("pc", m->__ss.__pc);
    where("lr", m->__ss.__lr);
    // the frame chain, while it stays in host code
    uint64_t *fp = (uint64_t *)m->__ss.__fp;
    for (int i = 0; i < 12 && fp && ((uint64_t)fp & 7) == 0; i++, fp = (uint64_t *)fp[0]) where("  ", fp[1]);
}

// A fault in guest code becomes the guest's signal; without a guest handler it ends the process.
static void guest_fault(struct __darwin_mcontext64 *m, int lsig, int code, uint64_t addr, const char *what) {
    am_ctx c;
    am_ctx_from_mc(&c, m);
    if (getenv("AM_DEBUG")) dump(what, m, addr);
    if (am_signal_fault(lsig, code, addr, &c)) {
        am_ctx_to_mc(m, &c);
        return;
    }
    dump(what, m, addr);
    am_proc_exit(lsig);
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
        am_ctx_from_mc(&c, m);
        c.pc += 4;
        am_call_on_host_stack(trap_syscall, &c);
        am_ctx_to_mc(m, &c);
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
        am_ctx_to_mc(m, (const am_ctx *)m->__ss.__x[0]);
    } else {
        // The guest's own breakpoint (__builtin_trap, abort's last resort): SIGTRAP to it.
        guest_fault(m, 5, 1 /* TRAP_BRKPT */, m->__ss.__pc, "guest brk");
    }
}

static void on_fault(int sig, siginfo_t *si, void *uv) {
    struct __darwin_mcontext64 *m = ((ucontext_t *)uv)->uc_mcontext;
    const char *what = sig == SIGSEGV ? "SIGSEGV" : sig == SIGBUS ? "SIGBUS" : sig == SIGILL ? "SIGILL" : "SIGFPE";
    if (!am_self || am_self->in_runtime) {
        // The runtime's own fault (or a bad pointer handed to a system call): stop here.
        dump(what, m, (uint64_t)si->si_addr);
        fprintf(stderr, "andromach: fault inside the runtime\n");
        _exit(128 + sig);
    }
    // Linux numbers: SIGSEGV 11, SIGBUS 7, SIGILL 4, SIGFPE 8. Darwin reports some bad
    // accesses as SIGBUS that Linux would call SIGSEGV; unmapped/protection faults are SEGV.
    int lsig = sig == SIGSEGV || sig == SIGBUS ? 11 : sig == SIGILL ? 4 : 8;
    int code = si->si_code == SEGV_ACCERR ? 2 : 1;
    guest_fault(m, lsig, code, (uint64_t)si->si_addr, what);
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
