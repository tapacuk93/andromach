// Signals, as Linux delivers them: per-thread and per-process pending sets, handlers entered
// through a Linux arm64 rt_sigframe on the guest stack, rt_sigreturn, and the default actions.
//
// A signal for a thread running guest code is delivered at once: the sender kicks the target's
// host thread with SIGUSR2, and the handler rewrites the interrupted context. A thread inside a
// system call gets it when the call returns; a blocking call is cut short with EINTR by the same
// kick.
#include "am.h"
#include "linux.h"
#include <dlfcn.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ucontext.h>
#include <unistd.h>

#define AM_SIG_KICK SIGUSR2
#define BIT(s) (1ull << ((s) - 1))
#define LSIG_KILL 9
#define LSIG_STOP 19
#define UNBLOCKABLE (BIT(LSIG_KILL) | BIT(LSIG_STOP))
#define SA_SIGINFO_L 0x4
#define SA_ONSTACK_L 0x08000000
#define SA_RESTORER_L 0x04000000
#define SA_NODEFER_L 0x40000000
#define SA_RESETHAND_L 0x80000000u

// ---- the Linux arm64 signal frame --------------------------------------------------------
typedef struct {
    int32_t si_signo, si_errno, si_code, _pad;
    union {
        struct { int32_t pid; uint32_t uid; } kill;
        struct { int32_t pid; uint32_t uid; int32_t status; int64_t utime, stime; } chld;
        struct { uint64_t addr; } fault;
        uint8_t _bytes[112];
    };
} linux_siginfo;
_Static_assert(sizeof(linux_siginfo) == 128, "siginfo");

typedef struct {
    uint64_t fault_address;
    uint64_t regs[31];
    uint64_t sp, pc, pstate;
    uint8_t __attribute__((aligned(16))) reserved[4096];
} linux_sigcontext;

typedef struct {
    uint64_t uc_flags, uc_link;
    uint64_t ss_sp; int32_t ss_flags, _pad; uint64_t ss_size;
    uint64_t uc_sigmask;
    uint8_t _unused[120];
    linux_sigcontext uc_mcontext;
} linux_ucontext;
_Static_assert(__builtin_offsetof(linux_ucontext, uc_mcontext) == 176, "ucontext");

typedef struct { uint32_t magic, size; uint32_t fpsr, fpcr; __uint128_t v[32]; } linux_fpsimd;
#define FPSIMD_MAGIC 0x46508001

typedef struct {
    linux_siginfo info;
    linux_ucontext uc;
    uint64_t fp, lr;   // frame record, so unwinders walk through the handler
} linux_rt_sigframe;

// ---- per-thread state for the call being handled -----------------------------------------
static __thread bool suspend_active;  // rt_sigsuspend: deliver with the mask from before it
static __thread uint64_t suspend_old;

static bool default_ignored(int sig) {
    return sig == 17 || sig == 18 || sig == 23 || sig == 28 ||  // CHLD CONT URG WINCH
           sig == 19 || sig == 20 || sig == 21 || sig == 22;    // stop signals: no job control yet
}

static uint64_t deliverable(am_thread *t) {
    return (t->sigpending | t->proc->sigpending) & ~(t->sigmask & ~UNBLOCKABLE);
}

static void kick(am_thread *t) {
    __atomic_add_fetch(&t->wake, 1, __ATOMIC_SEQ_CST);
    am_futex_wake(&t->wake, 1);
    if (t != am_self && t->host) pthread_kill(t->host, AM_SIG_KICK);
}

long am_kill_thread(am_thread *t, int sig, int code, int from_pid) {
    if (sig == 0) return 0;
    if (sig < 1 || sig > 64) return AM_ERR(LINUX_EINVAL);
    am_proc *p = t->proc;
    if (sig == LSIG_KILL) return am_kill_proc(p, sig, code, from_pid);
    uint64_t h = p->sig[sig].handler;
    if (h == 1 || (h == 0 && default_ignored(sig))) return 0;  // discarded at once
    __atomic_or_fetch(&t->sigpending, BIT(sig), __ATOMIC_SEQ_CST);
    kick(t);
    return 0;
}

long am_kill_proc(am_proc *p, int sig, int code, int from_pid) {
    if (sig == 0) return 0;
    if (sig < 1 || sig > 64) return AM_ERR(LINUX_EINVAL);
    pthread_mutex_lock(&p->lock);
    if (sig == LSIG_KILL) {
        p->exiting = true;
        p->exit_status = sig;
        for (am_thread *t = p->threads; t; t = t->next) { t->killed = true; kick(t); }
        pthread_mutex_unlock(&p->lock);
        return 0;
    }
    uint64_t h = p->sig[sig].handler;
    if (h == 1 || (h == 0 && default_ignored(sig))) { pthread_mutex_unlock(&p->lock); return 0; }
    am_thread *target = NULL;
    for (am_thread *t = p->threads; t; t = t->next)
        if (!(t->sigmask & BIT(sig))) { if (!target || t->tid == p->pid) target = t; }
    if (target) {
        __atomic_or_fetch(&target->sigpending, BIT(sig), __ATOMIC_SEQ_CST);
        kick(target);
    } else {
        __atomic_or_fetch(&p->sigpending, BIT(sig), __ATOMIC_SEQ_CST);
    }
    pthread_mutex_unlock(&p->lock);
    return 0;
}

// Takes the lowest deliverable signal off the pending sets; 0 if none.
static int take_signal(am_thread *t, uint64_t allowed) {
    for (;;) {
        uint64_t d = deliverable(t) & allowed;
        if (!d) return 0;
        int sig = __builtin_ctzll(d) + 1;
        uint64_t b = BIT(sig);
        if (__atomic_fetch_and(&t->sigpending, ~b, __ATOMIC_SEQ_CST) & b) return sig;
        if (__atomic_fetch_and(&t->proc->sigpending, ~b, __ATOMIC_SEQ_CST) & b) return sig;
    }
}

static bool on_altstack(am_thread *t, uint64_t sp) {
    return t->altstack[1] != 2 && sp > t->altstack[0] && sp <= t->altstack[0] + t->altstack[2];
}

// Enters the handler for sig: frame on the guest stack, registers as Linux sets them.
static void enter_handler(am_ctx *c, int sig, const linux_siginfo *info, uint64_t fault_addr) {
    am_thread *t = am_self;
    am_sigaction *sa = &t->proc->sig[sig];
    uint64_t sp = c->sp;
    if ((sa->flags & SA_ONSTACK_L) && t->altstack[1] != 2 && !on_altstack(t, sp))
        sp = t->altstack[0] + t->altstack[2];
    sp = (sp - sizeof(linux_rt_sigframe)) & ~15ull;
    linux_rt_sigframe *f = (void *)sp;
    memset(f, 0, offsetof(linux_rt_sigframe, uc.uc_mcontext.reserved) + sizeof(linux_fpsimd) + 8);
    f->info = *info;
    f->uc.ss_sp = t->altstack[0];
    f->uc.ss_flags = t->altstack[1] == 2 ? 2 : on_altstack(t, c->sp) ? 1 : 0;
    f->uc.ss_size = t->altstack[2];
    f->uc.uc_sigmask = suspend_active ? suspend_old : t->sigmask;
    suspend_active = false;
    linux_sigcontext *m = &f->uc.uc_mcontext;
    m->fault_address = fault_addr;
    memcpy(m->regs, c->x, sizeof m->regs);
    m->sp = c->sp;
    m->pc = c->pc;
    m->pstate = c->pstate;
    linux_fpsimd *fp = (void *)m->reserved;
    fp->magic = FPSIMD_MAGIC;
    fp->size = sizeof *fp;
    fp->fpsr = c->fpsr;
    fp->fpcr = c->fpcr;
    memcpy(fp->v, c->v, sizeof fp->v);
    // the zero terminator after it is already in place
    f->fp = c->x[29];
    f->lr = c->pc;

    t->sigmask |= sa->mask;
    if (!(sa->flags & SA_NODEFER_L)) t->sigmask |= BIT(sig);
    t->sigmask &= ~UNBLOCKABLE;
    uint64_t handler = sa->handler;
    if (sa->flags & SA_RESETHAND_L) sa->handler = 0;

    c->x[0] = sig;
    c->x[1] = (uint64_t)&f->info;
    c->x[2] = (uint64_t)&f->uc;
    c->sp = sp;
    c->x[29] = (uint64_t)&f->fp;
    extern void am_sigreturn_trampoline(void);
    c->x[30] = (sa->flags & SA_RESTORER_L) && sa->restorer ? sa->restorer : (uint64_t)am_sigreturn_trampoline;
    c->pc = handler;
}

static void default_action(int sig) {
    if (default_ignored(sig)) return;
    if (am_strace || sig != 13)
        fprintf(stderr, "andromach: pid %d killed by signal %d\n", am_self->proc->pid, sig);
    am_proc_exit(sig);  // a signal status, not an exit code
}

bool am_signal_deliver(am_ctx *c) {
    am_thread *t = am_self;
    if (t->killed) am_thread_exit();
    for (;;) {
        int sig = take_signal(t, ~0ull);
        if (!sig) return false;
        uint64_t h = t->proc->sig[sig].handler;
        if (h == 1) continue;
        if (h == 0) { default_action(sig); continue; }
        linux_siginfo si = {0};
        si.si_signo = sig;
        si.si_code = 0;  // SI_USER
        si.kill.pid = t->proc->pid;
        enter_handler(c, sig, &si, 0);
        return true;
    }
}

bool am_signal_fault(int sig, int code, uint64_t addr, am_ctx *c) {
    am_thread *t = am_self;
    uint64_t h = t->proc->sig[sig].handler;
    if (h <= 1 || (t->sigmask & BIT(sig))) return false;
    linux_siginfo si = {0};
    si.si_signo = sig;
    si.si_code = code;
    si.fault.addr = addr;
    enter_handler(c, sig, &si, addr);
    return true;
}

static long sigreturn(am_ctx *c) {
    am_thread *t = am_self;
    linux_rt_sigframe *f = (void *)c->sp;
    linux_sigcontext *m = &f->uc.uc_mcontext;
    memcpy(c->x, m->regs, sizeof c->x);
    c->sp = m->sp;
    c->pc = m->pc;
    c->pstate = m->pstate;
    const linux_fpsimd *fp = (const void *)m->reserved;
    if (fp->magic == FPSIMD_MAGIC) {
        c->fpsr = fp->fpsr;
        c->fpcr = fp->fpcr;
        memcpy(c->v, fp->v, sizeof c->v);
    }
    t->sigmask = f->uc.uc_sigmask & ~UNBLOCKABLE;
    return (long)c->x[0];  // the interrupted state's x0, which am_syscall writes back
}

// ---- host side ---------------------------------------------------------------------------
static void park(void *unused) { am_mg_yield(); }

static void on_kick(int sig, siginfo_t *si, void *uv) {
    (void)sig; (void)si;
    am_thread *t = am_self;
    if (!t || t->in_runtime) return;  // the system call in progress sees it on its way out
    struct __darwin_mcontext64 *m = ((ucontext_t *)uv)->uc_mcontext;
    // in_runtime is set a few instructions into a system call and cleared a few before its end;
    // around those, the thread is in host code or on its host stack, which counts as inside too.
    uint64_t sp = m->__ss.__sp;
    if (sp > (uint64_t)t->host_stack && sp <= (uint64_t)t->host_stack_top) return;
    if (dladdr((void *)m->__ss.__pc, &(Dl_info){0})) return;
    am_ctx c;
    am_ctx_from_mc(&c, m);
    if (t->killed) {
        // Leave guest code for the exit path on the host stack.
        memset(&c, 0, sizeof c);
        c.x[0] = (uint64_t)t;
        c.sp = (uint64_t)t->host_stack_top;
        c.pc = (uint64_t)am_thread_exit_tail;
        am_ctx_to_mc(m, &c);
        return;
    }
    t->in_runtime = 1;
    if (am_signal_deliver(&c)) am_ctx_to_mc(m, &c);
    // Another member of our memory group wants to run: park until it is our turn again. On
    // the host stack: this handler's frames are on the guest stack, whose pages the switch
    // swaps out.
    if (am_mg_wanted()) am_call_on_host_stack(park, NULL);
    t->in_runtime = 0;
}

void am_signal_init(void) {
    struct sigaction sa = {0};
    sa.sa_sigaction = on_kick;
    sa.sa_flags = SA_SIGINFO;  // no SA_RESTART: a kick must interrupt blocking host calls
    sigaction(AM_SIG_KICK, &sa, NULL);
    signal(SIGPIPE, SIG_IGN);  // the guest gets EPIPE, and SIGPIPE through its own rules
}

// ---- system calls ------------------------------------------------------------------------
#define A(i) (c->x[i])

typedef struct { int tid; am_thread *t; } find_q;

static void find_scan(am_proc *pp, void *arg) {
    find_q *q = arg;
    pthread_mutex_lock(&pp->lock);
    for (am_thread *t = pp->threads; t; t = t->next) if (t->tid == q->tid) q->t = t;
    pthread_mutex_unlock(&pp->lock);
}

typedef struct { int pgid, sig, from, n; } kill_q;

static void kill_each(am_proc *p, void *arg) {
    kill_q *q = arg;
    if (q->pgid && p->pgid != q->pgid) return;
    if (!q->pgid && p->pid == q->from) return;
    am_kill_proc(p, q->sig, 0, q->from);
    q->n++;
}

static am_thread *find_thread(int tid) {
    am_proc *p = am_self->proc;
    am_thread *found = NULL;
    pthread_mutex_lock(&p->lock);
    for (am_thread *t = p->threads; t; t = t->next) if (t->tid == tid) found = t;
    pthread_mutex_unlock(&p->lock);
    if (found) return found;
    // A thread of another process: look through them all.
    find_q q = {tid, NULL};
    am_proc_for_each(find_scan, &q);
    return q.t;
}

static long sys_kill(int pid, int sig) {
    am_proc *self = am_self->proc;
    if (pid > 0) {
        am_proc *p = am_proc_get(pid);
        if (!p) return AM_ERR(LINUX_ESRCH);
        return am_kill_proc(p, sig, 0, self->pid);
    }
    // a process group (0: our own), or every process (-1)
    kill_q q = {pid == 0 ? self->pgid : -pid, sig, self->pid, 0};
    if (pid == -1) q.pgid = 0;
    am_proc_for_each(kill_each, &q);
    return q.n ? 0 : AM_ERR(LINUX_ESRCH);
}

long sys_signal(am_ctx *c, long nr, bool *handled, int from_trap) {
    *handled = true;
    am_thread *t = am_self;
    am_proc *p = t->proc;
    switch (nr) {
    case LINUX_SYS_rt_sigaction: {
        int sig = (int)A(0);
        if (sig < 1 || sig > 64) return AM_ERR(LINUX_EINVAL);
        if (A(2)) *(am_sigaction *)A(2) = p->sig[sig];
        if (A(1)) {
            if (sig == LSIG_KILL || sig == LSIG_STOP) return AM_ERR(LINUX_EINVAL);
            p->sig[sig] = *(am_sigaction *)A(1);
        }
        return 0;
    }
    case LINUX_SYS_rt_sigprocmask: {
        uint64_t old = t->sigmask;
        if (A(1)) {
            uint64_t set = *(uint64_t *)A(1);
            if (A(0) == 0) t->sigmask |= set;
            else if (A(0) == 1) t->sigmask &= ~set;
            else if (A(0) == 2) t->sigmask = set;
            else return AM_ERR(LINUX_EINVAL);
            t->sigmask &= ~UNBLOCKABLE;
        }
        if (A(2)) *(uint64_t *)A(2) = old;
        return 0;
    }
    case LINUX_SYS_sigaltstack: {
        if (A(1)) {
            uint64_t *o = (uint64_t *)A(1);
            o[0] = t->altstack[0];
            o[1] = t->altstack[1] == 2 ? 2 : on_altstack(t, c->sp) ? 1 : 0;
            o[2] = t->altstack[2];
        }
        if (A(0)) {
            if (on_altstack(t, c->sp)) return AM_ERR(LINUX_EPERM);
            const uint64_t *n = (const uint64_t *)A(0);
            t->altstack[0] = n[0];
            t->altstack[1] = (uint32_t)n[1] & 2;
            t->altstack[2] = n[2];
        }
        return 0;
    }
    case LINUX_SYS_rt_sigpending: *(uint64_t *)A(0) = (t->sigpending | p->sigpending) & t->sigmask; return 0;
    case LINUX_SYS_rt_sigreturn: return sigreturn(c);
    case LINUX_SYS_rt_sigsuspend: {
        suspend_old = t->sigmask;
        t->sigmask = *(uint64_t *)A(0) & ~UNBLOCKABLE;
        for (;;) {
            uint32_t w = __atomic_load_n(&t->wake, __ATOMIC_SEQ_CST);
            if (deliverable(t) || t->killed) break;
            am_block_begin();
            am_futex_wait_interruptible(&t->wake, w);
            am_block_end();
        }
        suspend_active = true;  // the handler's frame records the old mask, restored on return
        return AM_ERR(LINUX_EINTR);
    }
    case LINUX_SYS_rt_sigtimedwait: {
        uint64_t set = *(uint64_t *)A(0);
        const struct linux_timespec *ts = (void *)A(2);
        uint64_t deadline = 0;
        if (ts) {
            struct timespec now;
            clock_gettime(CLOCK_MONOTONIC, &now);
            deadline = (now.tv_sec + ts->tv_sec) * 1000000000ull + now.tv_nsec + ts->tv_nsec;
        }
        for (;;) {
            uint32_t w = __atomic_load_n(&t->wake, __ATOMIC_SEQ_CST);
            uint64_t avail = (t->sigpending | p->sigpending) & set;
            if (avail) {
                int sig = __builtin_ctzll(avail) + 1;
                __atomic_fetch_and(&t->sigpending, ~BIT(sig), __ATOMIC_SEQ_CST);
                __atomic_fetch_and(&p->sigpending, ~BIT(sig), __ATOMIC_SEQ_CST);
                if (A(1)) {
                    linux_siginfo *si = (void *)A(1);
                    memset(si, 0, sizeof *si);
                    si->si_signo = sig;
                }
                return sig;
            }
            if (deliverable(t) & ~set) return AM_ERR(LINUX_EINTR);
            if (ts) {
                struct timespec now;
                clock_gettime(CLOCK_MONOTONIC, &now);
                uint64_t n = now.tv_sec * 1000000000ull + now.tv_nsec;
                if (n >= deadline) return AM_ERR(LINUX_EAGAIN);
                am_block_begin();
                usleep((deadline - n) / 1000 < 10000 ? (deadline - n) / 1000 : 10000);
                am_block_end();
            } else {
                am_block_begin();
                am_futex_wait_interruptible(&t->wake, w);
                am_block_end();
            }
        }
    }
    case LINUX_SYS_kill: return sys_kill((int)A(0), (int)A(1));
    case LINUX_SYS_tgkill: case LINUX_SYS_tkill: case 240: /* rt_tgsigqueueinfo */ {
        int tid = (int)(nr == LINUX_SYS_tkill ? A(0) : A(1));
        int sig = (int)(nr == LINUX_SYS_tkill ? A(1) : A(2));
        am_thread *target = find_thread(tid);
        if (!target) return AM_ERR(LINUX_ESRCH);
        return am_kill_thread(target, sig, 0, p->pid);
    }
    case 138: /* rt_sigqueueinfo */ {
        am_proc *target = am_proc_get((int)A(0));
        if (!target) return AM_ERR(LINUX_ESRCH);
        return am_kill_proc(target, (int)A(1), 0, p->pid);
    }
    }
    (void)from_trap;
    *handled = false;
    return 0;
}
