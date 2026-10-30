// Threads and futexes. Each guest thread is a Darwin pthread; its guest thread pointer lives in
// a reserved TSD slot (see trap.c), and Linux futexes map onto os_sync_wait_on_address.
#include "am.h"
#include "linux.h"
#include <errno.h>
#include <mach/mach_time.h>
#include <os/os_sync_wait_on_address.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

static int next_tid = 0;  // pids and tids share one space, as on Linux; the first process is pid 1

int am_new_tid(void) { return __atomic_add_fetch(&next_tid, 1, __ATOMIC_RELAXED); }


// ---- futex -------------------------------------------------------------------------------
static uint64_t now_ns(int clock) {
    struct timespec ts;
    clock_gettime(clock, &ts);
    return (uint64_t)ts.tv_sec * 1000000000ull + ts.tv_nsec;
}

static long futex_wait(uint32_t *addr, uint32_t val, const struct linux_timespec *ts, bool absolute, bool realtime) {
    if (__atomic_load_n(addr, __ATOMIC_SEQ_CST) != val) return AM_ERR(LINUX_EAGAIN);
    int r;
    if (!ts) {
        r = os_sync_wait_on_address(addr, val, 4, OS_SYNC_WAIT_ON_ADDRESS_NONE);
    } else {
        uint64_t ns = (uint64_t)ts->tv_sec * 1000000000ull + ts->tv_nsec;
        if (absolute) {
            uint64_t now = now_ns(realtime ? CLOCK_REALTIME : CLOCK_MONOTONIC);
            if (ns <= now) return AM_ERR(LINUX_ETIMEDOUT);
            ns -= now;
        }
        if (!ns) return AM_ERR(LINUX_ETIMEDOUT);
        r = os_sync_wait_on_address_with_timeout(addr, val, 4, OS_SYNC_WAIT_ON_ADDRESS_NONE,
                                                 OS_CLOCK_MACH_ABSOLUTE_TIME, ns);
    }
    if (r >= 0) return 0;
    if (errno == ETIMEDOUT) return AM_ERR(LINUX_ETIMEDOUT);
    if (errno == EINTR) return AM_ERR(LINUX_EINTR);
    return 0;
}

long am_futex_wake(uint32_t *addr, int n) {
    if (n <= 0) return 0;
    int r = n == 1 ? os_sync_wake_by_address_any(addr, 4, OS_SYNC_WAKE_BY_ADDRESS_NONE)
                   : os_sync_wake_by_address_all(addr, 4, OS_SYNC_WAKE_BY_ADDRESS_NONE);
    return r == 0 ? 1 : 0;  // the number woken is not reported; callers only test for > 0
}

long am_futex_wait_interruptible(uint32_t *addr, uint32_t val) {
    // Bounded, so a kick that lands just before the wait cannot strand the thread.
    struct linux_timespec ts = {0, 50 * 1000000};
    return futex_wait(addr, val, &ts, false, false);
}

#define FUTEX_WAITERS 0x80000000u
#define FUTEX_TID_MASK 0x3FFFFFFFu

static long futex_lock_pi(uint32_t *addr, const struct linux_timespec *ts) {
    uint32_t tid = am_self->tid;
    for (;;) {
        uint32_t v = __atomic_load_n(addr, __ATOMIC_SEQ_CST);
        if (!(v & FUTEX_TID_MASK)) {
            if (__atomic_compare_exchange_n(addr, &v, tid | (v & FUTEX_WAITERS), false, __ATOMIC_SEQ_CST, __ATOMIC_SEQ_CST))
                return 0;
            continue;
        }
        if ((v & FUTEX_TID_MASK) == tid) return AM_ERR(35);  // EDEADLK
        if (!(v & FUTEX_WAITERS) &&
            !__atomic_compare_exchange_n(addr, &v, v | FUTEX_WAITERS, false, __ATOMIC_SEQ_CST, __ATOMIC_SEQ_CST))
            continue;
        long r = futex_wait(addr, v | FUTEX_WAITERS, ts, true, true);
        if (r == AM_ERR(LINUX_ETIMEDOUT)) return r;
    }
}

static long futex_unlock_pi(uint32_t *addr) {
    __atomic_store_n(addr, 0, __ATOMIC_SEQ_CST);
    os_sync_wake_by_address_all(addr, 4, OS_SYNC_WAKE_BY_ADDRESS_NONE);
    return 0;
}

static long sys_futex(uint32_t *addr, int op, uint32_t val, uint64_t arg4, uint32_t *addr2, uint32_t val3) {
    bool realtime = op & LINUX_FUTEX_CLOCK_REALTIME;
    const struct linux_timespec *ts = (const void *)arg4;
    switch (op & 0x7F) {
    case LINUX_FUTEX_WAIT: return futex_wait(addr, val, ts, false, false);
    case LINUX_FUTEX_WAIT_BITSET: return futex_wait(addr, val, ts, true, realtime);
    case LINUX_FUTEX_WAKE: case LINUX_FUTEX_WAKE_BITSET: return am_futex_wake(addr, (int)val);
    case LINUX_FUTEX_REQUEUE: case LINUX_FUTEX_CMP_REQUEUE:
        if ((op & 0x7F) == LINUX_FUTEX_CMP_REQUEUE && __atomic_load_n(addr, __ATOMIC_SEQ_CST) != val3)
            return AM_ERR(LINUX_EAGAIN);
        // Waking everyone is a valid (spurious-wakeup) implementation of requeue.
        am_futex_wake(addr, 0x7FFFFFFF);
        am_futex_wake(addr2, 0x7FFFFFFF);
        return 1;
    case LINUX_FUTEX_WAKE_OP: {
        // *addr2 = op(*addr2, oparg); wake addr; if cmp(old, cmparg) wake addr2.
        int opc = (val3 >> 28) & 7, cmp = (val3 >> 24) & 15;
        int oparg = (int)(val3 << 8) >> 20, cmparg = (int)(val3 << 20) >> 20;
        if (val3 & (8u << 28)) oparg = 1 << oparg;
        uint32_t old = __atomic_load_n(addr2, __ATOMIC_SEQ_CST), nv;
        do {
            switch (opc) {
            case 0: nv = oparg; break;
            case 1: nv = old + oparg; break;
            case 2: nv = old | oparg; break;
            case 3: nv = old & ~oparg; break;
            default: nv = old ^ oparg; break;
            }
        } while (!__atomic_compare_exchange_n(addr2, &old, nv, false, __ATOMIC_SEQ_CST, __ATOMIC_SEQ_CST));
        long n = am_futex_wake(addr, (int)val);
        bool hit;
        switch (cmp) {
        case 0: hit = (int)old == cmparg; break;
        case 1: hit = (int)old != cmparg; break;
        case 2: hit = (int)old < cmparg; break;
        case 3: hit = (int)old <= cmparg; break;
        case 4: hit = (int)old > cmparg; break;
        default: hit = (int)old >= cmparg; break;
        }
        if (hit) n += am_futex_wake(addr2, (int)arg4);
        return n;
    }
    case LINUX_FUTEX_LOCK_PI: return futex_lock_pi(addr, ts);
    case 13: /* FUTEX_LOCK_PI2 */ return futex_lock_pi(addr, ts);
    case LINUX_FUTEX_UNLOCK_PI: return futex_unlock_pi(addr);
    case 8: /* FUTEX_TRYLOCK_PI */ {
        uint32_t z = 0;
        return __atomic_compare_exchange_n(addr, &z, am_self->tid, false, __ATOMIC_SEQ_CST, __ATOMIC_SEQ_CST)
                   ? 0 : AM_ERR(LINUX_EAGAIN);
    }
    }
    return AM_ERR(LINUX_ENOSYS);
}

// ---- threads -----------------------------------------------------------------------------
#define HOST_STACK (128 * 1024)

am_thread *am_thread_new(am_proc *p, int tid) {
    am_thread *t = calloc(1, sizeof *t);
    t->proc = p;
    t->tid = tid;
    t->altstack[1] = 2;  // SS_DISABLE
    t->host_stack = malloc(HOST_STACK);
    t->host_stack_top = (void *)(((uintptr_t)t->host_stack + HOST_STACK) & ~15ul);
    pthread_mutex_lock(&p->lock);
    t->next = p->threads;
    p->threads = t;
    p->nthreads++;
    pthread_mutex_unlock(&p->lock);
    return t;
}

// Unlinks t from its process; returns how many threads the process has left.
static int thread_unlink(am_thread *t) {
    am_proc *p = t->proc;
    pthread_mutex_lock(&p->lock);
    for (am_thread **pp = &p->threads; *pp; pp = &(*pp)->next)
        if (*pp == t) { *pp = t->next; break; }
    int left = --p->nthreads;
    pthread_mutex_unlock(&p->lock);
    return left;
}

void am_thread_free(am_thread *t) {
    // The host stack may be the one we are running on; it is leaked rather than freed under us.
    free(t);
}

// Switches the calling thread to its host stack and runs fn there. For leaving a guest stack
// that is about to be unmapped or restored (thread exit, exec, the end of a fork child).
void am_run_on_host_stack(void (*fn)(void *), void *arg) {
    am_ctx c = {0};
    c.x[0] = (uint64_t)arg;
    c.sp = (uint64_t)am_self->host_stack_top;
    c.pc = (uint64_t)fn;
    am_resume(&c);
}

typedef struct { am_thread *t; am_ctx ctx; uint64_t tls; } start_arg;

static void *thread_main(void *arg) {
    start_arg a = *(start_arg *)arg;
    free(arg);
    am_self = a.t;
    am_thread_tsd_init(a.tls);
    am_resume(&a.ctx);
}

// Runs t on a new host thread from register state c, with guest thread pointer tls.
int am_thread_start(am_thread *t, const am_ctx *c, uint64_t tls) {
    start_arg *a = malloc(sizeof *a);
    a->t = t;
    a->ctx = *c;
    a->tls = tls;
    pthread_attr_t at;
    pthread_attr_init(&at);
    pthread_attr_setstacksize(&at, 256 * 1024);
    pthread_attr_setdetachstate(&at, PTHREAD_CREATE_DETACHED);
    int r = pthread_create(&t->host, &at, thread_main, a);
    pthread_attr_destroy(&at);
    if (r) free(a);
    return r;
}

void am_thread_exit_tail(void *arg) {
    am_thread *t = arg;
    if (t->clear_child_tid) {
        __atomic_store_n((uint32_t *)t->clear_child_tid, 0, __ATOMIC_SEQ_CST);
        am_futex_wake((uint32_t *)t->clear_child_tid, 1);
    }
    am_proc *p = t->proc;
    int left = thread_unlink(t);
    am_self = NULL;
    am_thread_free(t);
    if (!left && !p->exiting) {
        // The last thread leaving ends the process, with status 0 as Linux does.
        am_thread tmp = {.proc = p, .tid = p->pid};
        am_self = &tmp;
        am_proc_exit(0);
    }
    pthread_exit(NULL);
}

void am_thread_exit(void) {
    am_run_on_host_stack(am_thread_exit_tail, am_self);
}

static long sys_clone(am_ctx *c, uint64_t flags, uint64_t newsp, uint64_t ptid, uint64_t tls, uint64_t ctid) {
    int tid = am_new_tid();
    am_thread *t = am_thread_new(am_self->proc, tid);
    t->sigmask = am_self->sigmask;
    if (flags & LINUX_CLONE_CHILD_CLEARTID) t->clear_child_tid = ctid;
    if (flags & LINUX_CLONE_PARENT_SETTID) *(int *)ptid = tid;
    if (flags & LINUX_CLONE_CHILD_SETTID) *(int *)ctid = tid;
    am_ctx child = *c;
    child.x[0] = 0;
    if (newsp) child.sp = newsp;
    uint64_t *tsd;
    __asm__ volatile("mrs %0, tpidrro_el0" : "=r"(tsd));
    if (am_thread_start(t, &child, (flags & LINUX_CLONE_SETTLS) ? tls : tsd[AM_TSD_GUEST_TP])) {
        thread_unlink(t);
        am_thread_free(t);
        return AM_ERR(LINUX_EAGAIN);
    }
    return tid;
}

#define A(i) (c->x[i])

long sys_thread(am_ctx *c, long nr, bool *handled) {
    *handled = true;
    switch (nr) {
    case LINUX_SYS_clone:
        if (!(A(0) & LINUX_CLONE_THREAD)) break;  // a new process: proc.c
        return sys_clone(c, A(0), A(1), A(2), A(3), A(4));
    case LINUX_SYS_clone3: {
        struct { uint64_t flags, pidfd, child_tid, parent_tid, exit_signal, stack, stack_size, tls; } *a = (void *)A(0);
        if (!(a->flags & LINUX_CLONE_THREAD)) break;
        return sys_clone(c, a->flags, a->stack ? a->stack + a->stack_size : 0, a->parent_tid, a->tls, a->child_tid);
    }
    case LINUX_SYS_exit: am_thread_exit();
    case LINUX_SYS_futex: return sys_futex((uint32_t *)A(0), (int)A(1), (uint32_t)A(2), A(3), (uint32_t *)A(4), (uint32_t)A(5));
    case LINUX_SYS_set_tid_address: am_self->clear_child_tid = A(0); return am_self->tid;
    case LINUX_SYS_set_robust_list: return 0;
    case LINUX_SYS_gettid: return am_self->tid;
    case LINUX_SYS_getpid: return am_self->proc->pid;
    case LINUX_SYS_getppid: return am_self->proc->ppid;
    }
    *handled = false;
    return 0;
}
